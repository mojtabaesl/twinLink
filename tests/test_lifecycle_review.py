"""Regression tests for withdrawal, preflight, boot, and receipt review findings."""
import contextlib
import copy
import io
import json
from unittest.mock import patch, MagicMock

from tests.test_v2 import V2Fixture, FACTS, FakeRuntime
from tests.test_profile_runtime import SystemHost
from twinlink import cli
from twinlink.contracts import validate_reservations, validate_revision, next_revision
from twinlink.coordination import Coordinator, new_transaction, steps, validate_receipt, receipt_hash, consume
from twinlink.models import ValidationError
from twinlink.ownership import Ownership
from twinlink.profile_runtime import ProfileRuntime
from twinlink.profiles import table_name, gre_record
from twinlink.store import Store, StateError, atomic_write


class RuntimeFixture(V2Fixture):
    def setUp(self):
        super().setUp()
        self.host = SystemHost(self.root / "units")
        self.binary = self.root / "rathole"
        atomic_write(self.binary, "pinned test binary", 0o755)
        self.runtime = ProfileRuntime(self.store, self.host, str(self.host.unit_dir), rathole_binary=str(self.binary))

    def prepare(self, role="vps1", revision=None):
        with patch("twinlink.rathole.check_version"):
            self.runtime.materialize(revision or self.r, role)

    def committed(self, profile="direct-rathole"):
        state = self.store.read()
        state["pairs"]["edge"].update(active={"profile": profile, "revision": 1, "epoch": 1}, epoch=1)
        self.store.write(state)
        return state["pairs"]["edge"]


class WithdrawalReviewTests(RuntimeFixture):
    def setUp(self):
        super().setUp()
        self.stage()
        self.prepare()

    def inactive_conflict(self):
        path = self.host.unit_dir / self.runtime.runtime_unit(self.r, "gre-rathole")
        path.write_text("foreign inactive unit")
        return path

    def test_active_process_stops_before_inactive_unit_conflict_is_reported(self):
        control = self.committed()
        active = self.runtime.runtime_unit(self.r, "direct-rathole")
        self.host.active.add(active)
        foreign = self.inactive_conflict()
        checked = []
        original = self.runtime.assert_unit_safe
        def check(name):
            checked.append(name)
            return original(name)
        with patch.object(self.runtime, "assert_unit_safe", side_effect=check), self.assertRaises(StateError):
            self.runtime.quiesce(self.r, "vps1", "direct-rathole", control, {"previous": control["active"]})
        self.assertNotIn(active, self.host.active)
        self.assertEqual(checked[0], active)
        self.assertEqual(foreign.read_text(), "foreign inactive unit")

    def test_inactive_conflict_does_not_prevent_kernel_withdrawal(self):
        control = self.committed("gre-kernel")
        tx = {"previous": control["active"]}
        self.runtime.prepare(self.r, "vps1", "gre-kernel", control, tx)
        self.runtime.start(self.r, "vps1", "gre-kernel", control, tx)
        foreign = self.inactive_conflict()
        with self.assertRaises(StateError):
            self.runtime.quiesce(self.r, "vps1", "gre-kernel", control, tx)
        self.assertFalse(self.host.tables)
        self.assertFalse(self.host.links())
        self.assertEqual(self.host.forwarding, "0")
        self.assertEqual(foreign.read_text(), "foreign inactive unit")

    def test_expiry_withdraws_active_process_despite_inactive_conflict(self):
        state = self.store.read()
        control = state["pairs"]["edge"]
        tx = new_transaction("edge", self.r, "direct-rathole", control, now=100)
        tx.update(phase="verifying", verification_deadline=160)
        control["transition"] = tx
        self.store.write(state)
        active = self.runtime.runtime_unit(self.r, "direct-rathole")
        self.host.active.add(active)
        self.runtime.arm_verification_expiry(self.r, "vps1", "direct-rathole", control, tx)
        foreign = self.inactive_conflict()
        with self.assertRaises(StateError):
            Coordinator(self.store, self.runtime, lambda: 161).expire_verification("edge")
        self.assertNotIn(active, self.host.active)
        self.assertEqual(foreign.read_text(), "foreign inactive unit")
        self.assertEqual(self.store.read()["pairs"]["edge"]["transition"]["phase"], "recovery-required")


class BackendReviewTests(RuntimeFixture):
    def setUp(self):
        super().setUp()
        self.stage("vps2")
        self.prepare("vps2")
        self.host.addresses = lambda: [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": self.r["public_endpoints"]["vps2"]}]}]

    def preflight(self, revision=None):
        with patch.object(self.runtime, "discover", return_value=FACTS):
            self.runtime.preflight(revision or self.r, "vps2", "gre-kernel", self.store.read()["pairs"]["edge"], {})

    def test_unreachable_replacement_backend_keeps_working_runtime(self):
        control = self.committed()
        active = self.runtime.runtime_unit(self.r, "direct-rathole")
        self.host.active.add(active)
        peer = Store(self.root / "peer")
        self.stage("vps1", peer)
        state = peer.read()
        state["pairs"]["edge"].update(active=control["active"], epoch=1)
        peer.write(state)
        incoming = Coordinator(peer, FakeRuntime(), lambda: 100).advance("edge", self.r, "gre-kernel")["receipt"]
        with patch.object(self.runtime, "discover", return_value=FACTS), patch("twinlink.diagnostics.application_probe", return_value={"result": "fail", "error": "TimeoutError"}) as probe:
            with self.assertRaisesRegex(StateError, "Backend preflight"):
                Coordinator(self.store, self.runtime, lambda: 100).advance("edge", self.r, "gre-kernel", incoming)
        self.assertEqual(probe.call_args.args[0]["address"], "10.20.30.40")
        self.assertEqual(probe.call_args.args[0]["port"], 80)
        self.assertIn(active, self.host.active)
        self.assertEqual(self.store.read()["pairs"]["edge"]["active"], control["active"])
        self.assertFalse(any(a[:2] == ["systemctl", "stop"] for a in self.host.commands))

    def test_all_backend_range_ports_receive_bounded_exchanges(self):
        with patch("twinlink.diagnostics.application_probe", return_value={"result": "pass"}) as probe:
            self.preflight()
        self.assertEqual([c.args[0]["port"] for c in probe.call_args_list], [80, 81])
        for call in probe.call_args_list:
            self.assertEqual(call.args[0]["exchange"], self.r["services"][0]["probe"])
            self.assertLessEqual(call.kwargs["timeout"], 3)

    def test_many_to_one_backend_probes_are_deduplicated(self):
        service = copy.deepcopy(self.r["services"][0])
        service["backend"]["ports"] = "80"
        revised = next_revision(self.r, services=[service])
        self.store.stage(self.store.read(), revised, "vps2", self.creds, FACTS)
        self.prepare("vps2", revised)
        with patch("twinlink.diagnostics.application_probe", return_value={"result": "pass"}) as probe:
            self.preflight(revised)
        self.assertEqual(probe.call_count, 1)

    def test_backend_budget_and_unknown_results_fail_closed(self):
        with patch("twinlink.diagnostics.application_probe", return_value={"result": "unknown", "error": "PermissionError"}), self.assertRaisesRegex(StateError, "Backend preflight"):
            self.preflight()
        clock = [0]
        def slow(*args, **kwargs):
            clock[0] += 31
            return {"result": "pass"}
        with patch("twinlink.profile_runtime.time.monotonic", side_effect=lambda: clock[0]), patch("twinlink.diagnostics.application_probe", side_effect=slow):
            with self.assertRaisesRegex(StateError, "60-second"):
                self.preflight()

    def test_tcp_and_udp_backend_recipes_execute_actual_exchange_code(self):
        for protocol, response, succeeds in (("tcp", b"b", True), ("udp", b"b", True), ("udp", b"b-extra", False)):
            with self.subTest(protocol=protocol, response=response):
                revision = copy.deepcopy(self.r)
                revision["services"][0].update(protocol=protocol, ports="8081", backend={"address": "10.20.30.40", "ports": "80"})
                sock = MagicMock()
                sock.__enter__.return_value = sock
                sock.recv.side_effect = lambda length: response[:length]
                with patch("socket.socket", return_value=sock):
                    if succeeds:
                        self.runtime.probe_backends(revision)
                    else:
                        with self.assertRaises(StateError):
                            self.runtime.probe_backends(revision)
                sock.connect.assert_called_once_with(("10.20.30.40", 80))
                sock.sendall.assert_called_once_with(b"a")


class ReservationReviewTests(V2Fixture):
    def other(self, key=None, reverse=False):
        other = copy.deepcopy(self.r)
        other.update(pair_id="other", transport={"port": 4567}, services=[])
        other["gre"].update(addresses={"vps1": "10.78.0.1/30", "vps2": "10.78.0.2/30"}, key=key, mtu=1472)
        if reverse:
            other["public_endpoints"] = {"vps1": self.r["public_endpoints"]["vps2"], "vps2": self.r["public_endpoints"]["vps1"]}
        return validate_revision(other)

    def test_duplicate_endpoint_key_identity_rejected_even_with_distinct_ports_subnets(self):
        for key in (None, 42):
            proposed = validate_revision({**self.r, "gre": {**self.r["gre"], "key": key, "mtu": 1472}})
            for reverse in (False, True):
                with self.subTest(key=key, reverse=reverse), self.assertRaisesRegex(ValidationError, "GRE endpoints and key"):
                    validate_reservations(proposed, [self.other(key, reverse)])

    def test_distinct_key_or_endpoint_and_same_pair_revision_are_permitted(self):
        validate_reservations(self.r, [self.other(42)])
        other = self.other()
        other["public_endpoints"]["vps2"] = "203.0.113.3"
        validate_reservations(self.r, [other])
        validate_reservations(self.r, [{**self.r, "revision": 2}])

    def test_staging_checks_another_pairs_active_revision_as_well_as_staged(self):
        state = self.stage()
        state["pairs"]["edge"].update(active={"revision": 1, "profile": "gre-kernel", "epoch": 1}, epoch=1)
        self.store.write(state)
        revised = next_revision(self.r, gre={**self.r["gre"], "key": 42, "mtu": 1472})
        state = self.store.stage(state, revised, "vps1", self.creds, FACTS)
        with self.assertRaisesRegex(ValidationError, "GRE endpoints and key"):
            self.store.stage(state, self.other(), "vps1", self.creds, FACTS)
        self.assertEqual(self.store.read(), state)


class BootReviewTests(RuntimeFixture):
    def setUp(self):
        super().setUp()
        self.stage()
        self.prepare()
        self.other = copy.deepcopy(self.r)
        self.other.update(pair_id="other", transport={"port": 4567})
        self.other["public_endpoints"]["vps2"] = "203.0.113.3"
        self.other["services"][0]["ports"] = "9081-9082"
        self.other["gre"]["addresses"] = {"vps1": "10.78.0.1/30", "vps2": "10.78.0.2/30"}
        state = self.store.stage(self.store.read(), self.other, "vps1", self.creds, FACTS)
        self.prepare(revision=self.other)
        for control in state["pairs"].values():
            control.update(active={"profile": "gre-kernel", "revision": 1, "epoch": 1}, epoch=1)
        self.store.write(state)

    def test_stale_pair_does_not_block_another_committed_pair(self):
        self.store.preparation_path("edge", 1).unlink()
        with patch.object(self.runtime, "discover", return_value=FACTS):
            results = self.runtime.boot()
        self.assertEqual([(r["pair"], r["status"]) for r in results], [("edge", "failed"), ("other", "active-unverified")])
        self.assertEqual(results[0]["phase"], "preflight")
        self.assertIn(table_name("other"), self.host.tables)

    def test_failed_start_withdraws_only_its_partial_resources_and_continues(self):
        original = self.host.run
        def fail(argv, **kwargs):
            if argv == ["nft", "--file", "-"] and table_name("edge") in kwargs.get("input", ""):
                raise OSError("injected nft failure")
            return original(argv, **kwargs)
        with patch.object(self.runtime, "discover", return_value=FACTS), patch.object(self.host, "run", side_effect=fail):
            results = self.runtime.boot()
        self.assertEqual(results[0]["status"], "failed")
        self.assertEqual(results[0]["phase"], "start")
        self.assertEqual(results[1]["status"], "active-unverified")
        self.assertNotIn(gre_record(self.r, "vps1")["interface"], {r["ifname"] for r in self.host.links()})
        self.assertIn(table_name("other"), self.host.tables)
        self.assertEqual(self.runtime.ledger.read()["resources"]["sysctl:net.ipv4.ip_forward"]["owners"], ["other"])

    def test_internal_restore_reports_aggregate_failure_and_all_pair_results(self):
        expected = [{"pair": "edge", "status": "failed", "error": "stale preparation"}, {"pair": "other", "status": "active-unverified"}]
        output = io.StringIO()
        with patch.object(ProfileRuntime, "boot", return_value=expected), contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(["--state-dir", str(self.store.directory), "internal", "restore"]), 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["pairs"], expected)


class CheckReviewTests(RuntimeFixture):
    def setUp(self):
        super().setUp()
        self.stage()
        self.prepare()

    def check(self):
        with patch.object(cli, "Host", return_value=self.host), patch.object(ProfileRuntime, "discover", return_value=FACTS), contextlib.redirect_stdout(io.StringIO()):
            return cli.main(["--state-dir", str(self.store.directory), "--unit-dir", str(self.host.unit_dir), "profile", "check", "gre-kernel"])

    def test_pending_enablement_is_not_reconciled_by_read_only_profile_check(self):
        self.runtime.ledger.begin("unit-enable:twinlink-v2-restore.service", "unit-enable", "edge", True, True, "restore-unit-enablement")
        before = self.runtime.ledger.path.read_bytes()
        state_before = self.store.path.read_bytes()
        self.assertEqual(self.check(), 4)
        self.assertEqual(self.runtime.ledger.path.read_bytes(), before)
        self.assertEqual(self.store.path.read_bytes(), state_before)
        # The applied lifecycle can reconcile under its normal mutation lock.
        with self.store.lock(), patch.object(self.runtime, "discover", return_value=FACTS):
            self.runtime.preflight(self.r, "vps1", "gre-kernel", self.store.read()["pairs"]["edge"], {})
        self.assertEqual(self.runtime.ledger.read()["resources"]["unit-enable:twinlink-v2-restore.service"]["status"], "complete")

    def test_pending_nft_proof_is_not_bound_or_saved_by_profile_check(self):
        with patch.object(Ownership, "bind_expected", side_effect=OSError("death before proof bind")), self.assertRaises(OSError):
            self.runtime._install_table(self.r, "vps1", "gre-kernel")
        before = self.runtime.ledger.path.read_bytes()
        self.assertEqual(self.check(), 4)
        self.assertEqual(self.runtime.ledger.path.read_bytes(), before)

    def test_completed_ownership_profile_check_is_read_only_and_passes(self):
        before = self.runtime.ledger.path.read_bytes()
        with patch.object(Store, "lock", side_effect=AssertionError("read-only check must not mutate")):
            self.assertEqual(self.check(), 0)
        self.assertEqual(self.runtime.ledger.path.read_bytes(), before)


class PhaseRevalidationReviewTests(RuntimeFixture):
    def setUp(self):
        super().setUp()
        self.stage()
        self.prepare()

    def test_prepare_refresh_checks_gre_instead_of_recreating_it(self):
        control = self.store.read()["pairs"]["edge"]
        tx = {"previous": None, "refresh_step": "prepare"}
        with self.assertRaises(StateError):
            self.runtime.revalidate(self.r, "vps1", "gre-kernel", control, tx)
        self.assertFalse(any(a[:3] == ["ip", "link", "add"] for a in self.host.commands))
        self.runtime.prepare(self.r, "vps1", "gre-kernel", control, tx)
        count = len(self.host.commands)
        self.runtime.revalidate(self.r, "vps1", "gre-kernel", control, tx)
        self.assertFalse(any(a[:3] == ["ip", "link", "add"] for a in self.host.commands[count:]))

    def test_start_refresh_checks_local_runtime_without_restarting_or_public_probes(self):
        control = self.store.read()["pairs"]["edge"]
        tx = {"previous": None, "refresh_step": "start"}
        self.runtime.prepare(self.r, "vps1", "gre-kernel", control, tx)
        self.runtime.start(self.r, "vps1", "gre-kernel", control, tx)
        count = len(self.host.commands)
        with patch.object(self.runtime, "start", side_effect=AssertionError("must not restart")), patch("socket.socket", side_effect=AssertionError("local-only start revalidation")):
            self.runtime.revalidate(self.r, "vps1", "gre-kernel", control, tx)
        self.assertFalse(any(a[0] == "sysctl" and a[1] == "-w" for a in self.host.commands[count:]))
        self.host.tables[table_name("edge")]["nftables"].append({"foreign": True})
        with self.assertRaises(StateError):
            self.runtime.revalidate(self.r, "vps1", "gre-kernel", control, tx)

    def test_commit_refresh_requires_the_saved_selection_epoch(self):
        control = self.committed()
        self.host.active.add(self.runtime.runtime_unit(self.r, "direct-rathole"))
        tx = {"previous": None, "refresh_step": "commit", "revision": 1, "epoch": 1}
        self.runtime.revalidate(self.r, "vps1", "direct-rathole", control, tx)
        control["active"]["epoch"] = 2
        with self.assertRaisesRegex(StateError, "selection changed"):
            self.runtime.revalidate(self.r, "vps1", "direct-rathole", control, tx)


class ReceiptRefreshReviewTests(V2Fixture):
    def setUp(self):
        super().setUp()
        self.stage()
        self.peer = Store(self.root / "peer")
        self.stage("vps2", self.peer)
        self.a, self.b = FakeRuntime(), FakeRuntime()

    def quiesced_vps1(self):
        first = Coordinator(self.store, self.a, lambda: 100).advance("edge", self.r, "direct-rathole")["receipt"]
        self.peer_preflight = Coordinator(self.peer, self.b, lambda: 100).advance("edge", self.r, "direct-rathole", first)["receipt"]
        return Coordinator(self.store, self.a, lambda: 100).advance("edge", self.r, "direct-rathole", self.peer_preflight)["receipt"]

    def test_expired_quiescence_receipt_refreshes_and_resumes_without_chain_fork(self):
        old = self.quiesced_vps1()
        with self.assertRaises(ValidationError):
            validate_receipt(old, self.creds["management"], 401)
        result = Coordinator(self.store, self.a, lambda: 401).advance("edge", self.r, "direct-rathole", self.peer_preflight)
        renewed = result["receipt"]
        self.assertEqual(receipt_hash(old), receipt_hash(renewed))
        self.assertEqual(renewed["refresh"]["body"]["expires"], 701)
        self.assertEqual(validate_receipt(renewed, self.creds["management"], 401)["step"], "quiesce")
        self.assertEqual(self.a.calls[-1][1], "revalidate")
        incoming = renewed
        for role, action in steps("direct-rathole")[3:]:
            store, runtime = (self.store, self.a) if role == "vps1" else (self.peer, self.b)
            incoming = Coordinator(store, runtime, lambda: 401).advance("edge", self.r, "direct-rathole", incoming)["receipt"]
        self.assertEqual(Coordinator(self.peer, self.b, lambda: 401).advance("edge", self.r, "direct-rathole", incoming)["status"], "complete")

    def test_peer_that_already_consumed_original_accepts_refresh_idempotently(self):
        old = self.quiesced_vps1()
        Coordinator(self.peer, self.b, lambda: 100).advance("edge", self.r, "direct-rathole", old)
        before = self.peer.read()["pairs"]["edge"]["transition"]["cursor"]
        renewed = Coordinator(self.store, self.a, lambda: 401).advance("edge", self.r, "direct-rathole")["receipt"]
        result = Coordinator(self.peer, self.b, lambda: 401).advance("edge", self.r, "direct-rathole", renewed)
        self.assertEqual(self.peer.read()["pairs"]["edge"]["transition"]["cursor"], before)
        self.assertEqual(result["receipt"]["body"]["index"], before - 1)
        self.assertEqual(sum(action == "quiesce" for _, action, _ in self.b.calls), 1)

    def test_forged_expired_or_replayed_refresh_is_rejected(self):
        self.quiesced_vps1()
        refreshed = Coordinator(self.store, self.a, lambda: 401).advance("edge", self.r, "direct-rathole")["receipt"]
        for field, value in (("receipt_hash", "0" * 64), ("time", 999), ("nonce", "invalid")):
            invalid = copy.deepcopy(refreshed)
            invalid["refresh"]["body"][field] = value
            with self.subTest(field=field), self.assertRaises(ValidationError):
                validate_receipt(invalid, self.creds["management"], 401)
        with self.assertRaises(ValidationError):
            validate_receipt(refreshed, self.creds["management"], 702)
        tx = self.peer.read()["pairs"]["edge"]["transition"]
        consume(tx, refreshed, self.creds["management"], 401)
        with self.assertRaises(ValidationError):
            consume(tx, refreshed, self.creds["management"], 401)

    def test_invalid_refresh_on_an_already_accepted_phase_is_still_rejected(self):
        old = self.quiesced_vps1()
        Coordinator(self.peer, self.b, lambda: 100).advance("edge", self.r, "direct-rathole", old)
        refreshed = Coordinator(self.store, self.a, lambda: 401).advance("edge", self.r, "direct-rathole")["receipt"]
        refreshed["refresh"]["hmac"] = "0" * 64
        with self.assertRaises(ValidationError):
            Coordinator(self.peer, self.b, lambda: 401).advance("edge", self.r, "direct-rathole", refreshed)

    def test_recovery_receipt_refresh_uses_the_same_authenticated_chain(self):
        self.quiesced_vps1()
        coordinator = Coordinator(self.store, self.a, lambda: 100)
        revision, target = coordinator.begin_recovery("edge")
        old = coordinator.advance("edge", revision, target, operation="recover")["receipt"]
        renewed = Coordinator(self.store, self.a, lambda: 401).advance("edge", revision, target, operation="recover", refresh=True)["receipt"]
        self.assertEqual(receipt_hash(old), receipt_hash(renewed))
        result = Coordinator(self.peer, self.b, lambda: 401).advance("edge", revision, target, renewed, operation="recover")
        self.assertEqual(result["receipt"]["body"]["step"], "quiesce")

    def test_final_acknowledgement_refresh_revalidates_and_preserves_identity(self):
        incoming = None
        txid = None
        for role, _ in steps("direct-rathole"):
            store, runtime = (self.store, self.a) if role == "vps1" else (self.peer, self.b)
            result = Coordinator(store, runtime, lambda: 100).advance("edge", self.r, "direct-rathole", incoming)
            incoming, txid = result["receipt"], result["transaction"]
        renewed = Coordinator(self.store, self.a, lambda: 401).advance("edge", self.r, "direct-rathole", transaction_id=txid)["receipt"]
        self.assertEqual(receipt_hash(incoming), receipt_hash(renewed))
        self.assertEqual(self.a.calls[-1][1], "revalidate")
        self.assertEqual(Coordinator(self.peer, self.b, lambda: 401).advance("edge", self.r, "direct-rathole", renewed)["status"], "complete")

    def test_failed_revalidation_does_not_issue_fresh_receipt(self):
        old = self.quiesced_vps1()
        self.a.fail = "revalidate"
        with self.assertRaises(RuntimeError):
            Coordinator(self.store, self.a, lambda: 401).advance("edge", self.r, "direct-rathole", refresh=True)
        tx = self.store.read()["pairs"]["edge"]["transition"]
        self.assertEqual(tx["last_receipt"], old)
        self.assertEqual(tx["phase"], "rollback-required")

    def test_preflight_receipt_refresh_cannot_bypass_cutover_freshness(self):
        Coordinator(self.store, self.a, lambda: 100).advance("edge", self.r, "direct-rathole")
        with self.assertRaisesRegex(ValidationError, "Preflight evidence expired"):
            Coordinator(self.store, self.a, lambda: 401).advance("edge", self.r, "direct-rathole", refresh=True)
        self.assertFalse(any(action == "quiesce" for _, action, _ in self.a.calls))

    def test_receipt_refresh_cannot_extend_unverified_exposure(self):
        incoming = self.quiesced_vps1()
        incoming = Coordinator(self.peer, self.b, lambda: 100).advance("edge", self.r, "direct-rathole", incoming)["receipt"]
        Coordinator(self.store, self.a, lambda: 100).advance("edge", self.r, "direct-rathole", incoming)
        with self.assertRaisesRegex(StateError, "deadline expired"):
            Coordinator(self.store, self.a, lambda: 161).advance("edge", self.r, "direct-rathole", refresh=True)
        tx = self.store.read()["pairs"]["edge"]["transition"]
        self.assertEqual(tx["verification_deadline"], 160)
        self.assertEqual(tx["phase"], "rollback-required")
        self.assertEqual(sum(action == "arm_verification_expiry" for _, action, _ in self.a.calls), 1)

    def test_cli_refresh_retries_original_command_and_exports_private_receipt(self):
        old = self.quiesced_vps1()
        incoming, outgoing = self.root / "old-input.json", self.root / "fresh-output.json"
        atomic_write(incoming, json.dumps(self.peer_preflight))
        with patch.object(cli, "Host", return_value=SystemHost(self.root / "units")), patch("twinlink.v2_cli.runtime", return_value=self.a), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(["--state-dir", str(self.store.directory), "profile", "switch", "direct-rathole", "--transaction", old["body"]["transaction_id"], "--step", "quiesce", "--refresh-receipt", "--receipt-file", str(incoming), "--output", str(outgoing), "--apply", "--yes"])
        self.assertEqual(code, 3)
        self.assertIn("refresh", json.loads(outgoing.read_text()))
        self.assertEqual(outgoing.stat().st_mode & 0o777, 0o600)
