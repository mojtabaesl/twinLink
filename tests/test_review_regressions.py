"""Regressions for the eight follow-up implementation review findings."""
import base64
import contextlib
import copy
import io
import json
from unittest.mock import MagicMock, patch

from tests.test_v2 import V2Fixture, FACTS, FakeRuntime
from tests.test_profile_runtime import SystemHost
from twinlink import cli
from twinlink.cleanup import delete_pair
from twinlink.contracts import canonical, next_revision, strict_json
from twinlink.coordination import Coordinator, Pending, steps, new_transaction
from twinlink.diagnostics import collect, evidence
from twinlink.models import ValidationError
from twinlink.ownership import Ownership, MAX_LEDGER_BYTES
from twinlink.pair_bundle import decode
from twinlink.profile_runtime import ProfileRuntime
from twinlink.reports import parse
from twinlink.store import Store, StateError, atomic_write


class LedgerReviewTests(V2Fixture):
    def test_thirteen_large_revisions_remain_recoverable_and_deletable(self):
        self.r["services"][0].update(ports="8000-8255", backend={"address": "10.20.30.40", "ports": "80"})
        state = self.stage()
        state["pairs"]["edge"].update(active={"revision": 1, "profile": "gre-kernel", "epoch": 1}, epoch=1)
        self.store.write(state)
        current = self.r
        for number in range(2, 14):
            current = next_revision(current, transport={"port": 3456 + number})
            state = self.store.stage(self.store.read(), current, "vps1", self.creds, FACTS)
            if number == 2:
                state["pairs"]["edge"]["last_good"] = {"revision": 2, "profile": "gre-kernel", "epoch": 1}
                self.store.write(state)
            self.assertLessEqual((self.store.directory / "ownership.json").stat().st_size, MAX_LEDGER_BYTES)
        for number in (1, 2, 13):
            self.assertTrue((self.store.revision_path("edge", number) / "vps1/gre-kernel/manifest.json").exists())
        for number in range(3, 13):
            self.assertFalse((self.store.revision_path("edge", number) / "vps1").exists())
            self.assertEqual(self.store.revision("edge", number)["revision"], number)
            self.assertEqual(self.store.credentials("edge", number), self.creds)
        peer = Store(self.root / "peer")
        peer_state = peer.stage(peer.read(), current, "vps2", self.creds, FACTS)
        peer_state["pairs"]["edge"].update(active=state["pairs"]["edge"]["active"], epoch=1)
        peer.write(peer_state)
        # The peer needs the saved active revision to model the off barrier.
        atomic_write(peer.revision_path("edge", 1) / "pair.json", canonical(self.r))
        host = SystemHost(self.root / "units")
        runtime = ProfileRuntime(self.store, host, str(host.unit_dir))
        incoming = None
        for role, _ in steps(None):
            store, rt = (self.store, runtime) if role == "vps1" else (peer, FakeRuntime())
            incoming = Coordinator(store, rt, lambda: 100).advance("edge", self.r, None, incoming)["receipt"]
        Coordinator(peer, FakeRuntime(), lambda: 100).advance("edge", self.r, None, incoming)
        delete_pair(self.store, runtime, "edge")
        self.assertFalse(self.store.read()["pairs"])

    def test_legacy_oversized_ledger_compacts_without_losing_restore_bytes(self):
        ledger = Ownership(self.store)
        path = self.root / "large-owned"
        content = "x" * (2 * 1024 * 1024)
        ledger.write_file(path, content, "edge")
        value = ledger.file_value(path)
        legacy = ledger.read()
        row = legacy["resources"]["file:" + str(path)]
        row["after"] = row["observed_before"] = value
        atomic_write(ledger.path, canonical(legacy))
        self.assertGreater(ledger.path.stat().st_size, MAX_LEDGER_BYTES)
        ledger.remove_file(path, "edge")
        self.assertFalse(path.exists())
        self.assertLess(ledger.path.stat().st_size, MAX_LEDGER_BYTES)
        # Original contents and permissions are still retained for restoration.
        original = {"content": base64.b64encode(b"original").decode(), "mode": 0o640}
        applied = {"content": base64.b64encode(b"applied").decode(), "mode": 0o600}
        ledger.begin("file:" + str(path), "file", "edge", original, applied, "restore-file")
        atomic_write(path, "applied")
        ledger.complete("file:" + str(path), ledger.file_value(path))
        ledger.remove_file(path, "edge")
        self.assertEqual(path.read_text(), "original")
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_write_capacity_failure_precedes_mutation_and_preserves_readable_ledger(self):
        ledger = Ownership(self.store)
        existing = self.root / "existing"
        ledger.write_file(existing, "owned", "edge")
        saved = ledger.path.read_bytes()
        with patch("twinlink.ownership.MAX_LEDGER_BYTES", len(saved) + 1):
            with self.assertRaisesRegex(StateError, "capacity"):
                ledger.write_file(self.root / "new", "new", "edge")
        self.assertFalse((self.root / "new").exists())
        self.assertEqual(ledger.path.read_bytes(), saved)
        ledger.remove_file(existing, "edge")

    def test_staging_capacity_reserves_space_for_withdrawal_records(self):
        ledger = Ownership(self.store)
        existing = self.root / "existing"
        ledger.write_file(existing, "owned", "edge")
        size = ledger.path.stat().st_size
        receipt = self.store.directory / "journals/receipt-edge-transaction.json"
        with patch("twinlink.ownership.MAX_LEDGER_BYTES", size + 8192), patch("twinlink.ownership.RECOVERY_RESERVE_BYTES", 8192):
            with self.assertRaisesRegex(StateError, "capacity"):
                ledger.write_file(self.root / "extra-stage", "staged", "edge")
            ledger.write_file(receipt, "off receipt", "edge")
            ledger.remove_file(existing, "edge")
        self.assertEqual(receipt.read_text(), "off receipt")
        self.assertFalse(existing.exists())

    def test_obsolete_foreign_edit_is_preserved_and_retirement_resumes_after_unlink(self):
        state = self.stage()
        second = next_revision(self.r, transport={"port": 4567})
        path = self.store.revision_path("edge", 1) / "vps1/gre-kernel/rules.nft"
        path.write_text("foreign edit")
        with self.assertRaises(StateError):
            self.store.stage(state, second, "vps1", self.creds, FACTS)
        self.assertEqual(path.read_text(), "foreign edit")
        self.assertTrue(self.store.revision_path("edge", 1).joinpath("pair.json").exists())
        # Use a separate untouched pair store to exercise a crash after unlink.
        fresh = Store(self.root / "fresh")
        state = fresh.stage(fresh.read(), self.r, "vps1", self.creds, FACTS)
        remove = Ownership.remove_file
        fired = []
        def crash(ledger, path, owner):
            remove(ledger, path, owner)
            if not fired:
                fired.append(True)
                raise OSError("death after retirement unlink")
        with patch.object(Ownership, "remove_file", crash):
            with self.assertRaises(OSError):
                fresh.stage(state, second, "vps1", self.creds, FACTS)
        fresh.stage(fresh.read(), second, "vps1", self.creds, FACTS)
        self.assertIsNone(fresh.pending_stage("edge"))
        self.assertFalse((fresh.revision_path("edge", 1) / "vps1").exists())


class RevisionExportReviewTests(V2Fixture):
    def test_multiple_edits_can_be_exported_and_imported_in_order(self):
        state = self.stage()
        state["pairs"]["edge"].update(active={"revision": 1, "profile": "direct-rathole", "epoch": 1}, epoch=1)
        self.store.write(state)
        peer = Store(self.root / "peer")
        peer_creds = {k: v for k, v in self.creds.items() if k != "noise_private"}
        other = peer.stage(peer.read(), self.r, "vps2", peer_creds, FACTS)
        other["pairs"]["edge"].update(active=state["pairs"]["edge"]["active"], epoch=1)
        peer.write(other)
        second = next_revision(self.r, transport={"port": 4567})
        third = next_revision(second, gre={**second["gre"], "mtu": 1400})
        for r in (second, third):
            self.store.stage(self.store.read(), r, "vps1", self.creds, FACTS)
        # Directly skipping the parent still rejects forks/missing evidence.
        with self.assertRaises(StateError):
            peer.stage(peer.read(), third, "vps2", peer_creds, FACTS)
        for expected in (second, third):
            transfer = self.root / (str(expected["revision"]) + ".bundle")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["--state-dir", str(self.store.directory), "pair", "export", "--revision", str(expected["revision"]), "--output", str(transfer)]), 0)
            self.assertEqual(decode(transfer.read_text().strip(), stored_management_key=self.creds["management"])[0], expected)
            host = SystemHost(self.root / "units")
            with patch.object(cli, "Host", return_value=host), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["--state-dir", str(peer.directory), "pair", "import", "--pair", "edge", "--file", str(transfer), "--apply", "--yes"]), 0)
            self.assertEqual(peer.read()["pairs"]["edge"]["staged_revision"], expected["revision"])
            self.assertEqual(peer.read()["pairs"]["edge"]["active"]["revision"], 1)
        self.assertEqual(self.store.read()["pairs"]["edge"]["active"]["revision"], 1)
        for invalid in (0, 4):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["--state-dir", str(self.store.directory), "pair", "export", "--revision", str(invalid)]), 2)


class PreflightReviewTests(V2Fixture):
    def setUp(self):
        super().setUp()
        self.host = SystemHost(self.root / "units")
        self.runtime = ProfileRuntime(self.store, self.host, str(self.host.unit_dir))

    def test_missing_service_recipe_fails_before_either_cutover(self):
        self.r["services"].append({**copy.deepcopy(self.r["services"][0]), "id": "unprobed", "ports": "9000-9001", "probe": None})
        for role in ("vps1", "vps2"):
            store = Store(self.root / role)
            state = self.stage(role, store)
            state["pairs"]["edge"].update(active={"revision": 1, "profile": "gre-kernel", "epoch": 1}, epoch=1)
            store.write(state)
            runtime = ProfileRuntime(store, self.host, str(self.host.unit_dir))
            for profile in ("gre-kernel", "gre-rathole", "direct-rathole"):
                with self.subTest(role=role, profile=profile), self.assertRaisesRegex(ValidationError, "unprobed"):
                    runtime.preflight(self.r, role, profile, state["pairs"]["edge"], {})
            self.assertEqual(store.read()["pairs"]["edge"]["active"]["profile"], "gre-kernel")
            self.assertFalse(self.host.commands)

    def test_kernel_requires_matching_owned_enabled_boot_preparation(self):
        state = self.stage()
        control = state["pairs"]["edge"]
        with self.assertRaisesRegex(StateError, "not prepared"):
            self.runtime.preflight(self.r, "vps1", "gre-kernel", control, {})
        self.runtime.materialize(self.r, "vps1")
        with patch.object(self.runtime, "discover", return_value=FACTS):
            self.runtime.preflight(self.r, "vps1", "gre-kernel", control, {})
            self.host.enabled.remove("twinlink-v2-restore.service")
            with self.assertRaisesRegex(StateError, "disabled"):
                self.runtime.preflight(self.r, "vps1", "gre-kernel", control, {})
            self.host.enabled.add("twinlink-v2-restore.service")
            path = self.runtime.unit_dir / "twinlink-v2-restore.service"
            path.write_text("foreign coordinator")
            with self.assertRaises(StateError):
                self.runtime.preflight(self.r, "vps1", "gre-kernel", control, {})

    def test_stale_kernel_preparation_rejected(self):
        state = self.stage()
        self.runtime.materialize(self.r, "vps1")
        path = self.store.preparation_path("edge", 1)
        metadata = self.store.private_read(path)
        metadata["config_digest"] = "0" * 64
        atomic_write(path, canonical(metadata))
        with self.assertRaisesRegex(StateError, "stale"):
            self.runtime.preflight(self.r, "vps1", "gre-kernel", state["pairs"]["edge"], {})

    def test_runtime_only_boot_enablement_is_insufficient(self):
        state = self.stage()
        self.runtime.materialize(self.r, "vps1")
        original = self.host.unit_status
        def status(name):
            value = original(name)
            if name == "twinlink-v2-restore.service":
                value["properties"]["UnitFileState"] = "enabled-runtime"
            return value
        with patch.object(self.host, "unit_status", side_effect=status), self.assertRaisesRegex(StateError, "disabled"):
            self.runtime.preflight(self.r, "vps1", "gre-kernel", state["pairs"]["edge"], {})

    def test_committed_boot_restore_does_not_need_cutover_only_watchdog_units(self):
        state = self.stage()
        self.runtime.materialize(self.r, "vps1")
        for unit in self.runtime.expiry_units("edge"):
            self.runtime.ledger.remove_file(self.runtime.unit_dir / unit, "edge")
        # Model a committed installation prepared before watchdogs existed.
        state["pairs"]["edge"].update(active={"revision": 1, "profile": "gre-kernel", "epoch": 1}, epoch=1)
        self.store.write(state)
        with patch.object(self.runtime, "discover", return_value=FACTS):
            self.assertEqual(self.runtime.boot()[0]["status"], "active-unverified")
            with self.assertRaises(StateError):
                self.runtime.preflight(self.r, "vps1", "gre-kernel", state["pairs"]["edge"], {})

    def test_udp_verification_compares_one_complete_datagram(self):
        self.r["services"][0].update(protocol="udp", ports="8081", backend={"address": "10.20.30.40", "ports": "80"})
        self.r["services"][0]["probe"]["response_hex"] = "6162"
        for replies, succeeds in (([b"ab"], True), ([b"ab-extra"], False), ([b"a", b"b"], False)):
            with self.subTest(replies=replies):
                sock = MagicMock()
                sock.__enter__.return_value = sock
                pending = iter(replies)
                sock.recv.side_effect = lambda size: next(pending)[:size]
                with patch("socket.socket", return_value=sock), patch.object(self.runtime, "_verify_gre"), patch.object(self.runtime.ledger, "check"):
                    if succeeds:
                        self.runtime.verify(self.r, "vps2", "gre-kernel", {}, {})
                    else:
                        with self.assertRaisesRegex(StateError, "response mismatch"):
                            self.runtime.verify(self.r, "vps2", "gre-kernel", {}, {})
                self.assertEqual(sock.recv.call_count, 1)
                self.assertGreaterEqual(sock.recv.call_args.args[0], 65507)


class ExpiryReviewTests(V2Fixture):
    def setUp(self):
        super().setUp()
        self.stage()
        self.peer = Store(self.root / "peer")
        self.stage("vps2", self.peer)
        self.a, self.b = FakeRuntime(), FakeRuntime()

    def pending_verification(self):
        incoming = None
        for role, action in steps("direct-rathole"):
            store, runtime = (self.store, self.a) if role == "vps1" else (self.peer, self.b)
            if action == "verify":
                with patch.object(runtime, "verify", side_effect=Pending("Operator evidence pending")):
                    with self.assertRaises(Pending):
                        Coordinator(store, runtime, lambda: 100).advance("edge", self.r, "direct-rathole", incoming)
                return incoming
            incoming = Coordinator(store, runtime, lambda: 100).advance("edge", self.r, "direct-rathole", incoming)["receipt"]

    def test_abandoned_pending_verification_is_withdrawn_by_separate_callback(self):
        self.pending_verification()
        tx = self.peer.read()["pairs"]["edge"]["transition"]
        self.assertEqual(tx["verification_deadline"], 160)
        before = list(self.b.calls)
        self.assertEqual(Coordinator(self.peer, self.b, lambda: 159).expire_verification("edge")["status"], "pending")
        self.assertEqual(self.b.calls, before)
        result = Coordinator(self.peer, self.b, lambda: 160).expire_verification("edge")
        self.assertEqual(result["local_status"], "off")
        self.assertEqual(self.b.calls[-1], ("vps2", "quiesce", "direct-rathole"))
        self.assertEqual(self.peer.read()["pairs"]["edge"]["transition"]["phase"], "rollback-required")
        self.assertIsNone(self.peer.read()["pairs"]["edge"]["active"])

    def test_clock_rollback_cannot_extend_the_same_boot_verification_budget(self):
        with patch.object(Ownership, "boot_id", return_value="same-boot"), patch("twinlink.coordination.time.monotonic", return_value=10):
            self.pending_verification()
        with patch.object(Ownership, "boot_id", return_value="same-boot"), patch("twinlink.coordination.time.monotonic", return_value=71):
            self.assertEqual(Coordinator(self.peer, self.b, lambda: 50).expire_verification("edge")["local_status"], "off")

    def test_expired_verification_cannot_succeed_on_resume(self):
        incoming = self.pending_verification()
        with self.assertRaisesRegex(StateError, "deadline expired"):
            Coordinator(self.peer, self.b, lambda: 161).advance("edge", self.r, "direct-rathole", incoming)
        self.assertEqual(self.b.calls[-1][1], "quiesce")

    def test_verification_that_finishes_after_its_deadline_cannot_issue_receipt(self):
        incoming = self.pending_verification()
        now = [159]
        def slow(*args):
            now[0] = 161
        with patch.object(self.b, "verify", side_effect=slow), self.assertRaisesRegex(StateError, "original deadline"):
            Coordinator(self.peer, self.b, lambda: now[0]).advance("edge", self.r, "direct-rathole", incoming)
        self.assertEqual(self.peer.read()["pairs"]["edge"]["transition"]["phase"], "rollback-required")
        self.assertEqual(self.b.calls[-1][1], "quiesce")

    def test_installed_expiry_callback_routes_to_locked_withdrawal(self):
        self.pending_verification()
        coordinator = Coordinator(self.peer, self.b, lambda: 160)
        with patch("twinlink.v2_cli.Coordinator", return_value=coordinator), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["--state-dir", str(self.peer.directory), "internal", "verification-expire", "edge"]), 0)
        self.assertEqual(self.peer.read()["pairs"]["edge"]["transition"]["phase"], "rollback-required")

    def test_pending_verification_can_resume_within_original_budget(self):
        incoming = self.pending_verification()
        result = Coordinator(self.peer, self.b, lambda: 159).advance("edge", self.r, "direct-rathole", incoming)
        self.assertEqual(result["receipt"]["body"]["step"], "verify")
        self.assertEqual(self.peer.read()["pairs"]["edge"]["transition"]["verification_deadline"], 160)

    def test_failed_expiry_withdrawal_keeps_recovery_journal(self):
        self.pending_verification()
        self.b.fail = "quiesce"
        with self.assertRaises(RuntimeError):
            Coordinator(self.peer, self.b, lambda: 160).expire_verification("edge")
        self.assertEqual(self.peer.read()["pairs"]["edge"]["transition"]["phase"], "recovery-required")

    def test_timer_is_prepared_disabled_armed_before_exposure_and_not_reset(self):
        host = SystemHost(self.root / "units")
        runtime = ProfileRuntime(self.store, host, str(host.unit_dir))
        runtime.materialize(self.r, "vps1")
        service, timer = runtime.expiry_units("edge")
        self.assertIn('"verification-expire" "edge"', (host.unit_dir / service).read_text())
        self.assertIn("Restart=on-failure", (host.unit_dir / service).read_text())
        self.assertIn("OnActiveSec=60s", (host.unit_dir / timer).read_text())
        self.assertIn("OnUnitActiveSec=1s", (host.unit_dir / timer).read_text())
        self.assertNotIn(timer, host.enabled)
        control = self.store.read()["pairs"]["edge"]
        for _ in range(2):
            runtime.arm_verification_expiry(self.r, "vps1", "gre-kernel", control, {})
        self.assertEqual(host.commands.count(["systemctl", "start", timer]), 1)
        runtime.quiesce(self.r, "vps1", "gre-kernel", control, {"previous": None})
        self.assertNotIn(timer, host.active)
        self.pending_verification()
        for calls in (self.a.calls, self.b.calls):
            names = [c[1] for c in calls]
            self.assertLess(names.index("arm_verification_expiry"), names.index("start"))

    def test_timer_arm_failure_never_starts_target(self):
        incoming = None
        for role, action in steps("direct-rathole"):
            store, runtime = (self.store, self.a) if role == "vps1" else (self.peer, self.b)
            if action == "start":
                runtime.fail = "arm_verification_expiry"
                with self.assertRaises(RuntimeError):
                    Coordinator(store, runtime, lambda: 100).advance("edge", self.r, "direct-rathole", incoming)
                self.assertFalse(any(c[1] == "start" for c in runtime.calls))
                self.assertEqual(store.read()["pairs"]["edge"]["transition"]["phase"], "rollback-required")
                break
            incoming = Coordinator(store, runtime, lambda: 100).advance("edge", self.r, "direct-rathole", incoming)["receipt"]

    def test_pending_watchdog_survives_recovery_or_off_replacing_the_transaction(self):
        host = SystemHost(self.root / "units")
        runtime = ProfileRuntime(self.store, host, str(host.unit_dir))
        runtime.materialize(self.r, "vps1")
        for target in ("direct-rathole", None):
            with self.subTest(target=target):
                state = self.store.read()
                control = state["pairs"]["edge"]
                control.update(transition=None, active=None, commit_pending=False)
                tx = new_transaction("edge", self.r, target, control, now=100)
                if target:
                    tx["recovery_of"] = "a" * 32
                control["transition"] = tx
                self.store.write(state)
                unit = runtime.runtime_unit(self.r, "direct-rathole")
                host.active.add(unit)
                runtime.arm_verification_expiry(self.r, "vps1", "direct-rathole", control, tx)
                result = Coordinator(self.store, runtime, lambda: 160).expire_verification("edge")
                self.assertEqual(result["local_status"], "off")
                self.assertNotIn(unit, host.active)
                self.assertNotIn(runtime.expiry_units("edge")[1], host.active)
                self.assertEqual(self.store.read()["pairs"]["edge"]["transition"]["phase"], "rollback-required" if target else "local-withdrawal")

    def test_failed_withdrawal_does_not_disarm_the_watchdog(self):
        host = SystemHost(self.root / "units")
        runtime = ProfileRuntime(self.store, host, str(host.unit_dir))
        runtime.materialize(self.r, "vps1")
        control = self.store.read()["pairs"]["edge"]
        unit = runtime.runtime_unit(self.r, "direct-rathole")
        host.active.add(unit)
        runtime.arm_verification_expiry(self.r, "vps1", "direct-rathole", control, {})
        original = host.run
        def fail(argv, **kwargs):
            if argv == ["systemctl", "stop", unit]:
                raise OSError("systemctl unavailable")
            return original(argv, **kwargs)
        with patch.object(host, "run", side_effect=fail), self.assertRaises(OSError):
            runtime.quiesce(self.r, "vps1", "direct-rathole", control, {"previous": None})
        self.assertIn(runtime.expiry_units("edge")[1], host.active)
        self.assertIn(unit, host.active)
        runtime.quiesce(self.r, "vps1", "direct-rathole", control, {"previous": None})
        self.assertNotIn(unit, host.active)
        self.assertNotIn(runtime.expiry_units("edge")[1], host.active)

    def test_verified_or_committed_targets_are_not_withdrawn_by_late_callback(self):
        incoming = None
        for role, _ in steps("direct-rathole"):
            store, runtime = (self.store, self.a) if role == "vps1" else (self.peer, self.b)
            incoming = Coordinator(store, runtime, lambda: 100).advance("edge", self.r, "direct-rathole", incoming)["receipt"]
            tx = store.read()["pairs"]["edge"]["transition"]
            if tx and Coordinator.verified(tx):
                before = len([c for c in runtime.calls if c[1] == "quiesce"])
                self.assertEqual(Coordinator(store, runtime, lambda: 200).expire_verification("edge")["status"], "complete")
                self.assertEqual(len([c for c in runtime.calls if c[1] == "quiesce"]), before)
        self.assertEqual(Coordinator(self.store, self.a, lambda: 200).expire_verification("edge")["status"], "complete")
        self.assertIsNotNone(self.store.read()["pairs"]["edge"]["active"])


class ReportReviewTests(V2Fixture):
    def report(self):
        self.stage()
        return collect(self.store, "edge", redaction="secrets", sample_fn=lambda: ({}, []),
                       command_fn=lambda *a, **k: {"returncode": 0, "stdout": "", "error": None, "truncated": False})

    def test_merge_applies_requested_redaction_to_all_nested_evidence(self):
        first = self.report()
        first["log_events"].append({"message": self.creds["paqet"] + " 198.51.100.1:3456"})
        second = copy.deepcopy(first)
        second["report_id"], second["host"]["role"] = "peer", "vps2"
        paths = [self.root / "first.json", self.root / "second.json"]
        for path, report in zip(paths, (first, second)):
            atomic_write(path, json.dumps(report))
        for level in ("share", "secrets"):
            exported = self.root / (level + ".json")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["--state-dir", str(self.store.directory), "doctor", "--merge", *map(str, paths), "--redaction", level, "--export", str(exported)]), 3)
            text = exported.read_text()
            self.assertNotIn(self.creds["paqet"], text)
            result = json.loads(text)
            self.assertEqual(result["redaction_summary"]["level"], level)
            self.assertEqual(result["reports"][0]["host"]["pair_id"], result["reports"][1]["host"]["pair_id"])
            if level == "share":
                self.assertNotIn("198.51.100.1", text)
                self.assertNotIn('"pair_id": "edge"', text)
            else:
                self.assertIn("198.51.100.1", text)
            self.assertEqual(exported.stat().st_mode & 0o777, 0o600)

    def test_long_watch_reports_parse_merge_and_compare(self):
        report = self.report()
        sample = evidence("service", "pass", "bounded evidence " * 70, 0, "vps1")
        report["probes"] = [{**sample, "id": str(i)} for i in range(1200)]
        text = json.dumps(report)
        self.assertGreater(len(text), 1024 * 1024)
        self.assertEqual(len(parse(text)["probes"]), 1200)
        other = copy.deepcopy(report)
        other["report_id"], other["host"]["role"] = "peer", "vps2"
        first, second = self.root / "first.json", self.root / "second.json"
        for path, value in ((first, report), (second, other)):
            atomic_write(path, json.dumps(value))
        args = ["--state-dir", str(self.store.directory), "doctor", "--redaction", "secrets"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main([*args, "--merge", str(first), str(second)]), 3)
            with patch("twinlink.diagnostics.collect", return_value=copy.deepcopy(report)):
                self.assertEqual(cli.main([*args, "--compare", str(first)]), 3)
        # Configuration limits remain strict; report imports are still bounded.
        with self.assertRaises(ValidationError):
            strict_json(text, 10 * 1024 * 1024)
        report["probes"] = [None] * 100001
        with self.assertRaises(ValidationError):
            parse(json.dumps(report))
        for invalid in ('{"schema_version":1,"schema_version":1}', '{"x":NaN}', '[' * 18 + '0' + ']' * 18):
            with self.assertRaises(ValidationError):
                parse(invalid)
