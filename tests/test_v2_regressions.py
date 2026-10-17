"""Regression coverage for staged revisions, interrupted ownership and doctor."""
import copy
import contextlib
import io
import json
import socket
import threading
from pathlib import Path
from unittest.mock import patch
from unittest.mock import MagicMock

from tests.test_v2 import V2Fixture, FACTS
from tests.test_profile_runtime import SystemHost
from tests.test_rathole import KEYS, PRIVATE
from twinlink import cli, paqet
from twinlink.contracts import digest, next_revision
from twinlink.coordination import Coordinator, new_transaction
from twinlink.cleanup import delete_pair, restore_system, remove_program
from twinlink.diagnostics import collect, application_probe
from twinlink.migration import inventory, adopt
from twinlink.ownership import Ownership
from twinlink.profile_runtime import ProfileRuntime, nft_expectation
from twinlink.profiles import table_name, manifests
from twinlink.reports import merge
from twinlink.store import StateError, atomic_write


class FakeClock:
    def __init__(self):
        self.value = 0
    def __call__(self):
        return self.value
    def sleep(self, seconds):
        self.value += seconds


class RevisionRegressions(V2Fixture):
    def setUp(self):
        super().setUp()
        self.host = SystemHost(self.root / "units")
        self.binary = self.root / "rathole"
        atomic_write(self.binary, "pinned fake native binary", 0o755)
        self.runtime = ProfileRuntime(self.store, self.host, str(self.host.unit_dir), rathole_binary=str(self.binary))

    def prepare(self, revision):
        with patch("twinlink.rathole.check_version"):
            self.runtime.materialize(revision, "vps1")

    def active_then_stage(self):
        self.stage()
        self.prepare(self.r)
        state = self.store.read()
        state["pairs"]["edge"].update(active={"profile": "direct-rathole", "revision": 1, "epoch": 1}, epoch=1)
        self.store.write(state)
        changed = next_revision(self.r, transport={"port": 4567})
        self.store.stage(state, changed, "vps1", self.creds, FACTS)
        self.prepare(changed)
        return changed

    def test_reboot_and_rollback_use_original_preparation_with_new_revision_staged(self):
        changed = self.active_then_stage()
        with patch.object(self.runtime, "discover", return_value=FACTS):
            self.assertEqual(self.runtime.boot()[0]["status"], "active-unverified")
            state = self.store.read()
            control = state["pairs"]["edge"]
            tx = new_transaction("edge", changed, "direct-rathole", control, now=100)
            control["transition"] = tx
            self.store.write(state)
            original, target = Coordinator(self.store, self.runtime, lambda: 101).begin_recovery("edge")
            self.assertEqual(original, self.r)
            self.runtime.preflight(original, "vps1", target, self.store.read()["pairs"]["edge"], {"previous": control["active"]})
        self.assertEqual(self.store.private_read(self.store.preparation_path("edge", 1))["config_digest"], digest(self.r))
        self.assertEqual(self.store.private_read(self.store.preparation_path("edge", 2))["config_digest"], digest(changed))
        self.assertIn(self.runtime.runtime_unit(self.r, "direct-rathole"), self.host.active)
        self.assertNotIn(self.runtime.runtime_unit(changed, "direct-rathole"), self.host.active)

    def test_staged_facts_do_not_overwrite_active_facts(self):
        self.stage()
        changed = next_revision(self.r, transport={"port": 4567})
        new_facts = {**FACTS, "interface": "eth1"}
        self.store.stage(self.store.read(), changed, "vps1", self.creds, new_facts)
        self.assertEqual(self.store.facts("edge", 1), FACTS)
        self.assertEqual(self.store.facts("edge", 2), new_facts)

    def test_restart_and_reapply_coordinate_active_revision(self):
        self.active_then_stage()
        for action in ("restart", "reapply"):
            with self.subTest(action=action):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = cli.main(["--state-dir", str(self.store.directory), "--json", "profile", action])
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(output.getvalue())["revision"], 1)
                with patch.object(cli, "Host", return_value=self.host), patch.object(Coordinator, "advance", return_value={"status": "pending"}) as advance, contextlib.redirect_stdout(io.StringIO()):
                    code = cli.main(["--state-dir", str(self.store.directory), "--json", "profile", action, "--apply", "--yes"])
                self.assertEqual(code, 3)  # Pending manual coordination.
                self.assertEqual(advance.call_args.args[1]["revision"], 1)

    def test_initial_noise_addition_is_transactional_and_retryable(self):
        self.r["public_keys"]["noise"] = None
        self.creds.pop("noise_private")
        state = self.stage()
        changed = next_revision(self.r, public_keys={"noise": KEYS["noise_public_key"]})
        updated = {**self.creds, "noise_private": PRIVATE}
        with patch.object(self.store, "write", side_effect=OSError("crash before pointer commit")):
            with self.assertRaises(OSError):
                self.store.stage(state, changed, "vps1", updated, FACTS)
        self.assertEqual(self.store.credentials("edge"), self.creds)
        self.assertEqual(self.store.pending_stage("edge")["credentials"], updated)
        self.store.stage(state, changed, "vps1", updated, FACTS)
        self.prepare(changed)
        self.assertEqual(self.store.credentials("edge", 1), self.creds)
        self.assertEqual(self.store.credentials("edge", 2), updated)
        for profile in ("direct-rathole", "gre-rathole"):
            self.assertFalse(manifests(changed, "vps1", updated, FACTS)[profile]["preparation_errors"])

    def test_setup_without_binary_then_install_and_regenerate(self):
        missing = self.root / "installed-later"
        args = ["--state-dir", str(self.store.directory), "--unit-dir", str(self.host.unit_dir), "--rathole-binary", str(missing), "--json"]
        with patch.object(cli, "Host", return_value=self.host), patch.object(ProfileRuntime, "discover", return_value=FACTS), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main([*args, "setup", "--pair", "edge", "--vps1", "198.51.100.1", "--vps2", "203.0.113.2", "--apply", "--yes"]), 0)
            original = self.store.credentials("edge")
            atomic_write(missing, "newly installed rathole", 0o755)
            with patch("twinlink.rathole.check_version"), patch("twinlink.rathole.generate_keypair", return_value=KEYS):
                self.assertEqual(cli.main([*args, "config", "regenerate", "--apply", "--yes"]), 0)
        self.assertEqual(self.store.read()["pairs"]["edge"]["staged_revision"], 2)
        self.assertNotIn("noise_private", self.store.credentials("edge", 1))
        self.assertEqual(self.store.credentials("edge", 2)["noise_private"], PRIVATE)
        self.assertEqual(self.store.credentials("edge")["rathole"], original["rathole"])

    def test_staging_recovers_crash_after_pointer_commit(self):
        state = self.stage()
        changed = next_revision(self.r, transport={"port": 4567})
        original_write = self.store.write
        def crash(new):
            original_write(new)
            raise OSError("process died after committed pointer")
        with patch.object(self.store, "write", side_effect=crash):
            with self.assertRaises(OSError):
                self.store.stage(state, changed, "vps1", self.creds, FACTS)
        self.assertEqual(self.store.pending_stage("edge")["revision_config"], changed)
        self.store.stage(self.store.read(), changed, "vps1", self.creds, FACTS)
        self.assertIsNone(self.store.pending_stage("edge"))


class OwnershipRegressions(V2Fixture):
    def setUp(self):
        super().setUp()
        self.stage()
        self.host = SystemHost(self.root / "units")
        self.runtime = ProfileRuntime(self.store, self.host, str(self.host.unit_dir))
        self.control = self.store.read()["pairs"]["edge"]

    def test_file_crash_before_and_after_mutation_can_retry_or_delete(self):
        for applied in (False, True):
            for retry in (False, True):
                with self.subTest(applied=applied, retry=retry):
                    path = self.root / f"owned-{applied}-{retry}"
                    ledger = Ownership(self.store)
                    expected = {"content": "c2VjcmV0", "mode": 0o600}
                    ledger.begin("file:" + str(path), "file", "edge", None, expected, "restore-file")
                    if applied:
                        atomic_write(path, "secret")
                    if retry:
                        ledger.write_file(path, "secret", "edge")
                    ledger.remove_file(path, "edge")
                    self.assertFalse(path.exists())

    def test_pending_foreign_value_is_preserved(self):
        path = self.root / "foreign-edit"
        ledger = Ownership(self.store)
        ledger.begin("file:" + str(path), "file", "edge", None, {"content": "c2VjcmV0", "mode": 0o600}, "restore-file")
        atomic_write(path, "operator")
        with self.assertRaises(StateError):
            ledger.remove_file(path, "edge")
        self.assertEqual(path.read_text(), "operator")

    def test_kernel_mutation_boundaries_retry_and_quiesce(self):
        # Inject process death both before and after every mutating command.
        predicates = [lambda a: a[:3] == ["ip", "link", "add"], lambda a: a[:3] == ["ip", "address", "replace"],
                      lambda a: a[:3] == ["ip", "link", "set"], lambda a: a[:2] == ["sysctl", "-w"],
                      lambda a: a[:3] == ["nft", "--file", "-"]]
        for boundary, predicate in enumerate(predicates):
            for applied in (False, True):
                for retry in (False, True):
                    with self.subTest(boundary=boundary, applied=applied, retry=retry):
                        # Fully release the preceding scenario's ledger/runtime.
                        original = self.host.run
                        fired = [False]
                        def run(argv, **kwargs):
                            if not fired[0] and predicate(argv):
                                fired[0] = True
                                if applied:
                                    original(argv, **kwargs)
                                raise OSError("injected process death")
                            return original(argv, **kwargs)
                        with patch.object(self.host, "run", side_effect=run):
                            with self.assertRaises(OSError):
                                self.runtime.prepare(self.r, "vps1", "gre-kernel", self.control, {"previous": None})
                                self.runtime.start(self.r, "vps1", "gre-kernel", self.control, {"previous": None})
                        self.assertTrue(fired[0])
                        if retry:
                            self.runtime.prepare(self.r, "vps1", "gre-kernel", self.control, {"previous": None})
                            self.runtime.start(self.r, "vps1", "gre-kernel", self.control, {"previous": None})
                        self.runtime.quiesce(self.r, "vps1", "gre-kernel", self.control, {"previous": None})
                        self.assertFalse(self.host.link_rows)
                        self.assertFalse(self.host.tables)
                        self.assertEqual(self.host.forwarding, "0")

    def test_crash_between_binding_expected_and_completing_is_recoverable(self):
        original = Ownership.complete
        for target in ("link:", "nft:", "sysctl:"):
            with self.subTest(target=target):
                fired = [False]
                def crash(ledger, resource, observed):
                    if resource.startswith(target) and not fired[0]:
                        fired[0] = True
                        raise OSError("crash at complete")
                    return original(ledger, resource, observed)
                with patch.object(Ownership, "complete", crash):
                    with self.assertRaises(OSError):
                        self.runtime.prepare(self.r, "vps1", "gre-kernel", self.control, {"previous": None})
                        self.runtime.start(self.r, "vps1", "gre-kernel", self.control, {"previous": None})
                self.runtime.prepare(self.r, "vps1", "gre-kernel", self.control, {"previous": None})
                self.runtime.start(self.r, "vps1", "gre-kernel", self.control, {"previous": None})
                self.runtime.quiesce(self.r, "vps1", "gre-kernel", self.control, {"previous": None})

    def test_pending_enablement_and_sysctl_restore(self):
        ledger = Ownership(self.store)
        ledger.begin("unit-enable:test.service", "unit-enable", "edge", False, True, "restore-unit-enablement")
        self.host.enabled.add("test.service")
        ledger.begin("sysctl:net.ipv4.ip_forward", "sysctl", "edge", "0", "1", "restore-sysctl")
        self.host.forwarding = "1"
        result = restore_system(self.store, self.runtime)
        self.assertEqual(result["conflicts"], [])
        self.assertNotIn("test.service", self.host.enabled)
        self.assertEqual(self.host.forwarding, "0")

    def test_boot_retries_pending_partial_gre_creation_through_preflight(self):
        self.runtime.materialize(self.r, "vps1")
        state = self.store.read()
        state["pairs"]["edge"].update(active={"profile": "gre-kernel", "revision": 1, "epoch": 1}, epoch=1)
        self.store.write(state)
        original = self.host.run
        def crash(argv, **kwargs):
            result = original(argv, **kwargs)
            if argv[:3] == ["ip", "link", "add"]:
                raise OSError("death after owned link creation")
            return result
        with patch.object(self.host, "run", side_effect=crash):
            with self.assertRaises(OSError):
                self.runtime.prepare(self.r, "vps1", "gre-kernel", self.control, {"previous": None})
        with patch.object(self.runtime, "discover", return_value=FACTS):
            self.assertEqual(self.runtime.boot()[0]["status"], "active-unverified")
        self.assertTrue(self.host.tables)

    def test_pending_gre_and_nft_foreign_changes_are_never_adopted(self):
        for target in ("link:", "nft:"):
            with self.subTest(target=target):
                original_bind = Ownership.bind_expected
                def interrupt_bind(ledger, resource, observed, proof=None):
                    if resource.startswith(target):
                        raise OSError("death before binding")
                    return original_bind(ledger, resource, observed, proof)
                with patch.object(Ownership, "bind_expected", interrupt_bind):
                    with self.assertRaises(OSError):
                        self.runtime.prepare(self.r, "vps1", "gre-kernel", self.control, {"previous": None})
                        self.runtime.start(self.r, "vps1", "gre-kernel", self.control, {"previous": None})
                if target == "link:":
                    self.host.link_rows[0]["mtu"] += 1
                else:
                    self.host.tables[table_name("edge")]["nftables"].append({"foreign": True})
                with self.assertRaises(StateError):
                    self.runtime.quiesce(self.r, "vps1", "gre-kernel", self.control, {"previous": None})
                # Restore the test's external change, then complete safe cleanup.
                if target == "link:":
                    self.host.link_rows[0]["mtu"] -= 1
                else:
                    self.host.tables[table_name("edge")]["nftables"].pop()
                self.runtime.quiesce(self.r, "vps1", "gre-kernel", self.control, {"previous": None})

    def test_process_start_stop_and_enablement_mutation_boundaries(self):
        self.runtime.materialize(self.r, "vps1")
        unit = self.runtime.runtime_unit(self.r, "direct-rathole")
        for action in ("start", "stop", "enable"):
            for applied in (False, True):
                with self.subTest(action=action, applied=applied):
                    original = self.host.run
                    fired = [False]
                    def crash(argv, **kwargs):
                        if argv[:2] == ["systemctl", action] and not fired[0]:
                            fired[0] = True
                            if applied:
                                original(argv, **kwargs)
                            raise OSError("process death at systemctl boundary")
                        return original(argv, **kwargs)
                    with patch.object(self.host, "run", side_effect=crash):
                        with self.assertRaises(OSError):
                            if action == "start":
                                self.runtime.start(self.r, "vps1", "direct-rathole", self.control, {"previous": None})
                            elif action == "stop":
                                self.runtime.quiesce(self.r, "vps1", "direct-rathole", self.control, {"previous": None})
                            else:
                                self.runtime.set_enablement(unit, "edge", True)
                    if action == "enable":
                        self.runtime.set_enablement(unit, "edge", True)
                        self.runtime.set_enablement(unit, "edge", False)
                    elif action == "start":
                        self.runtime.start(self.r, "vps1", "direct-rathole", self.control, {"previous": None})
                    self.runtime.quiesce(self.r, "vps1", "direct-rathole", self.control, {"previous": None})
                    self.assertNotIn(unit, self.host.active)


class DoctorRegressions(V2Fixture):
    def setUp(self):
        super().setUp()
        self.stage("vps2")
        state = self.store.read()
        state["pairs"]["edge"].update(active={"profile": "direct-rathole", "revision": 1, "epoch": 1}, epoch=1)
        self.store.write(state)
        self.clock = FakeClock()

    def command(self, argv, timeout=3):
        t = self.clock()
        out = ""
        if argv[0] == "ip":
            if "route" in argv:
                out = json.dumps([{"dst": "default", "dev": "eth0", "gateway": "198.51.100.254" if t == 0 else "198.51.100.253"}])
            else:
                out = json.dumps([{"ifname": "eth0", "ifindex": 2, "stats64": {"tx": {"packets": int(t + 1)}, "rx": {"packets": 1}}}])
        elif argv[0] == "systemctl":
            out = "ActiveState=active\nSubState=running\nNRestarts=" + str(int(t))
        elif argv[0] == "journalctl":
            out = json.dumps({"MESSAGE": "plain values " + self.creds["rathole"] + " and " + self.creds["paqet"], "PRIORITY": "3", "__REALTIME_TIMESTAMP": "1"})
        elif argv[0] == "nft":
            out = '{"nftables": []}'
        return {"returncode": 0, "stdout": out, "error": None, "truncated": False}

    def probe(self, definition, timeout=3):
        result = "fail" if self.clock() == 1 and definition["kind"] == "service" else "pass"
        return {"result": result, "latency_ms": 10, "error": None if result == "pass" else "TimeoutError"}

    def report(self, **kwargs):
        return collect(self.store, "edge", redaction="secrets", clock=self.clock, sleep=self.clock.sleep,
                       command_fn=self.command, probe_fn=self.probe, sample_fn=lambda: ({"boot_id": "boot"}, []), **kwargs)

    def test_watch_repeats_path_service_backend_and_unit_evidence(self):
        report = self.report(duration=3, interval=1)
        self.assertEqual(report["overall_status"], "degraded")
        self.assertEqual(len(report["probes"]), 12)
        self.assertEqual(len([r for r in report["interface_route_samples"] if r["source"] == "route"]), 3)
        observations = " ".join(f["observation"] for f in report["findings"])
        self.assertIn("Intermittent", observations)
        self.assertIn("route changed", observations)
        self.assertIn("unit changed", observations)
        self.assertIn("without observed receive", observations)
        self.assertTrue(report["inactive_readiness"])
        ids = {e["id"] for bucket in ("probes", "profile_evidence", "interface_route_samples", "processes_systemd") for e in report[bucket]}
        for finding in report["findings"]:
            self.assertTrue(finding["evidence_ids"])
            self.assertTrue(set(finding["evidence_ids"] + finding["counterevidence_ids"]) <= ids)
        self.assertNotIn(self.creds["paqet"], json.dumps(report))
        self.assertNotIn(self.creds["rathole"], json.dumps(report))
        stats = [e["value"] for e in report["profile_evidence"] if e["source"] == "probe-statistics" and e["value"]["fail"]]
        self.assertEqual(stats[0]["longest_failure_run"], 1)
        self.assertEqual(stats[0]["recovery_offsets"], [2])

    def test_active_configuration_and_staged_differences_are_separate(self):
        changed = next_revision(self.r, transport={"port": 4567}, services=[])
        self.store.stage(self.store.read(), changed, "vps2", self.creds, FACTS)
        report = self.report()
        self.assertEqual(report["config_digest"], digest(self.r))
        self.assertEqual(report["service_mappings"][0]["ports"], self.r["services"][0]["ports"])
        self.assertEqual(report["revisions"]["staged_configuration"]["config_digest"], digest(changed))
        self.assertEqual(report["revisions"]["staged_configuration"]["service_mappings"], [])

    def test_missing_probe_unknown_and_failed_unit_failure(self):
        self.r["services"][0]["probe"] = None
        definitions = __import__("twinlink.diagnostics", fromlist=["probe_definitions"]).probe_definitions(self.r, "vps2", "direct-rathole")
        self.assertEqual(application_probe(definitions[0])["result"], "unknown")
        def command(argv, **kwargs):
            result = self.command(argv, **kwargs)
            if argv[0] == "systemctl":
                result["stdout"] = "ActiveState=failed\nSubState=failed\nNRestarts=2"
            return result
        report = collect(self.store, "edge", redaction="secrets", command_fn=command,
                         probe_fn=lambda *a, **k: {"result": "unknown"}, sample_fn=lambda: ({}, []))
        self.assertEqual(report["overall_status"], "failed")

    def test_logs_and_doctor_export_redact_plain_transport_credentials(self):
        args = ["--state-dir", str(self.store.directory), "--json"]
        output = io.StringIO()
        with patch("twinlink.diagnostics.bounded_command", side_effect=self.command), contextlib.redirect_stdout(output):
            self.assertEqual(cli.main([*args, "logs"]), 0)
        for key in ("rathole", "paqet"):
            self.assertNotIn(self.creds[key], output.getvalue())
        exported = self.root / "doctor.json"
        with patch("twinlink.diagnostics.bounded_command", side_effect=self.command), patch("twinlink.diagnostics.application_probe", return_value={"result": "pass", "latency_ms": 1}), contextlib.redirect_stdout(io.StringIO()):
            self.assertIn(cli.main([*args, "doctor", "--redaction", "secrets", "--export", str(exported)]), (0, 3))
        for key in ("rathole", "paqet"):
            self.assertNotIn(self.creds[key], exported.read_text())
        self.assertEqual(exported.stat().st_mode & 0o777, 0o600)

    def test_merge_keeps_revision_mismatch_as_evidence(self):
        first = self.report()
        second = copy.deepcopy(first)
        second["report_id"], second["host"]["role"] = "peer", "vps1"
        second["config_digest"] = "a" * 64
        second["service_mappings"] = []
        result = merge(first, second)
        self.assertEqual(result["overall_status"], "degraded")
        self.assertEqual(result["reports"], [first, second])
        self.assertIn("config_digest", result["configuration_differences"])
        self.assertTrue(result["findings"][0]["evidence_ids"])

    def test_actual_tcp_and_udp_exchanges(self):
        for protocol in ("tcp", "udp"):
            with self.subTest(protocol=protocol), socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM) as server:
                try:
                    server.bind(("127.0.0.1", 0))
                except PermissionError:
                    self.skipTest("Sandbox does not permit local socket listeners")
                server.settimeout(3)
                if protocol == "tcp":
                    server.listen()
                def echo():
                    if protocol == "tcp":
                        with server.accept()[0] as client:
                            client.sendall(client.recv(1))
                    else:
                        data, address = server.recvfrom(32)
                        server.sendto(data, address)
                thread = threading.Thread(target=echo, daemon=True)
                thread.start()
                definition = {"address": "127.0.0.1", "port": server.getsockname()[1], "protocol": protocol,
                              "exchange": {"request_hex": "61", "response_hex": "61"}}
                self.assertEqual(application_probe(definition)["result"], "pass")
                thread.join(3)

    def test_exchange_detects_short_tcp_response_and_wrong_udp_datagram(self):
        for protocol, replies, expected in (("tcp", [b"a", b"b"], "pass"), ("tcp", [b"a", b""], "fail"),
                                             ("udp", [b"ab-extra"], "fail")):
            with self.subTest(protocol=protocol, replies=replies):
                sock = MagicMock()
                sock.__enter__.return_value = sock
                sock.recv.side_effect = replies
                definition = {"address": "127.0.0.1", "port": 8080, "protocol": protocol,
                              "exchange": {"request_hex": "61", "response_hex": "6162"}}
                with patch("socket.socket", return_value=sock):
                    self.assertEqual(application_probe(definition)["result"], expected)

    def test_pressure_correlation_and_rate_limit_are_explicit(self):
        def sample():
            return {"boot_id": "boot", "cpu_psi": "some avg10=" + str(int(self.clock() * 20))}, []
        with patch("twinlink.diagnostics.read_sample", side_effect=sample):
            report = collect(self.store, "edge", duration=3, interval=1, redaction="secrets", clock=self.clock, sleep=self.clock.sleep,
                             command_fn=self.command, probe_fn=self.probe)
        self.assertTrue(any("Host pressure" in f["observation"] for f in report["findings"]))
        starts = []
        def command(argv, **kwargs):
            if argv[0] == "ping":
                starts.append(self.clock())
            return self.command(argv, **kwargs)
        def probe(definition, **kwargs):
            starts.append(self.clock())
            return self.probe(definition, **kwargs)
        self.clock.value = 0
        collect(self.store, "edge", duration=2, interval=.25, clock=self.clock, sleep=self.clock.sleep,
                command_fn=command, probe_fn=probe, sample_fn=lambda: ({}, []))
        for start in starts:
            self.assertLessEqual(sum(start <= t < start + 1 for t in starts), 20)

    def test_slow_collectors_record_scheduling_gaps(self):
        def sample():
            self.clock.value += 2
            return {"boot_id": "boot"}, []
        report = collect(self.store, "edge", duration=5, interval=1, redaction="secrets", clock=self.clock, sleep=self.clock.sleep,
                         command_fn=self.command, probe_fn=self.probe, sample_fn=sample)
        self.assertTrue(any(e["scheduling_gap"] >= 1 for e in report["host_samples"]))

    def test_export_size_cap_preserves_valid_finding_references(self):
        from twinlink.diagnostics import cap_report
        report = self.report()
        report["host_samples"].extend(copy.deepcopy(report["host_samples"][0]) for _ in range(50))
        for i, sample in enumerate(report["host_samples"]):
            sample["id"] = f"sample-{i}"
            sample["value"] = "a" * 500
        report["findings"] = [{"evidence_ids": [sample["id"] for sample in report["host_samples"]], "counterevidence_ids": []}]
        with patch("twinlink.diagnostics.MAX_REPORT_BYTES", 16000):
            capped = cap_report(report)
        self.assertLessEqual(len(json.dumps(capped, indent=2).encode()), 16000)
        ids = {e["id"] for e in capped["host_samples"]}
        self.assertTrue(set(capped["findings"][0]["evidence_ids"]) <= ids)


class MigrationRegressions(V2Fixture):
    def setUp(self):
        super().setUp()
        from tests.test_engine import active_state
        from twinlink.render import render_files
        self.legacy = active_state("rathole")
        for t in self.legacy["tunnels"].values():
            t.update(running=False, enabled=False, verified=False)
        for f in self.legacy["forwards"].values():
            f.update(running=False, enabled=False, rathole_transport="noise", noise_private_key=PRIVATE, noise_public_key=KEYS["noise_public_key"])
        self.host = SystemHost(self.root / "units")
        self.runtime = ProfileRuntime(self.store, self.host, str(self.host.unit_dir))
        self.store.write(self.legacy)
        self.files = render_files(self.legacy, str(self.store.directory), str(self.host.unit_dir), self.runtime.executable, self.runtime.binaries["rathole"])
        for path, spec in self.files.items():
            atomic_write(path, spec["content"], spec["mode"])

    def test_migration_delete_and_uninstall_remove_legacy_secrets(self):
        args = ["--state-dir", str(self.store.directory), "--unit-dir", str(self.host.unit_dir), "--json"]
        with patch.object(cli, "Host", return_value=self.host), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main([*args, "config", "migrate", "--apply", "--yes"]), 0)
        self.assertEqual(self.store.read()["version"], 2)
        adopted = [r for r in Ownership(self.store).read()["resources"].values() if r.get("provenance")]
        self.assertEqual(len(adopted), len(self.files))
        delete_pair(self.store, self.runtime, "edge")
        self.assertFalse(any(Path(p).exists() for p in self.files))
        # An existing recorded installer baseline allows the final local purge.
        atomic_write(self.store.directory / "baseline.json", json.dumps({"historical_baseline": "recorded", "package_delta": {}, "directories": {}}))
        self.assertFalse(restore_system(self.store, self.runtime, dependencies=True)["conflicts"])
        prefix = self.root / "prefix"
        executable = prefix / "libexec/twinlink-runtime"
        launcher = prefix / "bin/twinlink"
        import hashlib
        for path in (executable, launcher):
            atomic_write(path, "owned program", 0o755)
        atomic_write(executable.parent / "twinlink-install.json", json.dumps({"owner": "twinlink", "version": 1, "files": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (executable, launcher)}}))
        self.runtime.executable = str(executable)
        self.assertEqual(remove_program(self.store, self.runtime)["status"], "complete")
        self.assertFalse(self.store.path.exists())

    def test_modified_legacy_config_blocks_adoption_without_deleting(self):
        path = next(Path(p) for p in self.files if p.endswith(".toml"))
        path.write_text(path.read_text() + "# operator edit\n")
        with self.assertRaises(StateError):
            inventory(self.store, self.runtime, self.legacy)
        self.assertIn("operator edit", path.read_text())
        self.assertFalse(Ownership(self.store).read()["resources"])

    def test_empty_legacy_table_is_proven_and_retired(self):
        from twinlink.render import render_nft
        self.host.run(["nft", "--file", "-"], input=render_nft(self.legacy))
        rows = inventory(self.store, self.runtime, self.legacy)
        adopt(self.store, self.runtime, rows)
        self.assertNotIn("twinlink", self.host.tables)
        self.assertEqual(Ownership(self.store).read()["resources"]["nft:twinlink"]["status"], "restored")

    def test_migration_recovers_crash_after_legacy_table_delete(self):
        from twinlink.render import render_nft
        self.host.run(["nft", "--file", "-"], input=render_nft(self.legacy))
        rows = inventory(self.store, self.runtime, self.legacy)
        original = self.host.run
        def crash(argv, **kwargs):
            value = original(argv, **kwargs)
            if argv[:3] == ["nft", "delete", "table"]:
                raise OSError("death after table withdrawal")
            return value
        with patch.object(self.host, "run", side_effect=crash):
            with self.assertRaises(OSError):
                adopt(self.store, self.runtime, rows)
        adopt(self.store, self.runtime, inventory(self.store, self.runtime, self.legacy))
        self.assertEqual(Ownership(self.store).read()["resources"]["nft:twinlink"]["status"], "restored")

    def test_paqet_stays_gated_until_binary_and_packet_qualification(self):
        from twinlink.profiles import capabilities
        self.assertFalse(capabilities(self.r, "direct-paqet")["compatible"])
        with self.assertRaises(ValueError):
            paqet.binary_pin("unqualified-architecture")
