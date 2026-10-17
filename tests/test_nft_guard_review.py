"""V2 nft serializer compatibility and per-launch preparation checks."""
import contextlib
import hashlib
import io
import json
import shlex
from unittest.mock import patch

from tests.test_lifecycle_review import RuntimeFixture
from tests.test_profile_runtime import SystemHost
from twinlink import cli
from twinlink.contracts import canonical, next_revision
from twinlink.coordination import new_transaction
from twinlink.diagnostics import collect
from twinlink.host import Host
from twinlink.ownership import Ownership
from twinlink.profiles import table_name
from twinlink.reports import validate
from twinlink.store import StateError, Store, atomic_write


class OmittedCommentHost(SystemHost):
    def __init__(self, unit_dir):
        super().__init__(unit_dir)
        self.omit_comments = True
        self.scripts = {}
        self.text_override = None
        self.text_code = 0

    def run(self, argv, **kwargs):
        result = super().run(argv, **kwargs)
        if argv[:3] == ["nft", "--file", "-"]:
            table = next(reversed(self.tables))
            script = kwargs["input"]
            self.scripts[table] = script[script.index("table ip " + table + " {"):]
        elif argv[:3] == ["nft", "-j", "list"] and result["returncode"] == 0 and self.omit_comments:
            snapshot = json.loads(result["stdout"])
            for item in snapshot["nftables"]:
                if "table" in item:
                    item["table"].pop("comment", None)
            result["stdout"] = json.dumps(snapshot)
        elif argv[:3] == ["nft", "list", "table"]:
            result.update(returncode=self.text_code, stdout=self.text_override if self.text_override is not None else self.scripts.get(argv[-1], ""))
        return result


class NftCommentReviewTests(RuntimeFixture):
    def setUp(self):
        super().setUp()
        self.host = OmittedCommentHost(self.host.unit_dir)
        self.runtime.host = self.host
        self.stage()
        self.prepare()
        self.control = self.store.read()["pairs"]["edge"]
        self.tx = {"previous": None}
        self.table = table_name("edge")
        self.marker = "twinlink:" + self.store.read()["installation_id"]
        self.doctor_commands = []

    def activate(self):
        self.runtime.prepare(self.r, "vps1", "gre-kernel", self.control, self.tx)
        self.runtime.start(self.r, "vps1", "gre-kernel", self.control, self.tx)

    def withdraw(self):
        self.runtime.quiesce(self.r, "vps1", "gre-kernel", self.control, self.tx)
        self.assertFalse(self.host.tables)
        self.assertFalse(self.host.links())
        self.assertEqual(self.host.forwarding, "0")
        self.assertEqual(self.runtime.ledger.read()["resources"]["nft:" + self.table]["status"], "restored")

    def doctor_command(self, argv, **kwargs):
        self.doctor_commands.append((list(argv), kwargs))
        value = ""
        if argv[0] == "ip":
            value = json.dumps(self.host.links() if "link" in argv else self.host.addresses() if "address" in argv else self.host.routes())
        elif argv[0] == "nft":
            result = self.host.run(argv, check=False)
            return {**result, "error": None, "truncated": False}
        return {"returncode": 0, "stdout": value, "error": None, "truncated": False}

    def collect_doctor(self, **kwargs):
        self.committed("gre-kernel")
        return collect(self.store, "edge", redaction="secrets", command_fn=kwargs.pop("command_fn", self.doctor_command),
                       probe_fn=lambda *a, **k: {"result": "pass", "latency_ms": 1},
                       sample_fn=lambda: ({"boot_id": "boot"}, []), **kwargs)

    def assert_doctor_nft(self, report, owned):
        validate(report)
        resources = next(item for item in report["profile_evidence"] if item["source"] == "profile-resources")
        self.assertEqual(resources["value"]["checks"]["owned_nft"], owned)
        self.assertEqual(resources["result"], "unknown" if owned is None else "pass" if owned else "fail")
        self.assertEqual(report["overall_status"], "unknown" if owned is None else "healthy" if owned else "degraded")
        drift = [row for row in report["findings"] if row["inference"] == "Local resource drift observed"]
        if owned is None:
            self.assertFalse(drift)
        elif owned is False:
            self.assertEqual(len(drift), 1)
            self.assertEqual(drift[0]["confidence"], "high")
            self.assertEqual(drift[0]["evidence_ids"], [resources["id"]])
        return next(item["value"] for item in report["firewall_conntrack"] if item["source"] == "nft")

    def test_activation_and_cleanup_recover_marker_missing_from_json(self):
        self.activate()
        self.runtime.verify(self.r, "vps1", "gre-kernel", self.control, self.tx)
        self.assertEqual(self.runtime.ledger.read()["resources"]["nft:" + self.table]["status"], "complete")
        self.assertEqual(self.runtime._table_snapshot(self.table)["nftables"][0]["table"]["comment"], self.marker)
        self.assertIn(["nft", "list", "table", "ip", self.table], self.host.commands)
        before = self.runtime.ledger.path.read_bytes()
        snapshot = self.assert_doctor_nft(self.collect_doctor(), True)
        self.assertEqual(snapshot["nftables"][0]["table"]["comment"], self.marker)
        self.assertEqual(self.runtime.ledger.path.read_bytes(), before)
        self.withdraw()

    def test_doctor_exports_normalized_evidence_at_both_redaction_levels(self):
        self.activate()
        self.runtime.verify(self.r, "vps1", "gre-kernel", self.control, self.tx)
        self.committed("gre-kernel")
        before = {str(p): p.read_bytes() for p in self.store.directory.rglob("*") if p.is_file()}
        for level in ("share", "secrets"):
            with self.subTest(level=level):
                exported = self.root / (level + ".json")
                with patch("twinlink.diagnostics.bounded_command", side_effect=self.doctor_command), patch("twinlink.diagnostics.application_probe", return_value={"result": "pass", "latency_ms": 1}), patch("twinlink.diagnostics.read_sample", return_value=({"boot_id": "boot"}, [])), contextlib.redirect_stdout(io.StringIO()) as out:
                    code = cli.main(["--state-dir", str(self.store.directory), "doctor", "--redaction", level, "--export", str(exported)])
                self.assertEqual(code, 0)
                report = json.loads(exported.read_text())
                self.assertEqual(json.loads(out.getvalue())["report"], report)
                self.assertEqual(exported.stat().st_mode & 0o777, 0o600)
                snapshot = self.assert_doctor_nft(report, True)
                marker = snapshot["nftables"][0]["table"]["comment"]
                links = next(item["value"] for item in report["interface_route_samples"] if item["source"] == "link")
                self.assertEqual(marker, links[0]["ifalias"].rsplit(":", 1)[0])
                if level == "share":
                    self.assertNotIn(self.marker, json.dumps(report))
                else:
                    self.assertEqual(marker, self.marker)
        after = {str(p): p.read_bytes() for p in self.store.directory.rglob("*") if p.is_file()}
        self.assertEqual(after, before)

    def test_doctor_preserves_explicit_json_comments_without_text_fallback(self):
        self.activate()
        self.host.omit_comments = False
        for marker, owned in ((self.marker, True), ("twinlink:foreign", False)):
            with self.subTest(marker=marker):
                self.doctor_commands.clear()
                self.host.tables[self.table]["nftables"][0]["table"]["comment"] = marker
                snapshot = self.assert_doctor_nft(self.collect_doctor(), owned)
                self.assertEqual(snapshot["nftables"][0]["table"]["comment"], marker)
                self.assertFalse(any(argv[:3] == ["nft", "list", "table"] for argv, _ in self.doctor_commands))

    def test_doctor_rejects_wrong_table_foreign_and_nested_text_markers(self):
        self.activate()
        for text in ('table ip other { comment "' + self.marker + '" }',
                     'table ip ' + self.table + ' { comment "twinlink:foreign" }',
                     'table ip ' + self.table + ' { chain x { comment "' + self.marker + '" } }'):
            with self.subTest(text=text):
                self.host.text_override = text
                snapshot = self.assert_doctor_nft(self.collect_doctor(), False)
                self.assertNotIn("comment", snapshot["nftables"][0]["table"])

    def test_doctor_recovered_marker_does_not_hide_rule_drift(self):
        self.activate()
        rule = next(row["rule"] for row in self.host.tables[self.table]["nftables"] if "rule" in row)
        rule["expr"].append({"accept": None})
        snapshot = self.assert_doctor_nft(self.collect_doctor(), False)
        self.assertEqual(snapshot["nftables"][0]["table"]["comment"], self.marker)

    def test_doctor_rejects_truncated_failed_and_timed_out_comment_reads(self):
        self.activate()
        for outcome in ({"truncated": True}, {"returncode": 1}, {"returncode": None, "error": "TimeoutError"},
                        {"returncode": 0, "error": "OverflowError"}):
            def command(argv, **kwargs):
                result = self.doctor_command(argv, **kwargs)
                return {**result, **outcome} if argv[:3] == ["nft", "list", "table"] else result
            with self.subTest(outcome=outcome):
                report = self.collect_doctor(command_fn=command)
                snapshot = self.assert_doctor_nft(report, None)
                self.assertNotIn("comment", snapshot["nftables"][0]["table"])
                self.assertIn("nft-comment", [row["collector"] for row in report["collection_errors"]])
                self.assertTrue(report["probes"])
                self.assertTrue(all(row["result"] == "pass" for row in report["probes"]))
                if outcome.get("truncated"):
                    self.assertIn("nft-comment", report["truncation"])

    def test_doctor_comment_read_uses_remaining_budget_and_stops_at_deadline(self):
        self.activate()
        for elapsed in (14.5, 15):
            now = [0]
            def command(argv, **kwargs):
                result = self.doctor_command(argv, **kwargs)
                if argv[:3] == ["nft", "-j", "list"]:
                    now[0] = elapsed
                return result
            with self.subTest(elapsed=elapsed):
                self.doctor_commands.clear()
                report = self.collect_doctor(command_fn=command, clock=lambda: now[0])
                text_reads = [kwargs for argv, kwargs in self.doctor_commands if argv[:3] == ["nft", "list", "table"]]
                snapshot = next(item["value"] for item in report["firewall_conntrack"] if item["source"] == "nft")
                if elapsed < 15:
                    self.assertEqual(text_reads, [{"timeout": 0.5}])
                    self.assertEqual(snapshot["nftables"][0]["table"]["comment"], self.marker)
                else:
                    self.assert_doctor_nft(report, None)
                    self.assertFalse(text_reads)
                    self.assertNotIn("comment", snapshot["nftables"][0]["table"])
                    self.assertIn("nft-comment", [row["collector"] for row in report["collection_errors"]])

    def test_unavailable_comment_proof_does_not_hide_observed_rule_or_gre_drift(self):
        self.activate()
        def command(argv, **kwargs):
            result = self.doctor_command(argv, **kwargs)
            return {**result, "returncode": None, "error": "TimeoutError"} if argv[:3] == ["nft", "list", "table"] else result
        rule = next(row["rule"] for row in self.host.tables[self.table]["nftables"] if "rule" in row)
        for kind in ("rule", "gre"):
            with self.subTest(kind=kind):
                if kind == "rule":
                    rule["expr"].append({"accept": None})
                else:
                    self.host.link_rows[0]["mtu"] -= 1
                report = self.collect_doctor(command_fn=command)
                validate(report)
                resources = next(row for row in report["profile_evidence"] if row["source"] == "profile-resources")
                self.assertEqual(resources["value"]["checks"]["owned_nft"], False if kind == "rule" else None)
                self.assertEqual(resources["result"], "fail")
                self.assertEqual(report["overall_status"], "degraded")
                drift = [row for row in report["findings"] if row["inference"] == "Local resource drift observed"]
                self.assertEqual(len(drift), 1)
                self.assertEqual(drift[0]["confidence"], "high")
                self.assertEqual(drift[0]["evidence_ids"], [resources["id"]])
                if kind == "rule":
                    rule["expr"].pop()

    def test_unknown_comment_proof_exports_as_pending_without_drift_finding(self):
        self.activate()
        self.committed("gre-kernel")
        for level, outcome in (("share", {"truncated": True}), ("secrets", {"returncode": None, "error": "TimeoutError"})):
            def command(argv, **kwargs):
                result = self.doctor_command(argv, **kwargs)
                return {**result, **outcome} if argv[:3] == ["nft", "list", "table"] else result
            with self.subTest(level=level):
                exported = self.root / (level + "-unknown.json")
                with patch("twinlink.diagnostics.bounded_command", side_effect=command), patch("twinlink.diagnostics.application_probe", return_value={"result": "pass", "latency_ms": 1}), patch("twinlink.diagnostics.read_sample", return_value=({"boot_id": "boot"}, [])), contextlib.redirect_stdout(io.StringIO()) as out:
                    code = cli.main(["--state-dir", str(self.store.directory), "doctor", "--redaction", level, "--export", str(exported)])
                self.assertEqual(code, 3)
                report = json.loads(exported.read_text())
                self.assertEqual(json.loads(out.getvalue())["report"], report)
                snapshot = self.assert_doctor_nft(report, None)
                self.assertNotIn("comment", snapshot["nftables"][0]["table"])
                self.assertEqual(exported.stat().st_mode & 0o777, 0o600)

    def test_comment_proof_availability_is_reset_between_watch_samples(self):
        self.activate()
        now, text_reads = [0], []
        def sleep(delay):
            now[0] += delay
        def command(argv, **kwargs):
            result = self.doctor_command(argv, **kwargs)
            if argv[:3] == ["nft", "list", "table"]:
                text_reads.append(argv)
                if len(text_reads) == 1:
                    result.update(returncode=None, error="TimeoutError")
            return result
        report = self.collect_doctor(command_fn=command, duration=1.5, clock=lambda: now[0], sleep=sleep)
        validate(report)
        resources = [row for row in report["profile_evidence"] if row["source"] == "profile-resources"]
        self.assertEqual([row["value"]["checks"]["owned_nft"] for row in resources], [None, True])
        self.assertEqual([row["result"] for row in resources], ["unknown", "pass"])
        self.assertEqual(report["overall_status"], "unknown")
        self.assertFalse(any(row["inference"] == "Local resource drift observed" for row in report["findings"]))

    def test_serializer_change_does_not_change_owned_table_fingerprint(self):
        self.host.omit_comments = False
        self.activate()
        original = self.runtime._table_value(self.table)
        self.host.omit_comments = True
        self.assertEqual(self.runtime._table_value(self.table), original)
        self.withdraw()

    def test_interrupted_apply_with_missing_json_marker_can_withdraw(self):
        self.runtime.prepare(self.r, "vps1", "gre-kernel", self.control, self.tx)
        with patch.object(Ownership, "bind_expected", side_effect=KeyboardInterrupt()), self.assertRaises(KeyboardInterrupt):
            self.runtime.start(self.r, "vps1", "gre-kernel", self.control, self.tx)
        self.assertTrue(self.host.tables)
        self.assertEqual(self.runtime.ledger.read()["resources"]["nft:" + self.table]["status"], "pending")
        self.withdraw()

    def test_missing_or_wrong_text_proof_preserves_pending_table(self):
        self.host.text_override = 'table ip ' + self.table + ' { chain x { comment "' + self.marker + '" } }'
        self.runtime.prepare(self.r, "vps1", "gre-kernel", self.control, self.tx)
        with self.assertRaises(StateError):
            self.runtime.start(self.r, "vps1", "gre-kernel", self.control, self.tx)
        with self.assertRaises(StateError):
            self.runtime.quiesce(self.r, "vps1", "gre-kernel", self.control, self.tx)
        self.assertTrue(self.host.tables)
        self.assertEqual(self.runtime.ledger.read()["resources"]["nft:" + self.table]["status"], "pending")
        self.host.text_override = None
        self.withdraw()

    def test_v2_fallback_rejects_untrusted_text_and_never_overwrites_json_marker(self):
        cases = [(0, 'table ip other { comment "' + self.marker + '" }'),
                 (0, 'table ip ' + self.table + ' { comment "twinlink:foreign" }'),
                 (0, 'table ip ' + self.table + ' { chain x { comment "' + self.marker + '" } }'),
                 (1, 'table ip ' + self.table + ' { comment "' + self.marker + '" }')]
        for code, text in cases:
            snapshot = {"nftables": [{"table": {"family": "ip", "name": self.table}}]}
            with self.subTest(text=text), patch.object(self.host, "run", return_value={"returncode": code, "stdout": text}):
                actual = Host.nft_table_comments(self.host, snapshot, {self.table: self.marker})
                self.assertNotIn("comment", actual["nftables"][0]["table"])
        snapshot = {"nftables": [{"table": {"family": "ip", "name": self.table, "comment": "foreign"}}]}
        with patch.object(self.host, "run", side_effect=AssertionError("Do not override explicit JSON ownership")):
            Host.nft_table_comments(self.host, snapshot, {self.table: self.marker})
        self.assertEqual(snapshot["nftables"][0]["table"]["comment"], "foreign")

    def test_recovered_marker_does_not_hide_changed_rule_expressions(self):
        self.activate()
        rule = next(row["rule"] for row in self.host.tables[self.table]["nftables"] if "rule" in row)
        rule["expr"].append({"accept": None})
        with self.assertRaises(StateError):
            self.runtime.quiesce(self.r, "vps1", "gre-kernel", self.control, self.tx)
        self.assertTrue(self.host.tables)


class LaunchGuardReviewTests(RuntimeFixture):
    def setUp(self):
        super().setUp()
        self.stage()
        self.prepare()
        self.committed()

    def arguments(self, profile="direct-rathole", revision=None):
        revision = revision or self.r
        unit = self.runtime.runtime_unit(revision, profile)
        text = (self.host.unit_dir / unit).read_text()
        command = next(line.split("=", 1)[1] for line in text.splitlines() if line.startswith("ExecCondition="))
        return shlex.split(command)[1:]

    def guard(self, profile="direct-rathole", revision=None, argv=None):
        with patch.object(cli, "Host", return_value=self.host), contextlib.redirect_stdout(io.StringIO()) as out:
            result = cli.main(argv or self.arguments(profile, revision))
        return result, out.getvalue()

    def test_generated_guard_keeps_custom_binary_unit_and_runtime_paths(self):
        args = self.arguments()
        self.assertEqual(args[args.index("--rathole-binary") + 1], str(self.binary))
        self.assertEqual(args[args.index("--unit-dir") + 1], str(self.host.unit_dir))
        self.assertEqual(args[args.index("--runtime-path") + 1], self.runtime.executable)
        self.assertEqual(self.guard()[0], 0)

    def test_launch_guard_is_read_only_and_does_not_reacquire_mutation_lock(self):
        before = {str(p): p.read_bytes() for p in self.store.directory.rglob("*") if p.is_file()}
        with self.store.lock(), patch.object(Store, "lock", side_effect=AssertionError("startup lock would deadlock")), patch.object(Ownership, "save", side_effect=AssertionError("read-only guard")), patch("twinlink.rathole.check_version", side_effect=AssertionError("must not execute binary")), patch("socket.socket", side_effect=AssertionError("launch guard must not probe")):
            self.assertEqual(self.guard()[0], 0)
        after = {str(p): p.read_bytes() for p in self.store.directory.rglob("*") if p.is_file()}
        self.assertEqual(after, before)

    def test_binary_replacement_is_rejected_on_initial_launch_and_restart(self):
        self.assertEqual(self.guard()[0], 0)
        self.host.active.add(self.runtime.runtime_unit(self.r, "direct-rathole"))
        atomic_write(self.binary, "changed binary", 0o755)
        code, output = self.guard()
        self.assertEqual(code, 1)
        self.assertIn("Prepared binary changed", output)
        with patch.object(self.runtime, "discover", return_value=self.store.facts("edge", 1)), self.assertRaises(StateError):
            self.runtime.preflight(self.r, "vps1", "direct-rathole", self.store.read()["pairs"]["edge"], {})

    def test_gre_rathole_guard_checks_the_same_binary_pin(self):
        self.committed("gre-rathole")
        self.assertEqual(self.guard("gre-rathole")[0], 0)
        atomic_write(self.binary, "changed binary", 0o755)
        self.assertEqual(self.guard("gre-rathole")[0], 1)

    def test_changed_missing_or_insecure_generated_config_is_rejected(self):
        path = self.runtime.root(self.r, "vps1", "direct-rathole") / "config.toml"
        original = path.read_bytes()
        for kind in ("changed", "missing", "mode"):
            with self.subTest(kind=kind):
                atomic_write(path, original)
                if kind == "changed":
                    path.write_bytes(b"X" + original[1:])
                elif kind == "missing":
                    path.unlink()
                else:
                    path.chmod(0o644)
                self.assertEqual(self.guard()[0], 1)

    def test_missing_preparation_or_stale_facts_is_rejected(self):
        path = self.store.preparation_path("edge", 1)
        before = path.read_bytes()
        path.unlink()
        self.assertEqual(self.guard()[0], 1)
        atomic_write(path, before)
        facts = self.store.facts("edge", 1)
        facts["gateway"] = "198.51.100.253"
        atomic_write(self.store.facts_path("edge", 1), json.dumps(facts))
        self.assertEqual(self.guard()[0], 1)

    def test_pending_artifact_ownership_is_rejected_without_reconciliation(self):
        path = self.runtime.root(self.r, "vps1", "direct-rathole") / "config.toml"
        data = self.runtime.ledger.read()
        data["resources"]["file:" + str(path)]["status"] = "pending"
        self.runtime.ledger.save(data)
        before = self.runtime.ledger.path.read_bytes()
        self.assertEqual(self.guard()[0], 1)
        self.assertEqual(self.runtime.ledger.path.read_bytes(), before)

    def test_unit_edits_or_foreign_drop_ins_are_rejected(self):
        unit = self.runtime.runtime_unit(self.r, "direct-rathole")
        args = self.arguments()
        original = self.host.unit_status
        def status(name):
            result = original(name)
            if name == unit:
                result["properties"]["DropInPaths"] = "/foreign/override.conf"
            return result
        with patch.object(self.host, "unit_status", side_effect=status):
            self.assertEqual(self.guard(argv=args)[0], 1)
        (self.host.unit_dir / unit).write_text("foreign unit")
        self.assertEqual(self.guard(argv=args)[0], 1)

    def test_selected_revision_is_checked_when_newer_configuration_is_staged(self):
        newer = next_revision(self.r, transport={"port": 4567})
        self.store.stage(self.store.read(), newer, "vps1", self.creds, self.store.facts("edge", 1))
        self.assertEqual(self.guard()[0], 0)
        self.assertEqual(self.guard(revision=newer, argv=[*self.arguments()[:-1], "2"])[0], 1)

    def test_target_starting_checks_pins_before_allowing_each_attempt(self):
        state = self.store.read()
        c = state["pairs"]["edge"]
        tx = new_transaction("edge", self.r, "gre-rathole", c, now=100)
        tx["phase"] = "target-starting"
        c["transition"] = tx
        self.store.write(state)
        self.assertEqual(self.guard("gre-rathole")[0], 0)
        atomic_write(self.binary, "changed binary", 0o755)
        self.assertEqual(self.guard("gre-rathole")[0], 1)

    def test_off_and_standby_still_cannot_start(self):
        self.assertEqual(self.guard("gre-rathole")[0], 1)
        state = self.store.read()
        state["pairs"]["edge"]["active"] = None
        self.store.write(state)
        self.assertEqual(self.guard()[0], 1)

    def test_missing_nonexecutable_and_symlinked_binary_cannot_launch(self):
        original = self.binary.read_bytes()
        self.binary.chmod(0o600)
        self.assertEqual(self.guard()[0], 1)
        self.binary.unlink()
        self.assertEqual(self.guard()[0], 1)
        replacement = self.root / "same-content"
        atomic_write(replacement, original, 0o755)
        self.binary.symlink_to(replacement)
        self.assertEqual(self.guard()[0], 1)

    def test_paqet_launch_and_restart_use_their_own_prepared_binary_pin(self):
        from twinlink import paqet
        binary = self.root / "paqet"
        atomic_write(binary, "fixture paqet binary", 0o755)
        checksum = hashlib.sha256(binary.read_bytes()).hexdigest()
        self.runtime.binaries["paqet"] = str(binary)
        with patch.object(paqet, "TRUSTED_BINARY_HASHES", {"fixture": checksum}), patch.object(paqet, "QUALIFIED_PROTOCOLS", frozenset(("tcp",))):
            self.prepare()
            self.committed("direct-paqet")
            self.assertEqual(self.guard("direct-paqet")[0], 0)
            atomic_write(binary, "changed paqet binary", 0o755)
            self.assertEqual(self.guard("direct-paqet")[0], 1)

    def test_paqet_config_fingerprint_is_stable_after_canonical_roundtrip(self):
        from twinlink import paqet
        facts = self.store.facts("edge", 1)
        first = paqet.render_config(self.r, "vps1", facts, self.creds["paqet"])
        second = paqet.render_config(json.loads(canonical(self.r)), "vps1", facts, self.creds["paqet"])
        self.assertEqual(first, second)
