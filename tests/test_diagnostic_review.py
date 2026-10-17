"""Uninstall interruption and diagnostic artifact/import/export regressions."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from tests.test_lifecycle_review import RuntimeFixture
from tests.test_v2 import V2Fixture, FACTS
from twinlink import cli
from twinlink.cleanup import remove_program
from twinlink.contracts import canonical, empty_v2
from twinlink.diagnostics import collect, readiness, evidence, cap_report, MAX_REPORT_BYTES, MAX_COMMAND_BYTES
from twinlink.models import ValidationError
from twinlink.reports import parse, validate, merge, compare
from twinlink.store import atomic_write


class UninstallInterruptionReviewTests(V2Fixture):
    def setUp(self):
        super().setUp()
        self.store.write(empty_v2())
        prefix = self.root / "prefix"
        self.launcher = prefix / "bin/twinlink"
        self.binary = prefix / "libexec/twinlink-runtime"
        self.manifest = self.binary.parent / "twinlink-install.json"
        for path in (self.launcher, self.binary):
            atomic_write(path, "owned executable", 0o755)
        atomic_write(self.manifest, canonical({"owner": "twinlink", "version": 1,
            "files": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.launcher, self.binary)}}), 0o644)
        atomic_write(self.store.directory / "baseline.json", canonical({"package_delta": {}, "directories": {
            str(p): {"existed": False} for p in (prefix, self.launcher.parent, self.binary.parent, self.store.directory)}}))
        self.runtime = MagicMock(executable=str(self.binary))
        self.journal = self.store.directory / "uninstall.json"
        self.originals = {p: (p.read_bytes(), p.stat().st_mode & 0o777) for p in
                          (self.launcher, self.binary, self.manifest, self.store.path, self.store.directory / "baseline.json")}

    def assert_recoverable(self):
        for path, (content, mode) in self.originals.items():
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(path.stat().st_mode & 0o777, mode)
        self.assertTrue(self.journal.is_file())
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)
        self.assertEqual(remove_program(self.store, self.runtime)["status"], "complete")
        self.assertFalse(self.binary.exists())
        self.assertFalse(self.launcher.exists())
        self.assertFalse(self.store.directory.exists())

    def interrupt_checkpoint(self, exception):
        interrupted = []
        def write(path, content, mode=0o600):
            atomic_write(path, content, mode)
            if Path(path) == self.journal and json.loads(content)["status"] == "program-removed" and not interrupted:
                self.assertFalse(self.binary.exists())
                self.assertFalse(self.launcher.exists())
                interrupted.append(True)
                raise exception()
        with patch("twinlink.cleanup.atomic_write", side_effect=write), self.assertRaises(exception):
            remove_program(self.store, self.runtime)
        self.assertTrue(interrupted)
        self.assert_recoverable()

    def test_keyboard_interrupt_after_program_deletion_restores_recovery_command(self):
        self.interrupt_checkpoint(KeyboardInterrupt)

    def test_system_exit_after_program_deletion_restores_recovery_command(self):
        self.interrupt_checkpoint(SystemExit)

    def test_keyboard_interrupt_after_private_record_deletion_restores_records_too(self):
        original = Path.unlink
        interrupted = []
        def unlink(path, *args, **kwargs):
            original(path, *args, **kwargs)
            if path == self.store.path and not interrupted:
                interrupted.append(True)
                raise KeyboardInterrupt()
        with patch.object(Path, "unlink", unlink), self.assertRaises(KeyboardInterrupt):
            remove_program(self.store, self.runtime)
        self.assertTrue(interrupted)
        self.assert_recoverable()


class ArtifactBoundReviewTests(RuntimeFixture):
    def setUp(self):
        super().setUp()
        self.r["services"][0]["ports"] = "10000-10255"
        self.r["services"][0]["backend"]["ports"] = "80"
        self.stage()
        self.prepare()
        root = self.store.revision_path("edge", 1) / "vps1" / "gre-kernel"
        self.rules = next(p for p in root.iterdir() if p.name != "manifest.json")
        self.assertGreater(self.rules.stat().st_size, MAX_COMMAND_BYTES)

    def kernel(self):
        return next(row for row in readiness(self.store, self.r, "vps1") if row["profile"] == "gre-kernel")

    def test_full_256_port_rules_pass_preflight_and_diagnostic_readiness(self):
        with patch.object(self.runtime, "discover", return_value=FACTS):
            self.runtime.preflight(self.r, "vps1", "gre-kernel", self.store.read()["pairs"]["edge"], {})
        self.assertTrue(self.kernel()["artifacts_match"])
        self.assertTrue(self.kernel()["preparation_matches"])

    def test_same_size_corruption_is_drift(self):
        data = self.rules.read_bytes()
        self.rules.write_bytes(b"X" + data[1:])
        self.assertFalse(self.kernel()["artifacts_match"])

    def test_oversized_artifact_is_rejected_without_reading_its_body(self):
        with self.rules.open("ab") as stream:
            stream.write(b"extra")
        original = Path.open
        def bounded(path, *args, **kwargs):
            if path == self.rules:
                raise AssertionError("Size-mismatched artifact should not be read")
            return original(path, *args, **kwargs)
        with patch.object(Path, "open", bounded):
            self.assertFalse(self.kernel()["artifacts_match"])

    def test_insecure_artifact_mode_is_still_drift(self):
        self.rules.chmod(0o644)
        self.assertFalse(self.kernel()["artifacts_match"])


class ReportFixture(V2Fixture):
    def setUp(self):
        super().setUp()
        self.stage()
        self.report = collect(self.store, "edge", redaction="secrets", sample_fn=lambda: ({"boot_id": "boot"}, []),
                              command_fn=lambda *args, **kwargs: {"returncode": None, "stdout": "", "error": "unavailable", "truncated": False})
        self.peer = copy.deepcopy(self.report)
        self.peer["report_id"], self.peer["host"]["role"] = "peer-report", "vps2"

    def paths(self, first, second):
        paths = self.root / "first.json", self.root / "second.json"
        for path, report in zip(paths, (first, second)):
            atomic_write(path, json.dumps(report, indent=2))
        return paths

    def finding(self, ids):
        return {"observation": "Fixture failure", "inference": "Fixture", "likely_cause": "Fixture",
                "evidence_ids": list(ids), "counterevidence_ids": [], "confidence": "low", "suggested_next_checks": []}


class ReportValidationReviewTests(ReportFixture):
    def invalid_at(self, path, value):
        report = copy.deepcopy(self.report)
        target = report
        for name in path[:-1]:
            target = target[name]
        target[path[-1]] = value
        return report

    def test_nested_containers_scalars_and_enums_are_validated(self):
        cases = [(('host',), None), (('host', 'role'), {}), (('host', 'pair_id'), []), (('host', 'boot_id'), 1),
                 (('host', 'clock'), None), (('collection_window',), []), (('collection_window', 'monotonic'), []),
                 (('collection_window', 'monotonic', 'start'), True), (('collection_window', 'monotonic', 'end'), -1),
                 (('redaction_summary',), None), (('redaction_summary', 'level'), 'public'), (('redaction_summary', 'context'), {}),
                 (('schema_version',), True), (('collector_version',), False), (('versions',), None), (('revisions',), []),
                 (('report_id',), []), (('active_profile',), 'unsupported'), (('config_digest',), {}), (('overall_status',), []),
                 (('probes',), {}), (('log_events',), [None]), (('service_mappings',), [1]),
                 (('inactive_readiness',), [False]), (('collection_errors',), [1]), (('unknowns',), [None]), (('truncation',), [1])]
        for path, value in cases:
            with self.subTest(path=path), self.assertRaises(ValidationError):
                parse(json.dumps(self.invalid_at(path, value)))

    def test_evidence_and_finding_fields_are_validated(self):
        item = evidence("link", "pass", [], 0, "vps1")
        for field, value in (("id", None), ("role", []), ("source", {}), ("result", "healthy"),
                             ("monotonic_offset", -1), ("scheduling_gap", "0"), ("error", {}), ("observed_at_utc", "bad")):
            invalid = copy.deepcopy(self.report)
            invalid["probes"] = [{**item, field: value}]
            with self.subTest(field=field), self.assertRaises(ValidationError):
                parse(json.dumps(invalid))
        for item in (None, {}, {"id": "partial"}):
            with self.assertRaises(ValidationError):
                parse(json.dumps({**self.report, "probes": [item]}))
        for field, value in (("observation", None), ("evidence_ids", "id"), ("confidence", "certain"), ("suggested_next_checks", [None])):
            invalid = {**self.report, "findings": [{**self.finding([]), field: value}]}
            with self.subTest(field=field), self.assertRaises(ValidationError):
                parse(json.dumps(invalid))

    def test_timestamps_require_valid_aware_ordered_windows(self):
        for path, value in ((('created_at_utc',), 'not-a-date'),
                            (('collection_window', 'start'), '2026-10-17T10:00:00'),
                            (('collection_window', 'end'), '2000-01-01T00:00:00+00:00'),
                            (('collection_window', 'monotonic', 'end'), float('inf'))):
            with self.subTest(path=path), self.assertRaises(ValidationError):
                parse(json.dumps(self.invalid_at(path, value)))

    def test_z_timestamps_and_both_redaction_levels_remain_valid(self):
        for level in ("share", "secrets"):
            report = copy.deepcopy(self.report)
            report["redaction_summary"]["level"] = level
            for name in ("start", "end"):
                report["collection_window"][name] = report["collection_window"][name].replace("+00:00", "Z")
            self.assertEqual(parse(json.dumps(report)), report)
            if level == "secrets":
                self.assertEqual(len(merge(report, self.peer)["reports"]), 2)

    def test_link_rows_and_statistics_cannot_crash_compare(self):
        for value in ([None], [{"ifname": []}], [{"ifname": "eth0", "stats64": None}],
                      [{"ifname": "eth0", "stats64": {"rx": []}}],
                      [{"ifname": "eth0", "stats64": {"rx": {"bytes": "bad"}}}]):
            invalid = copy.deepcopy(self.report)
            invalid["interface_route_samples"] = [evidence("link", "pass", value, 0, "vps1")]
            with self.subTest(value=value), self.assertRaises(ValidationError):
                compare(invalid, self.peer)

    def test_cli_merge_returns_structured_invalid_for_null_host(self):
        first, second = self.paths({**self.report, "host": None}, self.peer)
        exported = self.root / "invalid-export.json"
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.main(["--state-dir", str(self.store.directory), "doctor", "--merge", str(first), str(second), "--export", str(exported)])
        self.assertEqual(code, 2)
        result = json.loads(out.getvalue())
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["status"], "invalid")
        self.assertIn("host", result["error"])
        self.assertFalse(exported.exists())

    def test_cli_compare_returns_structured_invalid_for_bad_nested_field(self):
        first, _ = self.paths(self.invalid_at(("redaction_summary",), None), self.peer)
        with patch("twinlink.diagnostics.collect", return_value=copy.deepcopy(self.report)), contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.main(["--state-dir", str(self.store.directory), "doctor", "--compare", str(first)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())["status"], "invalid")

    def test_unknown_local_role_can_be_reported_but_cannot_claim_paired_merge(self):
        report = copy.deepcopy(self.report)
        report["host"]["role"] = None
        validate(report)
        with self.assertRaises(ValidationError):
            merge(report, self.peer)


class MergedReportBoundReviewTests(ReportFixture):
    def large_reports(self):
        for report, letter in ((self.report, "x"), (self.peer, "y")):
            report["probes"] = [{**evidence("service", "fail", {"text": letter * 270000}, i, report["host"]["role"]),
                                  "id": report["report_id"] + "-" + str(i)} for i in range(20)]
            report["findings"] = [self.finding(e["id"] for e in report["probes"])]
            self.assertGreater(len(json.dumps(report, indent=2).encode()), MAX_REPORT_BYTES // 2)
            self.assertLess(len(json.dumps(report, indent=2).encode()), MAX_REPORT_BYTES)
        self.peer["config_digest"] = "a" * 64

    def assert_provenance(self, report):
        self.assertEqual(report["provenance"], [self.report["report_id"], self.peer["report_id"]])
        self.assertTrue(report["truncation"])
        self.assertEqual(len(report["reports"]), 2)
        self.assertEqual(len(report["profile_evidence"]), 2)
        top_ids = {item["id"] for item in report["profile_evidence"]}
        self.assertTrue(set(report["findings"][0]["evidence_ids"]) <= top_ids)
        for source, original in zip(report["reports"], (self.report, self.peer)):
            self.assertEqual(source["report_id"], original["report_id"])
            self.assertEqual(source["host"]["role"], original["host"]["role"])
            self.assertEqual(source["collection_window"], original["collection_window"])
            self.assertEqual(source["created_at_utc"], original["created_at_utc"])
            validate(source)
            ids = {item["id"] for item in source["probes"]}
            for finding in source["findings"]:
                self.assertTrue(set(finding["evidence_ids"] + finding["counterevidence_ids"]) <= ids)
        self.assertTrue(any(source["truncation"] for source in report["reports"]))

    def test_final_merge_export_and_cli_emission_are_below_ten_mib(self):
        self.large_reports()
        first, second = self.paths(self.report, self.peer)
        exported = self.root / "merged.json"
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.main(["--state-dir", str(self.store.directory), "doctor", "--merge", str(first), str(second),
                             "--redaction", "secrets", "--export", str(exported)])
        self.assertEqual(code, 3)
        self.assertLessEqual(exported.stat().st_size, MAX_REPORT_BYTES)
        self.assertLessEqual(len(out.getvalue().encode()), MAX_REPORT_BYTES)
        report = json.loads(exported.read_text())
        self.assertEqual(json.loads(out.getvalue())["report"], report)
        self.assert_provenance(report)
        self.assertEqual(exported.stat().st_mode & 0o777, 0o600)

    def test_paired_cap_preserves_inputs_and_removes_dangling_finding_references(self):
        for report in (self.report, self.peer):
            report["probes"] = [evidence("service", "fail", "x" * 500, i) for i in range(40)]
            report["findings"] = [self.finding(e["id"] for e in report["probes"])]
        self.peer["config_digest"] = "b" * 64
        originals = copy.deepcopy((self.report, self.peer))
        merged = merge(self.report, self.peer)
        with patch("twinlink.diagnostics.MAX_REPORT_BYTES", 50000):
            result = cap_report(merged)
        self.assertLessEqual(len(json.dumps(result, indent=2).encode()), 50000)
        self.assertEqual((self.report, self.peer), originals)
        self.assert_provenance(result)

    def test_irreducible_metadata_fails_before_export_or_emission(self):
        self.report["versions"]["metadata"] = "x" * 40000
        first, second = self.paths(self.report, self.peer)
        exported = self.root / "too-large.json"
        with patch("twinlink.diagnostics.MAX_REPORT_BYTES", 20000), contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.main(["--state-dir", str(self.store.directory), "doctor", "--merge", str(first), str(second), "--export", str(exported)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())["status"], "invalid")
        self.assertFalse(exported.exists())

    def test_small_merge_is_unchanged_by_the_cap(self):
        report = merge(self.report, self.peer)
        before = copy.deepcopy(report)
        self.assertEqual(cap_report(report), before)

    def test_opaque_log_fields_are_not_assumed_to_be_evidence_ids(self):
        self.report["log_events"] = [{"id": ["opaque", "log", "field"], "MESSAGE": "x" * 40000}]
        validate(self.report)
        with patch("twinlink.diagnostics.MAX_REPORT_BYTES", 20000):
            report = cap_report(merge(self.report, self.peer))
        self.assertLessEqual(len(json.dumps(report, indent=2).encode()), 20000)
        self.assertTrue(report["truncation"])
