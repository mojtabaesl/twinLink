"""Interrupted pair purge and context-aware diagnostic privacy regressions."""
import contextlib
import copy
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tests.test_lifecycle_review import RuntimeFixture
from twinlink import cli
from twinlink.cleanup import delete_pair
from twinlink.diagnostics import collect
from twinlink.ownership import Ownership
from twinlink.profiles import table_name
from twinlink.redaction import Redactor
from twinlink.reports import validate
from twinlink.store import StateError, atomic_write


class PairDeletionReviewTests(RuntimeFixture):
    def setUp(self):
        super().setUp()
        self.stage()
        self.prepare()
        self.target = self.store.revision_path("edge", 1) / "vps1/direct-rathole/config.toml"
        self.journal = self.store.directory / "journals/purge-edge.json"

    def interrupted_unlink(self, target=None, applied=False):
        target = target or self.target
        original = Path.unlink
        fired = []
        def unlink(path, *args, **kwargs):
            if path == target and not fired:
                fired.append(True)
                if applied:
                    original(path, *args, **kwargs)
                raise KeyboardInterrupt()
            return original(path, *args, **kwargs)
        with patch.object(Path, "unlink", unlink), self.assertRaises(KeyboardInterrupt):
            delete_pair(self.store, self.runtime, "edge")
        self.assertTrue(fired)
        self.assertTrue(self.journal.exists())
        self.assertEqual(self.runtime.ledger.read()["resources"]["file:" + str(target)]["status"], "restoring")
        return target

    def assert_deleted(self):
        self.assertEqual(delete_pair(self.store, self.runtime, "edge")["status"], "complete")
        self.assertNotIn("edge", self.store.read()["pairs"])
        self.assertFalse(self.journal.exists())
        self.assertFalse(self.store.revision_path("edge", 1).parent.exists())
        self.assertFalse(any("edge" in row["owners"] for row in self.runtime.ledger.read()["resources"].values()))

    def test_retry_resumes_file_restoration_interrupted_before_unlink(self):
        self.interrupted_unlink()
        self.assertTrue(self.target.exists())
        self.assert_deleted()

    def test_retry_finishes_file_restoration_interrupted_after_unlink(self):
        self.interrupted_unlink(applied=True)
        self.assertFalse(self.target.exists())
        self.assert_deleted()

    def test_retry_revalidates_a_still_present_restoring_unit_file(self):
        target = self.host.unit_dir / self.runtime.runtime_unit(self.r, "direct-rathole")
        self.interrupted_unlink(target)
        self.assertTrue(target.exists())
        self.assert_deleted()

    def interrupted_disable(self, applied):
        unit = "twinlink-v2-restore.service"
        original = self.host.run
        fired = []
        def run(argv, **kwargs):
            if argv == ["systemctl", "disable", unit] and not fired:
                fired.append(True)
                if applied:
                    original(argv, **kwargs)
                raise KeyboardInterrupt()
            return original(argv, **kwargs)
        with patch.object(self.host, "run", side_effect=run), self.assertRaises(KeyboardInterrupt):
            delete_pair(self.store, self.runtime, "edge")
        self.assertTrue(fired)
        self.assertEqual(self.runtime.ledger.read()["resources"]["unit-enable:" + unit]["status"], "restoring")
        self.host.commands.clear()
        return unit

    def test_retry_resumes_disable_interrupted_before_host_mutation(self):
        unit = self.interrupted_disable(applied=False)
        self.assertIn(unit, self.host.enabled)
        self.assert_deleted()
        self.assertIn(["systemctl", "disable", unit], self.host.commands)

    def test_retry_after_disable_commits_without_repeating_the_host_mutation(self):
        unit = self.interrupted_disable(applied=True)
        self.assertNotIn(unit, self.host.enabled)
        self.assert_deleted()
        self.assertNotIn(["systemctl", "disable", unit], self.host.commands)

    def test_foreign_edit_after_interruption_blocks_retry_before_more_deletion(self):
        self.interrupted_unlink()
        self.target.write_text("foreign content")
        before = {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        with self.assertRaises(StateError):
            delete_pair(self.store, self.runtime, "edge")
        self.assertEqual({str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}, before)

    def test_foreign_drop_in_still_blocks_a_restoring_unit_file(self):
        target = self.host.unit_dir / self.runtime.runtime_unit(self.r, "direct-rathole")
        self.interrupted_unlink(target)
        original = self.host.unit_status
        def status(unit):
            result = original(unit)
            if unit == target.name:
                result["properties"]["DropInPaths"] = "/foreign/override.conf"
            return result
        with patch.object(self.host, "unit_status", side_effect=status), self.assertRaises(StateError):
            delete_pair(self.store, self.runtime, "edge")
        self.assertTrue(target.exists())
        self.assertIn("edge", self.store.read()["pairs"])

    def test_default_checks_do_not_treat_restoring_artifacts_as_runtime_ready(self):
        target = self.host.unit_dir / self.runtime.runtime_unit(self.r, "direct-rathole")
        self.interrupted_unlink(target)
        before = self.runtime.ledger.path.read_bytes()
        with self.assertRaises(StateError):
            self.runtime.assert_unit_safe(target.name)
        with self.assertRaises(StateError):
            self.runtime.ledger.check("file:" + str(target), self.runtime.ledger.file_value(target))
        self.assertEqual(self.runtime.ledger.path.read_bytes(), before)

    def test_other_pair_and_shared_restore_coordinator_survive_resumed_delete(self):
        other = copy.deepcopy(self.r)
        other.update(pair_id="other", public_endpoints={"vps1": "198.51.100.3", "vps2": "203.0.113.4"}, transport={"port": 4567}, services=[])
        other["gre"].update(addresses={"vps1": "10.78.0.1/30", "vps2": "10.78.0.2/30"}, key=42, mtu=1472)
        self.store.stage(self.store.read(), other, "vps1", self.creds)
        with patch("twinlink.rathole.check_version"):
            self.runtime.materialize(other, "vps1")
        root = self.store.revision_path("other", 1)
        before = {str(p): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        self.interrupted_unlink()
        self.assert_deleted()
        self.assertEqual(self.store.revision("other", 1), other)
        self.assertEqual({str(p): p.read_bytes() for p in root.rglob("*") if p.is_file()}, before)
        self.assertIn("twinlink-v2-restore.service", self.host.enabled)
        rows = self.runtime.ledger.read()["resources"]
        self.assertEqual(rows["unit-enable:twinlink-v2-restore.service"]["owners"], ["other"])


class EvidenceScrubbingReviewTests(unittest.TestCase):
    def setUp(self):
        self.redactor = Redactor("share", context=b"context for regression coverage")

    def match(self, right, field="dport", protocol="tcp"):
        return {"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": field}}, "right": right}}

    def test_scalar_match_ports_equal_structured_port_pseudonyms(self):
        for protocol in ("tcp", "udp", "th"):
            for field in ("sport", "dport"):
                with self.subTest(protocol=protocol, field=field):
                    result = self.redactor.scrub(self.match(8081, field, protocol))
                    self.assertEqual(result["match"]["right"], self.redactor.scrub({"port": "8081"})["port"])
                    self.assertEqual(result["match"]["left"]["payload"]["field"], field)
                    self.assertNotIn("8081", json.dumps(result))

    def test_match_ranges_and_sets_preserve_range_widths_and_equality(self):
        result = self.redactor.scrub(self.match({"range": [8081, 8083]}))
        self.assertEqual(result["match"]["right"]["range"], self.redactor.scrub({"ports": "8081-8083"})["ports"])
        result = self.redactor.scrub(self.match({"set": [8081, {"range": [9000, 9002]}]}))
        self.assertEqual(result["match"]["right"]["set"][0], self.redactor.pseudonym(8081, "port"))
        self.assertEqual(result["match"]["right"]["set"][1]["range"]["width"], 3)
        self.assertNotIn("8081", json.dumps(result))

    def test_nat_port_ranges_are_scrubbed_without_redacting_counters(self):
        result = self.redactor.scrub({"dnat": {"addr": "203.0.113.2", "port": {"range": [8081, 8083]}},
                                      "counter": {"packets": 8081, "bytes": 9002}})
        self.assertEqual(result["dnat"]["port"]["range"]["width"], 3)
        self.assertEqual(result["counter"], {"packets": 8081, "bytes": 9002})

    def test_interface_match_operand_equals_link_ifname_and_keeps_its_selector(self):
        value = {"ifname": "gre-customer", "expr": [{"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": {"set": ["gre-customer", "eth0"]}}}]}
        result = self.redactor.scrub(value)
        match = result["expr"][0]["match"]
        self.assertEqual(match["right"]["set"][0], result["ifname"])
        self.assertEqual(match["left"]["meta"]["key"], "iifname")
        self.assertNotIn("gre-customer", json.dumps(result))

    def test_old_private_report_with_lost_meta_selector_hides_the_operand(self):
        value = {"match": {"op": "==", "left": {"meta": {"key": "<redacted>"}}, "right": "customer-interface"}}
        result = self.redactor.scrub(value)
        self.assertNotIn("customer-interface", json.dumps(result))
        self.assertTrue(result["match"]["right"].startswith("operand-"))

    def test_ownership_markers_link_aliases_and_structured_ids_agree(self):
        installation = "12345678-1234-1234-1234-123456789abc"
        raw = {"installation_id": installation, "pair_id": "edge", "ifalias": "twinlink:" + installation + ":edge",
               "comment": "twinlink:" + installation, "message": "Selected twinlink:" + installation + ":edge"}
        result = self.redactor.scrub(raw)
        alias = "twinlink:" + result["installation_id"] + ":" + result["pair_id"]
        self.assertEqual(result["ifalias"], alias)
        self.assertEqual(result["comment"], "twinlink:" + result["installation_id"])
        self.assertEqual(result["message"], "Selected " + alias)
        self.assertNotIn(installation, json.dumps(result))
        self.assertNotIn("edge", json.dumps(result))

    def test_foreign_aliases_and_generated_rule_identities_do_not_leak_names_or_ports(self):
        value = {"ifalias": "customer installation in zone one", "comment": "twinlink:s12345-8081:dnat:0"}
        result = self.redactor.scrub(value)
        self.assertNotIn("customer", json.dumps(result))
        self.assertNotIn("8081", json.dumps(result))
        self.assertEqual(result, self.redactor.scrub(value))

    def test_secrets_level_retains_identity_and_port_evidence_but_scrubs_credentials(self):
        value = {"ifalias": "twinlink:12345678-1234-1234-1234-123456789abc:edge", "expr": [self.match(8081)], "message": "known credential"}
        result = Redactor("secrets", known_secrets=("known credential",)).scrub(value)
        self.assertEqual(result["ifalias"], value["ifalias"])
        self.assertEqual(result["expr"][0]["match"]["right"], 8081)
        self.assertEqual(result["message"], "<redacted>")


class ExportedEvidencePrivacyReviewTests(RuntimeFixture):
    def setUp(self):
        super().setUp()
        self.stage()
        self.prepare()
        control = self.committed("gre-kernel")
        self.runtime.prepare(self.r, "vps1", "gre-kernel", control, {"previous": None})
        self.runtime.start(self.r, "vps1", "gre-kernel", control, {"previous": None})
        self.installation = self.store.read()["installation_id"]
        self.alias = "twinlink:" + self.installation + ":edge"

    def command(self, argv, **kwargs):
        value = ""
        if argv[0] == "ip":
            value = json.dumps(self.host.links() if "link" in argv else self.host.addresses() if "address" in argv else self.host.routes())
        elif argv[0] == "nft":
            value = json.dumps(self.host.tables[table_name("edge")])
        return {"returncode": 0, "stdout": value, "error": None, "truncated": False}

    def assert_private_evidence(self, report):
        validate(report)
        text = json.dumps(report)
        self.assertNotIn(self.installation, text)
        self.assertNotIn(self.alias, text)
        # Check semantic port positions, avoiding coincidental digits in UUIDs,
        # timestamps or digest pseudonyms.
        self.assertNotRegex(text, r'"(?:port|ports|right)"\s*:\s*"?(?:8081|8082|10000|10001)(?=["\s,}\-])')
        self.assertNotRegex(text, r'twinlink:[^"\s]*-(?:8081|8082|10000|10001):')
        links = next(item["value"] for item in report["interface_route_samples"] if item["source"] == "link")
        alias = links[0]["ifalias"]
        self.assertTrue(alias.endswith(":" + report["host"]["pair_id"]))
        snapshot = next(item["value"] for item in report["firewall_conntrack"] if item["source"] == "nft")
        self.assertEqual(snapshot["nftables"][0]["table"]["comment"], alias.rsplit(":", 1)[0])
        ports, interfaces = [], []
        for row in snapshot["nftables"]:
            for expression in row.get("rule", {}).get("expr", []):
                match = expression.get("match", {})
                if match.get("left", {}).get("payload", {}).get("field") in ("dport", "sport"):
                    ports.append(match["right"])
                if match.get("left", {}).get("meta", {}).get("key") in ("iifname", "oifname"):
                    interfaces.append(match["right"])
        self.assertIn(report["service_mappings"][0]["ports"]["start"], ports)
        for operand in ports:
            self.assertNotIn(operand, (8081, 8082, 10000, 10001))
        self.assertIn(links[0]["ifname"], interfaces)

    def test_default_share_export_and_cli_response_scrub_complete_kernel_evidence(self):
        exported = self.root / "share.json"
        with patch("twinlink.diagnostics.bounded_command", side_effect=self.command), patch("twinlink.diagnostics.application_probe", return_value={"result": "pass", "latency_ms": 1}), patch("twinlink.diagnostics.read_sample", return_value=({"boot_id": "boot"}, [])), contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.main(["--state-dir", str(self.store.directory), "doctor", "--export", str(exported)])
        self.assertIn(code, (0, 3))
        report = json.loads(exported.read_text())
        self.assertEqual(json.loads(out.getvalue())["report"], report)
        self.assert_private_evidence(report)
        self.assertEqual(exported.stat().st_mode & 0o777, 0o600)

    def test_merged_share_export_scrubs_both_originals_with_one_context(self):
        first = collect(self.store, "edge", redaction="secrets", command_fn=self.command,
                        probe_fn=lambda *a, **k: {"result": "pass", "latency_ms": 1}, sample_fn=lambda: ({"boot_id": "boot"}, []))
        self.assertIn(self.alias, json.dumps(first))
        second = copy.deepcopy(first)
        second["report_id"], second["host"]["role"] = "peer", "vps2"
        paths = self.root / "first.json", self.root / "second.json"
        for path, report in zip(paths, (first, second)):
            atomic_write(path, json.dumps(report))
        exported = self.root / "paired-share.json"
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(["--state-dir", str(self.store.directory), "doctor", "--merge", *map(str, paths), "--export", str(exported)]), 3)
        report = json.loads(exported.read_text())
        for original in report["reports"]:
            self.assert_private_evidence(original)
        self.assertNotIn(self.installation, out.getvalue())
        self.assertNotRegex(out.getvalue(), r'"(?:port|ports|right)"\s*:\s*"?8081(?=["\s,}\-])')
