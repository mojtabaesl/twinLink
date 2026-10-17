"""V2 contracts, pure renderers, private storage and authenticated barriers."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from twinlink import cli, paqet
from twinlink.contracts import (new_revision, next_revision, validate_revision, validate_reservations,
                                strict_json, digest, PROFILES)
from twinlink.models import empty_state, ValidationError
from twinlink.pair_bundle import credentials, encode, decode, fingerprint
from twinlink.profiles import manifests, capabilities
from twinlink.store import Store, StateError, atomic_write
from twinlink.coordination import Coordinator, new_transaction, receipt, consume, validate_receipt, steps, Pending
from twinlink.ownership import Ownership
from twinlink.diagnostics import bounded_command, collect
from twinlink.redaction import Redactor
from twinlink.reports import validate, merge, compare
from twinlink.migration import plan as migration_plan
from tests.test_rathole import PRIVATE, KEYS

FACTS = {"interface": "eth0", "source": "198.51.100.1", "gateway": "198.51.100.254",
         "router_mac": "cc:46:d6:21:67:45", "ephemeral_range": [32768, 60999]}


def revision(protocol="tcp", loopback=False):
    return new_revision("edge", {"vps1": "198.51.100.1", "vps2": "203.0.113.2"}, 3456,
        [{"id": "web", "bind": "198.51.100.1", "protocol": protocol, "ports": "8081-8082",
          "backend": {"address": "127.0.0.1" if loopback else "10.20.30.40", "ports": "80-81"},
          "probe": {"kind": "exchange", "request_hex": "61", "response_hex": "62"}}])


class V2Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").exists() else None)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / "state")
        self.r = revision()
        self.r["public_keys"]["noise"] = KEYS["noise_public_key"]
        self.creds = {**credentials(), "noise_private": PRIVATE}

    def stage(self, role="vps1", store=None):
        store = store or self.store
        with store.lock():
            return store.stage(store.read(), self.r, role, self.creds, FACTS)


class ContractTests(V2Fixture):
    def test_validation_is_pure_and_strict(self):
        before = copy.deepcopy(self.r)
        self.assertEqual(validate_revision(self.r), before)
        self.assertEqual(self.r, before)
        for bad in ({**self.r, "transport_port": 3456}, {**self.r, "revision": True},
                    {**self.r, "pins": {}}, {**self.r, "public_endpoints": {"vps1": "127.0.0.1", "vps2": "203.0.113.2"}}):
            with self.assertRaises(ValidationError):
                validate_revision(bad)
        for text in ('{"x":1,"x":2}', '{"x": NaN}', '[' * 18 + '0' + ']' * 18):
            with self.assertRaises(ValidationError):
                strict_json(text)

    def test_all_mapping_capabilities(self):
        self.assertTrue(capabilities(self.r, "gre-kernel")["compatible"])
        self.assertTrue(capabilities(self.r, "direct-rathole")["compatible"])
        self.assertFalse(capabilities(revision("udp"), "direct-rathole")["compatible"])
        self.assertFalse(capabilities(revision(loopback=True), "gre-kernel")["compatible"])
        self.assertFalse(capabilities(self.r, "direct-paqet")["compatible"])
        mixed = copy.deepcopy(self.r)
        mixed["services"].append({**mixed["services"][0], "id": "dns", "protocol": "udp"})
        output = manifests(mixed, "vps1", self.creds, FACTS)
        self.assertFalse(output["direct-rathole"]["compatible"])
        self.assertEqual(output["direct-rathole"]["files"], {})

    def test_one_port_all_roles_and_manual_paqet_template(self):
        for role in ("vps1", "vps2"):
            facts = {**FACTS, "source": self.r["public_endpoints"][role]}
            output = manifests(self.r, role, self.creds, facts)
            self.assertEqual(set(output), set(PROFILES))
            for profile in PROFILES:
                self.assertEqual(output[profile]["transport_port"], 3456)
            direct = output["direct-rathole"]["files"]["config.toml"]
            gre = output["gre-rathole"]["files"]["config.toml"]
            self.assertIn("198.51.100.1:3456", direct)
            self.assertIn("10.77.0.1:3456", gre)
            p = json.loads(output["direct-paqet"]["files"]["config.yaml"])
            self.assertEqual(p["transport"]["conn"], 4)
            self.assertEqual(p["transport"]["kcp"]["mode"], "manual")
            self.assertEqual(p["transport"]["kcp"]["resend"], 1)
            self.assertEqual(p["network"]["tcp"]["local_flag"], ["SA"])
            self.assertNotIn("socks5", p)
            self.assertEqual(p["role"], "client" if role == "vps1" else "server")
            if role == "vps1":
                self.assertEqual(p["server"]["addr"], "203.0.113.2:3456")
                self.assertEqual(len(p["forward"]), 2)
            else:
                rules = output["direct-paqet"]["files"]["rules.nft"]
                self.assertIn("priority -300", rules)
                self.assertIn("ip saddr 198.51.100.1 ip daddr 203.0.113.2 tcp dport 3456", rules)
                self.assertNotIn("flush ruleset", rules)
                self.assertIn("tcp flags & rst == rst", rules)
        changed = next_revision(self.r, transport={"port": 4567})
        out = manifests(changed, "vps1", self.creds, FACTS)
        self.assertIn(":4567", out["direct-rathole"]["files"]["config.toml"])
        self.assertEqual(changed["parent_digest"], digest(self.r))

    def test_port_and_pair_reservations(self):
        for port in (22, 8081, 8082, True):
            with self.assertRaises(ValidationError):
                validate_revision({**self.r, "transport": {"port": port}})
        other = {**self.r, "pair_id": "other"}
        with self.assertRaises(ValidationError):
            validate_reservations(self.r, [other])
        validate_reservations(self.r, [self.r])
        ephemeral = {**self.r, "transport": {"port": 40000}}
        with self.assertRaises(ValidationError):
            paqet.render_config(ephemeral, "vps2", {**FACTS, "source": "203.0.113.2"}, self.creds["paqet"])

    def test_revision_read_is_nonmutating(self):
        self.stage()
        before = self.store.path.read_bytes()
        self.assertEqual(self.store.read()["version"], 2)
        self.assertEqual(self.store.revision("edge", 1), self.r)
        self.assertEqual(self.store.path.read_bytes(), before)
        for path in self.store.directory.rglob("*"):
            self.assertEqual(path.stat().st_mode & 0o077, 0, str(path))

    def test_lineage_staging_and_active_revision_retention(self):
        state = self.stage()
        state["pairs"]["edge"]["active"] = {"revision": 1, "profile": "direct-rathole", "epoch": 1}
        self.store.write(state)
        r2 = next_revision(self.r, transport={"port": 4567})
        new = self.store.stage(state, r2, "vps1", self.creds, FACTS)
        self.assertEqual(new["pairs"]["edge"]["active"]["revision"], 1)
        self.assertEqual(new["pairs"]["edge"]["staged_revision"], 2)
        self.assertEqual(self.store.credentials("edge"), self.creds)
        for bad in (self.r, {**r2, "transport": {"port": 5678}}, next_revision(r2, parent_digest="0" * 64)):
            if bad["revision"] == 3:
                bad["parent_digest"] = "0" * 64
            with self.assertRaises(StateError):
                self.store.stage(new, bad, "vps1", self.creds, FACTS)

    def test_secret_and_symlink_safety(self):
        self.stage()
        (self.root / "foreign").write_text("unchanged")
        path = self.store.revision_path("edge", 1) / "evil.json"
        path.symlink_to(self.root / "foreign")
        with self.assertRaises(StateError):
            atomic_write(path, "secret")
        self.assertEqual((self.root / "foreign").read_text(), "unchanged")


class BundleTests(V2Fixture):
    def test_complete_bundle_private_key_absent_and_fingerprint_required(self):
        code = encode(self.r, self.creds)
        with self.assertRaises(ValidationError):
            decode(code)
        r, creds = decode(code, fingerprint(code))
        self.assertEqual(r, self.r)
        self.assertNotIn("noise_private", creds)
        self.assertEqual(creds["paqet"], self.creds["paqet"])
        self.assertNotIn(PRIVATE, json.dumps(creds))
        self.assertEqual(decode(code, stored_management_key=self.creds["management"])[0], self.r)
        for bad in (code[:-8], "p2." + "A" * 131072, "r1.foo", code + "!"):
            with self.assertRaises(ValidationError):
                decode(bad, fingerprint(bad))

    def test_bootstrap_does_not_replace_existing_trust(self):
        code = encode(self.r, credentials())
        with self.assertRaises(ValidationError):
            decode(code, fingerprint(code), self.creds["management"])


class FakeRuntime:
    def __init__(self):
        self.calls, self.fail = [], None
    def __getattr__(self, action):
        def run(revision, role, target, control, tx):
            self.calls.append((role, action, target))
            if action == self.fail:
                raise RuntimeError("injected failure")
        return run


class CoordinationTests(V2Fixture):
    def setUp(self):
        super().setUp()
        self.stage()
        self.peer = Store(self.root / "peer")
        self.stage("vps2", self.peer)
        self.a, self.b = FakeRuntime(), FakeRuntime()

    def test_all_targets_preserve_stop_barriers(self):
        for target in (*PROFILES, None):
            with self.subTest(target=target):
                # Fresh local/peer controls for each transition.
                for store in (self.store, self.peer):
                    state = store.read()
                    state["pairs"]["edge"].update(active=None, transition=None, epoch=0, commit_pending=False)
                    store.write(state)
                incoming, txid = None, None
                for role, action in steps(target):
                    store, rt = (self.store, self.a) if role == "vps1" else (self.peer, self.b)
                    result = Coordinator(store, rt, lambda: 100).advance("edge", self.r, target, incoming, txid, action)
                    incoming, txid = result["receipt"], result["transaction"]
                result = Coordinator(self.peer, self.b, lambda: 100).advance("edge", self.r, target, incoming, txid)
                self.assertEqual(result["status"], "complete")
                self.assertEqual(self.peer.read()["pairs"]["edge"]["active"] is None, target is None)
                actions = steps(target)
                if target:
                    first_start = next(i for i, (_, action) in enumerate(actions) if action == "start")
                    self.assertIn(("vps1", "quiesce"), actions[:first_start])
                    self.assertIn(("vps2", "quiesce"), actions[:first_start])

    def test_cannot_start_without_peer_quiescence(self):
        c = Coordinator(self.store, self.a, lambda: 100)
        first = c.advance("edge", self.r, "direct-rathole")
        before = list(self.a.calls)
        wait = c.advance("edge", self.r, "direct-rathole")
        self.assertEqual(wait["next_host"], "vps2")
        self.assertEqual(self.a.calls, before)
        forged = copy.deepcopy(first["receipt"])
        forged["body"]["step"] = "quiesce"
        with self.assertRaises(ValidationError):
            c.advance("edge", self.r, "direct-rathole", forged)

    def test_receipt_replay_wrong_role_and_expiry(self):
        state = self.store.read()
        c = state["pairs"]["edge"]
        tx = new_transaction("edge", self.r, "direct-rathole", c, now=100)
        signed = receipt(tx, "vps1", "preflight", self.creds["management"], 100)
        with self.assertRaises(ValidationError):
            validate_receipt(signed, self.creds["management"], 401)
        consume(tx, signed, self.creds["management"], 100)
        with self.assertRaises(ValidationError):
            consume(tx, signed, self.creds["management"], 100)

    def test_failure_leaves_off_and_requires_coordinated_recovery(self):
        first = Coordinator(self.store, self.a, lambda: 100).advance("edge", self.r, "direct-rathole")
        second = Coordinator(self.peer, self.b, lambda: 100).advance("edge", self.r, "direct-rathole", first["receipt"])
        self.a.fail = "quiesce"
        with self.assertRaises(RuntimeError):
            Coordinator(self.store, self.a, lambda: 100).advance("edge", self.r, "direct-rathole", second["receipt"])
        control = self.store.read()["pairs"]["edge"]
        self.assertIsNone(control["active"])
        self.assertEqual(control["transition"]["phase"], "recovery-required")


class OwnershipTests(V2Fixture):
    def test_conditional_file_restore_and_foreign_conflicts(self):
        ledger = Ownership(self.store)
        target = self.root / "unit"
        ledger.write_file(target, "owned", "edge", 0o600)
        target.write_text("foreign edit")
        with self.assertRaises(StateError):
            ledger.remove_file(target, "edge")
        self.assertEqual(target.read_text(), "foreign edit")
        self.assertEqual(ledger.summary()[0]["status"], "conflict")
        foreign = self.root / "foreign"
        foreign.write_text("foreign")
        with self.assertRaises(StateError):
            ledger.write_file(foreign, "overwrite", "edge")

    def test_refcount_restores_only_after_last_pair(self):
        ledger = Ownership(self.store)
        ledger.begin("sysctl:example", "sysctl", "one", "0", "1", "restore")
        ledger.complete("sysctl:example", "1")
        ledger.begin("sysctl:example", "sysctl", "two", "1", "1", "restore")
        ledger.complete("sysctl:example", "1")
        restored = []
        def restore(value):
            restored.append(value)
            return value
        ledger.release("sysctl:example", "one", "1", restore)
        self.assertEqual(restored, [])
        ledger.release("sysctl:example", "two", "1", restore)
        self.assertEqual(restored, ["0"])


class DiagnosticsTests(V2Fixture):
    def test_stream_limits_and_timeout(self):
        result = bounded_command([sys.executable, "-c", "print('x'*200000)"], output_limit=1024)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["stdout"]), 1024)
        result = bounded_command([sys.executable, "-c", "import time;time.sleep(5)"], timeout=0.1)
        self.assertEqual(result["error"], "TimeoutError")

    def test_redaction_and_unknown_report(self):
        self.stage()
        secret = self.creds["paqet"]
        redactor = Redactor("share", [secret], b"x" * 32)
        value = redactor.scrub({"key": secret, "message": "ip 203.0.113.2 key=" + secret, "port": 3456})
        self.assertNotIn(secret, json.dumps(value))
        self.assertNotIn("203.0.113.2", json.dumps(value))
        self.assertEqual(redactor.pseudonym(3456, "port"), value["port"])
        with patch("twinlink.diagnostics.bounded_command", return_value={"returncode": None, "stdout": "", "error": "Unavailable", "truncated": False}):
            report = collect(self.store, "edge", redaction="secrets")
        validate(report)
        self.assertEqual(report["overall_status"], "off")
        self.assertTrue(report["collection_errors"])
        self.assertNotIn(secret, json.dumps(report))
        self.assertEqual(compare(report, report)["same_pair"], True)
        peer = copy.deepcopy(report)
        peer["report_id"] = "other-report"
        peer["host"]["role"] = "vps2"
        self.assertEqual(len(merge(report, peer)["reports"]), 2)
        with self.assertRaises(ValidationError):
            merge(report, report)
        schema = json.loads((Path(__file__).parents[1] / "docs/schemas/doctor-report-v1.schema.json").read_text())
        self.assertEqual(set(schema["required"]), set(report))

    def test_capture_allowlists_metadata_and_scopes_command(self):
        from twinlink.diagnostics import capture_metadata
        response = {"returncode": 0, "stdout": "1234.5 IP 198.51.100.1.1000 > 203.0.113.2.3456: tcp 42\npassword=not-metadata\n",
                    "stderr": "0 packets dropped by kernel\n", "error": None, "truncated": False}
        with patch("twinlink.diagnostics.bounded_command", return_value=response) as command:
            value = capture_metadata("eth0", "203.0.113.2", 3456)
        self.assertEqual(len(value["records"]), 1)
        self.assertNotIn("password", json.dumps(value))
        self.assertIn("1000", command.call_args.args[0])
        self.assertIn("203.0.113.2", command.call_args.args[0])
        self.assertEqual(command.call_args.kwargs["timeout"], 10)
        with self.assertRaises(ValidationError):
            capture_metadata("eth0;evil", "203.0.113.2", 3456)


class V2CLITests(V2Fixture):
    def invoke(self, args):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            result = cli.main(["--state-dir", str(self.store.directory), "--json", *args])
        return result, json.loads(buffer.getvalue())

    def test_setup_preview_and_versioned_status(self):
        code, data = self.invoke(["setup", "--pair", "edge", "--vps1", "198.51.100.1", "--vps2", "203.0.113.2"])
        self.assertEqual(code, 0)
        self.assertEqual(data["schema_version"], 2)
        self.assertFalse(self.store.directory.exists())
        self.stage()
        code, data = self.invoke(["status"])
        self.assertEqual(code, 0)
        self.assertEqual(data["pairs"][0]["shared_transport"]["value"], 3456)

    def test_port_edit_preview_no_secret_output(self):
        self.stage()
        before = self.store.path.read_bytes()
        code, data = self.invoke(["config", "set", "transport.port", "4567"])
        self.assertEqual(code, 0)
        self.assertEqual(data["configuration"]["transport"]["port"], 4567)
        self.assertEqual(self.store.path.read_bytes(), before)
        self.assertNotIn(self.creds["paqet"], json.dumps(data))

    def test_no_implicit_legacy_migration(self):
        code, data = self.invoke(["profile", "list"])
        self.assertEqual(code, 2)
        self.assertFalse(self.store.directory.exists())
        self.assertEqual(migration_plan(empty_state())["pairs"], [])

    def test_apply_setup_and_edit_emit_one_document_and_keep_credentials_private(self):
        from tests.test_profile_runtime import SystemHost
        host = SystemHost(self.root / "units")
        buffer = io.StringIO()
        args = ["--state-dir", str(self.store.directory), "--rathole-binary", str(self.root / "missing"), "--json"]
        with patch.object(cli, "Host", return_value=host), contextlib.redirect_stdout(buffer):
            code = cli.main([*args, "setup", "--pair", "edge", "--vps1", "198.51.100.1", "--vps2", "203.0.113.2", "--apply", "--yes"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buffer.getvalue())["status"], "complete")
        credentials_before = self.store.credentials("edge")
        buffer = io.StringIO()
        with patch.object(cli, "Host", return_value=host), contextlib.redirect_stdout(buffer):
            code = cli.main([*args, "config", "set", "transport.port", "4567", "--apply", "--yes"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buffer.getvalue())["staged_revision"], 2)
        self.assertEqual(self.store.credentials("edge"), credentials_before)
        self.assertNotIn(credentials_before["management"], buffer.getvalue())
