"""Backend intent, schema preservation and readiness; no host networking."""
import contextlib
import copy
import io
import json
import argparse
from unittest.mock import patch

from tests.test_v2 import V2Fixture, FACTS
from tests.test_lifecycle_review import RuntimeFixture
from twinlink import cli, paqet
from twinlink.backends import address, effective, readiness
from twinlink.contracts import canonical, digest, next_revision, validate_revision
from twinlink.diagnostics import backend_observation, probe_definitions
from twinlink.models import ValidationError
from twinlink.pair_bundle import encode, decode, fingerprint
from twinlink.profiles import capabilities, expanded_services, manifests, render_kernel
from twinlink.profile_runtime import nft_expectation
from twinlink.store import StateError


def local_revision(revision):
    r = copy.deepcopy(revision)
    r["services"][0]["backend"] = {"target": "vps2-local", "ports": "9000"}
    return validate_revision(r)


class BackendTests(V2Fixture):
    def test_coordinator_persists_preliminary_readiness_without_claiming_delivery(self):
        from tests.test_v2 import FakeRuntime
        from twinlink.coordination import Coordinator
        self.stage()
        preliminary = {"backend_checks": [{"result": "deferred", "address": "10.77.0.2", "application": "pass"}],
                       "service_path": "pending"}
        runtime = FakeRuntime()
        with patch.object(runtime, "preflight", return_value=preliminary):
            result = Coordinator(self.store, runtime).advance("edge", self.r, "gre-kernel")
        self.assertEqual(result["local_readiness"], preliminary)
        control = self.store.read()["pairs"]["edge"]
        self.assertEqual(control["transition"]["local_readiness"], preliminary)
        self.assertIsNone(control["active"])

    def test_schema2_digest_and_rendering_survive_read_and_bundle(self):
        old = copy.deepcopy(self.r)
        old["schema_version"] = 2
        del old["services"][0]["backend"]["target"]
        original = canonical(old)
        self.assertEqual(canonical(validate_revision(old)), original)
        code = encode(old, self.creds)
        imported, _ = decode(code, fingerprint(code))
        self.assertEqual(canonical(imported), original)
        self.assertEqual(manifests(imported, "vps2", self.creds, FACTS)["gre-kernel"]["renderer_version"], 1)
        promoted = next_revision(old)
        self.assertEqual(promoted["schema_version"], 3)
        self.assertEqual(promoted["parent_digest"], digest(old))
        self.assertEqual(promoted["services"][0]["backend"]["target"], "address")
        self.assertEqual(canonical(old), original)

    def test_schema2_loopback_stays_explicit_and_incompatible(self):
        old = copy.deepcopy(self.r)
        old["schema_version"] = 2
        old["services"][0]["backend"] = {"address": "127.0.0.1", "ports": "9000"}
        self.assertFalse(capabilities(validate_revision(old), "gre-kernel")["compatible"])
        promoted = next_revision(old)
        self.assertEqual(promoted["services"][0]["backend"]["address"], "127.0.0.1")
        self.assertFalse(capabilities(promoted, "gre-kernel")["compatible"])

    def test_schema3_roundtrip_and_resolver_profiles(self):
        r = local_revision(self.r)
        code = encode(r, self.creds)
        imported, _ = decode(code, fingerprint(code))
        self.assertEqual(imported, r)
        self.assertTrue(capabilities(r, "gre-kernel")["compatible"])
        for profile in r["profiles"]:
            self.assertEqual(address(r, r["services"][0], profile), "10.77.0.2" if profile == "gre-kernel" else "127.0.0.1")
        self.assertNotIn("address", r["services"][0]["backend"])

    def test_invalid_backend_tags_and_schemas(self):
        for backend in ({"target": "vps2-local", "address": "127.0.0.1", "ports": "9000"},
                        {"target": "address", "ports": "9000"}, {"target": "other", "ports": "9000"},
                        {"target": "address", "address": "::1", "ports": "9000"},
                        {"address": "127.0.0.1", "ports": "9000"}):
            r = local_revision(self.r)
            r["services"][0]["backend"] = backend
            with self.subTest(backend=backend), self.assertRaises(ValidationError):
                validate_revision(r)
        with self.assertRaisesRegex(ValidationError, "both peers"):
            validate_revision({**self.r, "schema_version": 4})

    def test_new_gre_addresses_change_local_intent_only(self):
        r = local_revision(self.r)
        changed = next_revision(r, gre={**r["gre"], "addresses": {"vps1": "10.78.0.1/30", "vps2": "10.78.0.2/30"}})
        self.assertEqual(effective(changed)["web"]["gre-kernel"]["address"], "10.78.0.2")
        self.assertEqual(effective(changed)["web"]["direct-rathole"]["address"], "127.0.0.1")
        explicit = next_revision(self.r, gre=changed["gre"])
        self.assertEqual(address(explicit, explicit["services"][0], "gre-kernel"), "10.20.30.40")

    def test_local_kernel_rules_port_translation_and_scoped_input_reply(self):
        for protocol in ("tcp", "udp"):
            r = local_revision(self.r)
            r["services"][0]["protocol"] = protocol
            script = render_kernel(r, "vps2", "00000000-0000-0000-0000-000000000000")
            self.assertIn("dport 10000 counter dnat to 10.77.0.2:9000", script)
            self.assertIn("dport 10001 counter dnat to 10.77.0.2:9000", script)
            self.assertIn("ip saddr 10.77.0.1 ip daddr 10.77.0.2", script)
            self.assertIn("ct original proto-dst 10000", script)
            self.assertIn("sport 9000 ct state established", script)
            self.assertNotIn("masquerade", script)
            expectation = nft_expectation(script)
            self.assertEqual(expectation["chains"]["input"]["hook"], "input")
            self.assertEqual(len(expectation["rules"]["input"]), 2)
            self.assertIn("snat to 10.77.0.1", render_kernel(r, "vps1", "00000000-0000-0000-0000-000000000000"))
        self.assertIn("masquerade", render_kernel(self.r, "vps2", "00000000-0000-0000-0000-000000000000"))

    def test_all_proxy_renderers_resolve_local_intent(self):
        r = local_revision(self.r)
        generated = manifests(r, "vps2", self.creds, {**FACTS, "source": r["public_endpoints"]["vps2"]})
        for profile in ("direct-rathole", "gre-rathole"):
            self.assertIn("127.0.0.1:9000", generated[profile]["files"]["config.toml"])
        config = json.loads(paqet.render_config(r, "vps1", FACTS, self.creds["paqet"]))
        self.assertTrue(all(s["target"] == "127.0.0.1:9000" for s in config["forward"]))
        definitions = probe_definitions(r, "vps2", "gre-kernel")
        self.assertTrue(all(p["address"] == "10.77.0.2" for p in definitions if p["kind"] == "backend"))

    def test_cli_add_default_preview_edit_omission_and_reset(self):
        self.stage()
        def run(arguments):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                result = cli.main(["--state-dir", str(self.store.directory), *arguments])
            self.assertEqual(result, 0, out.getvalue())
            return json.loads(out.getvalue())
        add = ["service", "add", "app", "--pair", "edge", "--ports", "8083", "--backend-ports", "9000",
               "--probe-request-hex", "50494e470a", "--probe-response-hex", "504f4e470a"]
        preview = run(add)
        self.assertEqual(preview["effective_backends"]["app"]["gre-kernel"]["address"], "10.77.0.2")
        with patch("twinlink.host.Host.require_linux_root"):
            run(add + ["--apply", "--yes"])
            def backend():
                c = self.store.read()["pairs"]["edge"]
                return next(s["backend"] for s in self.store.revision("edge", c["staged_revision"])["services"] if s["id"] == "app")
            self.assertEqual(backend(), {"target": "vps2-local", "ports": "9000"})
            edit = ["service", "edit", "app", "--pair", "edge", "--apply", "--yes"]
            run(edit + ["--backend-address", "10.20.30.40"])
            before = backend()
            run(edit + ["--ports", "8084"])
            self.assertEqual(backend(), before)
            run(edit + ["--backend-local"])
            self.assertEqual(backend(), {"target": "vps2-local", "ports": "9000"})
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.build_parser().parse_args(add + ["--backend-local", "--backend-address", "127.0.0.1"])

    def test_readiness_distinguishes_binding_deferred_exact_and_unknown(self):
        r = local_revision(self.r)
        s = expanded_services(r)[0]
        wildcard = [{"protocol": "tcp", "address": "0.0.0.0", "port": 9000}]
        loopback = [{**wildcard[0], "address": "127.0.0.1"}]
        self.assertEqual(readiness(r, s, "gre-kernel", set(), wildcard)["result"], "deferred")
        self.assertEqual(readiness(r, s, "gre-kernel", set(), wildcard)["probe_address"], "127.0.0.1")
        self.assertIn("loopback-only", readiness(r, s, "gre-kernel", set(), loopback)["reason"])
        self.assertEqual(readiness(r, s, "gre-kernel", {"10.77.0.2"}, wildcard)["result"], "ready-to-probe")
        self.assertEqual(readiness(r, s, "gre-kernel", set(), wildcard, allow_deferred=False)["result"], "fail")
        definition = next(d for d in probe_definitions(r, "vps2", "gre-kernel") if d["kind"] == "backend")
        self.assertEqual(backend_observation(r, "gre-kernel", definition, {})["result"], "unknown")
        self.assertEqual(backend_observation(r, "gre-kernel", definition, {"address": [], "listeners": wildcard})["result"], "deferred")

    def test_share_redaction_scrubs_original_conntrack_ports(self):
        from twinlink.redaction import Redactor
        value = {"match": {"left": {"ct": {"key": "proto-dst", "dir": "original"}}, "op": "==", "right": 10000}}
        result = Redactor("share").scrub(value)
        self.assertNotIn("10000", json.dumps(result))
        self.assertEqual(result["match"]["left"]["ct"]["key"], "proto-dst")

    def test_identity_aliases_and_protocol_qualification_are_independent(self):
        for alias in ("amd64", "x86_64"):
            self.assertEqual(paqet.binary_pin(alias)["sha256"], paqet.INSTALL_RELEASES["amd64"]["binary_sha256"])
        for alias in ("arm64", "aarch64"):
            self.assertEqual(paqet.binary_pin(alias)["architecture"], "arm64")
        r = local_revision(self.r)
        self.assertTrue(paqet.qualification(r, "amd64"))
        evidence = {"evidence": "INJECTED UNIT FIXTURE; NOT PACKET EVIDENCE", "renderer_version": 2,
                    "binary_sha256": paqet.binary_pin("amd64")["sha256"], "settings_digests": [digest(r["profiles"]["direct-paqet"])],
                    "mapping_features": ["ranges", "many-to-one"], "backend_intents": ["vps2-local"], "max_expanded_services": 2}
        with patch.dict(paqet.RELEASE_MANIFEST["qualification"], {"amd64": {"tcp": evidence}}):
            self.assertFalse(paqet.qualification(r, "amd64"))
            self.assertTrue(paqet.qualification(r, "arm64"))
            r["services"][0]["protocol"] = "udp"
            self.assertTrue(paqet.qualification(r, "amd64"))
            r["services"][0]["protocol"] = "tcp"
            r["profiles"]["direct-paqet"]["conn"] = 3
            self.assertTrue(paqet.qualification(r, "amd64"))

    def test_menu_add_defaults_local_and_edit_preserves_target(self):
        from twinlink.menu import run_v2_menu
        self.stage()
        for action, prompts, expected in (("2", ["app", "", "", "8083", "9000", "", "", ""], "--backend-local"),
                                          ("3", ["web", "", "", "", "", "", "", ""], None)):
            answers = iter(["2", action, *prompts, "", "0"])
            calls = []
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run_v2_menu(argparse.Namespace(state_dir=str(self.store.directory)), command_runner=lambda args: calls.append(args) or 0,
                    input_fn=lambda prompt: next(answers), output_fn=lambda _: None), 0)
            self.assertTrue(calls)
            if expected:
                self.assertIn(expected, calls[0])
            else:
                self.assertNotIn("--backend-local", calls[0])
                self.assertNotIn("--backend-address", calls[0])


class BackendRuntimeTests(RuntimeFixture):
    def test_local_backend_range_overlapping_another_relay_passes_without_exempting_foreign_listeners(self):
        self.r = local_revision(self.r)
        self.r["services"][0]["backend"]["ports"] = "10001-10002"
        self.stage("vps2")
        self.prepare("vps2")
        control = self.store.read()["pairs"]["edge"]
        listeners = [{"address": "0.0.0.0", "port": port, "protocol": "tcp"} for port in (10001, 10002)]
        assigned = [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "203.0.113.2"}]}]
        outcome = {"result": "pass"}
        with patch.object(self.host, "addresses", return_value=assigned), patch.object(self.host, "listeners", return_value=listeners), \
             patch.object(self.runtime, "discover", return_value=FACTS), patch("twinlink.diagnostics.application_probe", return_value=outcome) as probe:
            result = self.runtime.preflight(self.r, "vps2", "gre-kernel", control, {})
            self.assertEqual({row["port"] for row in result["backend_checks"]}, {10001, 10002})
            self.assertEqual({call.args[0]["port"] for call in probe.call_args_list}, {10001, 10002})
            self.assertTrue(all(row["result"] == "deferred" for row in result["backend_checks"]))
            self.assertFalse(self.host.link_rows)
            listeners.append({"address": "0.0.0.0", "port": 10000, "protocol": "tcp"})
            with self.assertRaisesRegex(ValidationError, "conflicts with an existing host listener"):
                self.runtime.preflight(self.r, "vps2", "gre-kernel", control, {})
            listeners.pop()
            outcome.update(result="fail", error="Application response mismatch")
            with self.assertRaisesRegex(StateError, "Backend preflight exchange failed"):
                self.runtime.preflight(self.r, "vps2", "gre-kernel", control, {})

    def test_local_reply_route_is_checked_after_gre_preparation(self):
        self.r = local_revision(self.r)
        self.stage("vps2")
        c = self.store.read()["pairs"]["edge"]
        self.runtime.prepare(self.r, "vps2", "gre-kernel", c, {"previous": None})
        original = self.host.run
        def route_elsewhere(argv, **kwargs):
            if argv[:4] == ["ip", "-j", "route", "get"]:
                return {"returncode": 0, "stdout": '[{"dev":"foreign0"}]', "stderr": ""}
            return original(argv, **kwargs)
        with patch.object(self.host, "run", side_effect=route_elsewhere), self.assertRaisesRegex(StateError, "different return route"):
            self.runtime._verify_gre(self.r, "vps2")

    def test_paqet_doctor_requires_exact_packet_exceptions(self):
        from twinlink.diagnostics import profile_resources
        from twinlink.profiles import table_name
        facts = {**FACTS, "source": self.r["public_endpoints"]["vps2"]}
        owner = "00000000-0000-0000-0000-000000000000"
        script = paqet.packet_exceptions(self.r, facts, table_name("edge"), owner)
        self.host.run(["nft", "--file", "-"], input=script)
        snapshot = self.host.tables[table_name("edge")]
        observations = {"nft": snapshot, "raw-route": [{"dev": facts["interface"], "prefsrc": facts["source"], "gateway": facts["gateway"]}],
                        "raw-neighbor": [{"lladdr": facts["router_mac"]}]}
        self.assertEqual(profile_resources(self.r, "vps2", "direct-paqet", observations, owner, facts)["result"], "pass")
        changed = copy.deepcopy(snapshot)
        next(row["rule"] for row in changed["nftables"] if "rule" in row)["expr"] = [{"accept": None}]
        self.assertEqual(profile_resources(self.r, "vps2", "direct-paqet", {"nft": changed}, owner, facts)["result"], "fail")
        unknown = copy.deepcopy(snapshot)
        del next(row["table"] for row in unknown["nftables"] if "table" in row)["comment"]
        self.assertIsNone(profile_resources(self.r, "vps2", "direct-paqet", {"nft": unknown, "nft_comment_available": False}, owner, facts)["checks"]["owned_nft"])
        self.assertEqual(profile_resources(self.r, "vps2", "direct-paqet", {**observations, "raw-neighbor": [{"lladdr": "aa:bb:cc:dd:ee:ff"}]}, owner, facts)["result"], "fail")
        self.assertEqual(profile_resources(self.r, "vps2", "direct-paqet", {**observations, "raw-route": [{**observations["raw-route"][0], "gateway": "198.51.100.253"}]}, owner, facts)["result"], "fail")

    def test_profile_check_reports_deferred_without_creating_gre_or_reconciling(self):
        self.r = local_revision(self.r)
        self.stage("vps2")
        self.prepare("vps2")
        wildcard = [{"address": "0.0.0.0", "port": 9000, "protocol": "tcp"}]
        assigned = [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "203.0.113.2"}]}]
        before = self.runtime.ledger.path.read_bytes()
        with patch.object(cli, "Host", return_value=self.host), patch.object(self.host, "addresses", return_value=assigned), \
             patch.object(self.host, "listeners", return_value=wildcard), patch("twinlink.profile_runtime.ProfileRuntime.discover", return_value=FACTS), \
             patch("twinlink.diagnostics.application_probe", return_value={"result": "pass"}), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(["--state-dir", str(self.store.directory), "--unit-dir", str(self.host.unit_dir), "profile", "check", "gre-kernel", "--pair", "edge"]), 0)
        result = json.loads(out.getvalue())
        self.assertEqual(result["status"], "deferred-local")
        self.assertEqual(result["backend_checks"][0]["result"], "deferred")
        self.assertFalse(self.host.link_rows)
        self.assertEqual(self.runtime.ledger.path.read_bytes(), before)

    def test_deferred_probe_is_read_only_and_exact_check_requires_address(self):
        r = local_revision(self.r)
        wildcard = [{"address": "0.0.0.0", "port": 9000, "protocol": "tcp"}]
        with patch.object(self.host, "listeners", return_value=wildcard), patch("twinlink.diagnostics.application_probe", return_value={"result": "pass"}) as probe:
            results = self.runtime.probe_backends(r)
            self.assertEqual(results[0]["result"], "deferred")
            self.assertEqual(probe.call_args.args[0]["address"], "127.0.0.1")
            with self.assertRaisesRegex(StateError, "not assigned"):
                self.runtime.probe_backends(r, allow_deferred=False)
            self.assertFalse(self.host.commands)
            self.host.addr_rows = [{"ifname": "test", "addr_info": [{"family": "inet", "local": "10.77.0.2"}]}]
            results = self.runtime.probe_backends(r, allow_deferred=False)
            self.assertEqual(results[0]["result"], "ready-to-probe")
            self.assertEqual(probe.call_args.args[0]["address"], "10.77.0.2")

    def test_exact_target_failure_prevents_public_exposure(self):
        self.r = local_revision(self.r)
        self.stage(role="vps2")
        control = self.store.read()["pairs"]["edge"]
        self.runtime.prepare(self.r, "vps2", "gre-kernel", control, {"previous": None})
        with patch.object(self.host, "listeners", return_value=[{"address": "0.0.0.0", "port": 9000, "protocol": "tcp"}]), patch("twinlink.diagnostics.application_probe", return_value={"result": "fail", "error": "ConnectionRefused"}):
            with self.assertRaisesRegex(StateError, "exchange failed"):
                self.runtime.start(self.r, "vps2", "gre-kernel", control, {"previous": None})
        self.assertFalse(self.host.tables)
        self.assertEqual(self.host.forwarding, "0")

    def test_paqet_server_process_is_checked_even_when_nft_matches(self):
        with patch.object(self.runtime.ledger, "check") as ledger, patch.object(self.runtime, "_table_value", return_value="owned"), patch.object(self.runtime, "assert_unit_safe", return_value={"active": False}):
            with self.assertRaisesRegex(StateError, "process stopped"):
                self.runtime.verify_local(self.r, "vps2", "direct-paqet")
            ledger.assert_called_once()
