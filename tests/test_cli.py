"""Exercise scriptable CLI output and lifecycle through the transaction engine."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from twinlink import cli
from twinlink.models import empty_state
from twinlink.store import Store
from tests.test_engine import MemoryHost, active_state
from tests.test_rathole import KEYS, PRIVATE, noise_pair


CREATE = ["tunnel", "create", "edge", "--side", "vps1", "--local-public", "198.51.100.1",
          "--remote-public", "203.0.113.2", "--local-private", "10.77.0.1/30",
          "--remote-private", "10.77.0.2/30", "--key", "41"]
ADD = ["forward", "add", "web", "--tunnel", "edge", "--mode", "kernel", "--protocol", "tcp",
       "--bind-port", "8080", "--destination-address", "10.20.30.40", "--destination-port", "80"]


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").exists() else None)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.state_dir, self.unit_dir = self.directory / "state", self.directory / "units"
        self.store = Store(self.state_dir)
        self.host = MemoryHost(self.state_dir, self.unit_dir)

    def invoke(self, arguments, parse_json=True):
        buffer = io.StringIO()
        argv = ["--json", "--state-dir", str(self.state_dir), "--unit-dir", str(self.unit_dir),
                "--runtime-path", "/usr/local/libexec/twinlink-runtime", "--no-systemd", *arguments]
        with patch.dict(os.environ, {"TWINLINK_TESTING": "1"}), patch.object(cli, "Host", return_value=self.host), contextlib.redirect_stdout(buffer):
            code = cli.main(argv)
        text = buffer.getvalue()
        return code, json.loads(text) if parse_json else text

    def create_verified_gre(self):
        code, result = self.invoke(CREATE + ["--apply", "--yes"])
        self.assertEqual(code, 0, result)
        code, result = self.invoke(["tunnel", "check", "edge", "--record", "--apply", "--yes"])
        self.assertEqual(code, 0, result)
        self.assertTrue(self.store.read()["tunnels"]["edge"]["verified"])

    def install_kernel(self):
        self.create_verified_gre()
        code, result = self.invoke(ADD + ["--apply", "--yes"])
        self.assertEqual(code, 0, result)

    def test_default_mutation_is_preview_without_state_files_or_network_commands(self):
        code, result = self.invoke(CREATE)
        self.assertEqual(code, 0)
        self.assertEqual(result["action"], "tunnel create")
        self.assertTrue(result["commands"])
        self.assertTrue(result["rollback"])
        self.assertFalse(self.state_dir.exists())
        self.assertFalse(self.unit_dir.exists())
        self.assertFalse(self.host.commands)

    def test_apply_json_is_one_document_with_preview_and_commit(self):
        code, result = self.invoke(CREATE + ["--apply", "--yes"])
        self.assertEqual(code, 0, result)
        self.assertTrue(result["committed"])
        self.assertEqual(result["plan"]["action"], "tunnel create")
        self.assertEqual(len(self.host.link_data), 1)

    def test_noninteractive_apply_requires_explicit_yes(self):
        with patch("twinlink.cli.sys.stdin.isatty", return_value=False):
            code, result = self.invoke(CREATE + ["--apply"])
        self.assertEqual(code, 1)
        self.assertIn("--yes", result["error"])
        self.assertFalse(self.host.link_data)
        self.assertFalse(self.state_dir.exists())

    def test_forward_creation_requires_successfully_recorded_gre_probe(self):
        code, result = self.invoke(CREATE + ["--apply", "--yes"])
        self.assertEqual(code, 0, result)
        code, result = self.invoke(ADD)
        self.assertEqual(code, 1)
        self.assertIn("verify GRE", result["error"])
        self.assertFalse(self.store.read()["forwards"])

    def test_check_record_preview_does_not_record_verification(self):
        self.invoke(CREATE + ["--apply", "--yes"])
        code, result = self.invoke(["tunnel", "check", "edge", "--record"])
        self.assertEqual(code, 0, result)
        self.assertTrue(result["configuration"]["tunnels"]["edge"]["verified"])
        self.assertFalse(self.store.read()["tunnels"]["edge"]["verified"])

    def test_failed_check_record_json_is_one_document(self):
        self.invoke(CREATE + ["--apply", "--yes"])
        self.host.link_data.clear()
        code, result = self.invoke(["tunnel", "check", "edge", "--record", "--apply", "--yes"])
        self.assertEqual(code, 1)
        self.assertIn("error", result)
        self.assertFalse(self.store.read()["tunnels"]["edge"]["verified"])

    def test_forward_edit_stops_exposure_and_requires_new_peer_revision(self):
        self.install_kernel()
        before = self.store.read()["forwards"]["web"]
        code, result = self.invoke(["forward", "edit", "web", "--destination-port", "81", "--apply", "--yes"])
        self.assertEqual(code, 0, result)
        after = self.store.read()["forwards"]["web"]
        self.assertEqual(after["destination_port"], "81")
        self.assertEqual(after["revision"], before["revision"] + 1)
        self.assertFalse(after["enabled"])
        self.assertFalse(after["running"])
        self.assertFalse(any("rule" in row for row in self.host.nft["nftables"]))
        code, shown = self.invoke(["forward", "show", "web", "--no-probe"])
        self.assertEqual(code, 0)
        self.assertTrue(shown["peer_transfer_required"])

    def test_tunnel_edit_invalidates_verification_and_stops_dependents(self):
        self.install_kernel()
        code, result = self.invoke(["tunnel", "edit", "edge", "--mtu", "1400", "--apply", "--yes"])
        self.assertEqual(code, 0, result)
        state = self.store.read()
        self.assertFalse(state["tunnels"]["edge"]["verified"])
        self.assertEqual(self.host.link_data[0]["mtu"], 1400)
        self.assertFalse(state["forwards"]["web"]["running"])
        self.assertFalse(state["forwards"]["web"]["enabled"])

    def test_disable_then_restart_preserves_enabled_state_and_removes_rules(self):
        self.install_kernel()
        code, result = self.invoke(["forward", "disable", "web", "--apply", "--yes"])
        self.assertEqual(code, 0, result)
        self.assertFalse(self.store.read()["forwards"]["web"]["running"])
        self.assertFalse(any("rule" in row for row in self.host.nft["nftables"]))
        code, result = self.invoke(["forward", "restart", "web", "--apply", "--yes"])
        self.assertEqual(code, 0, result)
        entry = self.store.read()["forwards"]["web"]
        self.assertTrue(entry["running"])
        self.assertFalse(entry["enabled"])
        self.assertTrue(any("rule" in row for row in self.host.nft["nftables"]))

    def test_running_restart_forces_runtime_refresh_with_identical_desired_state(self):
        self.install_kernel()
        old = copy.deepcopy(self.store.read()["forwards"]["web"])
        self.host.commands.clear()
        code, result = self.invoke(["forward", "restart", "web", "--apply", "--yes"])
        self.assertEqual(code, 0, result)
        self.assertEqual(old, self.store.read()["forwards"]["web"])
        self.assertTrue(any(argv[0] == "conntrack" for argv, _ in self.host.commands))

    def test_stale_queued_tunnel_down_respects_latest_running_state(self):
        self.create_verified_gre()
        self.host.commands.clear()
        code, text = self.invoke(["internal", "tunnel-down", "edge"], parse_json=False)
        self.assertEqual(code, 0, text)
        self.assertTrue(self.host.link_data)
        self.assertFalse(any(argv[:3] == ["ip", "link", "delete"] for argv, _ in self.host.commands))

    def test_stale_queued_tunnel_down_after_delete_is_idempotent(self):
        self.create_verified_gre()
        code, result = self.invoke(["tunnel", "delete", "edge", "--cascade", "--apply", "--yes"])
        self.assertEqual(code, 0, result)
        code, text = self.invoke(["internal", "tunnel-down", "edge"], parse_json=False)
        self.assertEqual(code, 0, text)
        self.assertFalse(self.host.link_data)

    def test_tunnel_delete_identifies_dependencies_and_requires_cascade(self):
        self.install_kernel()
        code, result = self.invoke(["tunnel", "delete", "edge", "--no-cascade", "--apply", "--yes"])
        self.assertEqual(code, 1)
        self.assertIn("web", result["error"])
        self.assertIn("--cascade", result["error"])
        self.assertTrue(self.host.link_data)
        code, result = self.invoke(["tunnel", "delete", "edge", "--cascade", "--apply", "--yes"])
        self.assertEqual(code, 0, result)
        self.assertFalse(self.store.read()["tunnels"])
        self.assertFalse(self.store.read()["forwards"])
        self.assertFalse(self.host.link_data)
        self.assertIsNone(self.host.nft)

    def test_status_and_preview_never_expose_rathole_token(self):
        state = active_state("rathole")
        self.store.write(state)
        secret = state["forwards"]["web"]["token"]
        for command in (["forward", "show", "web", "--no-probe"], ["forward", "edit", "web", "--destination-port", "81"]):
            code, text = self.invoke(command, parse_json=False)
            self.assertEqual(code, 0, text)
            json.loads(text)
            self.assertNotIn(secret, text)
            self.assertIn("<redacted>", text)

    def test_secret_export_is_explicit_private_and_refuses_overwrite(self):
        state = active_state("rathole")
        self.store.write(state)
        destination = self.directory / "peer-config.txt"
        code, result = self.invoke(["forward", "export", "web", "--output", str(destination)])
        self.assertEqual(code, 0, result)
        self.assertTrue(result["contains_secret"])
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        original = destination.read_bytes()
        code, result = self.invoke(["forward", "export", "web", "--output", str(destination)])
        self.assertEqual(code, 1)
        self.assertIn("overwrite", result["error"])
        self.assertEqual(destination.read_bytes(), original)

    def test_program_only_uninstall_does_not_remove_resources(self):
        self.install_kernel()
        state = self.store.read()
        code, result = self.invoke(["uninstall"])
        self.assertEqual(code, 0)
        self.assertEqual(result["managed_tunnels"], ["edge"])
        self.assertEqual(self.store.read(), state)
        self.assertTrue(self.host.link_data)

    def test_doctor_fails_when_required_dependency_is_missing(self):
        with patch.object(self.host, "dependency_report", return_value={"linux": True, "missing_required": ["nft"]}), patch("twinlink.cli.platform.system", return_value="Linux"):
            code, result = self.invoke(["doctor"])
        self.assertEqual(code, 1, result)

    def test_no_systemd_cannot_be_enabled_outside_isolated_test_mode(self):
        buffer = io.StringIO()
        with patch.dict(os.environ, {"TWINLINK_TESTING": "0"}), contextlib.redirect_stdout(buffer):
            code = cli.main(["--json", "--state-dir", str(self.state_dir), "--no-systemd", "status"])
        self.assertEqual(code, 1)
        self.assertIn("isolated integration", json.loads(buffer.getvalue())["error"])

    def test_unknown_record_has_actionable_json_error(self):
        code, result = self.invoke(["forward", "show", "missing"])
        self.assertEqual(code, 1)
        self.assertIn("Unknown forward", result["error"])

    def test_state_read_does_not_silently_accept_world_readable_secret_file(self):
        self.store.write(active_state("rathole"))
        self.store.path.chmod(0o644)
        code, result = self.invoke(["status"])
        self.assertEqual(code, 1)
        self.assertIn("chmod 600", result["error"])

    def test_noise_setup_batches_ports_and_exports_only_after_commit(self):
        self.create_verified_gre()
        arguments = ["rathole", "add", "app", "--tunnel", "edge", "--ports", "8080:80,8443:443"]
        with patch.object(cli.rathole, "generate_keypair", return_value=KEYS):
            code, result = self.invoke(arguments)
            self.assertEqual(code, 0, result)
            self.assertNotIn("pairing_code", result)
            self.assertNotIn(PRIVATE, json.dumps(result))
            self.assertFalse(self.store.read()["forwards"])
            code, result = self.invoke(arguments + ["--apply", "--yes"])
        self.assertEqual(code, 0, result)
        self.assertTrue(result["committed"])
        self.assertTrue(result["pairing_code"].startswith("r1."))
        self.assertNotIn(PRIVATE, json.dumps(result))
        saved = self.store.read()
        self.assertEqual(set(saved["forwards"]), {"app-8080", "app-8443"})
        tokens = {entry["token"] for entry in saved["forwards"].values()}
        self.assertEqual(len(tokens), 1)
        self.assertEqual(saved["forwards"]["app-8080"]["noise_private_key"], PRIVATE)
        config = (self.state_dir / "rathole/app.toml").read_text()
        self.assertIn('type = "noise"', config)
        self.assertIn('[server.services."app-8080"]', config)
        self.assertIn('[server.services."app-8443"]', config)
        self.assertEqual(len(list((self.state_dir / "rathole").glob("*.toml"))), 1)

    def test_noise_import_applies_bundle_and_enable_without_generating_keys(self):
        source, peer = noise_pair()
        from twinlink import pairing
        pairing_code = pairing.export_rathole(list(source["forwards"].values()), source)
        peer["tunnels"]["edge"].update(running=False, enabled=False)
        self.store.write(peer)
        with patch.object(cli.rathole, "generate_keypair") as generate:
            code, result = self.invoke(["rathole", "pair-import", "--code", pairing_code, "--apply", "--yes"])
            self.assertEqual(code, 0, result)
            generate.assert_not_called()
        entries = self.store.read()["forwards"]
        self.assertEqual(len(entries), 2)
        self.assertNotIn("noise_private_key", entries["web"])
        self.assertFalse(entries["web"]["running"])
        code, result = self.invoke(["rathole", "pair-import", "--code", pairing_code, "--enable"])
        self.assertEqual(code, 1)
        self.assertIn("Start the GRE", result["error"])

    def test_noise_import_enable_keeps_peer_public_key_and_boot_intent(self):
        source, peer = noise_pair()
        from twinlink import pairing
        pairing_code = pairing.export_rathole(list(source["forwards"].values()), source)
        self.store.write(peer)
        self.host.address_data[0]["addr_info"][0]["local"] = "203.0.113.2"
        code, result = self.invoke(["tunnel", "reapply", "edge", "--apply", "--yes"])
        self.assertEqual(code, 0, result)
        code, result = self.invoke(["rathole", "pair-import", "--code", pairing_code, "--enable", "--apply", "--yes"])
        self.assertEqual(code, 0, result)
        for entry in self.store.read()["forwards"].values():
            self.assertTrue(entry["running"])
            self.assertTrue(entry["enabled"])
            self.assertNotIn("noise_private_key", entry)
        self.assertIn("remote_public_key", (self.state_dir / "rathole/web.toml").read_text())

    def test_rathole_config_prints_quoted_paths_without_opening_editor(self):
        self.store.write(active_state("rathole"))
        with patch("subprocess.run") as run:
            code, result = self.invoke(["rathole", "config", "web"])
            run.assert_not_called()
        self.assertEqual(code, 0, result)
        self.assertEqual(result["path"], str(self.state_dir / "rathole/web.toml"))
        self.assertIn("sudo vim", result["edit_with_vim"])
        self.assertIn("overwritten", result["note"])

    def test_rathole_install_previews_without_downloading(self):
        with patch.object(cli.rathole, "install_plan", return_value={"path": "/opt/rathole", "already_installed": False}), patch.object(cli.rathole, "install") as install:
            code, result = self.invoke(["rathole", "install"])
            self.assertEqual(code, 0, result)
            install.assert_not_called()
            self.assertFalse(self.state_dir.exists())

    def test_rathole_upgrade_preserves_legacy_until_explicit_noise_edit(self):
        state = active_state("rathole")
        self.store.write(state)
        with patch.object(cli.rathole, "generate_keypair", return_value=KEYS):
            code, result = self.invoke(["forward", "edit", "web", "--rathole-transport", "noise"])
        self.assertEqual(code, 0, result)
        candidate = result["configuration"]["forwards"]["web"]
        self.assertEqual(candidate["rathole_transport"], "noise")
        self.assertFalse(candidate["running"])
        self.assertEqual(candidate["revision"], 2)
        self.assertNotIn("rathole_transport", self.store.read()["forwards"]["web"])

    def test_batch_invalid_second_port_never_commits_first_entry(self):
        self.create_verified_gre()
        with patch.object(cli.rathole, "generate_keypair", return_value=KEYS):
            code, result = self.invoke(["rathole", "add", "app", "--tunnel", "edge", "--ports", "8080:80,22:443", "--apply", "--yes"])
        self.assertEqual(code, 1, result)
        self.assertFalse(self.store.read()["forwards"])

    def test_setup_reads_saved_gre_and_applies_without_asking_for_names_or_ips(self):
        self.create_verified_gre()
        answers = iter(["my-rathole", "2444", "", "9090:90", "apply"])
        prompts = []
        def read(prompt):
            prompts.append(prompt)
            return next(answers)
        exists = os.path.exists
        with patch("builtins.input", side_effect=read), patch("twinlink.menu.os.path.exists", side_effect=lambda path: str(path) == "/usr/local/bin/rathole" or exists(path)), patch.object(cli.rathole, "generate_keypair", return_value=KEYS):
            code, result = self.invoke(["rathole", "setup"], parse_json=False)
        self.assertEqual(code, 0, result)
        entry = self.store.read()["forwards"]["my-rathole-9090"]
        self.assertEqual(entry["tunnel"], "edge")
        self.assertEqual(entry["bind_address"], "198.51.100.1")
        self.assertEqual(entry["destination_address"], "127.0.0.1")
        self.assertEqual(entry["bind_port"], "9090")
        self.assertTrue(entry["running"])
        self.assertEqual(entry["rathole_group"], "my-rathole")
        self.assertEqual(entry["transport_port"], 2444)
        self.assertEqual(len(prompts), 5)


if __name__ == "__main__":
    unittest.main()
