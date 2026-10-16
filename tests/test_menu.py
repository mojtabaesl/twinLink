import argparse
import unittest
from unittest.mock import patch

from twinlink.menu import _safe_command, run_menu, run_rathole_setup
from twinlink.models import empty_state
from twinlink.store import StateError
from tests.test_models import tunnel
from tests.test_rathole import noise_pair


def setup_state(side="vps1"):
    source, peer = noise_pair()
    source["forwards"] = {}
    return source if side == "vps1" else peer


class MenuTests(unittest.TestCase):
    def run_script(self, answers, result=0, state=None):
        calls, output = [], []
        self.prompts = []
        values = iter(answers)
        args = argparse.Namespace(state_dir="/private/state dir", unit_dir="/private/units",
                                  runtime_path="/usr/local/libexec/twinlink-runtime",
                                  rathole_binary="/opt/rathole", json=False, no_systemd=False)
        def runner(command):
            calls.append(command)
            return result
        def read(prompt):
            self.prompts.append(prompt)
            return next(values)
        with patch("twinlink.menu.Store.read", return_value=state if state is not None else empty_state()):
            self.assertEqual(run_menu(args, command_runner=runner, input_fn=read, output_fn=output.append), 0)
        return calls, output

    def test_overview_preserves_paths_as_single_arguments(self):
        calls, _ = self.run_script(["1", "0"])
        self.assertEqual(calls[0][-1], "status")
        self.assertIn("/private/state dir", calls[0])
        self.assertNotIn("--apply", calls[0])

    def test_guided_gre_creation_previews_then_applies_same_values(self):
        calls, _ = self.run_script(["2", "2", "edge", "1", "198.51.100.1", "203.0.113.2",
                                    "10.77.0.1/30", "10.77.0.2/30", "1472", "64", "42", "n", "apply", "0", "0"])
        self.assertEqual(len(calls), 2)
        preview, applied = calls
        self.assertEqual(preview[-3:], ["64", "--key", "42"])
        self.assertEqual(applied, preview + ["--apply", "--yes"])
        self.assertEqual(preview[preview.index("--side") + 1], "vps1")

    def test_failed_preview_never_reaches_apply_confirmation(self):
        calls, _ = self.run_script(["5", "0"], result=1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][-1], "recover")

    def test_rathole_wizard_collects_fields_without_asking_for_token(self):
        calls, output = self.run_script(["3", "2", "app", "edge", "2", "198.51.100.1", "8443",
                                        "127.0.0.1", "443", "25000", "y", "", "0", "0"])
        command = calls[0]
        self.assertEqual(command[command.index("--mode") + 1], "rathole")
        self.assertEqual(command[command.index("--protocol") + 1], "tcp")
        self.assertIn("--disabled", command)
        self.assertNotIn("--token", command)
        self.assertNotIn("--apply", command)

    def test_private_export_needs_explicit_export_choice(self):
        calls, _ = self.run_script(["3", "4", "app", "/root/private/app.pair", "", "0", "0"])
        self.assertEqual(calls, [])
        calls, _ = self.run_script(["3", "4", "app", "/root/private/app.pair", "export", "0", "0"])
        self.assertEqual(calls[0][-5:], ["forward", "export", "app", "--output", "/root/private/app.pair"])

    def test_expert_apply_flags_do_not_skip_preview(self):
        calls, _ = self.run_script(["6", "forward disable app --apply --yes", "", "0"])
        self.assertEqual(len(calls), 1)
        self.assertNotIn("--apply", calls[0])
        self.assertNotIn("--yes", calls[0])
        calls, _ = self.run_script(["6", "forward disable app --app --y", "", "0"])
        self.assertNotIn("--app", calls[0])
        self.assertNotIn("--y", calls[0])

    def test_import_uses_private_file_and_cascade_requires_explicit_choice(self):
        calls, _ = self.run_script(["3", "3", "/root/private/app.pair", "", "0", "2", "7", "edge", "7", "2", "", "0", "0"])
        self.assertEqual(calls[0][-4:], ["forward", "import", "--file", "/root/private/app.pair"])
        self.assertEqual(calls[1][-4:], ["tunnel", "delete", "edge", "--cascade"])
        self.assertTrue(all("--apply" not in call for call in calls))

    def test_secret_shaped_arguments_are_redacted_from_command_echo(self):
        result = _safe_command(["tunnel", "pair-import", "--code", "PRIVATECODE", "--token=SECRETTOKEN", "--password", "PASSWORD"])
        for private in ("PRIVATECODE", "SECRETTOKEN", "PASSWORD"):
            self.assertNotIn(private, result)
        self.assertIn("<redacted>", result)

    def test_noise_setup_installs_then_batches_ports_without_manual_credentials(self):
        with patch("twinlink.menu.os.path.exists", return_value=False):
            calls, output = self.run_script(["7", "", "2444", "", "8080:80,8443:443", "apply", "apply", "0"], state=setup_state())
        self.assertEqual(calls[0][-2:], ["rathole", "install"])
        self.assertEqual(calls[1], calls[0] + ["--apply", "--yes"])
        self.assertIn("8080:80,8443:443", calls[2])
        self.assertEqual(calls[3], calls[2] + ["--apply", "--yes"])
        self.assertEqual(len(calls), 4)
        self.assertNotIn("--token", calls[2])
        self.assertEqual(calls[2][calls[2].index("add") + 1], "edge-rathole")
        self.assertEqual(calls[2][calls[2].index("--tunnel") + 1], "edge")
        self.assertNotIn("--bind-address", calls[2])
        self.assertEqual(calls[2][calls[2].index("--transport-port") + 1], "2444")
        for prompt in self.prompts:
            for redundant in ("tunnel name", "name/prefix", "This server", "public IPv4", "private IPv4"):
                self.assertNotIn(redundant, prompt)

    def test_paste_pairing_text_is_redacted_and_reuses_existing_install(self):
        with patch("twinlink.menu.os.path.exists", return_value=True):
            calls, output = self.run_script(["7", "r1.SECRET_PAIRING", "apply", "0"], state=setup_state("vps2"))
        self.assertEqual(len(calls), 2)
        self.assertIn("r1.SECRET_PAIRING", calls[0])
        self.assertIn("--enable", calls[0])
        self.assertNotIn("r1.SECRET_PAIRING", "\n".join(output))

    def test_cancelled_install_does_not_attempt_noise_setup(self):
        with patch("twinlink.menu.os.path.exists", return_value=False):
            calls, _ = self.run_script(["7", "r1.SECRET", "", "0"], state=setup_state("vps2"))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][-2:], ["rathole", "install"])

    def test_direct_setup_propagates_failed_preview_exit_code(self):
        answers = iter(["r1.INVALID"])
        with patch("twinlink.menu.os.path.exists", return_value=True), patch("twinlink.menu.Store.read", return_value=setup_state("vps2")):
            result = run_rathole_setup(argparse.Namespace(), command_runner=lambda command: 1,
                                      input_fn=lambda prompt: next(answers), output_fn=lambda value: None)
        self.assertEqual(result, 1)

    def test_setup_selects_from_multiple_saved_tunnels_and_known_peer_ips(self):
        state = setup_state()
        state["tunnels"]["other"] = tunnel(name="other", key=42, local_private="10.78.0.1/30",
                                            remote_private="10.78.0.2/30", running=True)
        with patch("twinlink.menu.os.path.exists", return_value=True):
            calls, output = self.run_script(["7", "2", "", "", "2", "8080:80", "apply", "0"], state=state)
        command = calls[0]
        self.assertEqual(command[command.index("--tunnel") + 1], "other")
        self.assertEqual(command[command.index("--destination-address") + 1], "10.78.0.2")
        self.assertIn("other: peer 203.0.113.2 (GRE 10.78.0.2/30)", "\n".join(output))

    def test_setup_offers_saved_public_ip_without_typing_it(self):
        with patch("twinlink.menu.os.path.exists", return_value=True):
            calls, _ = self.run_script(["7", "", "", "3", "8080:80", "apply", "0"], state=setup_state())
        self.assertEqual(calls[0][calls[0].index("--destination-address") + 1], "203.0.113.2")

    def test_setup_only_prompts_for_ip_when_custom_backend_selected(self):
        with patch("twinlink.menu.os.path.exists", return_value=True):
            calls, _ = self.run_script(["7", "", "", "0", "10.20.30.40", "8080:80", "apply", "0"], state=setup_state())
        self.assertEqual(calls[0][calls[0].index("--destination-address") + 1], "10.20.30.40")

    def test_repeated_setup_exports_existing_names_without_install_or_port_prompts(self):
        source, _ = noise_pair()
        with patch("twinlink.menu.os.path.exists") as exists:
            calls, output = self.run_script(["7", "", "0"], state=source)
            exists.assert_not_called()
        self.assertEqual(calls[0][-4:], ["rathole", "pair-export", "tls", "web"])
        self.assertEqual(len(calls), 1)
        self.assertFalse(any("Forwarding ports" in prompt or "IPv4" in prompt for prompt in self.prompts))

    def test_adding_more_ports_reuses_saved_backend_and_avoids_name_collision(self):
        source, _ = noise_pair()
        source["forwards"]["edge-rathole"] = {**source["forwards"].pop("web"), "name": "edge-rathole", "destination_address": "10.20.30.40"}
        source["forwards"].pop("tls")
        with patch("twinlink.menu.os.path.exists", return_value=True):
            calls, output = self.run_script(["7", "2", "", "9000:90", "apply", "0"], state=source)
        self.assertEqual(calls[0][calls[0].index("add") + 1], "edge-rathole")
        self.assertEqual(calls[0][calls[0].index("--destination-address") + 1], "10.20.30.40")
        self.assertIn("Saved backend: 10.20.30.40", "\n".join(output))

    def test_client_pairing_matches_saved_tunnels_without_tunnel_selector(self):
        state = setup_state("vps2")
        state["tunnels"]["second"] = {**state["tunnels"]["edge"], "name": "second"}
        with patch("twinlink.menu.os.path.exists", return_value=True):
            calls, _ = self.run_script(["7", "r1.PAIR", "apply", "0"], state=state)
        self.assertEqual(len(calls), 2)
        self.assertFalse(any("tunnel" in prompt.lower() or "This server" in prompt for prompt in self.prompts))

    def test_unavailable_tunnels_show_saved_repair_commands_before_installation(self):
        state = setup_state()
        state["tunnels"]["edge"].update(running=False, verified=False)
        with patch("twinlink.menu.os.path.exists") as exists:
            calls, output = self.run_script(["7", "0"], state=state)
            exists.assert_not_called()
        self.assertFalse(calls)
        self.assertIn("tunnel start edge --apply", "\n".join(output))
        self.assertIn("tunnel check edge --record --apply", "\n".join(output))

    def test_setup_reads_custom_state_directory_without_mutation(self):
        args = argparse.Namespace(state_dir="/private/custom state")
        answers = iter(["r1.PAIR", ""])
        with patch("twinlink.menu.Store") as store, patch("twinlink.menu.os.path.exists", return_value=True):
            store.return_value.read.return_value = setup_state("vps2")
            run_rathole_setup(args, command_runner=lambda command: 0,
                              input_fn=lambda prompt: next(answers), output_fn=lambda value: None)
            store.assert_called_once_with("/private/custom state")
            store.return_value.write.assert_not_called()

    def test_setup_reports_invalid_state_instead_of_requesting_configuration_again(self):
        with patch("twinlink.menu.Store.read", side_effect=StateError("Invalid state")), patch("twinlink.menu.os.path.exists") as exists:
            output = []
            result = run_rathole_setup(argparse.Namespace(), command_runner=lambda command: self.fail(command),
                                      input_fn=lambda prompt: self.fail(prompt), output_fn=output.append)
            exists.assert_not_called()
        self.assertEqual(result, 1)
        self.assertIn("Invalid state", "\n".join(output))

    def test_mixed_saved_roles_prompt_only_for_the_ambiguous_role(self):
        state = setup_state()
        state["tunnels"]["backend"] = setup_state("vps2")["tunnels"]["edge"]
        with patch("twinlink.menu.os.path.exists", return_value=True):
            calls, output = self.run_script(["7", "2", "r1.PAIR", "apply", "0"], state=state)
        self.assertIn("both roles", "\n".join(output))
        self.assertEqual(calls[0][calls[0].index("rathole") + 1], "pair-import")

    def test_generated_names_fit_maximum_tunnel_name_and_multiple_ports(self):
        state = setup_state()
        record = state["tunnels"].pop("edge")
        record["name"] = "a" * 48
        state["tunnels"][record["name"]] = record
        with patch("twinlink.menu.os.path.exists", return_value=True):
            calls, _ = self.run_script(["7", "", "", "", "65534:80,65535:443", "apply", "0"], state=state)
        prefix = calls[0][calls[0].index("add") + 1]
        self.assertLessEqual(len(prefix + "-65535"), 48)

    def test_consolidation_collects_one_name_and_connection_port_without_forwarding_prompts(self):
        source, _ = noise_pair()
        with patch("twinlink.menu.os.path.exists", return_value=True):
            calls, output = self.run_script(["7", "3", "combined", "2555", "apply", "0"], state=source)
        self.assertEqual(calls[0][-7:], ["rathole", "consolidate", "combined", "--tunnel", "edge", "--transport-port", "2555"])
        self.assertFalse(any("Forwarding ports" in prompt or "Backend" in prompt for prompt in self.prompts))


if __name__ == "__main__":
    unittest.main()
