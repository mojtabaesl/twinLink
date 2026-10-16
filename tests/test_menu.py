import argparse
import unittest
from unittest.mock import patch

from twinlink.menu import _safe_command, run_menu, run_rathole_setup


class MenuTests(unittest.TestCase):
    def run_script(self, answers, result=0):
        calls, output = [], []
        values = iter(answers)
        args = argparse.Namespace(state_dir="/private/state dir", unit_dir="/private/units",
                                  runtime_path="/usr/local/libexec/twinlink-runtime",
                                  rathole_binary="/opt/rathole", json=False, no_systemd=False)
        def runner(command):
            calls.append(command)
            return result
        self.assertEqual(run_menu(args, command_runner=runner, input_fn=lambda prompt: next(values), output_fn=output.append), 0)
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
            calls, output = self.run_script(["7", "1", "app", "edge", "", "8080:80,8443:443", "apply", "apply", "0"])
        self.assertEqual(calls[0][-2:], ["rathole", "install"])
        self.assertEqual(calls[1], calls[0] + ["--apply", "--yes"])
        self.assertIn("8080:80,8443:443", calls[2])
        self.assertEqual(calls[3], calls[2] + ["--apply", "--yes"])
        self.assertEqual(len(calls), 4)
        self.assertNotIn("--token", calls[2])

    def test_paste_pairing_text_is_redacted_and_reuses_existing_install(self):
        with patch("twinlink.menu.os.path.exists", return_value=True):
            calls, output = self.run_script(["7", "2", "r1.SECRET_PAIRING", "apply", "0"])
        self.assertEqual(len(calls), 2)
        self.assertIn("r1.SECRET_PAIRING", calls[0])
        self.assertIn("--enable", calls[0])
        self.assertNotIn("r1.SECRET_PAIRING", "\n".join(output))

    def test_cancelled_install_does_not_attempt_noise_setup(self):
        with patch("twinlink.menu.os.path.exists", return_value=False):
            calls, _ = self.run_script(["7", "2", "r1.SECRET", "", "0"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][-2:], ["rathole", "install"])

    def test_direct_setup_propagates_failed_preview_exit_code(self):
        answers = iter(["2", "r1.INVALID"])
        with patch("twinlink.menu.os.path.exists", return_value=True):
            result = run_rathole_setup(argparse.Namespace(), command_runner=lambda command: 1,
                                      input_fn=lambda prompt: next(answers), output_fn=lambda value: None)
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
