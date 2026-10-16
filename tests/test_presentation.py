import contextlib
import copy
import io
import os
import unittest
from unittest.mock import patch

from twinlink import cli, presentation as p
from tests.test_engine import active_state
from twinlink.models import empty_state


class PresentationTests(unittest.TestCase):
    def test_health_and_empty_lists(self):
        record = active_state("kernel")["forwards"]["web"]
        for health in ("up", "down", "degraded", "unknown", "stopped"):
            text = "\n".join(p.render({"configuration": record, "operational": {"health": health, "reason": "Repair needed"}, "peer_transfer_required": True}, ("forward", "show", "web")))
            self.assertIn(health, text)
            self.assertIn("8080", text)
            self.assertIn("Saved intent", text)
            self.assertIn("Peer setup required", text)
        self.assertIn("forward setup", "\n".join(p.render([], ("forward", "list", ""))))

    def test_cascade_and_dependent_stop_impacts(self):
        old = active_state("kernel")
        text = "\n".join(p.render({}, ("tunnel", "delete", "edge"), "preview", old, empty_state()))
        self.assertIn("Delete tunnel edge", text)
        self.assertIn("Delete forward web", text)
        self.assertIn("No changes applied", text)
        new = active_state("kernel")
        new["forwards"]["web"].update(running=False, enabled=False)
        text = "\n".join(p.render({}, ("tunnel", "disable", "edge"), "preview", old, new))
        self.assertIn("web", text)
        self.assertIn("Stop now; disable at boot", text)

    def test_shared_service_restart(self):
        old = active_state("rathole")
        new = active_state("rathole")
        new["forwards"]["web"]["destination_port"] = "81"
        self.assertIn("Shared Rathole service restart", "\n".join(p.render({}, ("forward", "edit", "web"), "preview", old, new)))

    def test_other_families_hide_evidence(self):
        cases = [
            (("forward", "diagnose", "web"), {"status": {"health": "unknown", "reason": "Check peer"}, "evidence": [{"command": ["ping"], "returncode": 1, "stdout": "HIDDEN"}]}, "unknown"),
            (("doctor", "", ""), {"platform": "Linux", "systemd_runtime": True, "missing_required": ["ip"], "evidence": "HIDDEN"}, "Missing required dependency: ip"),
            (("recover", "", ""), {"recovered": False}, "no unfinished transaction"),
            (("recover", "", ""), {"pending": True}, "pending"),
            (("forward", "config", "web"), {"path": "/private/web.toml", "note": "Generated; overwritten on reapply", "edit_with_nano": "nano /private/web.toml"}, "overwritten"),
            (("forward", "export", "web"), {"exported": "/private/export", "transfer": "Use scp"}, "Private transfer"),
            (("rathole", "install", ""), {"path": "/bin/rathole"}, "/bin/rathole"),
            (("status", "", ""), {"unfinished_transaction": True, "tunnels": [], "forwards": []}, "Unfinished transaction"),
            (("uninstall", "", ""), {"managed_tunnels": ["edge"], "managed_forwards": ["web"], "program_only": "scripts/uninstall.sh", "purge": "purge managed"}, "web"),
            (("forward", "add", "web"), {"error": "Failed", "rollback_errors": ["HIDDEN"]}, "Rollback incomplete"),
        ]
        for context, payload, expected in cases:
            with self.subTest(context=context):
                text = "\n".join(p.render(payload, context))
                self.assertIn(expected, text)
                self.assertNotIn("HIDDEN", text)

    def test_color_policy_and_uncolored_payloads(self):
        stream = io.StringIO()
        stream.isatty = lambda: True
        with patch.dict(os.environ, {"TERM": "xterm", "NO_COLOR": ""}):
            self.assertIn("\033[", p.style("up", "up", stream))
            with patch.dict(os.environ, {"NO_COLOR": "1"}):
                self.assertEqual(p.style("up", "up", stream), "up")
            with patch.dict(os.environ, {"TERM": "dumb"}):
                self.assertEqual(p.style("up", "up", stream), "up")
            self.assertEqual(p.style("up", "up", io.StringIO()), "up")
            with contextlib.redirect_stdout(stream):
                p.output({"token": "SECRET"}, verbose=True)
                p.output({"token": "SECRET"}, True, verbose=True)
            self.assertNotIn("\033[", stream.getvalue())
            self.assertNotIn("SECRET", stream.getvalue())

    def test_verbose_global_and_leaf(self):
        parser = cli.build_parser()
        for args in (["--verbose", "status"], ["status", "--verbose"], ["--verbose", "forward", "show", "web"], ["rathole", "config", "web", "--verbose"]):
            self.assertTrue(parser.parse_args(args).verbose)

    def test_pairing_line_never_colored_and_pending_warning_visible(self):
        stream = io.StringIO()
        stream.isatty = lambda: True
        with patch.dict(os.environ, {"TERM": "xterm", "NO_COLOR": ""}), contextlib.redirect_stdout(stream):
            p.output({"pairing_code": "f1.FULL_CODE", "pending_peer": ["web"]},
                     context=("forward", "add", "web"), phase="applied",
                     old=empty_state(), candidate=active_state("kernel"))
        self.assertIn("\033[", stream.getvalue())
        self.assertIn("\nf1.FULL_CODE\n", stream.getvalue())
        self.assertIn("Pending peer: web", stream.getvalue())

    def test_structured_error_evidence_is_verbose_only(self):
        value = {"error": 'Apply failed: GRE verification failed for edge: [{"actual": "HIDDEN"}]; rollback completed'}
        text = "\n".join(p.render(value, ("tunnel", "edit", "edge")))
        self.assertIn("GRE verification failed for edge", text)
        self.assertIn("Rollback completed", text)
        self.assertNotIn("HIDDEN", text)

    def test_error_summary_handles_empty_and_bracketed_messages(self):
        for message in ("", "[Errno 13] Permission denied: '/private/[state]'", "Invalid path [state]"):
            with self.subTest(message=message):
                text = "\n".join(p.render({"error": message}, ("status", "", "")))
                self.assertIn("Failed", text)
                self.assertIn(message or "Operation failed", text)

    def test_only_changed_unpaired_revisions_require_fresh_peer_export(self):
        old = active_state("kernel")
        new = copy.deepcopy(old)
        # Lifecycle changes alone must not be presented as a fresh shared edit.
        new["forwards"]["web"].update(running=False, enabled=False)
        text = "\n".join(p.render({}, ("forward", "disable", "web"), "preview", old, new))
        self.assertNotIn("Peer update required", text)
        # An imported matching revision already has the peer configuration.
        entry = new["forwards"]["web"]
        entry.update(revision=entry["revision"] + 1, peer_revision=entry["revision"] + 1)
        text = "\n".join(p.render({}, ("forward", "pair-import", ""), "preview", old, new))
        self.assertNotIn("Peer update required", text)

    def test_peer_update_guidance_lists_every_changed_forward(self):
        old = active_state("kernel")
        old["forwards"]["other"] = dict(old["forwards"]["web"], name="other")
        new = copy.deepcopy(old)
        for entry in new["forwards"].values():
            entry.update(revision=entry["revision"] + 1, running=False, enabled=False)
        text = "\n".join(p.render({}, ("forward", "edit", "web"), "applied", old, new))
        self.assertIn("Peer update required: other, web", text)
        self.assertIn("for each listed forwarding entry", text)
        self.assertIn("enable NAME --apply on both hosts", text)

    def test_initial_settings_include_unset_key_without_internal_fields(self):
        new = active_state("rathole")
        new["tunnels"]["edge"]["key"] = None
        text = "\n".join(p.render({}, ("tunnel", "create", "edge"), "preview", empty_state(), new))
        self.assertIn("GRE key: none", text)
        self.assertIn("Rathole transport: tcp", text)
        self.assertNotIn(new["forwards"]["web"]["token"], text)
        self.assertNotIn("revision", text)

    def test_stopped_unverified_tunnel_needs_start_before_recording(self):
        new = active_state()
        new["tunnels"]["edge"].update(running=False, enabled=False, verified=False)
        text = "\n".join(p.render({}, ("tunnel", "create", "edge"), "applied", empty_state(), new))
        self.assertIn("tunnel start edge --apply", text)
        self.assertIn("tunnel check edge --record --apply", text)
        self.assertLess(text.index("tunnel start edge"), text.index("tunnel check edge"))

    def test_verified_tunnel_does_not_repeat_pairing_guidance(self):
        old = active_state()
        new = copy.deepcopy(old)
        text = "\n".join(p.render({}, ("tunnel", "edit", "edge"), "applied", old, new))
        self.assertNotIn("GRE unverified", text)
        self.assertNotIn("pair-export", text)
