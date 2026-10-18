"""Regressions for durable withdrawal, storage bounds and bounded diagnostics."""
import argparse
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

from tests.test_lifecycle_review import RuntimeFixture
from tests.test_packaging import packaging
from tests.test_v2 import V2Fixture, FACTS
from twinlink import cli
from twinlink.baseline import MAX_BASELINE_BYTES, MAX_BASELINE_ITEMS, parse, serialize
from twinlink.cleanup import remove_program, restore_packages
from twinlink.contracts import canonical, empty_v2, next_revision, validate_revision
from twinlink.coordination import Coordinator, new_transaction, receipt
from twinlink.diagnostics import bounded_command
from twinlink.models import ValidationError
from twinlink.pair_bundle import encode, decode, MAX_DECODED
from twinlink.redaction import Redactor
from twinlink.store import StateError, atomic_write


class OffIntentReviewTests(RuntimeFixture):
    def pending(self, role="vps1"):
        self.stage(role)
        self.prepare(role)
        state = self.store.read()
        c = state["pairs"]["edge"]
        tx = new_transaction("edge", self.r, "direct-rathole", {**c, "role": "vps1"}, now=100)
        tx.update(phase="verifying", verification_deadline=160)
        c["transition"] = tx
        self.store.write(state)
        active = self.runtime.runtime_unit(self.r, "direct-rathole")
        self.host.active.add(active)
        self.runtime.arm_verification_expiry(self.r, role, "direct-rathole", c, tx)
        return tx, active

    def off_receipt(self, old):
        c = self.store.read()["pairs"]["edge"]
        off = new_transaction("edge", self.r, None, {**c, "role": "vps1", "epoch": old["epoch"]}, now=100)
        return receipt(off, "vps1", "quiesce", self.creds["management"], 100)

    def assert_watchdog_withdraws(self, active):
        Coordinator(self.store, self.runtime, lambda: 161).expire_verification("edge")
        self.assertNotIn(active, self.host.active)

    def invalid_receipt_keeps_intent(self, role):
        old, active = self.pending(role)
        incoming = self.off_receipt(old)
        incoming["hmac"] = "0" * 64
        before = self.store.path.read_bytes()
        with self.assertRaises(ValidationError):
            Coordinator(self.store, self.runtime, lambda: 100).advance("edge", self.r, None, incoming)
        self.assertEqual(self.store.path.read_bytes(), before)
        self.assertIn(active, self.host.active)
        self.assert_watchdog_withdraws(active)

    def test_invalid_vps1_off_receipt_preserves_expiry_withdrawal(self):
        self.invalid_receipt_keeps_intent("vps1")

    def test_invalid_vps2_off_receipt_preserves_expiry_withdrawal(self):
        self.invalid_receipt_keeps_intent("vps2")

    def test_wrong_peer_chain_or_requested_step_cannot_replace_intent(self):
        old, active = self.pending("vps2")
        incoming = self.off_receipt(old)
        wrong_chain = copy.deepcopy(incoming)
        wrong_chain["history"] = [copy.deepcopy(incoming)]
        before = self.store.path.read_bytes()
        for kwargs in ({"incoming": wrong_chain}, {"incoming": incoming, "step": "start"},
                       {"incoming": incoming, "transaction_id": "a" * 32},
                       {"transaction_id": "invalid"}, {"step": "start"}, {"refresh": True}):
            with self.subTest(kwargs=list(kwargs)), self.assertRaises((ValidationError, StateError)):
                Coordinator(self.store, self.runtime, lambda: 100).advance("edge", self.r, None, **kwargs)
            self.assertEqual(self.store.path.read_bytes(), before)
        self.assertFalse(list((self.store.directory / "journals").glob("withdrawal-*")))
        self.assert_watchdog_withdraws(active)

    def failed_replacement(self, after_replace=False):
        old, active = self.pending()
        original = self.store.write
        observed = []
        def interrupted(state):
            observed.append(copy.deepcopy(state["pairs"]["edge"]["transition"]))
            if after_replace:
                original(state)
            raise OSError("simulated atomic write boundary")
        with patch.object(self.store, "write", side_effect=interrupted), self.assertRaises(OSError):
            Coordinator(self.store, self.runtime, lambda: 100).advance("edge", self.r, None)
        self.assertTrue(observed)
        self.assertTrue(all(tx is not None and tx["target"] is None for tx in observed))
        saved = self.store.read()["pairs"]["edge"]["transition"]
        self.assertEqual(saved["target"], None if after_replace else "direct-rathole")
        archive = self.store.directory / "journals" / ("withdrawal-edge-" + old["transaction_id"] + ".json")
        self.assertEqual(self.store.private_read(archive), old)
        self.assert_watchdog_withdraws(active)

    def test_failure_before_atomic_replace_retains_original_watchdog_intent(self):
        self.failed_replacement()

    def test_failure_after_atomic_replace_leaves_withdrawable_off_intent(self):
        self.failed_replacement(after_replace=True)

    def test_valid_off_replacement_is_durable_before_runtime_withdrawal(self):
        old, active = self.pending()
        original = self.runtime.quiesce
        observed = []
        def quiesce(*args):
            observed.append(self.store.read()["pairs"]["edge"]["transition"])
            return original(*args)
        with patch.object(self.runtime, "quiesce", side_effect=quiesce):
            result = Coordinator(self.store, self.runtime, lambda: 100).advance("edge", self.r, None)
        self.assertEqual(result["receipt"]["body"]["step"], "quiesce")
        self.assertEqual(observed[0]["target"], None)
        self.assertGreater(observed[0]["epoch"], old["epoch"])
        self.assertNotIn(active, self.host.active)


class RevisionBoundReviewTests(V2Fixture):
    def large_revision(self, count, probe_bytes):
        services = []
        for i in range(count):
            service = copy.deepcopy(self.r["services"][0])
            service.update(id="s" + str(i), ports=str(9000 + i))
            service["backend"]["ports"] = "80"
            service["probe"].update(request_hex="61" * probe_bytes, response_hex="62" * probe_bytes)
            services.append(service)
        return validate_revision({**self.r, "services": services})

    def test_initial_oversized_revision_is_rejected_before_artifacts_or_state(self):
        r = self.large_revision(9, 2048)
        self.assertGreater(len(canonical(r)), MAX_DECODED)
        for role in ("vps1", "vps2"):
            with self.subTest(role=role), self.assertRaises(ValidationError):
                self.store.stage(self.store.read(), r, role, self.creds, FACTS)
            self.assertFalse(self.store.directory.exists())

    def test_complete_bundle_overhead_is_checked_before_staging(self):
        r = self.large_revision(8, 1960)
        self.assertLess(len(canonical(r)), MAX_DECODED)
        with self.assertRaisesRegex(ValidationError, "Pair bundle exceeds"):
            self.store.stage(self.store.read(), r, "vps1", self.creds, FACTS)
        self.assertFalse(self.store.directory.exists())

    def test_oversized_edit_preserves_active_state_ledger_and_revision(self):
        self.stage()
        state = self.store.read()
        state["pairs"]["edge"].update(active={"profile": "gre-kernel", "revision": 1, "epoch": 1}, epoch=1)
        self.store.write(state)
        before = {str(p): p.read_bytes() for p in self.store.directory.rglob("*") if p.is_file()}
        r = next_revision(self.r, services=self.large_revision(9, 2048)["services"])
        with self.assertRaises(ValidationError):
            self.store.stage(state, r, "vps1", self.creds, FACTS, commit_state=False)
        self.assertEqual({str(p): p.read_bytes() for p in self.store.directory.rglob("*") if p.is_file()}, before)
        self.assertEqual(self.store.revision("edge", 1), self.r)

    def test_large_admissible_revision_remains_readable_and_exportable(self):
        r = self.large_revision(7, 2048)
        state = self.store.stage(self.store.read(), r, "vps1", self.creds, FACTS)
        self.assertEqual(state["pairs"]["edge"]["staged_revision"], 1)
        saved = self.store.revision("edge", 1)
        imported, _ = decode(encode(saved, self.creds), stored_management_key=self.creds["management"])
        self.assertEqual(imported, r)


class RedactionBoundReviewTests(unittest.TestCase):
    def test_long_words_and_repeated_keywords_finish_within_subprocess_budget(self):
        script = """from twinlink.redaction import Redactor
for level in ('secrets', 'share'):
    redactor = Redactor(level)
    for word in ('x' * 32768, 'key' * 10922):
        assert redactor.string(word) == word
        assert redactor.string(word + 'token=private') == word + 'token=\"<redacted>\"'
"""
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=4,
                                cwd=Path(__file__).resolve().parents[1])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_assignments_scrub_quotes_escapes_json_and_nested_messages(self):
        source = 'API_KEY = abc password=\'two words\' token="escaped \\" quote" message=secret=hidden {"access-token": "json hidden"}'
        for level in ("share", "secrets"):
            result = Redactor(level).string(source)
            for secret in ("abc", "two words", "escaped", "hidden"):
                self.assertNotIn(secret, result)
            self.assertEqual(result.count("<redacted>"), 5)
            self.assertIn('message=secret="<redacted>"', result)

    def test_unterminated_secret_and_known_unlabelled_secret_are_scrubbed(self):
        result = Redactor("secrets", known_secrets=("unlabelled-value",)).string('unlabelled-value password="hidden token=also hidden\nnormal line')
        self.assertNotIn("hidden", result)
        self.assertNotIn("unlabelled-value", result)
        self.assertTrue(result.endswith("\nnormal line"))


class BaselineBoundReviewTests(V2Fixture):
    def installer(self):
        self.args = argparse.Namespace(prefix=str(self.root / "prefix"), state_dir=str(self.store.directory),
                                       build_only=None, skip_deps=True, rathole=None, rathole_sha256=None)
        self.inventory = {"package-" + str(i): "1.0" for i in range(1100)}
        with patch.object(packaging, "installed_packages", return_value=self.inventory):
            return packaging.installer_baseline(self.args, Path(self.args.prefix), None)

    def test_installer_inventory_survives_setup_status_and_upgrade_reads(self):
        baseline = self.installer()
        self.assertEqual(self.store.baseline(), baseline)
        self.assertEqual(self.stage()["installation_id"], baseline["installation_id"])
        with patch.object(packaging, "installed_packages", side_effect=AssertionError("preserve original baseline")):
            self.assertEqual(packaging.installer_baseline(self.args, Path(self.args.prefix), None), baseline)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.main(["--state-dir", str(self.store.directory), "--json", "system", "changes"])
        self.assertEqual(code, 0, out.getvalue())
        self.assertEqual(self.store.baseline()["packages_before"], self.inventory)

    def test_install_operation_snapshots_use_the_same_large_inventory_limits(self):
        self.installer()
        def dependencies(skip):
            self.assertEqual(self.store.baseline()["operations"][-1]["packages_before"], self.inventory)
            return []
        with patch.object(packaging.os, "geteuid", return_value=0), patch.object(packaging, "installed_packages", return_value=self.inventory), patch.object(packaging, "distro_dependencies", side_effect=dependencies), patch.object(packaging, "build", side_effect=lambda path: atomic_write(path, "owned runtime", 0o755)), contextlib.redirect_stdout(io.StringIO()):
            packaging.install(self.args)
        self.assertEqual(self.store.baseline()["operations"][-1]["status"], "complete")
        self.assertEqual(self.store.baseline()["packages_before"], self.inventory)

    def test_dependency_cleanup_preserves_large_original_inventory(self):
        baseline = self.installer()
        baseline["package_delta"] = {"nftables": "new-version"}
        packaging.write_baseline(self.store.directory / "baseline.json", baseline)
        def run(argv, **kwargs):
            out = ""
            if argv[0] == "dpkg-query":
                out = "nftables\tnew-version\tinstalled\n" if "${Version}" in argv[-1] else "python3\tinstalled\n"
            elif "--simulate" in argv:
                out = "Remv nftables\n"
            return {"returncode": 0, "stdout": out}
        runtime = MagicMock()
        runtime.host.run.side_effect = run
        self.assertEqual(restore_packages(self.store, runtime), [])
        saved = self.store.baseline()
        self.assertEqual(saved["packages_before"], self.inventory)
        self.assertEqual(saved["package_delta"], {})
        self.assertEqual(saved["operations"][-1]["status"], "complete")
        self.assertIn(["apt-get", "remove", "--no-auto-remove", "-y", "nftables"], [c.args[0] for c in runtime.host.run.call_args_list])

    def test_large_baseline_uninstall_checkpoint_can_resume(self):
        baseline = self.installer()
        self.store.write(empty_v2(baseline["installation_id"]))
        prefix = Path(self.args.prefix)
        launcher, binary = prefix / "bin/twinlink", prefix / "libexec/twinlink-runtime"
        for path in (launcher, binary):
            atomic_write(path, "owned program", 0o755)
        atomic_write(binary.parent / "twinlink-install.json", canonical({"owner": "twinlink", "version": 1,
            "files": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (launcher, binary)}}))
        runtime = MagicMock(executable=str(binary))
        original = Path.unlink
        def interrupted(path, *args, **kwargs):
            if path == binary:
                raise OSError("simulated program removal failure")
            return original(path, *args, **kwargs)
        with patch.object(Path, "unlink", interrupted), self.assertRaises(OSError):
            remove_program(self.store, runtime)
        self.assertTrue(binary.exists())
        self.assertTrue((self.store.directory / "uninstall.json").exists())
        self.assertEqual(remove_program(self.store, runtime)["status"], "complete")
        self.assertFalse(prefix.exists())
        self.assertFalse(self.store.directory.exists())

    def test_baseline_writer_and_reader_reject_excessive_size_or_count(self):
        for value in ({"packages_before": {str(i): "1" for i in range(MAX_BASELINE_ITEMS + 1)}},
                      {"data": "x" * MAX_BASELINE_BYTES}):
            with self.subTest(kind=next(iter(value))), self.assertRaises(ValidationError):
                serialize(value)
            with self.assertRaises(ValidationError):
                parse(json.dumps(value))

    def test_oversized_initial_inventory_fails_before_bootstrap_creation(self):
        args = argparse.Namespace(state_dir=str(self.store.directory))
        with patch.object(packaging, "installed_packages", return_value={"pkg": "x" * MAX_BASELINE_BYTES}), self.assertRaises(ValidationError):
            packaging.installer_baseline(args, self.root / "prefix", None)
        self.assertEqual(list(self.root.iterdir()), [])


@unittest.skipUnless(hasattr(os, "killpg"), "POSIX process groups required")
class DescendantReviewTests(V2Fixture):
    def command(self, mode="timeout"):
        self.pids = self.root / "pids.json"
        self.heartbeat = self.root / "heartbeat"
        child = "import os,sys,time; f=open(sys.argv[1],'a',buffering=1); f.write('ready\\n'); "
        if mode == "overflow":
            child += "time.sleep(0.2)\ntry: os.write(1,b'x'*200000)\nexcept BrokenPipeError: pass\n"
        if mode == "complete":
            child += "os.close(1);os.close(2); "
        child += "\nwhile True: f.write('running\\n');time.sleep(0.01)"
        script = "import os,sys,json,subprocess; p=subprocess.Popen([sys.executable,'-c',sys.argv[2],sys.argv[3]]); "
        script += "open(sys.argv[1],'w').write(json.dumps([os.getpid(),p.pid])); print('parent complete',flush=True)"
        self.addCleanup(self.cleanup_group)
        return [sys.executable, "-c", script, str(self.pids), child, str(self.heartbeat)]

    def cleanup_group(self):
        if self.pids.exists():
            group, _ = json.loads(self.pids.read_text())
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def assert_descendant_stopped(self):
        # A heartbeat works without /proc or sandbox-restricted ps, and does
        # not mistake an unreaped orphan zombie for a running process.
        time.sleep(0.05)
        before = self.heartbeat.stat().st_size if self.heartbeat.exists() else 0
        time.sleep(0.2)
        after = self.heartbeat.stat().st_size if self.heartbeat.exists() else 0
        self.assertEqual(after, before, "Command descendant is still running")

    def test_timeout_kills_descendant_after_parent_exit(self):
        result = bounded_command(self.command(), timeout=0.7)
        self.assertEqual(result["error"], "TimeoutError")
        self.assertIn("parent complete", result["stdout"])
        self.assert_descendant_stopped()

    def test_output_limit_kills_descendant_after_parent_exit(self):
        result = bounded_command(self.command("overflow"), timeout=3, output_limit=1024)
        self.assertEqual(result["error"], "OverflowError")
        self.assertTrue(result["truncated"])
        self.assert_descendant_stopped()

    def test_interrupt_kills_descendant_after_parent_exit(self):
        argv = self.command()
        original_popen = subprocess.Popen
        children = []
        def popen(*args, **kwargs):
            child = original_popen(*args, **kwargs)
            children.append(child)
            return child
        import selectors
        selector = selectors.DefaultSelector()
        original_select = selector.select
        def select(timeout):
            if children[0].poll() is not None:
                raise KeyboardInterrupt()
            return original_select(timeout)
        with patch("twinlink.diagnostics.subprocess.Popen", side_effect=popen), patch("twinlink.diagnostics.selectors.DefaultSelector", return_value=selector), patch.object(selector, "select", side_effect=select), self.assertRaises(KeyboardInterrupt):
            bounded_command(argv)
        self.assertIsNotNone(children[0].returncode)
        self.assert_descendant_stopped()

    def test_successful_command_also_leaves_no_background_descendants(self):
        result = bounded_command(self.command("complete"))
        self.assertEqual(result["returncode"], 0)
        self.assertIsNone(result["error"])
        self.assert_descendant_stopped()
