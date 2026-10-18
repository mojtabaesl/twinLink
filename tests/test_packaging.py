import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


spec = importlib.util.spec_from_file_location("twinlink_packaging", Path(__file__).resolve().parents[1] / "scripts/package.py")
packaging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaging)


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="twinlink-packaging-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()

    def installed(self, records=False):
        prefix = self.root / "prefix"
        launcher, runtime, manifest_path = packaging.manifest_paths(prefix)
        launcher.parent.mkdir(parents=True)
        runtime.parent.mkdir(parents=True)
        launcher.write_text(packaging.LAUNCHER_MARKER)
        runtime.write_text("test runtime")
        manifest_path.write_text(json.dumps({"owner": "twinlink", "version": 1,
            "files": {str(path): packaging.sha256(path) for path in (launcher, runtime)}}))
        state_dir = self.root / "state"
        state_dir.mkdir(mode=0o700)
        state_path = state_dir / "state.json"
        state_path.write_text(json.dumps({"version": 1, "tunnels": {"edge": {}} if records else {}, "forwards": {}}))
        state_path.chmod(0o600)
        args = argparse.Namespace(prefix=str(prefix), state_dir=str(state_dir), unit_dir=str(self.root / "units"),
                                  purge_managed=False, cascade=False, yes=False)
        return launcher, runtime, manifest_path, args

    def test_zipapp_contains_application_not_workspace_secrets(self):
        output = self.root / "app.pyz"
        packaging.build(output)
        with zipfile.ZipFile(output) as archive:
            names = archive.namelist()
            self.assertIn("twinlink/cli.py", names)
            self.assertIn("__main__.py", names)
            self.assertFalse(any("__pycache__" in name or "state.json" in name for name in names))

    def test_zipapp_preserves_scriptable_success_and_failure_exit_codes(self):
        output = self.root / "app.pyz"
        packaging.build(output)
        success = subprocess.run([sys.executable, str(output), "--version"], text=True, capture_output=True)
        self.assertEqual(success.returncode, 0)
        missing = subprocess.run([sys.executable, str(output), "--state-dir", str(self.root / "empty-state"),
                                  "--json", "tunnel", "show", "missing"], text=True, capture_output=True)
        self.assertEqual(missing.returncode, 1)
        self.assertIn("Unknown tunnel", json.loads(missing.stdout)["error"])

    def test_foreign_and_modified_installations_are_not_overwritten(self):
        prefix = self.root / "foreign"
        (prefix / "bin").mkdir(parents=True)
        (prefix / "bin/twinlink").write_text("foreign executable")
        with self.assertRaisesRegex(RuntimeError, "ownership manifest"):
            packaging.read_manifest(prefix)
        launcher, runtime, manifest, args = self.installed()
        runtime.write_text("modified")
        with self.assertRaisesRegex(RuntimeError, "modified"):
            packaging.read_manifest(Path(args.prefix))

    def test_program_only_keeps_runtime_when_managed_records_exist(self):
        launcher, runtime, manifest, args = self.installed(records=True)
        with mock.patch.object(packaging.os, "geteuid", return_value=0), contextlib.redirect_stdout(io.StringIO()):
            packaging.uninstall(args)
        self.assertFalse(launcher.exists())
        self.assertTrue(runtime.exists())
        self.assertTrue(manifest.exists())
        self.assertTrue((Path(args.state_dir) / "state.json").exists())

    def test_owned_unit_retains_runtime_even_if_state_empty(self):
        launcher, runtime, manifest, args = self.installed()
        units = Path(args.unit_dir)
        units.mkdir()
        (units / "twinlink-restore.service").write_text("# twinlink-owned\n[Service]\n")
        with mock.patch.object(packaging.os, "geteuid", return_value=0), contextlib.redirect_stdout(io.StringIO()):
            packaging.uninstall(args)
        self.assertFalse(launcher.exists())
        self.assertTrue(runtime.exists())

    def test_empty_install_removes_only_program_and_retains_state(self):
        launcher, runtime, manifest, args = self.installed()
        with mock.patch.object(packaging.os, "geteuid", return_value=0), contextlib.redirect_stdout(io.StringIO()):
            packaging.uninstall(args)
        self.assertFalse(any(path.exists() for path in (launcher, runtime, manifest)))
        self.assertTrue((Path(args.state_dir) / "state.json").exists())

    def test_pending_journal_or_failed_purge_preserves_program(self):
        launcher, runtime, manifest, args = self.installed(records=True)
        journal = Path(args.state_dir) / "transaction.json"
        journal.write_text("{}")
        with mock.patch.object(packaging.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "unfinished transaction"):
                packaging.uninstall(args)
            journal.unlink()
            args.purge_managed = args.cascade = args.yes = True
            with mock.patch.object(packaging, "run", side_effect=subprocess.CalledProcessError(1, ["runtime"])):
                with self.assertRaises(subprocess.CalledProcessError):
                    packaging.uninstall(args)
        self.assertTrue(all(path.exists() for path in (launcher, runtime, manifest)))

    def test_baseline_precedes_program_directories_and_is_preserved(self):
        prefix = self.root / "prefix"
        args = argparse.Namespace(state_dir=str(self.root / "state"))
        with mock.patch.object(packaging, "installed_packages", return_value={"python3": "existing"}):
            baseline = packaging.installer_baseline(args, prefix, None)
        self.assertFalse((prefix / "bin").exists())
        self.assertEqual(baseline["packages_before"], {"python3": "existing"})
        self.assertFalse(baseline["directories"][args.state_dir]["existed"])
        with mock.patch.object(packaging, "installed_packages", side_effect=AssertionError("must not recapture")):
            self.assertEqual(packaging.installer_baseline(args, prefix, None), baseline)
        self.assertEqual((Path(args.state_dir) / "baseline.json").stat().st_mode & 0o777, 0o600)

    def test_apt_new_install_architecture_is_not_an_upgrade(self):
        for output, blocked in (
            ("Inst conntrack (1.4.8 Ubuntu:24.04/noble [amd64])\n", False),
            ("Inst libnetfilter-conntrack3 [1.0.9-1] (1.0.9-2 Ubuntu [amd64])\n", True),
            ("Remv foreign-package [1.0]\n", True),
            ("Purg foreign-package [1.0]\n", True),
        ):
            with self.subTest(output=output), \
                 mock.patch.object(packaging.sys, "platform", "linux"), \
                 mock.patch.object(Path, "is_dir", return_value=True), \
                 mock.patch.object(Path, "read_text", return_value='ID="ubuntu"\n'), \
                 mock.patch.object(packaging, "installed_packages", return_value={}), \
                 mock.patch.object(packaging.shutil, "which", return_value="/usr/bin/tool"), \
                 mock.patch.object(packaging, "run") as run, \
                 mock.patch.object(packaging.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")):
                if blocked:
                    with self.assertRaisesRegex(RuntimeError, "--resume --skip-deps"):
                        packaging.distro_dependencies()
                    self.assertEqual(run.call_count, 1)  # Only apt update; no package changes.
                else:
                    packaging.distro_dependencies()
                    self.assertEqual(run.call_count, 2)

    def test_resume_preserves_snapshot_and_completes_installation(self):
        args = argparse.Namespace(prefix=str(self.root / "prefix"), state_dir=str(self.root / "state"),
                                  build_only=None, rathole=None, rathole_sha256=None,
                                  skip_deps=True, resume=False)
        with mock.patch.object(packaging, "installed_packages", return_value={"original": "1"}):
            baseline = packaging.installer_baseline(args, Path(args.prefix), None)
        baseline["operations"].append({"operation": "install", "status": "pending",
                                       "packages_before": {"original": "1"}})
        baseline_path = Path(args.state_dir) / "baseline.json"
        packaging.write_baseline(baseline_path, baseline)
        original = baseline_path.read_bytes()
        def build(path):
            packaging.write_owned(path, "test runtime", 0o755)
        with mock.patch.object(packaging.os, "geteuid", return_value=0), \
             mock.patch.object(packaging, "installed_packages", return_value={"original": "1", "uncertain": "2"}), \
             mock.patch.object(packaging, "distro_dependencies", return_value=[]), \
             mock.patch.object(packaging, "build", side_effect=build), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "--resume"):
                packaging.install(args)
            self.assertEqual(baseline_path.read_bytes(), original)
            args.resume = True
            packaging.install(args)
        result = packaging.parse_baseline(baseline_path.read_bytes())
        self.assertEqual(result["packages_before"], {"original": "1"})
        self.assertEqual(result["package_delta"], {})
        self.assertEqual(result["operations"][0]["packages_before"], {"original": "1"})
        self.assertEqual([op["status"] for op in result["operations"]], ["interrupted", "complete"])
        backup, = Path(args.state_dir).parent.glob(".twinlink-baseline-*.backup-*.json")
        self.assertEqual(backup.read_bytes(), original)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertTrue(packaging.manifest_paths(Path(args.prefix))[0].exists())
        from twinlink.store import Store
        from twinlink.contracts import empty_v2
        from twinlink.cleanup import remove_program
        from types import SimpleNamespace
        store = Store(args.state_dir)
        store.write(empty_v2())
        runtime = packaging.manifest_paths(Path(args.prefix))[1]
        self.assertEqual(remove_program(store, SimpleNamespace(executable=str(runtime)))["status"], "complete")
        self.assertFalse(runtime.exists())
        self.assertTrue(backup.exists())

    def test_resume_partial_program_publication_and_reject_foreign_edits(self):
        for stop_after in ("twinlink-runtime", "twinlink", "twinlink-install.json"):
            for modified in (False, True):
                with self.subTest(stop_after=stop_after, modified=modified):
                    root = self.root / (stop_after + str(modified))
                    root.mkdir()
                    args = argparse.Namespace(prefix=str(root / "prefix"), state_dir=str(root / "state"),
                                              build_only=None, rathole=None, rathole_sha256=None,
                                              skip_deps=True, resume=False)
                    replace = packaging.os.replace
                    def interrupted_replace(source, target):
                        replace(source, target)
                        if Path(target).name == stop_after:
                            raise KeyboardInterrupt()
                    with mock.patch.object(packaging.os, "geteuid", return_value=0), \
                         mock.patch.object(packaging, "installed_packages", return_value={}), \
                         mock.patch.object(packaging, "distro_dependencies", return_value=[]), \
                         mock.patch.object(packaging, "build", side_effect=lambda path: packaging.write_owned(path, "runtime", 0o755)), \
                         contextlib.redirect_stdout(io.StringIO()):
                        with mock.patch.object(packaging.os, "replace", side_effect=interrupted_replace):
                            with self.assertRaises(KeyboardInterrupt):
                                packaging.install(args)
                        runtime = packaging.manifest_paths(Path(args.prefix))[1]
                        if modified:
                            runtime.write_text("foreign modification")
                        args.resume = True
                        if modified:
                            with self.assertRaisesRegex(RuntimeError, "differs"):
                                packaging.install(args)
                            self.assertEqual(runtime.read_text(), "foreign modification")
                        else:
                            # A second dependency failure must not lose proof for the
                            # already-published files from the first attempt.
                            with mock.patch.object(packaging, "distro_dependencies", side_effect=RuntimeError("dependency failure")):
                                with self.assertRaisesRegex(RuntimeError, "dependency failure"):
                                    packaging.install(args)
                            packaging.install(args)
                            self.assertIsNotNone(packaging.read_manifest(Path(args.prefix)))
                            baseline = packaging.parse_baseline((Path(args.state_dir) / "baseline.json").read_bytes())
                            self.assertEqual(baseline["operations"][-1]["status"], "complete")

    def test_resume_checkpoint_keeps_proof_before_and_after_atomic_replace(self):
        for after_replace in (False, True):
            with self.subTest(after_replace=after_replace):
                root = self.root / str(after_replace)
                root.mkdir()
                args = argparse.Namespace(prefix=str(root / "prefix"), state_dir=str(root / "state"),
                                          build_only=None, rathole=None, rathole_sha256=None,
                                          skip_deps=True, resume=False)
                baseline_path = Path(args.state_dir) / "baseline.json"
                runtime = packaging.manifest_paths(Path(args.prefix))[1]
                replace = packaging.os.replace
                def stop_publication(source, target):
                    replace(source, target)
                    if Path(target) == runtime:
                        raise KeyboardInterrupt()
                def stop_checkpoint(source, target):
                    if Path(target) == baseline_path:
                        if after_replace:
                            replace(source, target)
                        raise KeyboardInterrupt()
                    replace(source, target)
                with mock.patch.object(packaging.os, "geteuid", return_value=0), \
                     mock.patch.object(packaging, "installed_packages", return_value={"original": "1"}), \
                     mock.patch.object(packaging, "distro_dependencies", return_value=[]), \
                     mock.patch.object(packaging, "build", side_effect=lambda path: packaging.write_owned(path, "runtime", 0o755)), \
                     contextlib.redirect_stdout(io.StringIO()):
                    with mock.patch.object(packaging.os, "replace", side_effect=stop_publication), self.assertRaises(KeyboardInterrupt):
                        packaging.install(args)
                    original = packaging.parse_baseline(baseline_path.read_bytes())
                    proof = original["operations"][-1]["program_writes"]
                    args.resume = True
                    with mock.patch.object(packaging.os, "replace", side_effect=stop_checkpoint), self.assertRaises(KeyboardInterrupt):
                        packaging.install(args)
                    checkpoint = packaging.parse_baseline(baseline_path.read_bytes())
                    pending = [op for op in checkpoint["operations"] if op["status"] == "pending"]
                    self.assertEqual(len(pending), 1)
                    self.assertEqual(pending[0]["program_writes"], proof)
                    self.assertEqual(checkpoint["packages_before"], original["packages_before"])
                    self.assertEqual(len(checkpoint["operations"]), 2 if after_replace else 1)
                    packaging.install(args)
                    self.assertIsNotNone(packaging.read_manifest(Path(args.prefix)))
                    final = packaging.parse_baseline(baseline_path.read_bytes())
                    self.assertEqual(final["operations"][-1]["status"], "complete")

    def test_resume_does_not_adopt_unproven_partial_runtime(self):
        args = argparse.Namespace(prefix=str(self.root / "prefix"), state_dir=str(self.root / "state"),
                                  build_only=None, rathole=None, rathole_sha256=None,
                                  skip_deps=True, resume=True)
        with mock.patch.object(packaging, "installed_packages", return_value={}):
            baseline = packaging.installer_baseline(args, Path(args.prefix), None)
        baseline["operations"].append({"operation": "install", "status": "pending"})
        packaging.write_baseline(Path(args.state_dir) / "baseline.json", baseline)
        runtime = packaging.manifest_paths(Path(args.prefix))[1]
        runtime.parent.mkdir(parents=True)
        runtime.write_text("unproven runtime")
        with mock.patch.object(packaging.os, "geteuid", return_value=0), self.assertRaisesRegex(RuntimeError, "no durable ownership proof"):
            packaging.install(args)
        self.assertEqual(runtime.read_text(), "unproven runtime")

    def test_resume_refuses_pending_package_restoration(self):
        args = argparse.Namespace(prefix=str(self.root / "prefix"), state_dir=str(self.root / "state"),
                                  build_only=None, rathole=None, rathole_sha256=None,
                                  skip_deps=True, resume=True)
        with mock.patch.object(packaging, "installed_packages", return_value={}):
            baseline = packaging.installer_baseline(args, Path(args.prefix), None)
        baseline["operations"].append({"operation": "restore-packages", "status": "pending"})
        path = Path(args.state_dir) / "baseline.json"
        packaging.write_baseline(path, baseline)
        original = path.read_bytes()
        with mock.patch.object(packaging.os, "geteuid", return_value=0), self.assertRaisesRegex(RuntimeError, "non-install"):
            packaging.install(args)
        self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
