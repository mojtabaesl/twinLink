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


if __name__ == "__main__":
    unittest.main()
