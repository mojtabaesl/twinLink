"""Preserve legacy installer snapshots without trusting them as cleanup proof."""
import argparse
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_packaging as packaging_tests
from twinlink import cli
from twinlink.baseline_backups import plan, preserve
from twinlink.cleanup import remove_program
from twinlink.contracts import empty_v2
from twinlink.models import ValidationError
from twinlink.store import Store, StateError, atomic_write


class BaselineBackupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.store = Store(self.root / "state")
        self.prefix = self.root / "prefix"
        self.packaging = packaging_tests.packaging
        args = argparse.Namespace(state_dir=str(self.store.directory))
        with patch.object(self.packaging, "installed_packages", return_value={"pre-existing": "1"}):
            self.baseline = self.packaging.installer_baseline(args, self.prefix, None)
        self.store.write(empty_v2(self.baseline["installation_id"]))
        self.launcher, self.binary, self.manifest = self.packaging.manifest_paths(self.prefix)
        for path in (self.launcher, self.binary):
            atomic_write(path, "owned program", 0o755)
        atomic_write(self.manifest, json.dumps({"owner": "twinlink", "version": 1,
            "files": {str(path): self.packaging.sha256(path) for path in (self.launcher, self.binary)}}), 0o644)
        self.runtime = SimpleNamespace(executable=str(self.binary))
        self.backup = self.store.directory / "baseline.json.backup-1792311731993531669"
        snapshot = copy.deepcopy(self.baseline)
        snapshot["operations"] = [{"operation": "install", "status": "pending", "time": 1792269073.5432656,
                                   "packages_before": {"pre-existing": "1"}}]
        self.original = (json.dumps(snapshot, indent=2) + "\n").encode()
        atomic_write(self.backup, self.original, 0o600)

    def run_cli(self, *arguments):
        host = SimpleNamespace(require_linux_root=lambda: None,
            run=lambda *args, **kwargs: {"returncode": 0, "stdout": "", "stderr": ""})
        with patch.object(cli, "Host", return_value=host), contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(["--state-dir", str(self.store.directory), "--runtime-path", str(self.binary),
                             "--unit-dir", str(self.root / "units"), *arguments])
        return code, json.loads(output.getvalue())

    def preserve(self):
        with self.store.lock():
            return preserve(self.store)

    def test_observed_legacy_path_preview_preservation_and_full_removal(self):
        before = self.backup.read_bytes()
        code, preview = self.run_cli("system", "preserve-backups")
        self.assertEqual(code, 0)
        destination = Path(preview["baseline_backups"][0]["destination"])
        self.assertEqual(destination.parent, self.store.directory.parent)
        self.assertRegex(destination.name, r"^\.twinlink-baseline-[0-9a-f]{16}\.backup-1792311731993531669\.json$")
        self.assertFalse(destination.exists())
        self.assertEqual(self.backup.read_bytes(), before)
        code, preview = self.run_cli("uninstall", "--plan")
        self.assertEqual(preview["pairs"], [])
        self.assertEqual(preview["requires_off"], [])
        self.assertEqual(preview["legacy_baseline_backups"], [str(self.backup)])
        with self.assertRaisesRegex(StateError, "system preserve-backups"):
            remove_program(self.store, self.runtime)
        code, result = self.run_cli("system", "preserve-backups", "--apply", "--yes")
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "complete")
        self.assertFalse(self.backup.exists())
        self.assertEqual(destination.read_bytes(), self.original)
        self.assertEqual(destination.stat().st_mode & 0o7777, 0o600)
        self.assertEqual(destination.stat().st_uid, os.geteuid())
        code, result = self.run_cli("uninstall", "--purge", "--apply", "--yes")
        self.assertEqual(code, 0, result)
        self.assertEqual(result["status"], "complete")
        self.assertFalse(self.store.directory.exists())
        self.assertFalse(self.binary.exists())
        self.assertEqual(destination.read_bytes(), self.original)
        self.assertEqual(plan(self.store), [])

    def test_malformed_unrelated_or_modified_original_facts_are_rejected(self):
        malformed = [b"not JSON", b"{}", b'[]', b'{"version":1,"version":1}']
        for field, value in (("installation_id", "00000000-0000-0000-0000-000000000000"),
                             ("packages_before", {"different": "2"}), ("operations", None),
                             ("operations", [{"operation": "other", "status": "pending"}]),
                             ("package_delta", [])):
            snapshot = json.loads(self.original)
            snapshot[field] = value
            malformed.append(json.dumps(snapshot).encode())
        for data in malformed:
            with self.subTest(data=data[:100]):
                atomic_write(self.backup, data, 0o600)
                with self.assertRaises((ValidationError, StateError)):
                    self.preserve()
                self.assertEqual(self.backup.read_bytes(), data)
                self.assertFalse(list(self.root.glob(".twinlink-baseline-*.json")))
                self.assertTrue(self.binary.exists())

    def test_invalid_name_permissions_owner_and_oversize_rejected(self):
        for name in ("baseline.json.backup-not-a-timestamp", "baseline.json.backup-1792311731993531669.extra"):
            other = self.backup.with_name(name)
            self.backup.rename(other)
            with self.assertRaisesRegex(StateError, "filename"):
                self.preserve()
            other.rename(self.backup)
        for mode in (0o644, 0o400, 0o660, 0o700):
            self.backup.chmod(mode)
            with self.subTest(mode=mode), self.assertRaisesRegex(StateError, "mode-0600"):
                self.preserve()
        self.backup.chmod(0o600)
        with patch("twinlink.baseline_backups.os.geteuid", return_value=os.geteuid() + 1), self.assertRaisesRegex(StateError, "owned"):
            self.preserve()
        with patch("twinlink.baseline_backups.MAX_BASELINE_BYTES", 16), self.assertRaisesRegex(StateError, "size limit"):
            self.preserve()
        self.assertEqual(self.backup.read_bytes(), self.original)

    def test_source_and_destination_symlinks_are_preserved_and_rejected(self):
        destination = Path(plan(self.store)[0]["destination"])
        external = self.root / "external"
        atomic_write(external, self.original)
        self.backup.unlink()
        self.backup.symlink_to(external)
        with self.assertRaises(StateError):
            self.preserve()
        self.assertTrue(self.backup.is_symlink())
        self.backup.unlink()
        atomic_write(self.backup, self.original)
        destination.symlink_to(external)
        with self.assertRaises(StateError):
            self.preserve()
        self.assertTrue(destination.is_symlink())
        self.assertEqual(external.read_bytes(), self.original)
        self.assertEqual(self.backup.read_bytes(), self.original)

    def test_interrupted_after_publication_resumes_without_overwrite(self):
        destination = Path(plan(self.store)[0]["destination"])
        original_unlink = Path.unlink
        def interrupt(path, *args, **kwargs):
            if path == self.backup:
                raise KeyboardInterrupt()
            return original_unlink(path, *args, **kwargs)
        with patch.object(Path, "unlink", interrupt), self.assertRaises(KeyboardInterrupt):
            self.preserve()
        self.assertEqual(self.backup.read_bytes(), self.original)
        self.assertEqual(destination.read_bytes(), self.original)
        identity = destination.stat().st_ino
        self.preserve()
        self.assertFalse(self.backup.exists())
        self.assertEqual(destination.stat().st_ino, identity)
        self.assertEqual(self.preserve()["preserved_baseline_backups"], [])

    def test_modified_existing_destination_never_overwritten(self):
        destination = Path(plan(self.store)[0]["destination"])
        atomic_write(destination, "different original backup")
        with self.assertRaisesRegex(StateError, "Modified/different"):
            self.preserve()
        self.assertEqual(destination.read_text(), "different original backup")
        self.assertEqual(self.backup.read_bytes(), self.original)

    def test_source_modified_after_planning_is_retained(self):
        original_plan = plan
        changed = self.original + b" \n"
        def changed_plan(store):
            result = original_plan(store)
            atomic_write(self.backup, changed)
            return result
        with patch("twinlink.baseline_backups.plan", side_effect=changed_plan), self.assertRaisesRegex(StateError, "changed after validation"):
            self.preserve()
        self.assertEqual(self.backup.read_bytes(), changed)
        self.assertFalse(list(self.root.glob(".twinlink-baseline-*.json")))

    def test_large_installer_package_snapshot_uses_baseline_limits(self):
        baseline = copy.deepcopy(self.baseline)
        baseline["packages_before"] = {"original-package-" + str(index): "1.0-version-before-installation" for index in range(1100)}
        self.packaging.write_baseline(self.store.directory / "baseline.json", baseline)
        content = (json.dumps(baseline, indent=2) + "\n").encode()
        self.assertGreater(len(content), 65536)
        atomic_write(self.backup, content)
        result = self.preserve()
        self.assertEqual(Path(result["preserved_baseline_backups"][0]["destination"]).read_bytes(), content)

    def test_normalized_state_path_keeps_destination_outside_actual_state(self):
        child = self.store.directory / "child"
        child.mkdir()
        alternate = Store(child / "..")
        row, = plan(alternate)
        self.assertEqual(Path(row["destination"]).parent, self.root)
        with alternate.lock():
            preserve(alternate)
        self.assertFalse(self.backup.exists())
        self.assertEqual(Path(row["destination"]).read_bytes(), self.original)

    def test_unknown_artifacts_and_modified_program_still_block_removal(self):
        self.preserve()
        unknown = self.store.directory / "unrelated.json"
        atomic_write(unknown, "{}")
        with self.assertRaisesRegex(StateError, "Unresolved private artifact"):
            remove_program(self.store, self.runtime)
        self.assertTrue(unknown.exists())
        unknown.unlink()
        self.binary.write_text("modified program")
        with self.assertRaisesRegex(StateError, "Modified program"):
            remove_program(self.store, self.runtime)
        self.assertEqual(self.binary.read_text(), "modified program")
