"""Pinned Paqet installation, CLI dispatch and conditional binary restoration."""
import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from twinlink import cli, paqet
from twinlink.cleanup import restore_system
from twinlink.contracts import empty_v2
from twinlink.models import ValidationError
from twinlink.ownership import Ownership
from twinlink.profile_runtime import ProfileRuntime
from twinlink.store import StateError, Store, atomic_write
from tests.test_profile_runtime import SystemHost


class PaqetInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.binary = self.root / "bin" / "paqet"
        self.binary.parent.mkdir()
        self.store = Store(self.root / "state")
        self.host = SystemHost(self.root / "units")
        self.runtime = ProfileRuntime(self.store, self.host, str(self.host.unit_dir))
        self.payload = b"fixture-pinned-paqet-executable"

    def archive(self, members=None):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as package:
            for name, data, kind in members or [("paqet_linux_amd64", self.payload, tarfile.REGTYPE),
                                               ("README.md", b"upstream readme", tarfile.REGTYPE)]:
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.size = len(data) if kind == tarfile.REGTYPE else 0
                entry.linkname = "/foreign" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
                package.addfile(entry, io.BytesIO(data) if entry.isfile() else None)
        return output.getvalue()

    def response(self, archive):
        response = io.BytesIO(archive)
        response.geturl = lambda: "https://release-assets.githubusercontent.com/fixture"
        return response

    def native(self, argv, **kwargs):
        self.assertEqual(argv[1:], ["version"])
        self.assertEqual(kwargs["timeout"], 3)
        return subprocess.CompletedProcess(argv, 0, "Version:    " + paqet.VERSION + "\nGit Commit: " + paqet.COMMIT + "\n", "")

    @contextlib.contextmanager
    def installer(self, archive=None):
        archive = self.archive() if archive is None else archive
        pins = {"amd64": {"archive_sha256": hashlib.sha256(archive).hexdigest(),
                          "binary_sha256": hashlib.sha256(self.payload).hexdigest()}}
        with patch.object(paqet.platform, "machine", return_value="x86_64"), patch.object(paqet, "INSTALL_RELEASES", pins), patch.object(paqet.urllib.request, "urlopen", side_effect=lambda *a, **k: self.response(archive)) as download, patch.object(paqet.subprocess, "run", side_effect=self.native) as native:
            yield download, native

    def install(self):
        with self.store.lock():
            return paqet.install(str(self.binary), self.store)

    @contextlib.contextmanager
    def binary_permissions(self, mode):
        # Some development sandboxes strip setuid bits. Inject the observed
        # mode while keeping actual fixture files ordinary executables.
        self.binary.chmod(mode & 0o777)
        stat = Path.stat
        def observed(path, *args, **kwargs):
            value = stat(path, *args, **kwargs)
            if path == self.binary:
                fields = list(value)
                fields[0] = (value.st_mode & ~0o7777) | mode
                return os.stat_result(fields)
            return value
        with patch.object(Path, "stat", observed):
            yield

    def run_cli(self, *args):
        with patch.object(cli, "Host", return_value=self.host), contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.main(["--state-dir", str(self.store.directory), "--paqet-binary", str(self.binary), "paqet", "install", "--json", *args])
        return code, json.loads(out.getvalue())

    def test_cli_concise_default_and_opt_in_installation_details(self):
        base = ["--state-dir", str(self.store.directory), "--paqet-binary", str(self.binary)]
        with self.installer() as (download, _), patch.object(cli, "Host", return_value=self.host):
            for flags, expected in (([], "preview"), (["--apply", "--yes"], "completed"),
                                    (["--apply", "--yes"], "already installed")):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(cli.main(base + ["paqet", "install", *flags]), 0)
                self.assertIn("Paqet installation: " + expected, out.getvalue())
                self.assertIn(str(self.binary), out.getvalue())
                self.assertNotIn("archive_sha256", out.getvalue())
                self.assertNotIn("https://", out.getvalue())
            self.assertEqual(download.call_count, 1)
            for flags in (["--verbose", "paqet", "install"], ["paqet", "install", "--verbose"],
                          ["paqet", "install", "--json"]):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(cli.main(base + flags), 0)
                result = json.loads(out.getvalue())
                self.assertEqual(result["schema_version"], 2)
                self.assertIn("archive_sha256", result)
                self.assertIn("binary_sha256", result)
                self.assertIn("url", result)

    def test_cli_default_error_is_concise_and_verbose_error_is_structured(self):
        base = ["--state-dir", str(self.store.directory), "--paqet-binary", str(self.binary), "paqet", "install"]
        with self.installer(), patch.object(cli, "Host", return_value=self.host), \
             patch.object(paqet, "install_plan", side_effect=ValidationError("Unsupported architecture")):
            with contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(cli.main(base), 2)
            self.assertIn("Unsupported architecture", err.getvalue())
            self.assertEqual(out.getvalue(), "")
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(cli.main(base + ["--verbose"]), 2)
            self.assertEqual(json.loads(err.getvalue())["status"], "invalid")

    def test_official_architecture_aliases_and_preview_are_read_only(self):
        pins = paqet.INSTALL_RELEASES
        for machine, architecture in (("x86_64", "amd64"), ("amd64", "amd64"), ("aarch64", "arm64"), ("arm64", "arm64")):
            with self.subTest(machine=machine), patch.object(paqet.platform, "machine", return_value=machine), patch.object(paqet.urllib.request, "urlopen") as download, patch.object(paqet.subprocess, "run") as native:
                code, result = self.run_cli()
                self.assertEqual(code, 0)
                self.assertEqual(result["status"], "preview")
                self.assertEqual(result["archive_sha256"], pins[architecture]["archive_sha256"])
                self.assertTrue(result["url"].endswith(f"paqet-linux-{architecture}-{paqet.VERSION}.tar.gz"))
                download.assert_not_called()
                native.assert_not_called()
                self.assertFalse(self.store.directory.exists())
                self.assertFalse(self.binary.exists())

    def test_install_pins_both_checksums_and_records_conditional_removal(self):
        with self.installer() as (download, native):
            result = self.install()
        self.assertTrue(result["installed"])
        self.assertEqual(self.binary.read_bytes(), self.payload)
        self.assertEqual(self.binary.stat().st_mode & 0o7777, 0o755)
        self.assertEqual([path.name for path in self.binary.parent.iterdir()], ["paqet"])
        self.assertEqual(download.call_args.kwargs["timeout"], 30)
        native.assert_called_once()
        row = Ownership(self.store).read()["resources"]["binary:" + str(self.binary)]
        self.assertEqual(row["type"], "binary")
        self.assertEqual(row["owners"], ["installation"])
        self.assertEqual(row["status"], "complete")
        self.assertIsNone(row["before"])
        self.assertEqual(row["after"]["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(paqet.binary_pin("x86_64")["sha256"], paqet.RELEASE_MANIFEST["architectures"]["amd64"]["binary_sha256"])
        self.assertFalse(any(paqet.RELEASE_MANIFEST["qualification"].values()))

    def test_reuse_checks_version_without_download_or_adopting_external_binary(self):
        atomic_write(self.binary, self.payload, 0o755)
        with self.installer() as (download, native):
            self.assertTrue(self.install()["already_installed"])
        download.assert_not_called()
        native.assert_called_once()
        self.assertFalse(Ownership(self.store).read()["resources"])
        self.store.write(empty_v2())
        self.assertFalse(restore_system(self.store, self.runtime)["conflicts"])
        self.assertTrue(self.binary.is_file())

    def test_matching_installed_binary_preview_does_not_execute_it(self):
        atomic_write(self.binary, self.payload, 0o755)
        with self.installer() as (download, native):
            code, result = self.run_cli()
        self.assertEqual(code, 0)
        self.assertTrue(result["already_installed"])
        native.assert_not_called()
        download.assert_not_called()

    def test_invalid_paths_architectures_and_checksum_override_have_no_side_effects(self):
        for path in ("relative", str(self.root / ".." / "paqet"), str(self.root / "missing" / "paqet"), str(self.root / "bad\nname")):
            with self.subTest(path=path), self.assertRaises(ValidationError):
                paqet.install_plan(path)
        with patch.object(paqet.platform, "machine", return_value="mips"), self.assertRaises(ValidationError):
            paqet.install_plan(str(self.binary))
        with self.installer() as (download, native):
            for checksum in ("not-a-checksum", "f" * 64):
                code, result = self.run_cli("--sha256", checksum, "--apply", "--yes")
                self.assertEqual(code, 2)
                self.assertEqual(result["status"], "invalid")
            download.assert_not_called()
            native.assert_not_called()
        self.assertFalse(self.store.directory.exists())

    def test_symlink_parent_and_foreign_or_unsafe_existing_binary_are_preserved(self):
        other = self.root / "other"
        atomic_write(other, self.payload, 0o755)
        self.binary.symlink_to(other)
        with self.assertRaises(StateError):
            paqet.install_plan(str(self.binary))
        self.binary.unlink()
        parent_link = self.root / "link"
        parent_link.symlink_to(self.binary.parent, target_is_directory=True)
        with self.assertRaises(StateError):
            paqet.install_plan(str(parent_link / "paqet"))
        with self.installer() as (download, native):
            for payload, mode in ((b"foreign", 0o755), (self.payload, 0o644), (self.payload, 0o777), (self.payload, 0o4755)):
                atomic_write(self.binary, payload, mode)
                with self.binary_permissions(mode), self.subTest(mode=mode), self.assertRaises(ValidationError):
                    self.install()
                self.assertEqual(self.binary.read_bytes(), payload)
            download.assert_not_called()
            native.assert_not_called()

    def test_bad_download_checksum_and_oversized_download_never_execute_or_install(self):
        with self.installer() as (_, native):
            for archive in (b"not the pinned archive", b"x" * 1000):
                with patch.object(paqet.urllib.request, "urlopen", return_value=self.response(archive)), patch.object(paqet, "MAX_INSTALL_BYTES", 100), self.assertRaises(ValidationError):
                    self.install()
                self.assertFalse(self.binary.exists())
            native.assert_not_called()

    def test_archive_member_links_traversal_duplicates_and_devices_are_rejected(self):
        cases = [("../paqet", tarfile.REGTYPE), ("/paqet", tarfile.REGTYPE), ("dir\\paqet", tarfile.REGTYPE),
                 ("paqet_linux_amd64", tarfile.SYMTYPE), ("paqet_linux_amd64", tarfile.LNKTYPE), ("device", tarfile.CHRTYPE)]
        for name, kind in cases:
            archive = self.archive([(name, self.payload, kind)])
            with self.subTest(name=name, kind=kind), self.installer(archive) as (_, native), self.assertRaises(ValidationError):
                self.install()
            native.assert_not_called()
            self.assertFalse(self.binary.exists())
        duplicate = self.archive([("paqet_linux_amd64", self.payload, tarfile.REGTYPE)] * 2)
        with self.installer(duplicate), self.assertRaises(ValidationError):
            self.install()

    def test_archive_parser_bounds_and_binary_hash_are_enforced(self):
        huge = tarfile.TarInfo("paqet_linux_amd64")
        huge.size = paqet.MAX_INSTALL_BYTES + 1
        archives = [b"not a gzip archive", gzip.compress(huge.tobuf() + bytes(1024)),
                    self.archive([("README.md", b"missing binary", tarfile.REGTYPE)]),
                    self.archive([("paqet_linux_amd64", b"wrong executable", tarfile.REGTYPE)]),
                    self.archive([(str(i), b"", tarfile.REGTYPE) for i in range(33)])]
        for archive in archives:
            with self.subTest(size=len(archive)), self.installer(archive) as (_, native), self.assertRaises(ValidationError):
                self.install()
            native.assert_not_called()
            self.assertFalse(self.binary.exists())

    def test_network_failure_and_non_https_redirect_are_actionable(self):
        with self.installer() as (_, native):
            with patch.object(paqet.urllib.request, "urlopen", side_effect=urllib.error.URLError("blocked")), self.assertRaisesRegex(ValidationError, "download failed"):
                self.install()
            response = self.response(self.archive())
            response.geturl = lambda: "http://insecure/asset"
            with patch.object(paqet.urllib.request, "urlopen", return_value=response), self.assertRaisesRegex(ValidationError, "non-HTTPS"):
                self.install()
            native.assert_not_called()
        self.assertFalse(self.binary.exists())

    def test_native_version_and_execution_failures_leave_no_destination_or_tempfile(self):
        for outcome in ("Version: " + paqet.VERSION + "0\n", "secret native error", subprocess.TimeoutExpired("paqet", 3), OSError("wrong architecture")):
            with self.subTest(outcome=str(outcome)), self.installer():
                native = patch.object(paqet.subprocess, "run", side_effect=outcome) if isinstance(outcome, Exception) else patch.object(paqet.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, outcome, "secret"))
                with native, self.assertRaises(ValidationError) as error:
                    self.install()
                self.assertNotIn("secret", str(error.exception))
            self.assertFalse(list(self.binary.parent.iterdir()))

    def test_destination_race_never_overwrites_the_new_file(self):
        with self.installer():
            def native(argv, **kwargs):
                atomic_write(self.binary, "foreign newcomer", 0o755)
                return self.native(argv, **kwargs)
            with patch.object(paqet.subprocess, "run", side_effect=native), self.assertRaises(StateError):
                self.install()
        self.assertEqual(self.binary.read_text(), "foreign newcomer")

    def test_interrupted_install_resumes_before_or_after_atomic_publication(self):
        for after_link in (False, True):
            with self.subTest(after_link=after_link), self.installer() as (download, _):
                failure = patch.object(Ownership, "complete", side_effect=KeyboardInterrupt()) if after_link else patch.object(paqet.os, "link", side_effect=KeyboardInterrupt())
                with failure, self.assertRaises(KeyboardInterrupt):
                    self.install()
                self.assertEqual(self.binary.exists(), after_link)
                self.assertEqual(Ownership(self.store).read()["resources"]["binary:" + str(self.binary)]["status"], "pending")
                calls = download.call_count
                self.install()
                self.assertEqual(download.call_count, calls + (not after_link))
                self.assertEqual(Ownership(self.store).read()["resources"]["binary:" + str(self.binary)]["status"], "complete")
                self.store.write(empty_v2())
                self.assertFalse(restore_system(self.store, self.runtime)["conflicts"])
                self.assertFalse(self.binary.exists())

    def test_atomic_publication_race_does_not_adopt_even_a_matching_foreign_file(self):
        with self.installer():
            def publish(source, target):
                atomic_write(target, self.payload, 0o755)
                raise FileExistsError()
            with patch.object(paqet.os, "link", side_effect=publish), self.assertRaises(StateError):
                self.install()
            row = Ownership(self.store).read()["resources"]["binary:" + str(self.binary)]
            self.assertEqual(row["status"], "restored")
            self.assertFalse(row["owners"])
            self.assertTrue(self.install()["already_installed"])
        self.store.write(empty_v2())
        self.assertFalse(restore_system(self.store, self.runtime)["conflicts"])
        self.assertTrue(self.binary.exists())

    def test_large_binary_uses_fingerprint_ledger_and_can_be_restored(self):
        self.payload = b"a" * (5 * 1024 * 1024)
        with self.installer():
            self.install()
        self.assertLess(Ownership(self.store).path.stat().st_size, 4096)
        self.store.write(empty_v2())
        self.assertFalse(restore_system(self.store, self.runtime)["conflicts"])
        self.assertFalse(self.binary.exists())

    def test_restoration_preserves_foreign_changes_including_setuid_mode(self):
        with self.installer():
            self.install()
        self.store.write(empty_v2())
        ledger = Ownership(self.store)
        original = ledger.read()
        for payload, mode in ((b"foreign edit", 0o755), (self.payload, 0o4755)):
            ledger.save(original)
            atomic_write(self.binary, payload, mode)
            with self.binary_permissions(mode):
                self.assertTrue(restore_system(self.store, self.runtime)["conflicts"])
            self.assertTrue(self.binary.exists())

    def test_interrupted_binary_restoration_resumes_after_unlink(self):
        with self.installer():
            self.install()
        self.store.write(empty_v2())
        unlink = Path.unlink
        def interrupted(path, *args, **kwargs):
            result = unlink(path, *args, **kwargs)
            if path == self.binary:
                raise KeyboardInterrupt()
            return result
        with patch.object(Path, "unlink", interrupted), self.assertRaises(KeyboardInterrupt):
            restore_system(self.store, self.runtime)
        self.assertFalse(self.binary.exists())
        ledger = Ownership(self.store)
        self.assertEqual(ledger.read()["resources"]["binary:" + str(self.binary)]["status"], "restoring")
        self.assertFalse(restore_system(self.store, self.runtime)["conflicts"])
        self.assertEqual(ledger.read()["resources"]["binary:" + str(self.binary)]["status"], "restored")

    def test_cli_installs_on_fresh_and_v2_hosts_without_changing_pair_state(self):
        for v2 in (False, True):
            if v2:
                self.store.write(empty_v2())
            before = self.store.path.read_bytes() if self.store.path.exists() else None
            with self.subTest(v2=v2), self.installer():
                code, result = self.run_cli("--apply", "--yes")
                self.assertEqual(code, 0)
                self.assertEqual(result["status"], "complete")
                self.assertEqual(result["action"], "paqet install")
                self.assertIn("unavailable", result["activation"])
            self.assertEqual(self.store.path.read_bytes() if self.store.path.exists() else None, before)

    def test_cli_requires_root_and_blocks_pending_recovery_or_uninstall(self):
        with self.installer() as (download, _):
            with patch.object(self.host, "require_linux_root", side_effect=ValidationError("Linux root required")):
                self.assertEqual(self.run_cli("--apply", "--yes")[0], 2)
            with self.store.lock():
                pass
            for name in ("transaction.json", "uninstall.json"):
                journal = self.store.directory / name
                atomic_write(journal, "{}")
                self.assertEqual(self.run_cli("--apply", "--yes")[0], 4)
                journal.unlink()
            download.assert_not_called()

    def test_full_cli_uninstall_removes_owned_paqet_before_program_records(self):
        with self.installer():
            self.install()
        self.store.write(empty_v2())
        prefix = self.root / "program"
        launcher = prefix / "bin" / "twinlink"
        runtime = prefix / "libexec" / "twinlink-runtime"
        manifest = runtime.parent / "twinlink-install.json"
        for path in (launcher, runtime):
            atomic_write(path, "owned program", 0o755)
        atomic_write(manifest, json.dumps({"owner": "twinlink", "version": 1, "files": {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in (launcher, runtime)}}), 0o644)
        atomic_write(self.store.directory / "baseline.json", json.dumps({
            "historical_baseline": "recorded", "package_delta": {}, "directories": {
                str(path): {"existed": False} for path in (prefix, launcher.parent, runtime.parent, self.store.directory)}}))
        with patch.object(cli, "Host", return_value=self.host), contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.main(["--state-dir", str(self.store.directory), "--runtime-path", str(runtime),
                             "uninstall", "--purge", "--apply", "--yes"])
        self.assertEqual(code, 0, out.getvalue())
        self.assertFalse(self.binary.exists())
        self.assertFalse(any(path.exists() for path in (launcher, runtime, manifest, self.store.directory)))
