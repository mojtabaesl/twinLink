"""Regression coverage for restoration retries, reboot resets and install validation."""
import argparse
import base64
import contextlib
import io
from pathlib import Path
import subprocess
from unittest.mock import patch

from tests.test_lifecycle_review import RuntimeFixture
from tests.test_packaging import packaging
from tests.test_profile_runtime import SystemHost
from tests.test_v2 import V2Fixture
from twinlink.cleanup import restore_system
from twinlink.contracts import canonical, empty_v2
from twinlink.coordination import Coordinator
from twinlink.ownership import Ownership
from twinlink.profile_runtime import ProfileRuntime
from twinlink.store import StateError, atomic_write


class RestorationRetryReviewTests(V2Fixture):
    def setUp(self):
        super().setUp()
        self.store.write(empty_v2())
        self.host = SystemHost(self.root / "units")
        self.runtime = ProfileRuntime(self.store, self.host, str(self.host.unit_dir))
        self.ledger = self.runtime.ledger
        self.target = self.root / "owned.conf"

    def interrupt_completion(self, resource, operation=None):
        original = Ownership.save
        fired = []
        def save(ledger, data, **kwargs):
            if data["resources"][resource]["status"] == "restored" and not fired:
                fired.append(True)
                raise KeyboardInterrupt()
            return original(ledger, data, **kwargs)
        with patch.object(Ownership, "save", save), self.assertRaises(KeyboardInterrupt):
            (operation or (lambda: restore_system(self.store, self.runtime)))()
        self.assertTrue(fired)
        self.assertEqual(self.ledger.read()["resources"][resource]["status"], "restoring")

    def assert_restored(self, resource, dependencies=False):
        result = restore_system(self.store, self.runtime, dependencies=dependencies)
        self.assertEqual(result["status"], "complete", result)
        self.assertEqual(result["conflicts"], [])
        row = self.ledger.read()["resources"][resource]
        self.assertEqual(row["status"], "restored")
        self.assertEqual(row["owners"], [])

    def test_deleted_owned_file_resumes_without_repeating_the_unlink(self):
        resource = "file:" + str(self.target)
        self.ledger.write_file(self.target, "owned", "edge")
        self.interrupt_completion(resource)
        self.assertFalse(self.target.exists())
        original = Path.unlink
        def unlink(path, *args, **kwargs):
            if path == self.target:
                raise AssertionError("Already restored file must not be unlinked again")
            return original(path, *args, **kwargs)
        with patch.object(Path, "unlink", unlink):
            self.assert_restored(resource)

    def test_preexisting_file_resumes_with_original_content_and_mode(self):
        resource = "file:" + str(self.target)
        atomic_write(self.target, "original", 0o640)
        before = self.ledger.file_value(self.target)
        after = {"content": base64.b64encode(b"owned").decode(), "mode": 0o600}
        self.ledger.begin(resource, "file", "edge", before, after, "restore-file")
        atomic_write(self.target, "owned")
        self.ledger.complete(resource, self.ledger.file_value(self.target))
        self.interrupt_completion(resource)
        original = atomic_write
        def write(path, *args, **kwargs):
            if Path(path) == self.target:
                raise AssertionError("Already restored file must not be written again")
            return original(path, *args, **kwargs)
        with patch("twinlink.ownership.atomic_write", side_effect=write):
            self.assert_restored(resource)
        self.assertEqual(self.ledger.file_value(self.target), before)

    def test_restoration_interrupted_before_unlink_retries_the_owned_mutation(self):
        resource = "file:" + str(self.target)
        self.ledger.write_file(self.target, "owned", "edge")
        original = Path.unlink
        def unlink(path, *args, **kwargs):
            if path == self.target:
                raise KeyboardInterrupt()
            return original(path, *args, **kwargs)
        with patch.object(Path, "unlink", unlink), self.assertRaises(KeyboardInterrupt):
            restore_system(self.store, self.runtime)
        self.assertTrue(self.target.exists())
        self.assertEqual(self.ledger.read()["resources"][resource]["status"], "restoring")
        self.assert_restored(resource)
        self.assertFalse(self.target.exists())

    def test_foreign_file_after_interruption_remains_a_conflict(self):
        resource = "file:" + str(self.target)
        self.ledger.write_file(self.target, "owned", "edge")
        self.interrupt_completion(resource)
        atomic_write(self.target, "foreign replacement")
        result = restore_system(self.store, self.runtime)
        self.assertEqual(result["status"], "conflict")
        self.assertEqual(self.target.read_text(), "foreign replacement")
        self.assertEqual(self.ledger.read()["resources"][resource]["status"], "conflict")

    def test_unit_enablement_restore_resumes_without_disabling_again(self):
        resource = "unit-enable:test.service"
        self.ledger.begin(resource, "unit-enable", "edge", False, True, "restore-unit-enablement")
        self.host.enabled.add("test.service")
        self.ledger.complete(resource, True)
        self.interrupt_completion(resource)
        self.host.commands.clear()
        self.assert_restored(resource)
        self.assertNotIn(["systemctl", "disable", "test.service"], self.host.commands)

    def test_sysctl_restore_resumes_without_writing_the_original_value_again(self):
        resource = "sysctl:net.ipv4.ip_forward"
        self.ledger.begin(resource, "sysctl", "edge", "0", "1", "restore-sysctl")
        self.host.forwarding = "1"
        self.ledger.complete(resource, "1")
        self.interrupt_completion(resource)
        self.assertEqual(self.host.forwarding, "0")
        self.host.commands.clear()
        self.assert_restored(resource)
        self.assertFalse(any(cmd[:2] == ["sysctl", "-w"] for cmd in self.host.commands))

    def test_installation_file_restoration_can_resume_in_final_cleanup(self):
        target = self.store.directory / "installation-artifact"
        resource = "file:" + str(target)
        self.ledger.write_file(target, "owned", "installation")
        self.interrupt_completion(resource, lambda: self.ledger.remove_file(target, "installation"))
        atomic_write(self.store.directory / "baseline.json", canonical({"historical_baseline": "recorded", "package_delta": {}}))
        self.assert_restored(resource, dependencies=True)

    def test_private_pair_file_restoration_resumes_without_purging_other_configs(self):
        target = self.store.directory / "retired-config"
        retained = self.store.directory / "retained-config"
        self.ledger.write_file(target, "retiring", "edge")
        self.ledger.write_file(retained, "retained", "edge")
        resource = "file:" + str(target)
        self.interrupt_completion(resource, lambda: self.ledger.remove_file(target, "edge"))
        self.assert_restored(resource)
        self.assertEqual(retained.read_text(), "retained")
        self.assertEqual(self.ledger.read()["resources"]["file:" + str(retained)]["status"], "complete")

    def test_pending_shared_sysctl_cleanup_recognizes_a_reboot_reset(self):
        resource = "sysctl:net.ipv4.ip_forward"
        with patch.object(Ownership, "boot_id", return_value="boot-one"):
            self.ledger.begin(resource, "sysctl", "edge", "0", "1", "restore-sysctl")
            self.ledger.complete(resource, "1")
            self.ledger.begin(resource, "sysctl", "other", "1", "1", "restore-sysctl")
        with patch.object(Ownership, "boot_id", return_value="boot-two"):
            self.assert_restored(resource)
        self.assertFalse(any(cmd[:2] == ["sysctl", "-w"] for cmd in self.host.commands))


class RebootResetReviewTests(V2Fixture):
    def setUp(self):
        super().setUp()
        self.ledger = Ownership(self.store)
        self.resource = "sysctl:net.ipv4.ip_forward"

    def acquired(self, owners=("edge",), pending=False):
        with patch.object(Ownership, "boot_id", return_value="boot-one"):
            for i, owner in enumerate(owners):
                self.ledger.begin(self.resource, "sysctl", owner, "1" if i else "0", "1", "restore-sysctl")
                if not pending or i != len(owners) - 1:
                    self.ledger.complete(self.resource, "1")

    def no_write(self, value):
        raise AssertionError("Boot-reset setting must not be changed")

    def test_new_boot_original_setting_is_retired_without_a_write(self):
        self.acquired()
        with patch.object(Ownership, "boot_id", return_value="boot-two"):
            self.ledger.release(self.resource, "edge", "0", self.no_write)
        row = self.ledger.read()["resources"][self.resource]
        self.assertEqual(row["status"], "restored")
        self.assertEqual(row["before"], "0")
        self.assertEqual(row["boot_id"], "boot-one")

    def test_boot_reset_releases_only_the_requested_shared_owner(self):
        self.acquired(("edge", "other"))
        with patch.object(Ownership, "boot_id", return_value="boot-two"):
            self.ledger.release(self.resource, "edge", "0", self.no_write)
            self.assertEqual(self.ledger.read()["resources"][self.resource]["owners"], ["other"])
            self.ledger.release(self.resource, "other", "0", self.no_write)
        self.assertEqual(self.ledger.read()["resources"][self.resource]["status"], "restored")

    def test_pending_shared_acquisition_can_withdraw_after_boot_reset(self):
        self.acquired(("edge", "other"), pending=True)
        with patch.object(Ownership, "boot_id", return_value="boot-two"):
            self.ledger.release(self.resource, "other", "0", self.no_write)
            self.assertEqual(self.ledger.read()["resources"][self.resource]["owners"], ["edge"])
            self.ledger.release(self.resource, "edge", "0", self.no_write)

    def test_shared_owner_can_reactivate_without_losing_the_original_baseline(self):
        self.acquired(("edge", "other"))
        with patch.object(Ownership, "boot_id", return_value="boot-two"):
            self.ledger.release(self.resource, "edge", "0", self.no_write)
            self.ledger.begin(self.resource, "sysctl", "other", "0", "1", "restore-sysctl")
            self.ledger.complete(self.resource, "1")
            restored = []
            self.ledger.release(self.resource, "other", "1", lambda before: restored.append(before) or before)
        self.assertEqual(restored, ["0"])

    def test_same_boot_or_unknown_boot_does_not_hide_a_change(self):
        for recorded, current in (("boot-one", "boot-one"), ("boot-one", None), (None, "boot-two")):
            with self.subTest(recorded=recorded, current=current):
                self.ledger.path.unlink(missing_ok=True)
                with patch.object(Ownership, "boot_id", return_value=recorded):
                    self.ledger.begin(self.resource, "sysctl", "edge", "0", "1", "restore-sysctl")
                    self.ledger.complete(self.resource, "1")
                with patch.object(Ownership, "boot_id", return_value=current), self.assertRaises(StateError):
                    self.ledger.release(self.resource, "edge", "0", self.no_write)
                self.assertEqual(self.ledger.read()["resources"][self.resource]["status"], "conflict")

    def test_new_boot_foreign_value_stays_conflicted(self):
        self.acquired()
        with patch.object(Ownership, "boot_id", return_value="boot-two"), self.assertRaises(StateError):
            self.ledger.release(self.resource, "edge", "2", self.no_write)
        self.assertEqual(self.ledger.read()["resources"][self.resource]["status"], "conflict")

    def test_wrong_owner_cannot_retire_a_boot_reset_record(self):
        self.acquired()
        before = self.ledger.path.read_bytes()
        with patch.object(Ownership, "boot_id", return_value="boot-two"), self.assertRaises(StateError):
            self.ledger.release(self.resource, "other", "0", self.no_write)
        self.assertEqual(self.ledger.path.read_bytes(), before)


class KernelRebootOffReviewTests(RuntimeFixture):
    def test_kernel_activation_reboot_then_off_keeps_reset_forwarding_unchanged(self):
        self.stage()
        self.prepare()
        control = self.committed("gre-kernel")
        with patch.object(Ownership, "boot_id", return_value="boot-one"):
            self.runtime.prepare(self.r, "vps1", "gre-kernel", control, {"previous": None})
            self.runtime.start(self.r, "vps1", "gre-kernel", control, {"previous": None})
        self.host.link_rows, self.host.addr_rows, self.host.tables, self.host.forwarding = [], [], {}, "0"
        self.host.commands.clear()
        with patch.object(Ownership, "boot_id", return_value="boot-two"):
            result = Coordinator(self.store, self.runtime, lambda: 100).advance("edge", self.r, None)
        self.assertEqual(result["local_status"], "off")
        self.assertEqual(self.host.forwarding, "0")
        self.assertFalse(any(cmd[:2] == ["sysctl", "-w"] for cmd in self.host.commands))
        self.assertEqual(self.runtime.ledger.read()["resources"]["sysctl:net.ipv4.ip_forward"]["status"], "restored")


class InstallerValidationReviewTests(V2Fixture):
    def setUp(self):
        super().setUp()
        self.args = argparse.Namespace(prefix=str(self.root / "prefix"), state_dir=str(self.store.directory),
                                       build_only=None, skip_deps=True, rathole=None, rathole_sha256=None)

    def assert_rejected_without_mutation(self, exception=RuntimeError):
        before = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        with patch.object(packaging.os, "geteuid", return_value=0), patch.object(packaging, "installer_baseline") as baseline, patch.object(packaging, "distro_dependencies") as dependencies, patch.object(packaging, "build") as build:
            with self.assertRaises(exception):
                packaging.install(self.args)
            baseline.assert_not_called()
            dependencies.assert_not_called()
            build.assert_not_called()
        self.assertEqual({str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}, before)
        self.assertFalse(list(self.root.glob(".twinlink-bootstrap-*")))

    def binary(self, version="rathole 0.5.0"):
        binary = self.root / "rathole"
        atomic_write(binary, "#!/bin/sh\nprintf '%s\\n' '" + version + "'\n", 0o755)
        self.args.rathole = str(binary)
        return binary

    def test_checksum_without_binary_fails_before_baseline_or_dependencies(self):
        self.args.rathole_sha256 = "a" * 64
        self.assert_rejected_without_mutation()

    def test_corrected_retry_can_install_after_invalid_options(self):
        self.args.rathole_sha256 = "a" * 64
        self.assert_rejected_without_mutation()
        self.args.rathole_sha256 = None
        with patch.object(packaging.os, "geteuid", return_value=0), patch.object(packaging, "installed_packages", return_value={"python3": "existing"}), patch.object(packaging, "distro_dependencies", return_value=[]), patch.object(packaging, "build", side_effect=lambda path: atomic_write(path, "owned runtime", 0o755)), contextlib.redirect_stdout(io.StringIO()):
            packaging.install(self.args)
        self.assertEqual(self.store.baseline()["operations"][-1]["status"], "complete")
        self.assertTrue((Path(self.args.prefix) / "bin/twinlink").is_file())

    def test_missing_directory_or_nonexecutable_binary_is_rejected_early(self):
        for kind in ("missing", "directory", "nonexecutable"):
            with self.subTest(kind=kind):
                binary = self.root / kind
                if kind == "directory":
                    binary.mkdir()
                elif kind == "nonexecutable":
                    atomic_write(binary, "not executable")
                self.args.rathole = str(binary)
                self.assert_rejected_without_mutation()

    def test_symlinked_binary_is_rejected_early(self):
        binary = self.binary()
        link = self.root / "binary-link"
        link.symlink_to(binary)
        self.args.rathole = str(link)
        self.assert_rejected_without_mutation()

    def test_invalid_checksum_format_or_mismatch_precedes_version_execution(self):
        self.binary()
        for checksum in ("short", "a" * 64):
            with self.subTest(checksum=checksum), patch.object(packaging.subprocess, "run", side_effect=AssertionError("do not execute unchecked binary")):
                self.args.rathole_sha256 = checksum
                self.assert_rejected_without_mutation()

    def test_unsupported_binary_version_is_rejected_early(self):
        self.binary("rathole 0.4.0")
        self.assert_rejected_without_mutation()

    def test_failed_or_timed_out_version_check_is_rejected_early(self):
        self.binary()
        for error in (subprocess.CalledProcessError(1, ["rathole", "--version"]), subprocess.TimeoutExpired(["rathole", "--version"], 3)):
            with self.subTest(error=type(error).__name__), patch.object(packaging.subprocess, "run", side_effect=error):
                self.assert_rejected_without_mutation(type(error))

    def test_invalid_installation_directory_paths_are_rejected_early(self):
        blocked = self.root / "blocked"
        atomic_write(blocked, "foreign file")
        for prefix in (blocked, blocked / "nested"):
            with self.subTest(prefix=prefix):
                self.args.prefix = str(prefix)
                self.assert_rejected_without_mutation()
        self.args.prefix = str(self.root / "prefix")
        self.args.state_dir = str(self.root / "missing-parent" / "state")
        self.assert_rejected_without_mutation()

    def test_insecure_state_directory_does_not_create_a_bootstrap_journal(self):
        self.store.directory.mkdir(mode=0o755)
        self.assert_rejected_without_mutation()

    def test_blocked_or_symlinked_program_directory_is_rejected_early(self):
        prefix = Path(self.args.prefix)
        prefix.mkdir()
        atomic_write(prefix / "bin", "foreign file")
        self.assert_rejected_without_mutation()
        (prefix / "bin").unlink()
        (prefix / "bin").symlink_to(self.root, target_is_directory=True)
        self.assert_rejected_without_mutation()

    def test_invalid_upgrade_options_preserve_existing_baseline_and_program(self):
        with patch.object(packaging, "installed_packages", return_value={}):
            packaging.installer_baseline(self.args, Path(self.args.prefix), None)
        atomic_write(Path(self.args.prefix) / "bin/twinlink", "existing launcher", 0o755)
        atomic_write(Path(self.args.prefix) / "libexec/twinlink-runtime", "existing runtime", 0o755)
        self.args.rathole_sha256 = "a" * 64
        self.assert_rejected_without_mutation()

    def test_trusted_binary_is_validated_before_the_first_pending_record(self):
        binary = self.binary()
        self.args.rathole_sha256 = packaging.sha256(binary).upper()
        original = packaging.installer_baseline
        validated = []
        run = packaging.subprocess.run
        def version(*args, **kwargs):
            result = run(*args, **kwargs)
            validated.append(True)
            self.assertFalse(self.store.directory.exists())
            return result
        def baseline(*args):
            self.assertTrue(validated)
            return original(*args)
        with patch.object(packaging.os, "geteuid", return_value=0), patch.object(packaging.subprocess, "run", side_effect=version), patch.object(packaging, "installer_baseline", side_effect=baseline), patch.object(packaging, "installed_packages", return_value={"python3": "existing"}), patch.object(packaging, "distro_dependencies", return_value=[]), patch.object(packaging, "build", side_effect=lambda path: atomic_write(path, "owned runtime", 0o755)), contextlib.redirect_stdout(io.StringIO()):
            packaging.install(self.args)
        self.assertEqual(self.store.baseline()["operations"][-1]["status"], "complete")
