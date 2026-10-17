#!/usr/bin/env python3
"""Build/install a stdlib zipapp and remove only authenticated owned files."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import zipapp

SOURCE = Path(__file__).resolve().parents[1]
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))
from twinlink.baseline import MAX_BASELINE_BYTES, parse as parse_baseline, serialize as serialize_baseline

LAUNCHER_MARKER = "# Twinlink launcher; managed by scripts/install.sh"


def fail(message):
    raise RuntimeError(message)


def run(arguments):
    subprocess.run(arguments, check=True)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def reject_symlinks(path):
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            fail("Refusing symlink path: " + str(candidate))


def write_owned(path, content, mode):
    """Replace an owned file without following a raced leaf symlink."""
    reject_symlinks(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".twinlink-", dir=path.parent)
    temporary = Path(temporary)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_baseline(path, value):
    write_owned(path, serialize_baseline(value), 0o600)


def build(output):
    if sys.version_info < (3, 9):
        fail("Python 3.9 or newer is required")
    reject_symlinks(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="twinlink-build-") as directory:
        work = Path(directory)
        source = work / "source"
        source.mkdir(mode=0o700)
        shutil.copytree(SOURCE / "twinlink", source / "twinlink",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (source / "__main__.py").write_text("from twinlink.cli import main\nraise SystemExit(main())\n")
        archive = work / "runtime.pyz"
        try:
            zipapp.create_archive(source, target=archive, interpreter="/usr/bin/env python3", compressed=True)
            os.chmod(archive, 0o755)
            with tempfile.NamedTemporaryFile(prefix=".twinlink-", dir=output.parent, delete=False) as stream:
                temporary = Path(stream.name)
            try:
                shutil.copyfile(archive, temporary)
                os.chmod(temporary, 0o755)
                os.replace(temporary, output)
            finally:
                temporary.unlink(missing_ok=True)
        finally:
            archive.unlink(missing_ok=True)


def manifest_paths(prefix):
    return prefix / "bin/twinlink", prefix / "libexec/twinlink-runtime", prefix / "libexec/twinlink-install.json"


def read_manifest(prefix, required=False):
    launcher, runtime, manifest_path = manifest_paths(prefix)
    for path in (launcher, runtime, manifest_path):
        reject_symlinks(path)
    if not manifest_path.exists():
        if required or launcher.exists() or runtime.exists():
            fail("Installation ownership manifest is missing; refusing to replace or remove existing files")
        return None
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("owner") != "twinlink" or manifest.get("version") != 1:
        fail("Installation ownership manifest is invalid")
    expected = {str(launcher), str(runtime)}
    if set(manifest.get("files", {})) != expected:
        fail("Installation manifest points outside this installation prefix")
    for filename, checksum in manifest["files"].items():
        path = Path(filename)
        if path.exists() and (not path.is_file() or sha256(path) != checksum):
            fail("Installed file was modified; refusing to replace/remove it: " + str(path))
    return manifest


def distro_dependencies(skip=False):
    if sys.platform != "linux":
        fail("Installation requires Linux; use --build-only PATH to build a portable archive")
    if not Path("/run/systemd/system").is_dir():
        fail("Installation requires a running systemd host")
    release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release[key] = value.strip('"')
    distro = release.get("ID", "")
    prefix_commands = []
    if distro in {"debian", "ubuntu"}:
        required = ("iproute2", "nftables", "iputils-ping", "conntrack")
        existing = installed_packages()
        if existing is None:
            fail("Package provenance is unavailable; install prerequisites separately and use --skip-deps")
        missing_packages = [name for name in required if name not in existing]
        commands = []
        if missing_packages:
            if not skip:
                prefix_commands = [["apt-get", "update"]]
                run(prefix_commands[0])
            install_command = ["apt-get", "install", "--no-upgrade", "--no-install-recommends", "-y", *missing_packages]
            if not skip:
                simulation = subprocess.run(["apt-get", "--simulate", *install_command[1:]], capture_output=True, text=True, check=True)
                if any(line.startswith(("Remv ", "Purg ")) or line.startswith("Inst ") and "[" in line for line in simulation.stdout.splitlines()):
                    fail("Dependency simulation would upgrade/remove pre-existing packages; install prerequisites separately")
            commands.append(install_command)
    elif distro in {"fedora", "rocky", "almalinux", "rhel"}:
        existing = installed_packages()
        if existing is None:
            fail("Package provenance unavailable; install prerequisites separately")
        missing_packages = [name for name in ("iproute", "nftables", "iputils", "conntrack-tools") if name not in existing]
        commands = [["dnf", "install", "-y", "--setopt=install_weak_deps=False",
                     "--exclude=" + ",".join(sorted(existing)), *missing_packages]] if missing_packages else []
    else:
        fail("Supported distributions: Debian/Ubuntu and Fedora/Rocky/Alma/RHEL with Python >=3.9 and systemd")
    if not skip:
        for command in commands:
            run(command)
    missing = [command for command in ("ip", "ss", "nft", "ping", "conntrack", "systemctl") if not shutil.which(command)]
    if missing:
        fail("Missing required dependencies: " + ", ".join(missing))
    return prefix_commands + commands if not skip else []


def installed_packages():
    if shutil.which("dpkg-query"):
        command = ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\n"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return {row[0]: row[1] for row in (line.split("\t") for line in result.stdout.splitlines()) if len(row) == 3 and row[2] == "installed"}
    if shutil.which("rpm"):
        result = subprocess.run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"], capture_output=True, text=True, check=True)
        return dict(line.split("\t", 1) for line in result.stdout.splitlines() if "\t" in line)
    return None


def installer_baseline(args, prefix, previous):
    """Record original facts before packages or program directories change."""
    state_dir = Path(args.state_dir).absolute()
    reject_symlinks(state_dir)
    baseline = state_dir / "baseline.json"
    reject_symlinks(baseline)
    if baseline.exists():
        if baseline.stat().st_mode & 0o077:
            fail("Installer baseline must be private")
        with baseline.open("rb") as stream:
            return parse_baseline(stream.read(MAX_BASELINE_BYTES + 1))
    original = {str(path): {"existed": path.exists(), "mode": path.stat().st_mode & 0o777 if path.exists() else None}
                for path in (state_dir, prefix, prefix / "bin", prefix / "libexec")}
    record = {"version": 1, "installation_id": str(uuid.uuid4()), "created_at": time.time(),
              "historical_baseline": "unknown" if previous else "recorded", "directories": original,
              "packages_before": installed_packages(), "package_delta": {}, "operations": [],
              "python": {"path": sys.executable, "pre_existing": True}}
    content = serialize_baseline(record)
    # The bootstrap journal lives in the already-existing parent, so creation
    # of the private state directory itself also has durable prior intent.
    if not state_dir.parent.is_dir():
        fail("Create the state-directory parent before installing")
    bootstrap = state_dir.parent / (".twinlink-bootstrap-" + hashlib.sha256(str(state_dir).encode()).hexdigest()[:16] + ".json")
    reject_symlinks(bootstrap)
    if bootstrap.exists():
        fail("Interrupted installer bootstrap exists; inspect it before retrying: " + str(bootstrap))
    write_owned(bootstrap, json.dumps({"state_directory": str(state_dir), "before": original[str(state_dir)]}), 0o600)
    state_dir.mkdir(mode=0o700, exist_ok=True)
    if state_dir.stat().st_mode & 0o077:
        fail("State directory must be mode 0700")
    write_owned(baseline, content, 0o600)
    bootstrap.unlink()
    return record


def validate_install_options(args, prefix):
    """Reject invalid inputs before recording or performing install mutations."""
    if sys.version_info < (3, 9):
        fail("Python 3.9 or newer is required")
    if args.rathole_sha256 and not args.rathole:
        fail("--rathole-sha256 requires --rathole /path/to/trusted/binary")
    if args.rathole_sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", args.rathole_sha256):
        fail("--rathole-sha256 must be a complete SHA256 checksum")
    state_dir = Path(args.state_dir).absolute()
    for directory in (prefix, prefix / "bin", prefix / "libexec", state_dir):
        reject_symlinks(directory)
        existing = next(path for path in (directory, *directory.parents) if path.exists())
        if not existing.is_dir():
            fail("Installation directory path is not a directory: " + str(existing))
    if not state_dir.parent.is_dir():
        fail("Create the state-directory parent before installing")
    if state_dir.exists() and state_dir.stat().st_mode & 0o077:
        fail("State directory must be mode 0700")
    if not args.rathole:
        return None
    rathole = Path(args.rathole).absolute()
    reject_symlinks(rathole)
    if not rathole.is_file() or not os.access(rathole, os.X_OK):
        fail("--rathole must name an executable regular file")
    if args.rathole_sha256 and sha256(rathole).lower() != args.rathole_sha256.lower():
        fail("rathole SHA256 does not match the supplied trusted checksum")
    version = subprocess.run([str(rathole), "--version"], capture_output=True, text=True, check=True, timeout=3)
    if not re.search(r"\brathole\s+0\.5\.0\b", version.stdout + version.stderr):
        fail("Selected executable must identify itself as supported rathole 0.5.0 (TCP)")
    return rathole


def install(args):
    if args.build_only:
        requested = Path(args.build_only).absolute()
        if requested.is_symlink():
            fail("Refusing symlink output: " + str(requested))
        # /tmp is a system symlink on macOS. Build-only accepts the selected
        # parent directory's canonical path, but never a symlink output file.
        output = requested.parent.resolve() / requested.name
        build(output)
        print("Built " + str(output))
        return
    if os.geteuid() != 0:
        fail("Run installation as root (sudo scripts/install.sh)")
    prefix = Path(args.prefix).absolute()
    rathole = validate_install_options(args, prefix)
    previous = read_manifest(prefix)
    baseline = installer_baseline(args, prefix, previous)
    if any(operation.get("status") == "pending" for operation in baseline.get("operations", [])):
        fail("Interrupted installer operation in baseline.json; preserve its package snapshot and resolve provenance before retrying")
    baseline_path = Path(args.state_dir).absolute() / "baseline.json"
    baseline["operations"].append({"operation": "install", "status": "pending", "time": time.time()})
    write_baseline(baseline_path, baseline)
    operation_before = installed_packages()
    baseline["operations"][-1]["packages_before"] = operation_before
    write_baseline(baseline_path, baseline)
    package_commands = distro_dependencies(args.skip_deps)
    after = installed_packages()
    if operation_before is not None and after is not None:
        baseline["package_delta"].update({name: version for name, version in after.items() if name not in operation_before})
        baseline["operations"][-1]["commands"] = package_commands
        write_baseline(baseline_path, baseline)
    launcher, runtime, manifest_path = manifest_paths(prefix)
    for directory in (launcher.parent, runtime.parent):
        reject_symlinks(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=0o755)
    build(runtime)
    content = "#!/usr/bin/env python3\n" + LAUNCHER_MARKER + "\nimport os, sys\n"
    content += "os.execv(" + repr(str(runtime)) + ", [" + repr(str(runtime)) + ", '--runtime-path', " + repr(str(runtime)) + ", *sys.argv[1:]])\n"
    write_owned(launcher, content, 0o755)
    manifest = {"owner": "twinlink", "version": 1, "files": {str(path): sha256(path) for path in (launcher, runtime)}}
    write_owned(manifest_path, json.dumps(manifest, indent=2) + "\n", 0o644)
    baseline["operations"][-1]["status"] = "complete"
    baseline["operations"][-1].pop("packages_before", None)
    write_baseline(baseline_path, baseline)
    if rathole:
        # Do not overwrite a separately installed executable. The CLI accepts
        # --rathole-binary so the supplied trusted path can be used directly.
        print("Use --rathole-binary " + str(rathole) + " for rathole operations (no binary was downloaded or overwritten).")
    print("Installed " + str(launcher) + " with persistent runtime " + str(runtime))
    print("Run sudo " + str(launcher) + " doctor and then sudo " + str(launcher) + " menu")


def state_records(state_dir):
    reject_symlinks(state_dir)
    state_path = state_dir / "state.json"
    reject_symlinks(state_path)
    if not state_path.exists():
        return 0, 0
    if stat.S_IMODE(state_path.stat().st_mode) & 0o077:
        fail("State contains secrets and must be mode 0600 before uninstall")
    state = json.loads(state_path.read_text())
    if state.get("version") == 2 and isinstance(state.get("pairs"), dict):
        return len(state["pairs"]), 0
    if type(state.get("version")) is not int or state.get("version") != 1 or not isinstance(state.get("tunnels"), dict) or not isinstance(state.get("forwards"), dict):
        fail("Invalid state; recover it before uninstalling")
    return len(state["tunnels"]), len(state["forwards"])


def uninstall(args):
    if os.geteuid() != 0:
        fail("Run uninstallation as root (sudo scripts/uninstall.sh)")
    prefix = Path(args.prefix).absolute()
    manifest = read_manifest(prefix, required=True)
    launcher, runtime, manifest_path = manifest_paths(prefix)
    state_dir = Path(args.state_dir).absolute()
    reject_symlinks(state_dir / "transaction.json")
    if (state_dir / "transaction.json").exists():
        fail("An unfinished transaction exists. Run twinlink recover --apply before uninstalling")
    if (state_dir / "journals").exists() and any((state_dir / "journals").glob("purge-*.json")):
        fail("An unfinished pair purge exists; preserve the runtime and resume pair delete")
    tunnels, forwards = state_records(state_dir)
    if args.purge_managed:
        if not args.cascade:
            fail("--purge-managed requires --cascade to explicitly remove dependent forwarding entries")
        if not runtime.exists():
            fail("Persistent runtime is missing; restore the installation before removing managed resources")
        v2 = (state_dir / "state.json").exists() and json.loads((state_dir / "state.json").read_text()).get("version") == 2
        command = [str(runtime), "--state-dir", str(state_dir), "--unit-dir", args.unit_dir,
                   "--runtime-path", str(runtime), "uninstall", *(["--purge"] if v2 else ["--purge-managed", "--cascade"]), "--apply"]
        if args.yes:
            command.append("--yes")
        run(command)
        if v2:
            if any(path.exists() for path in (launcher, runtime, manifest_path)):
                fail("V2 program files remain; preserve recovery and inspect uninstall conflicts")
            print("Removed owned v2 resources and program files on this host; peer cleanup is separate.")
            return
        tunnels, forwards = state_records(state_dir)
        if tunnels or forwards:
            fail("Managed resources remain after purge; preserving all program files. Inspect twinlink status and repair failures")
    # Preserve a runtime if its units still exist even when state was lost.
    unit_dir = Path(args.unit_dir).absolute()
    owned_units = [path for path in unit_dir.glob("twinlink-*.service")
                   if path.is_file() and not path.is_symlink() and "# twinlink-owned" in path.read_text()[:512]]
    retained = bool(tunnels or forwards or owned_units)
    if launcher.exists():
        launcher.unlink()
    if retained:
        print(f"Removed the launcher. Preserved {tunnels} tunnels, {forwards} forwards, systemd units, secrets and runtime {runtime}.")
        print("Managed services continue using the retained runtime. Reinstall to restore the launcher, or run this script with --purge-managed --cascade to remove resources.")
    else:
        runtime.unlink(missing_ok=True)
        manifest_path.unlink()
        print("Removed program launcher and runtime. State/backups and separately installed dependencies/rathole were retained.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    install_parser = sub.add_parser("install", help="install the local source checkout")
    install_parser.add_argument("--prefix", default="/usr/local")
    install_parser.add_argument("--state-dir", default="/var/lib/twinlink", help="Private immutable installer baseline and journals")
    install_parser.add_argument("--skip-deps", action="store_true", help="check existing dependencies without package-manager changes")
    install_parser.add_argument("--build-only", metavar="PATH", help="build a zipapp without root or Linux package changes")
    install_parser.add_argument("--rathole", metavar="PATH", help="check a separately obtained trusted executable")
    install_parser.add_argument("--rathole-sha256", help="require this SHA256 for the supplied rathole executable")
    uninstall_parser = sub.add_parser("uninstall", help="remove the launcher, or explicitly purge managed resources")
    uninstall_parser.add_argument("--prefix", default="/usr/local")
    uninstall_parser.add_argument("--state-dir", default="/var/lib/twinlink")
    uninstall_parser.add_argument("--unit-dir", default="/etc/systemd/system")
    uninstall_parser.add_argument("--purge-managed", action="store_true")
    uninstall_parser.add_argument("--cascade", action="store_true")
    uninstall_parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()
    try:
        {"install": install, "uninstall": uninstall}[args.action](args)
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(1, "twinlink installer: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
