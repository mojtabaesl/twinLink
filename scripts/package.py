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
import zipapp

SOURCE = Path(__file__).resolve().parents[1]
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
    if distro in {"debian", "ubuntu"}:
        commands = [["apt-get", "update"], ["apt-get", "install", "-y", "python3", "iproute2",
                    "nftables", "iputils-ping", "iputils-tracepath", "conntrack"]]
    elif distro in {"fedora", "rocky", "almalinux", "rhel"}:
        commands = [["dnf", "install", "-y", "python3", "iproute", "nftables", "iputils", "conntrack-tools"]]
    else:
        fail("Supported distributions: Debian/Ubuntu and Fedora/Rocky/Alma/RHEL with Python >=3.9 and systemd")
    if not skip:
        for command in commands:
            run(command)
    missing = [command for command in ("ip", "ss", "nft", "ping", "conntrack", "systemctl") if not shutil.which(command)]
    if missing:
        fail("Missing required dependencies: " + ", ".join(missing))


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
    read_manifest(prefix)
    distro_dependencies(args.skip_deps)
    if args.rathole_sha256 and not args.rathole:
        fail("--rathole-sha256 requires --rathole /path/to/trusted/binary")
    rathole = None
    if args.rathole:
        rathole = Path(args.rathole).absolute()
        reject_symlinks(rathole)
        if not rathole.is_file() or not os.access(rathole, os.X_OK):
            fail("--rathole must name an executable regular file")
        if args.rathole_sha256 and sha256(rathole).lower() != args.rathole_sha256.lower():
            fail("rathole SHA256 does not match the supplied trusted checksum")
        version = subprocess.run([str(rathole), "--version"], capture_output=True, text=True, check=True)
        if not re.search(r"\brathole\s+0\.5\.0\b", version.stdout + version.stderr):
            fail("Selected executable must identify itself as supported rathole 0.5.0 (TCP)")
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
    tunnels, forwards = state_records(state_dir)
    if args.purge_managed:
        if not args.cascade:
            fail("--purge-managed requires --cascade to explicitly remove dependent forwarding entries")
        if not runtime.exists():
            fail("Persistent runtime is missing; restore the installation before removing managed resources")
        command = [str(runtime), "--state-dir", str(state_dir), "--unit-dir", args.unit_dir,
                   "--runtime-path", str(runtime), "uninstall", "--purge-managed", "--cascade", "--apply"]
        if args.yes:
            command.append("--yes")
        run(command)
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
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, "twinlink installer: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
