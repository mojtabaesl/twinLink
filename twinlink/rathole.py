"""Pinned upstream installation and native Noise key generation."""

import base64
import binascii
import hashlib
import io
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile

from .models import ValidationError
from .store import reject_symlink

VERSION = "0.5.0"
MAX_DOWNLOAD = 32 * 1024 * 1024
TARGETS = {"x86_64": "x86_64-unknown-linux-gnu", "amd64": "x86_64-unknown-linux-gnu",
           "aarch64": "aarch64-unknown-linux-musl", "arm64": "aarch64-unknown-linux-musl"}


def key(value):
    try:
        decoded = base64.b64decode(value, validate=True) if isinstance(value, str) else b""
    except (ValueError, binascii.Error):
        decoded = b""
    if len(decoded) != 32 or decoded == bytes(32):
        raise ValidationError("Noise keys must be nonzero base64-encoded 32-byte X25519 keys")
    return value


def _run(binary, argument):
    try:
        result = subprocess.run([str(binary), argument], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        raise ValidationError("Cannot execute rathole; run twinlink rathole install --apply or supply --rathole-binary") from None
    if result.returncode:
        # Never echo native output: --genkey output can contain private keys.
        raise ValidationError("Rathole failed " + argument + "; check binary compatibility and Noise support")
    return result.stdout + "\n" + result.stderr


def check_version(binary):
    output = _run(binary, "--version")
    match = re.search(r"(?m)^rathole[ \t]+(\S+)", output)
    if match is None and re.search(r"(?m)^rathole[ \t]*$", output):
        match = re.search(r"(?m)^Build Version:[ \t]+(\S+)[ \t]*$", output)
    if match is None or match.group(1) != VERSION:
        raise ValidationError("Supported rathole version is " + VERSION + "; existing executables are never overwritten")


def generate_keypair(binary):
    output = _run(binary, "--genkey")
    private = re.search(r"Private Key:\s*([A-Za-z0-9+/=]+)", output)
    public = re.search(r"Public Key:\s*([A-Za-z0-9+/=]+)", output)
    if not private or not public:
        raise ValidationError("Rathole did not generate a Noise keypair; use a build with the noise feature")
    return {"noise_private_key": key(private.group(1)), "noise_public_key": key(public.group(1))}


def install_plan(binary, sha256=None):
    target = Path(binary)
    if not target.is_absolute() or ".." in target.parts or any(ord(c) < 32 for c in str(target)):
        raise ValidationError("Rathole executable path must be absolute without traversal or control characters")
    reject_symlink(target)
    if sha256 is not None and not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
        raise ValidationError("--sha256 must be a 64-character archive SHA256")
    if target.exists():
        if not target.is_file() or not os.access(target, os.X_OK):
            raise ValidationError("Existing Rathole path is not an executable regular file; choose another path")
        check_version(target)
        return {"path": str(target), "version": VERSION, "already_installed": True}
    architecture = platform.machine().lower()
    if architecture not in TARGETS:
        raise ValidationError("No automatic Rathole release for " + architecture + "; install a trusted 0.5.0 build and supply --rathole-binary")
    asset = "rathole-" + TARGETS[architecture] + ".zip"
    return {"path": str(target), "version": VERSION, "already_installed": False,
            "url": "https://github.com/rathole-org/rathole/releases/download/v" + VERSION + "/" + asset,
            "archive_sha256": sha256,
            "verification": "HTTPS from the pinned official release, executable version and Noise key generation; optional trusted archive SHA256"}


def install(binary, sha256=None):
    """Download only after CLI confirmation; never replace an existing path."""
    plan = install_plan(binary, sha256)
    if plan["already_installed"]:
        generate_keypair(binary)
        return plan
    try:
        request = urllib.request.Request(plan["url"], headers={"User-Agent": "twinlink-rathole-installer"})
        with urllib.request.urlopen(request, timeout=30) as response:
            if not response.geturl().startswith("https://"):
                raise ValidationError("Refusing a non-HTTPS Rathole download redirect")
            archive = response.read(MAX_DOWNLOAD + 1)
    except (urllib.error.URLError, OSError):
        raise ValidationError("Rathole download failed. Download the official release on another host, copy its binary securely, and use --rathole-binary /path/to/rathole") from None
    if len(archive) > MAX_DOWNLOAD:
        raise ValidationError("Rathole release archive exceeds the download limit")
    checksum = hashlib.sha256(archive).hexdigest()
    if sha256 and checksum != sha256.lower():
        raise ValidationError("Rathole archive SHA256 does not match; nothing installed")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as package:
            members = [item for item in package.infolist() if item.filename == "rathole"]
            if len(members) != 1 or members[0].file_size > MAX_DOWNLOAD:
                raise ValidationError("Release archive must contain one bounded rathole executable")
            executable = package.read(members[0])
    except (zipfile.BadZipFile, RuntimeError):
        raise ValidationError("Invalid Rathole release archive; nothing installed") from None
    target = Path(binary)
    reject_symlink(target)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    descriptor, temporary = tempfile.mkstemp(prefix=".twinlink-rathole-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(executable)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o755)
        check_version(temporary)
        generate_keypair(temporary)
        # Hard-link is atomic and fails if the destination appeared meanwhile.
        reject_symlink(target)
        os.link(temporary, target)
    finally:
        os.unlink(temporary)
    return {**plan, "installed": True, "archive_sha256": checksum}


def port_mappings(value):
    mappings = []
    for item in value.split(","):
        match = re.fullmatch(r"\s*([0-9]+)(?::([0-9]+))?\s*", item)
        if not match:
            raise ValidationError("Ports must be comma-separated PUBLIC:DESTINATION pairs, e.g. 8080:80,8443:443 (one number keeps the same port)")
        public, destination = int(match.group(1)), int(match.group(2) or match.group(1))
        if not 1 <= public <= 65535 or not 1 <= destination <= 65535:
            raise ValidationError("Forwarding ports must be between 1 and 65535")
        if any(existing[0] == public for existing in mappings):
            raise ValidationError("Duplicate public forwarding port")
        mappings.append((public, destination))
    if not 1 <= len(mappings) <= 64:
        raise ValidationError("Set up between 1 and 64 forwarding ports at once")
    return mappings


def forward_names(name, mappings):
    return [f"{name[:42]}-{public}" for public, _ in mappings]
