"""Pinned Paqet renderer and scoped Linux packet exceptions.

No SOCKS listener is generated. TCP/UDP are deliberately unqualified until
version-specific namespace packet evidence is shipped with the release.
"""
import ipaddress
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request

from .contracts import PAQET_VERSION, PAQET_COMMIT
from .models import ValidationError, _ipv4, _integer, ports

VERSION, COMMIT = PAQET_VERSION, PAQET_COMMIT
# Do not populate these from a user's config or an unverified download.
TRUSTED_BINARY_HASHES = {}
QUALIFIED_PROTOCOLS = frozenset()
# Installation pins are distinct from runtime qualification. Archive hashes
# match GitHub asset digests; binary hashes were computed from the verified
# archive members on 17 October 2026:
# https://api.github.com/repos/hanselime/paqet/releases/tags/v1.0.0-alpha.21
INSTALL_RELEASES = {
    "amd64": {"archive_sha256": "4f2f69e0493746726598485ef18df43372470a1514f8021594137e522f0f4fc7",
              "binary_sha256": "edb5d928443b3d47e5c7c86ae394dbac117826e7ddb7c27355fbd2cdd9ee1791"},
    "arm64": {"archive_sha256": "be5c7b35a0a93832063e1dc7fddeb76d4597fb9de76abdfdf7b8574b775e3885",
              "binary_sha256": "f6db279a57a772a250efffe4bb0a79b112495331568ccc0f6e5f4398bbe962e3"},
}
INSTALL_ARCHITECTURES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
MAX_INSTALL_BYTES = 32 * 1024 * 1024
SYSTEM_REQUIREMENTS = ("Linux root/CAP_NET_RAW and packet capture permissions", "libpcap for dynamically linked builds",
                       "IPv4 route source, NIC and gateway neighbor MAC", "Dedicated raw transport port",
                       "Scoped pre-conntrack NOTRACK and kernel RST suppression on VPS2")


def validate_facts(value):
    if not isinstance(value, dict):
        raise ValidationError("Missing local NIC/source/gateway facts")
    interface = value.get("interface")
    if not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface):
        raise ValidationError("Invalid local interface")
    source = _ipv4(value.get("source"), "route source")
    gateway = _ipv4(value.get("gateway"), "gateway")
    mac = value.get("router_mac")
    if not isinstance(mac, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
        raise ValidationError("Missing gateway neighbor MAC; resolve it outside diagnostics then regenerate")
    if int(mac[:2], 16) & 1 or int(mac.replace(":", ""), 16) == 0:
        raise ValidationError("Gateway MAC must be nonzero unicast")
    low, high = value.get("ephemeral_range", (32768, 60999))
    low, high = _integer(low, "ephemeral lower", 1024, 65535), _integer(high, "ephemeral upper", low, 65535)
    return {"interface": interface, "source": source, "gateway": gateway,
            "router_mac": mac.lower(), "ephemeral_range": [low, high]}


def render_config(revision, role, facts, key):
    facts = validate_facts(facts)
    if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", key):
        raise ValidationError("Paqet requires a strong URL-safe key")
    p = revision["profiles"]["direct-paqet"]
    port = revision["transport"]["port"]
    client = role == "vps1"
    # JSON is a YAML subset: stdlib rendering avoids ambiguous YAML scalars.
    config = {"role": "client" if client else "server", "log": {"level": "info"},
              "network": {"interface": facts["interface"],
                          "ipv4": {"addr": f"{facts['source']}:{0 if client else port}", "router_mac": facts["router_mac"]},
                          "tcp": {"local_flag": p["local_flag"]}},
              "transport": {"protocol": "kcp", "conn": p["conn"], "kcp": {**p["kcp"], "key": key}}}
    if client:
        config["network"]["tcp"]["remote_flag"] = p["remote_flag"]
        config["server"] = {"addr": f"{revision['public_endpoints']['vps2']}:{port}"}
        config["forward"] = []
        for s in revision["services"]:
            a, b = ports(s["ports"])
            c, d = ports(s["backend"]["ports"])
            for offset in range(b - a + 1):
                config["forward"].append({"listen": f"{s['bind']}:{a + offset}",
                    "target": f"{s['backend']['address']}:{c + (offset if c != d else 0)}", "protocol": s["protocol"]})
    else:
        low, high = facts["ephemeral_range"]
        if low <= port <= high:
            raise ValidationError("Paqet transport overlaps the server's ephemeral port range")
        if facts["source"] != revision["public_endpoints"]["vps2"]:
            raise ValidationError("Paqet server requires its dedicated source to equal the public endpoint")
        config["listen"] = {"addr": f":{port}"}
    # Persisted revisions have canonical key order; keep artifact bytes stable
    # when preparation and launch checks render either representation.
    return json.dumps(config, indent=2, sort_keys=True) + "\n"


def packet_exceptions(revision, facts, table, owner):
    """Match address + peer + dedicated port; never broad ACCEPT or flush."""
    facts = validate_facts(facts)
    if not re.fullmatch(r"tl2_[0-9a-f]{16}", table) or not re.fullmatch(r"[0-9a-f-]{36}", owner):
        raise ValidationError("Invalid packet-rule ownership")
    port = revision["transport"]["port"]
    lo, hi = facts["ephemeral_range"]
    if lo <= port <= hi:
        raise ValidationError("Raw transport overlaps ephemeral ports")
    local, peer = facts["source"], revision["public_endpoints"]["vps1"]
    ipaddress.IPv4Address(peer)
    return f'''table ip {table} {{
    comment "twinlink:{owner}"
    chain raw_in {{
        type filter hook prerouting priority -300; policy accept;
        ip saddr {peer} ip daddr {local} tcp dport {port} counter notrack comment "twinlink:paqet:incoming"
    }}
    chain raw_out {{
        type filter hook output priority -300; policy accept;
        ip saddr {local} ip daddr {peer} tcp sport {port} counter notrack comment "twinlink:paqet:outgoing"
    }}
    chain rst_out {{
        type filter hook output priority -150; policy accept;
        ip saddr {local} ip daddr {peer} tcp sport {port} tcp flags & rst == rst counter drop comment "twinlink:paqet:rst"
    }}
}}
'''


def binary_pin(architecture):
    checksum = TRUSTED_BINARY_HASHES.get(architecture)
    if not checksum:
        raise ValidationError("No verified Paqet binary hash for this architecture; profile remains unavailable")
    return {"version": VERSION, "commit": COMMIT, "sha256": checksum}


def check_installed_version(binary):
    try:
        result = subprocess.run([str(binary), "version"], capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        raise ValidationError("Cannot execute pinned Paqet; check Linux architecture and runtime dependencies") from None
    if result.returncode or not re.search(r"(?m)^Version:[ \t]+" + re.escape(VERSION) + r"[ \t]*$", result.stdout):
        raise ValidationError("Installed executable must report Paqet " + VERSION + "; existing files are never overwritten")


def install_plan(binary, sha256=None):
    from .store import reject_symlink
    from .ownership import Ownership
    path = Path(binary)
    if not path.is_absolute() or ".." in path.parts or any(ord(c) < 32 for c in str(path)):
        raise ValidationError("Paqet executable path must be absolute without traversal or control characters")
    reject_symlink(path)
    if not path.parent.is_dir():
        raise ValidationError("Create the Paqet executable parent directory before installation")
    architecture = INSTALL_ARCHITECTURES.get(platform.machine().lower())
    if architecture is None:
        raise ValidationError("Automatic Paqet installation supports Linux x86_64/ARM64 only")
    pin = INSTALL_RELEASES[architecture]
    if sha256 is not None and (not re.fullmatch(r"[0-9a-fA-F]{64}", sha256) or sha256.lower() != pin["archive_sha256"]):
        raise ValidationError("--sha256 must match the pinned Paqet release archive checksum")
    observed = Ownership.binary_value(path)
    if observed is not None:
        if (observed["sha256"] != pin["binary_sha256"] or not os.access(path, os.X_OK)
                or path.stat().st_mode & 0o6022):
            raise ValidationError("Existing Paqet differs from the pinned executable or has unsafe permissions; never overwritten")
    asset = f"paqet-linux-{architecture}-{VERSION}.tar.gz"
    return {"path": str(path), "version": VERSION, "commit": COMMIT, "architecture": architecture,
            "url": f"https://github.com/hanselime/paqet/releases/download/{VERSION}/{asset}",
            **pin, "binary_member": "paqet_linux_" + architecture, "already_installed": observed is not None,
            "activation": "unavailable pending runtime binary and protocol qualification"}


def _install_payload(archive, plan):
    if len(archive) > MAX_INSTALL_BYTES or hashlib.sha256(archive).hexdigest() != plan["archive_sha256"]:
        raise ValidationError("Paqet release archive size/checksum mismatch; nothing installed")
    payload, names, total = None, set(), 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
            for member in package:
                path = PurePosixPath(member.name)
                total += member.size
                if (len(names) >= 32 or member.name in names or path.is_absolute() or ".." in path.parts
                        or "\\" in member.name or not (member.isfile() or member.isdir())
                        or not 0 <= member.size <= MAX_INSTALL_BYTES or total > 2 * MAX_INSTALL_BYTES):
                    raise ValidationError("Unsafe or oversized Paqet archive member; nothing installed")
                names.add(member.name)
                if member.name == plan["binary_member"] and member.isfile():
                    with package.extractfile(member) as stream:
                        payload = stream.read(MAX_INSTALL_BYTES + 1)
                    if len(payload) != member.size:
                        raise ValidationError("Incomplete Paqet executable in archive")
    except (tarfile.TarError, OSError, EOFError, ValueError):
        raise ValidationError("Invalid Paqet release archive; nothing installed") from None
    if payload is None or hashlib.sha256(payload).hexdigest() != plan["binary_sha256"]:
        raise ValidationError("Paqet executable missing or checksum mismatch; nothing installed")
    return payload


def install(binary, store, sha256=None):
    """Caller holds Store.lock(); pin both archive and binary before execution."""
    from .ownership import Ownership
    from .store import StateError, reject_symlink
    plan = install_plan(binary, sha256)
    path, ledger = Path(plan["path"]), Ownership(store)
    resource = "binary:" + str(path)
    if plan["already_installed"]:
        check_installed_version(path)
        row = ledger.read()["resources"].get(resource)
        if row and row["status"] != "restored":
            ledger.check(resource, ledger.binary_value(path))
        return plan
    try:
        request = urllib.request.Request(plan["url"], headers={"User-Agent": "twinlink-paqet-installer"})
        with urllib.request.urlopen(request, timeout=30) as response:
            if not response.geturl().startswith("https://"):
                raise ValidationError("Refusing a non-HTTPS Paqet download redirect")
            archive = response.read(MAX_INSTALL_BYTES + 1)
    except (urllib.error.URLError, OSError):
        raise ValidationError("Paqet download failed; obtain the pinned Linux release separately and retry") from None
    payload = _install_payload(archive, plan)
    descriptor, temporary = tempfile.mkstemp(prefix=".twinlink-paqet-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o755)
        check_installed_version(temporary)
        reject_symlink(path)
        if path.exists():
            raise StateError("Paqet destination appeared during installation; preserved")
        ledger.begin(resource, "binary", "installation", None,
                     {"sha256": plan["binary_sha256"], "mode": 0o755}, "remove-installed-binary")
        try:
            os.link(temporary, path)
        except FileExistsError:
            # Publication did not happen. Do not let retry reconcile an
            # identical but independently created file as our installation.
            data = ledger.read()
            data["resources"][resource].update(status="restored", owners=[])
            ledger.save(data)
            raise StateError("Paqet destination appeared during publication; preserved") from None
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        ledger.complete(resource, ledger.binary_value(path))
    finally:
        os.unlink(temporary)
    return {**plan, "installed": True}
