"""Pinned Paqet renderer and scoped Linux packet exceptions.

No SOCKS listener is generated. TCP/UDP are deliberately unqualified until
version-specific namespace packet evidence is shipped with the release.
"""
import ipaddress
import json
import re

from .contracts import PAQET_VERSION, PAQET_COMMIT
from .models import ValidationError, _ipv4, _integer, ports

VERSION, COMMIT = PAQET_VERSION, PAQET_COMMIT
# Do not populate these from a user's config or an unverified download.
TRUSTED_BINARY_HASHES = {}
QUALIFIED_PROTOCOLS = frozenset()
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
