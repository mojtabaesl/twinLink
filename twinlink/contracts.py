"""Strict, host-independent v2 pair revisions. No network or filesystem I/O."""
import copy
import hashlib
import json
import re
import uuid

from .models import (ValidationError, _name, _integer, _ipv4, _private,
                     _port_string, ports, _overlap, _addresses_overlap)

PROFILES = ("gre-kernel", "gre-rathole", "direct-rathole", "direct-paqet")
ROLES = ("vps1", "vps2")
PAQET_VERSION = "v1.0.0-alpha.21"
PAQET_COMMIT = "4b81ce0ab56b7cc9aec7501c87c4804676cdb1b4"
RATHOLE_COMMIT = "ebb764ae53d7ffe4fcb45f83f7563bec5c74199d"
PINS = {"rathole": {"version": "0.5.0", "commit": RATHOLE_COMMIT},
        "paqet": {"version": PAQET_VERSION, "commit": PAQET_COMMIT}}
KCP_DEFAULTS = {"mode": "manual", "block": "aes-128-gcm", "mtu": 1350,
                "nodelay": 1, "interval": 10, "resend": 1, "wdelay": False,
                "acknodelay": False, "nocongestion": 0}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def fields(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or set(required) - set(value):
        raise ValidationError("Missing or unknown fields; expected " + ", ".join(sorted(required)))


def strict_json(text, limit=65536, *, max_items=1024):
    if len(text.encode() if isinstance(text, str) else text) > limit:
        raise ValidationError("JSON exceeds the size limit")
    def unique(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValidationError("Duplicate JSON field")
            out[key] = value
        return out
    def walk(value, depth=0):
        if depth > 16:
            raise ValidationError("JSON exceeds the depth limit")
        if isinstance(value, (dict, list)):
            if len(value) > max_items:
                raise ValidationError("JSON exceeds the count limit")
            for child in value.values() if isinstance(value, dict) else value:
                walk(child, depth + 1)
    try:
        value = json.loads(text, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValidationError("Nonfinite JSON")))
        walk(value)
        return value
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise ValidationError("Invalid bounded JSON: " + str(exc)) from None


def empty_v2(installation_id=None):
    return {"version": 2, "installation_id": installation_id or str(uuid.uuid4()), "pairs": {}}


def selection(value):
    if value is None:
        return None
    fields(value, ("revision", "profile", "epoch"))
    if value["profile"] not in PROFILES:
        raise ValidationError("Unknown active profile")
    return {"profile": value["profile"],
            "revision": _integer(value["revision"], "revision", 1, 2147483647),
            "epoch": _integer(value["epoch"], "epoch", 1, 2147483647)}


def validate_control(value):
    fields(value, ("role", "author", "active", "staged_revision", "last_good", "transition", "peer_observations"),
           ("epoch", "commit_pending"))
    if value["role"] not in ROLES or value["author"] != "vps1":
        raise ValidationError("Invalid pair roles")
    out = copy.deepcopy(value)
    out["active"], out["last_good"] = selection(value["active"]), selection(value["last_good"])
    out["staged_revision"] = _integer(value["staged_revision"], "staged_revision", 1, 2147483647)
    if not isinstance(value["peer_observations"], list) or len(value["peer_observations"]) > 64:
        raise ValidationError("Invalid peer observations")
    if value["transition"] is not None and not isinstance(value["transition"], dict):
        raise ValidationError("Invalid transition journal")
    out["epoch"] = _integer(value.get("epoch", 0), "epoch", 0, 2147483647)
    return out


def validate_v2_state(value):
    fields(value, ("version", "installation_id", "pairs"))
    if type(value["version"]) is not int or value["version"] != 2:
        raise ValidationError("Expected schema v2")
    try:
        uuid.UUID(value["installation_id"])
    except (ValueError, TypeError, AttributeError):
        raise ValidationError("Invalid installation ID") from None
    if not isinstance(value["pairs"], dict) or len(value["pairs"]) > 64:
        raise ValidationError("At most 64 pairs are supported")
    return {**value, "pairs": {_name(k): validate_control(v) for k, v in value["pairs"].items()}}


def validate_service(value):
    fields(value, ("id", "bind", "protocol", "ports", "backend", "probe"))
    fields(value["backend"], ("address", "ports"))
    out = copy.deepcopy(value)
    out["id"] = _name(value["id"])
    out["bind"] = _ipv4(value["bind"], "service bind", wildcard=True)
    if value["protocol"] not in ("tcp", "udp"):
        raise ValidationError("Service protocol must be tcp or udp")
    out["ports"] = _port_string(value["ports"])
    out["backend"] = {"address": _ipv4(value["backend"]["address"], "backend", loopback=True),
                      "ports": _port_string(value["backend"]["ports"])}
    a, b = ports(out["ports"])
    c, d = ports(out["backend"]["ports"])
    if b - a >= 256 or (c != d and b - a != d - c):
        raise ValidationError("Service ranges require <=256 ports and matching widths or many-to-one")
    if _overlap(out["ports"], 22):
        raise ValidationError("Service includes protected management port 22")
    probe = value["probe"]
    if probe is not None:
        fields(probe, ("kind", "request_hex", "response_hex"))
        if probe["kind"] != "exchange":
            raise ValidationError("Only explicit application exchange probes are supported")
        for field in ("request_hex", "response_hex"):
            raw = probe[field]
            if not isinstance(raw, str) or not re.fullmatch(r"(?:[a-fA-F0-9]{2}){1,2048}", raw):
                raise ValidationError("Probe requires 1–2048 bytes of hex request and expected response")
    return out


def default_profiles(pair_id):
    return {"gre-kernel": {}, "gre-rathole": {}, "direct-rathole": {},
            "direct-paqet": {"conn": 4, "local_flag": ["SA"], "remote_flag": ["SA"], "kcp": dict(KCP_DEFAULTS)}}


def validate_revision(value):
    fields(value, ("schema_version", "pair_id", "revision", "parent_digest", "public_endpoints",
                   "transport", "gre", "services", "profiles", "credential_ids", "public_keys", "pins"),
           ("legacy_group_assignments",))
    if type(value["schema_version"]) is not int or value["schema_version"] != 2:
        raise ValidationError("Expected pair schema v2")
    out = copy.deepcopy(value)
    out["pair_id"] = _name(value["pair_id"])
    out["revision"] = _integer(value["revision"], "revision", 1, 2147483647)
    parent = value["parent_digest"]
    if (out["revision"] == 1 and parent is not None) or (out["revision"] > 1 and
            (not isinstance(parent, str) or not re.fullmatch("[0-9a-f]{64}", parent))):
        raise ValidationError("Revision requires its immediate parent digest")
    fields(value["public_endpoints"], ROLES)
    out["public_endpoints"] = {role: _ipv4(value["public_endpoints"][role], role) for role in ROLES}
    if len(set(out["public_endpoints"].values())) != 2:
        raise ValidationError("Public endpoints must differ")
    fields(value["transport"], ("port",))
    out["transport"] = {"port": _integer(value["transport"]["port"], "transport.port", 1024, 65535)}
    if out["transport"]["port"] in (1080, 3306, 5432, 6379, 8080, 8443):
        raise ValidationError("Use a dedicated non-service transport port")
    fields(value["gre"], ("addresses", "key", "mtu", "ttl"))
    fields(value["gre"]["addresses"], ROLES)
    gre = value["gre"]
    addresses = [_private(gre["addresses"][r], r) for r in ROLES]
    if addresses[0].network != addresses[1].network or addresses[0].ip == addresses[1].ip:
        raise ValidationError("GRE addresses must be distinct hosts in the same private subnet")
    out["gre"] = {"addresses": {r: str(a) for r, a in zip(ROLES, addresses)},
                  "key": None if gre["key"] is None else _integer(gre["key"], "GRE key", 1, 4294967295),
                  "mtu": _integer(gre["mtu"], "GRE MTU", 576, 1472 if gre["key"] is not None else 1476),
                  "ttl": _integer(gre["ttl"], "GRE TTL", 1, 255)}
    if not isinstance(value["services"], list) or len(value["services"]) > 64:
        raise ValidationError("At most 64 services are supported")
    out["services"] = [validate_service(s) for s in value["services"]]
    if sum(ports(s["ports"])[1] - ports(s["ports"])[0] + 1 for s in out["services"]) > 256:
        raise ValidationError("A pair may expand to at most 256 service ports")
    if len({s["id"] for s in out["services"]}) != len(out["services"]):
        raise ValidationError("Duplicate service ID")
    for i, service in enumerate(out["services"]):
        if _overlap(service["ports"], out["transport"]["port"]):
            raise ValidationError("Service overlaps the shared transport port")
        for other in out["services"][:i]:
            if service["protocol"] == other["protocol"] and _addresses_overlap(service["bind"], other["bind"]) and _overlap(service["ports"], other["ports"]):
                raise ValidationError("Overlapping service binds")
    fields(value["profiles"], PROFILES)
    for name in PROFILES[:3]:
        fields(value["profiles"][name], ())
    p = out["profiles"]["direct-paqet"]
    fields(p, ("conn", "local_flag", "remote_flag", "kcp"))
    p["conn"] = _integer(p["conn"], "paqet.conn", 1, 256)
    for field in ("local_flag", "remote_flag"):
        if not isinstance(p[field], list) or not 1 <= len(p[field]) <= 16 or any(
                not isinstance(f, str) or not re.fullmatch("[FSRPAUEC]{1,8}", f) for f in p[field]):
            raise ValidationError("Invalid paqet TCP flags")
    fields(p["kcp"], KCP_DEFAULTS)
    kcp = p["kcp"]
    if kcp["mode"] != "manual" or kcp["block"] != "aes-128-gcm":
        raise ValidationError("Paqet requires manual mode with authenticated aes-128-gcm")
    for key, lo, hi in (("mtu", 50, 1500), ("interval", 10, 5000), ("resend", 0, 2), ("nodelay", 0, 1), ("nocongestion", 0, 1)):
        kcp[key] = _integer(kcp[key], key, lo, hi)
    for key in ("wdelay", "acknodelay"):
        if type(kcp[key]) is not bool:
            raise ValidationError(key + " must be boolean")
    out["profiles"]["direct-paqet"] = copy.deepcopy(p)
    if value["pins"] != PINS:
        raise ValidationError("Transport source/version pins differ from this renderer")
    fields(value["credential_ids"], ("management", "rathole", "paqet", "noise"))
    for key, val in value["credential_ids"].items():
        _name(val)
    if len(set(value["credential_ids"].values())) != 4:
        raise ValidationError("Credential IDs must be distinct")
    fields(value["public_keys"], ("noise",))
    if value["public_keys"]["noise"] is not None:
        from .rathole import key
        key(value["public_keys"]["noise"])
    if "legacy_group_assignments" in value:
        groups = value["legacy_group_assignments"]
        if not isinstance(groups, dict) or set(groups) - {s["id"] for s in out["services"]}:
            raise ValidationError("Invalid legacy group assignments")
        for service, group in groups.items():
            fields(group, (), ("rathole_group", "relay_port", "transport_port"))
            if "rathole_group" in group:
                _name(group["rathole_group"])
            if "relay_port" in group:
                relay = ports(group["relay_port"])
                own = ports(next(s["ports"] for s in out["services"] if s["id"] == service))
                if relay[0] < 1024 or relay[1] - relay[0] != own[1] - own[0]:
                    raise ValidationError("Legacy relay ranges must match service widths and start above 1023")
            if "transport_port" in group:
                _integer(group["transport_port"], "legacy port", 1024, 65535)
        for left in out["services"]:
            a = groups.get(left["id"], {}).get("relay_port")
            for right in out["services"]:
                b = groups.get(right["id"], {}).get("relay_port")
                if left["id"] != right["id"] and left["protocol"] == right["protocol"] and a and b and _overlap(a, b):
                    raise ValidationError("Legacy relay ranges overlap")
    return out


def new_revision(pair_id, endpoints, transport_port=3456, services=(), gre=None):
    return validate_revision({"schema_version": 2, "pair_id": pair_id, "revision": 1,
        "parent_digest": None, "public_endpoints": endpoints, "transport": {"port": transport_port},
        "gre": gre or {"addresses": {"vps1": "10.77.0.1/30", "vps2": "10.77.0.2/30"},
                       "key": None, "mtu": 1476, "ttl": 64},
        "services": list(services), "profiles": default_profiles(pair_id),
        "credential_ids": {k: hashlib.sha256((pair_id + ":" + k).encode()).hexdigest()[:32] for k in ("management", "rathole", "paqet", "noise")},
        "public_keys": {"noise": None}, "pins": copy.deepcopy(PINS)})


def next_revision(previous, **changes):
    return validate_revision({**copy.deepcopy(previous), **changes,
        "revision": previous["revision"] + 1, "parent_digest": digest(previous)})


def validate_reservations(revision, others):
    """Reserve disabled pairs too. Same pair profiles reuse their one port."""
    import ipaddress
    for other in others:
        if other["pair_id"] == revision["pair_id"]:
            continue
        if (set(revision["public_endpoints"].values()) == set(other["public_endpoints"].values())
                and revision["gre"]["key"] == other["gre"]["key"]):
            raise ValidationError("GRE endpoints and key reserved by pair " + other["pair_id"])
        if revision["transport"]["port"] == other["transport"]["port"]:
            raise ValidationError("Transport port reserved by pair " + other["pair_id"])
        if ipaddress.IPv4Interface(revision["gre"]["addresses"]["vps1"]).network.overlaps(
                ipaddress.IPv4Interface(other["gre"]["addresses"]["vps1"]).network):
            raise ValidationError("GRE subnet reserved by pair " + other["pair_id"])
        for left in revision["services"]:
            if _overlap(left["ports"], other["transport"]["port"]):
                raise ValidationError("Service overlaps another pair's transport")
            for right in other["services"]:
                if _overlap(right["ports"], revision["transport"]["port"]):
                    raise ValidationError("Transport overlaps another pair's service")
                if left["protocol"] == right["protocol"] and _addresses_overlap(left["bind"], right["bind"]) and _overlap(left["ports"], right["ports"]):
                    raise ValidationError("Service reserved by another pair")
