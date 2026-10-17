"""Pure profile adapters: capabilities, generated outputs and readiness inputs."""
import hashlib
import ipaddress
import json

from .contracts import PROFILES, digest, validate_revision
from .models import ports, interface_name, ValidationError
from . import paqet

RENDERER_VERSION = 1


def table_name(pair_id):
    return "tl2_" + hashlib.sha256(pair_id.encode()).hexdigest()[:16]


def expanded_services(revision):
    out = []
    for service in revision["services"]:
        first, last = ports(service["ports"])
        target, target_last = ports(service["backend"]["ports"])
        for offset in range(last - first + 1):
            name = "s" + hashlib.sha256(service["id"].encode()).hexdigest()[:24] + "-" + str(first + offset)
            out.append({**service, "name": name,
                        "port": first + offset, "target_port": target + (offset if target != target_last else 0)})
    return out


def capabilities(revision, profile):
    reasons = []
    if profile not in PROFILES:
        raise ValidationError("Unknown profile")
    if not revision["services"]:
        reasons.append({"service": None, "reason": "No services; select off"})
    total = len(expanded_services(revision))
    if total > 256:
        reasons.append({"service": None, "reason": "At most 256 expanded services per pair"})
    for s in revision["services"]:
        reason = None
        if "rathole" in profile and s["protocol"] != "tcp":
            reason = "Pinned Rathole supports qualified TCP only"
        elif profile == "gre-kernel" and ipaddress.IPv4Address(s["backend"]["address"]).is_loopback:
            reason = "Kernel DNAT cannot target VPS2 loopback"
        elif profile == "direct-paqet" and s["protocol"] not in paqet.QUALIFIED_PROTOCOLS:
            reason = "Paqet " + s["protocol"].upper() + " requires pinned-version packet qualification"
        if reason:
            reasons.append({"service": s["id"], "reason": reason})
    return {"compatible": not reasons, "missing_services": reasons}


def gre_record(revision, role):
    peer = "vps2" if role == "vps1" else "vps1"
    g = revision["gre"]
    # Distinct names from v1; no hidden dependence on a verified legacy tunnel.
    name = revision["pair_id"] if "legacy_group_assignments" in revision else "p" + hashlib.sha256(revision["pair_id"].encode()).hexdigest()[:20]
    return {"name": name, "side": role, "interface": interface_name(name),
            "local_public": revision["public_endpoints"][role], "remote_public": revision["public_endpoints"][peer],
            "local_private": g["addresses"][role], "remote_private": g["addresses"][peer],
            "key": g["key"], "mtu": g["mtu"], "ttl": g["ttl"], "running": True, "enabled": False, "verified": False}


def kernel_state(revision, role):
    t = gre_record(revision, role)
    state = {"version": 1, "tunnels": {t["name"]: t}, "forwards": {}}
    for i, s in enumerate(expanded_services(revision)):
        legacy = revision.get("legacy_group_assignments", {}).get(s["id"], {})
        relay = 10000 + i
        if "relay_port" in legacy:
            relay = ports(legacy["relay_port"])[0] + s["port"] - ports(s["ports"])[0]
        # Reserve the same deterministic relay space on both ends.
        state["forwards"][s["name"]] = {"name": s["name"], "tunnel": t["name"], "side": role,
            "mode": "kernel", "protocol": s["protocol"], "bind_address": s["bind"],
            "bind_port": str(s["port"]), "destination_address": s["backend"]["address"],
            "destination_port": str(s["target_port"]), "relay_port": str(relay),
            "running": True, "enabled": False}
    return state


def render_kernel(revision, role, installation_id):
    from .render import render_nft
    return render_nft(kernel_state(revision, role)).replace("table ip twinlink {", "table ip " + table_name(revision["pair_id"]) + " {").replace(
        'comment "twinlink-owned"', 'comment "twinlink:' + installation_id + '"')


def render_rathole(revision, role, profile, credentials):
    server = role == "vps1"
    transport_ip = str(ipaddress.IPv4Interface(revision["gre"]["addresses"]["vps1"]).ip) if profile == "gre-rathole" else revision["public_endpoints"]["vps1"]
    port = revision["transport"]["port"]
    kind = "server" if server else "client"
    token = credentials.get("rathole")
    if not isinstance(token, str) or len(token) < 32:
        raise ValidationError("Rathole credential is missing")
    from .rathole import key
    noise = key(credentials.get("noise_private")) if server else key(revision["public_keys"]["noise"])
    lines = [f"[{kind}]", f'{"bind_addr" if server else "remote_addr"} = {json.dumps(f"{transport_ip}:{port}")}',
             f"default_token = {json.dumps(token)}", "", f"[{kind}.transport]", 'type = "noise"', "",
             f"[{kind}.transport.noise]", f'{"local_private_key" if server else "remote_public_key"} = {json.dumps(noise)}']
    for s in expanded_services(revision):
        address = f"{s['bind']}:{s['port']}" if server else f"{s['backend']['address']}:{s['target_port']}"
        lines += ["", f"[{kind}.services.{json.dumps(s['name'])}]", 'type = "tcp"',
                  f'{"bind_addr" if server else "local_addr"} = {json.dumps(address)}']
    return "\n".join(lines) + "\n"


def manifests(revision, role, credentials, facts=None, installation_id="00000000-0000-0000-0000-000000000000"):
    revision = validate_revision(revision)
    if role not in ("vps1", "vps2"):
        raise ValidationError("Invalid role")
    out = {}
    for profile in PROFILES:
        capability = capabilities(revision, profile)
        files, missing = {}, []
        try:
            if profile == "gre-kernel":
                files["rules.nft"] = render_kernel(revision, role, installation_id)
            elif "rathole" in profile:
                if any(s["protocol"] != "tcp" for s in revision["services"]):
                    raise ValidationError("No partial Rathole config for incompatible services")
                files["config.toml"] = render_rathole(revision, role, profile, credentials)
            else:
                files["config.yaml"] = paqet.render_config(revision, role, facts, credentials.get("paqet"))
                if role == "vps2":
                    files["rules.nft"] = paqet.packet_exceptions(revision, facts, table_name(revision["pair_id"]), installation_id)
        except ValidationError as exc:
            missing.append(str(exc))
        out[profile] = {"profile": profile, "role": role, "configured": True, **capability,
            "renderer_version": RENDERER_VERSION, "config_digest": digest(revision), "local_facts_digest": digest(facts),
            "pins": revision["pins"], "transport_port": revision["transport"]["port"],
            "transport_origin": "transport.port", "preparation_errors": missing,
            "files": files, "artifact_digest": digest(files),
            "requirements": (["GRE protocol 47"] if profile.startswith("gre-") else []) +
                            (list(paqet.SYSTEM_REQUIREMENTS) if profile == "direct-paqet" else [])}
    return out
