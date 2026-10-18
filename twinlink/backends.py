"""Pure resolution of canonical backend intent; no host or profile state."""
import copy
import ipaddress

from .models import ValidationError


def local(service):
    return service["backend"].get("target") == "vps2-local"


def address(revision, service, profile):
    if profile not in revision["profiles"]:
        raise ValidationError("Unknown backend profile")
    if local(service):
        return (str(ipaddress.IPv4Interface(revision["gre"]["addresses"]["vps2"]).ip)
                if profile == "gre-kernel" else "127.0.0.1")
    return service["backend"]["address"]


def promote(service):
    out = copy.deepcopy(service)
    if "target" not in out["backend"]:
        out["backend"]["target"] = "address"
    return out


def effective(revision):
    return {s["id"]: {p: {"address": address(revision, s, p), "ports": s["backend"]["ports"]}
                       for p in revision["profiles"]} for s in revision["services"]}


def readiness(revision, service, profile, assigned, listeners, *, allow_deferred=True):
    """Binding evidence is preliminary; never infer IPv4 from an IPv6 wildcard."""
    target = address(revision, service, profile)
    out = {"service": service["id"], "address": target, "probe_address": target,
           "result": "ready-to-probe", "firewall": "unknown; exact service-path exchange required"}
    if profile != "gre-kernel" or not local(service):
        return out
    rows = [row for row in listeners if row.get("protocol") == service["protocol"] and row.get("port") == service["target_port"]]
    wildcard = any(row.get("address") == "0.0.0.0" for row in rows)
    if target not in assigned:
        if not allow_deferred:
            return {**out, "result": "fail", "reason": "VPS2 GRE backend address is not assigned"}
        if not wildcard:
            return {**out, "result": "fail", "reason": "VPS2-local kernel backend requires an IPv4 wildcard binding before GRE exists; loopback-only binding is insufficient"}
        return {**out, "result": "deferred", "probe_address": "127.0.0.1",
                "reason": "GRE address delivery deferred until preparation; wildcard binding and loopback exchange are preliminary only"}
    if not wildcard and not any(row.get("address") == target for row in rows):
        return {**out, "result": "fail", "reason": "Backend is not bound to the VPS2 GRE address; loopback-only binding is insufficient"}
    return out
