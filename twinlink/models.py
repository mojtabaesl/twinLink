"""Validated configuration records. No functions here change the host network."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import secrets

from .rathole_groups import group_name


class ValidationError(ValueError):
    """An operator supplied configuration cannot safely be applied."""


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,47}$")
_PRIVATE = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def empty_state():
    return {"version": 1, "tunnels": {}, "forwards": {}}


def _name(value):
    if not isinstance(value, str) or not _NAME.fullmatch(value) or value in (".", ".."):
        raise ValidationError("name must be 1–48 letters, digits, dots, underscores or hyphens, starting with a letter or digit")
    return value


def interface_name(name):
    """A deterministic interface name in the app's own namespace (15 bytes)."""
    return "tl" + hashlib.sha256(_name(name).encode("ascii")).hexdigest()[:13]


def default_transport_port(name):
    return 20000 + int(hashlib.sha256(_name(name).encode("ascii")).hexdigest()[:8], 16) % 30000


def _integer(value, field, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValidationError(f"{field} must be an integer from {minimum} to {maximum}")
    if isinstance(value, str) and not re.fullmatch(r"[0-9]+", value):
        raise ValidationError(f"{field} must be an integer from {minimum} to {maximum}")
    try:
        number = int(value)
    except ValueError:
        raise ValidationError(f"{field} must be an integer from {minimum} to {maximum}") from None
    if not minimum <= number <= maximum:
        raise ValidationError(f"{field} must be from {minimum} to {maximum}")
    return number


def _boolean(value, field):
    if not isinstance(value, bool):
        raise ValidationError(f"{field} must be true or false")
    return value


def _ipv4(value, field, wildcard=False, loopback=False):
    try:
        if not isinstance(value, str):
            raise ValueError()
        address = ipaddress.IPv4Address(value)
    except (ValueError, ipaddress.AddressValueError):
        raise ValidationError(f"{field} must be an IPv4 address") from None
    if wildcard and address.is_unspecified:
        return str(address)
    if (address.is_unspecified or address.is_multicast or address.is_reserved
            or int(address) >= int(ipaddress.IPv4Address("240.0.0.0"))
            or str(address).startswith("0.") or address.is_link_local
            or (address.is_loopback and not loopback)):
        raise ValidationError(f"{field} must be a usable unicast IPv4 address")
    return str(address)


def _private(value, field):
    try:
        if not isinstance(value, str) or "/" not in value:
            raise ValueError()
        address = ipaddress.IPv4Interface(value)
    except (ValueError, ipaddress.AddressValueError):
        raise ValidationError(f"{field} must be an IPv4 host address with a CIDR prefix") from None
    if not any(address.network.subnet_of(network) for network in _PRIVATE):
        raise ValidationError(f"{field} must use an RFC1918 private subnet")
    if address.network.prefixlen < 31 and address.ip in (address.network.network_address, address.network.broadcast_address):
        raise ValidationError(f"{field} must be a usable host address, not the network or broadcast address")
    return address


def ports(value):
    """Parse a single port or inclusive port range; reject ambiguous syntax."""
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", value):
        raise ValidationError("port must be a number or an inclusive range such as 8000-8010")
    pieces = value.split("-")
    start = _integer(pieces[0], "port", 1, 65535)
    end = _integer(pieces[-1], "port", 1, 65535)
    if end < start:
        raise ValidationError("port range must be in ascending order")
    return start, end


def _port_string(value):
    first, last = ports(value)
    return str(first) if first == last else f"{first}-{last}"


def validate_tunnel(tunnel, state, existing_name=None):
    """Return a fresh, normalized tunnel, including managed-state conflicts.

    Live route, address and foreign interface ownership checks belong to the
    planner, which has access to the kernel. A name's interface is immutable.
    """
    if not isinstance(tunnel, dict):
        raise ValidationError("tunnel must be an object")
    name = _name(tunnel.get("name"))
    if existing_name is not None and name != existing_name:
        raise ValidationError("a tunnel's stable name cannot be changed")
    if name in state.get("tunnels", {}) and name != existing_name:
        raise ValidationError(f"tunnel {name!r} already exists")
    side = tunnel.get("side")
    if side not in ("vps1", "vps2"):
        raise ValidationError("side must be vps1 or vps2")
    local = _ipv4(tunnel.get("local_public"), "local_public")
    remote = _ipv4(tunnel.get("remote_public"), "remote_public")
    if local == remote:
        raise ValidationError("GRE public endpoints must differ")
    own = _private(tunnel.get("local_private"), "local_private")
    peer = _private(tunnel.get("remote_private"), "remote_private")
    if own.ip == peer.ip or own.network != peer.network:
        raise ValidationError("private GRE addresses must be distinct hosts in the same subnet and prefix")
    interface = interface_name(name)
    if tunnel.get("interface", interface) != interface:
        raise ValidationError("interface must be the generated twinlink interface name")
    key = tunnel.get("key")
    if key is not None:
        key = _integer(key, "key", 1, 4294967295)
    out = {
        "name": name, "side": side, "local_public": local, "remote_public": remote,
        "local_private": str(own), "remote_private": str(peer), "interface": interface,
        "key": key, "mtu": _integer(tunnel.get("mtu", 1472 if key is not None else 1476), "mtu", 576, 1476),
        "ttl": _integer(tunnel.get("ttl", 64), "ttl", 1, 255),
    }
    for field in ("enabled", "running", "verified"):
        out[field] = _boolean(tunnel.get(field, False), field)
    for other_name, other in state.get("tunnels", {}).items():
        if other_name == existing_name:
            continue
        if other.get("interface") == interface:
            raise ValidationError(f"interface is already used by tunnel {other_name!r}")
        if {other.get("local_public"), other.get("remote_public")} == {local, remote} and other.get("key") == key:
            raise ValidationError(f"GRE endpoints and key conflict with tunnel {other_name!r}")
        try:
            existing_network = ipaddress.IPv4Interface(other["local_private"]).network
        except (ValueError, KeyError):
            raise ValidationError(f"stored tunnel {other_name!r} has an invalid private subnet") from None
        if own.network.overlaps(existing_network):
            raise ValidationError(f"private GRE subnet overlaps tunnel {other_name!r}")
    return out


def _overlap(first, second):
    a, b = ports(first)
    c, d = ports(second)
    return a <= d and c <= b


def _addresses_overlap(first, second):
    return first == second or first in ("0.0.0.0", "::", "*") or second in ("0.0.0.0", "::", "*")


def _listener_conflict(address, port, protocol, listeners, existing_name):
    for listener in listeners:
        # Ownership may only be supplied after the caller verified the process
        # and unit; a coincidental port/name is not evidence of ownership.
        if existing_name and listener.get("managed") == existing_name:
            continue
        if listener.get("protocol", "tcp") != protocol:
            continue
        listener_port = listener.get("port")
        listener_address = listener.get("address", "0.0.0.0")
        if _addresses_overlap(address, listener_address) and _overlap(port, listener_port):
            raise ValidationError(f"{protocol} port {port} conflicts with an existing host listener at {listener_address}:{listener_port}")


def validate_forward(entry, state, existing_name=None, listeners=(), protected_ports=(22,), require_noise_private=True):
    """Normalize a forward and reject local and managed public port conflicts.

    Public bind addresses are canonical VPS1 addresses on both hosts. Disabled
    records reserve their ports so enabling cannot unexpectedly steal a port.
    Rathole UDP remains unsupported until version-specific end-to-end proof.
    """
    if not isinstance(entry, dict):
        raise ValidationError("forward must be an object")
    name = _name(entry.get("name"))
    if existing_name is not None and name != existing_name:
        raise ValidationError("a forwarding entry's stable name cannot be changed")
    if name in state.get("forwards", {}) and name != existing_name:
        raise ValidationError(f"forward {name!r} already exists")
    tunnel_name = entry.get("tunnel")
    if not isinstance(tunnel_name, str):
        raise ValidationError("forward must refer to an existing GRE tunnel")
    tunnel = state.get("tunnels", {}).get(tunnel_name)
    if tunnel is None:
        raise ValidationError("forward must refer to an existing GRE tunnel")
    if existing_name is None and not tunnel.get("verified"):
        raise ValidationError("verify GRE peer reachability with tunnel check before adding forwarding")
    side = tunnel["side"]
    if entry.get("side", side) != side:
        raise ValidationError("forward side must match its local tunnel")
    mode = entry.get("mode", "kernel")
    if mode not in ("kernel", "rathole"):
        raise ValidationError("mode must be kernel or rathole")
    protocol = entry.get("protocol", "tcp")
    if protocol not in ("tcp", "udp"):
        raise ValidationError("protocol must be tcp or udp")
    if mode == "rathole" and protocol != "tcp":
        raise ValidationError("rathole UDP is unavailable: a selected version must pass end-to-end tests first")
    vps1_public = tunnel["local_public"] if side == "vps1" else tunnel["remote_public"]
    bind = _ipv4(entry.get("bind_address", vps1_public), "bind_address", wildcard=True)
    # VPS1 may expose a secondary public address. Its actual assignment is
    # checked against live host addresses by Engine.safety; the peer retains
    # this canonical VPS1 bind rather than substituting its own endpoint.
    bind_port = _port_string(entry.get("bind_port"))
    destination = _ipv4(entry.get("destination_address"), "destination_address", loopback=mode == "rathole")
    dest_port = _port_string(entry.get("destination_port"))
    first, last = ports(bind_port)
    dest_first, dest_last = ports(dest_port)
    if mode == "rathole" and (first != last or dest_first != dest_last):
        raise ValidationError("rathole entries require a single bind and destination port")
    if last - first >= 256:
        raise ValidationError("a forwarding range may contain at most 256 ports")
    if mode == "kernel" and dest_last != dest_first and last - first != dest_last - dest_first:
        raise ValidationError("destination range must match the bind range size or be a single port")
    for protected in {22, *protected_ports}:
        if _overlap(bind_port, protected):
            raise ValidationError(f"public bind range includes protected SSH/management port {protected}")
    out = {
        "name": name, "tunnel": tunnel_name, "side": side, "mode": mode, "protocol": protocol,
        "bind_address": bind, "bind_port": bind_port,
        "destination_address": destination, "destination_port": dest_port,
        "enabled": _boolean(entry.get("enabled", False), "enabled"),
        "running": _boolean(entry.get("running", False), "running"),
        "revision": _integer(entry.get("revision", 1), "revision", 1, 2147483647),
        "peer_revision": entry.get("peer_revision"),
    }
    if out["peer_revision"] is not None:
        out["peer_revision"] = _integer(out["peer_revision"], "peer_revision", 1, 2147483647)
    if mode == "rathole":
        token = entry.get("token")
        if token is None:
            token = secrets.token_urlsafe(32)
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
            raise ValidationError("rathole token must contain 32–128 URL-safe letters, digits, underscores or hyphens")
        out["token"] = token
        if entry.get("rathole_group") is not None:
            out["rathole_group"] = _name(entry["rathole_group"])
        out["transport_port"] = _integer(entry.get("transport_port", default_transport_port(name)), "transport_port", 1024, 65535)
        transport = entry.get("rathole_transport", "tcp")
        if transport not in ("tcp", "noise"):
            raise ValidationError("rathole_transport must be tcp or noise")
        # Missing transport preserves compatibility with existing TCP records.
        if "rathole_transport" in entry:
            out["rathole_transport"] = transport
        if transport == "noise":
            from .rathole import key
            out["noise_public_key"] = key(entry.get("noise_public_key"))
            if side == "vps1" and require_noise_private:
                out["noise_private_key"] = key(entry.get("noise_private_key"))
    else:
        if entry.get("rathole_transport") is not None or entry.get("rathole_group") is not None:
            raise ValidationError("Noise transport applies only to rathole forwarding")
        width = last - first + 1
        relay_first = 20000 + int(hashlib.sha256(name.encode("ascii")).hexdigest()[:8], 16) % (40000 - width)
        default_relay = str(relay_first) if width == 1 else f"{relay_first}-{relay_first + width - 1}"
        out["relay_port"] = _port_string(entry.get("relay_port", default_relay))
        relay_first, relay_last = ports(out["relay_port"])
        if relay_first < 1024 or relay_last - relay_first != last - first:
            raise ValidationError("kernel relay range must start above port 1023 and match the public range size")
    for protected in {22, *protected_ports}:
        internal_port = out.get("relay_port", out.get("transport_port"))
        if _overlap(internal_port, protected):
            raise ValidationError(f"GRE relay/transport range includes protected SSH/management port {protected}")
    for other_name, other in state.get("forwards", {}).items():
        if other_name == existing_name:
            continue
        shared = mode == "rathole" and other.get("mode") == "rathole" and group_name(out) == group_name(other)
        if shared:
            fields = ("tunnel", "side", "transport_port", "noise_public_key", "noise_private_key")
            if (any(out.get(field) != other.get(field) for field in fields)
                    or out.get("rathole_transport", "tcp") != other.get("rathole_transport", "tcp")):
                raise ValidationError("Services in a Rathole group must share tunnel, transport port and Noise keys")
        if protocol == other.get("protocol") and _addresses_overlap(bind, other.get("bind_address")) and _overlap(bind_port, other.get("bind_port")):
            raise ValidationError(f"public bind overlaps forwarding entry {other_name!r}, including reserved disabled entries")
        if not shared and mode == "rathole" and other.get("mode") == "rathole" and out["transport_port"] == other.get("transport_port"):
            own_network = ipaddress.IPv4Interface(tunnel["local_private"]).network
            other_tunnel = state["tunnels"][other["tunnel"]]
            if own_network == ipaddress.IPv4Interface(other_tunnel["local_private"]).network:
                raise ValidationError(f"rathole GRE transport port conflicts with entry {other_name!r}")
        if not shared and mode == "rathole" and other.get("mode") == "rathole" and out["token"] == other.get("token"):
            raise ValidationError("separate Rathole groups require different service tokens")
        # Public wildcard listeners also cover private GRE addresses. Compare
        # rathole's private VPS1 TCP listener with all canonical public binds.
        if mode == "rathole" and other.get("protocol") == "tcp" and other.get("bind_address") == "0.0.0.0" and _overlap(out["transport_port"], other["bind_port"]):
            raise ValidationError(f"rathole GRE transport listener overlaps wildcard public entry {other_name!r}")
        if bind == "0.0.0.0" and protocol == "tcp" and other.get("mode") == "rathole" and _overlap(bind_port, other["transport_port"]):
            raise ValidationError(f"wildcard public listener overlaps rathole transport for {other_name!r}")
        if tunnel_name == other.get("tunnel"):
            own_relay = out.get("relay_port", out.get("transport_port"))
            other_relay = other.get("relay_port", other.get("transport_port"))
            if not shared and own_relay is not None and other_relay is not None and _overlap(own_relay, other_relay):
                # Rathole connects to VPS1 and kernel transit reaches VPS2.
                # Reserve both ports anyway, including future side changes.
                if protocol == other.get("protocol") or mode == "rathole" or other.get("mode") == "rathole":
                    raise ValidationError(f"GRE relay/transport port overlaps entry {other_name!r}")
    # Only VPS1 exposes the public service; VPS2 must not conflict-check its
    # unrelated local listeners against a public address on the other host.
    if side == "vps1":
        owner = group_name(out) if mode == "rathole" else existing_name
        _listener_conflict(bind, bind_port, protocol, listeners, owner)
        if mode == "rathole":
            private_address = str(ipaddress.IPv4Interface(tunnel["local_private"]).ip)
            _listener_conflict(private_address, out["transport_port"], "tcp", listeners, owner)
            if _addresses_overlap(bind, private_address) and _overlap(bind_port, out["transport_port"]):
                raise ValidationError("rathole public listener overlaps its own GRE connection listener")
    elif mode == "kernel":
        private_address = str(ipaddress.IPv4Interface(tunnel["local_private"]).ip)
        _listener_conflict(private_address, out["relay_port"], protocol, listeners, existing_name)
    return out


def validate_state(state):
    """Return a fully normalized state, or fail closed on malformed storage."""
    if not isinstance(state, dict) or type(state.get("version")) is not int or state.get("version") != 1:
        raise ValidationError("unsupported or missing state version (expected 1)")
    if not isinstance(state.get("tunnels"), dict) or not isinstance(state.get("forwards"), dict):
        raise ValidationError("state must contain tunnel and forward objects")
    out = empty_state()
    for name, tunnel in state["tunnels"].items():
        if not isinstance(tunnel, dict) or tunnel.get("name") != name:
            raise ValidationError("stored tunnel name does not match its key")
        out["tunnels"][name] = validate_tunnel(tunnel, out)
    for name, entry in state["forwards"].items():
        if not isinstance(entry, dict) or entry.get("name") != name:
            raise ValidationError("stored forward name does not match its key")
        if entry.get("mode") == "rathole" and not entry.get("token"):
            raise ValidationError("stored rathole entry is missing its service token; restore the matching private configuration")
        # Stored forwards can outlive a failed GRE health check. Validation
        # must still permit loading them to stop, inspect or repair them.
        out["forwards"][name] = validate_forward(entry, out, existing_name=name)
    return out
