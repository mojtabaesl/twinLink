"""Bounded, checksummed copy/paste configuration exchange.

GRE codes contain no secrets. Forwarding codes intentionally contain a rathole
token and must be transferred in a private mode-0600 file over a secure channel.
Checksums detect corruption; they do not authenticate or encrypt either code.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import io
import json
import re
import struct
import zlib

from .models import ValidationError, empty_state, validate_forward, validate_tunnel

MAX_DECODED_SIZE = 65536
MAX_CODE_SIZE = 131072
TUNNEL_PREFIX = "v1."
FORWARD_PREFIX = "f1."
_TUNNEL_FIELDS = ("name", "side", "local_public", "remote_public", "local_private", "remote_private", "key", "mtu", "ttl")
_FORWARD_FIELDS = ("name", "mode", "protocol", "bind_address", "bind_port", "destination_address", "destination_port", "token", "transport_port", "relay_port", "revision")


def _encode(kind, payload):
    body = json.dumps({"version": 1, "kind": kind, **payload}, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(body) > MAX_DECODED_SIZE:
        raise ValidationError("pairing payload is too large")
    framed = struct.pack(">I", zlib.crc32(body)) + gzip.compress(body, mtime=0)
    prefix = TUNNEL_PREFIX if kind == "tunnel" else FORWARD_PREFIX
    return prefix + base64.urlsafe_b64encode(framed).decode("ascii").rstrip("=")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _decode(code, kind):
    if not isinstance(code, str):
        raise ValidationError("pairing code must be text")
    code = code.strip()
    if not code:
        raise ValidationError("pairing code is empty")
    if len(code) > MAX_CODE_SIZE:
        raise ValidationError("pairing code is too large")
    prefix = TUNNEL_PREFIX if kind == "tunnel" else FORWARD_PREFIX
    if not code.startswith(prefix):
        raise ValidationError(f"unsupported pairing type or version; expected {prefix}")
    encoded = code[len(prefix):]
    if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", encoded):
        raise ValidationError("pairing code is not valid base64url")
    try:
        framed = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        if len(framed) < 5:
            raise ValueError("short frame")
        checksum = struct.unpack(">I", framed[:4])[0]
        with gzip.GzipFile(fileobj=io.BytesIO(framed[4:])) as reader:
            body = reader.read(MAX_DECODED_SIZE + 1)
        if len(body) > MAX_DECODED_SIZE:
            raise ValidationError("pairing code expands beyond the 65536-byte safety limit")
        if zlib.crc32(body) != checksum:
            raise ValidationError("pairing checksum failed; copy the complete code again")
        payload = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object,
                             parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    except ValidationError:
        raise
    except (ValueError, TypeError, OSError, EOFError, UnicodeError, binascii.Error, struct.error, zlib.error, RecursionError):
        raise ValidationError("pairing code is corrupt or incomplete") from None
    if not isinstance(payload, dict) or type(payload.get("version")) is not int or payload.get("version") != 1 or payload.get("kind") != kind:
        raise ValidationError("pairing payload has an unsupported version or kind")
    return payload


def export_tunnel(tunnel):
    normalized = validate_tunnel(tunnel, empty_state())
    return _encode("tunnel", {"tunnel": {field: normalized[field] for field in _TUNNEL_FIELDS}})


def decode_tunnel(code):
    """Decode and validate the producer's GRE parameters without mutation."""
    payload = _decode(code, "tunnel")
    if set(payload) != {"version", "kind", "tunnel"} or not isinstance(payload.get("tunnel"), dict):
        raise ValidationError("pairing payload does not contain GRE tunnel parameters")
    if set(payload["tunnel"]) - set(_TUNNEL_FIELDS):
        raise ValidationError("GRE pairing payload contains unknown or secret fields")
    return validate_tunnel(payload["tunnel"], empty_state())


def import_tunnel(code, name=None):
    """Return the mirrored local tunnel; never mark imported GRE as verified."""
    source = decode_tunnel(code)
    imported = {field: source[field] for field in _TUNNEL_FIELDS}
    imported["name"] = name if name is not None else source["name"]
    imported["side"] = "vps2" if source["side"] == "vps1" else "vps1"
    for own, peer in (("local_public", "remote_public"), ("local_private", "remote_private")):
        imported[own], imported[peer] = source[peer], source[own]
    return validate_tunnel(imported, empty_state())


def preview_tunnel(code, name=None):
    """A ready-to-display import preview, without storing or applying it."""
    return import_tunnel(code, name=name)


def export_forward(entry, tunnel):
    state = empty_state()
    local_tunnel = validate_tunnel(tunnel, state)
    state["tunnels"][local_tunnel["name"]] = local_tunnel
    normalized = validate_forward(entry, state, existing_name=entry.get("name"))
    return _encode("forward", {
        "tunnel": {field: local_tunnel[field] for field in _TUNNEL_FIELDS},
        "forward": {field: normalized[field] for field in _FORWARD_FIELDS if field in normalized},
    })


def decode_forward(code):
    """Validate forwarding exchange. The return value includes its secret."""
    payload = _decode(code, "forward")
    if set(payload) != {"version", "kind", "tunnel", "forward"}:
        raise ValidationError("forward pairing payload has unexpected fields")
    if not isinstance(payload["tunnel"], dict) or set(payload["tunnel"]) - set(_TUNNEL_FIELDS):
        raise ValidationError("forward pairing contains invalid GRE parameters")
    if not isinstance(payload["forward"], dict) or set(payload["forward"]) - set(_FORWARD_FIELDS):
        raise ValidationError("forward pairing contains invalid forwarding parameters")
    tunnel = validate_tunnel(payload["tunnel"], empty_state())
    state = empty_state()
    state["tunnels"][tunnel["name"]] = tunnel
    candidate = {**payload["forward"], "tunnel": tunnel["name"]}
    if candidate.get("mode") == "rathole" and not candidate.get("token"):
        raise ValidationError("rathole pairing is missing its matching service token")
    entry = validate_forward(candidate, state, existing_name=candidate.get("name"))
    return {"tunnel": tunnel, "forward": entry}


def _matching_tunnel(source, state):
    opposite = "vps2" if source["side"] == "vps1" else "vps1"
    fields = ("local_public", "remote_public", "local_private", "remote_private")
    desired = dict(zip(fields, (source["remote_public"], source["local_public"], source["remote_private"], source["local_private"])))
    matches = [tunnel for tunnel in state.get("tunnels", {}).values()
               if tunnel.get("side") == opposite
               and all(tunnel.get(field) == value for field, value in desired.items())
               and all(tunnel.get(field) == source.get(field) for field in ("key", "mtu", "ttl"))]
    if len(matches) != 1:
        raise ValidationError("import and verify the matching GRE peer tunnel first; endpoints, private addresses, key, MTU and TTL must agree")
    return matches[0]


def import_forward(code, state, name=None):
    """Match the local peer tunnel and validate a stopped forwarding record.

    A matching existing name is an explicit configuration replacement, with its
    public bind retained as the actual VPS1 address on either host. The caller
    must preview, apply, verify and commit this returned configuration.
    """
    payload = decode_forward(code)
    if payload["forward"]["mode"] == "rathole" and name is not None and name != payload["forward"]["name"]:
        raise ValidationError("rathole forward name must match both servers because it identifies the service")
    tunnel = _matching_tunnel(payload["tunnel"], state)
    if not tunnel.get("verified"):
        raise ValidationError("verify GRE peer reachability before importing forwarding configuration")
    entry = payload["forward"].copy()
    entry.update(name=name if name is not None else entry["name"], tunnel=tunnel["name"],
                 side=tunnel["side"], enabled=False, running=False,
                 peer_revision=entry["revision"])
    existing = state.get("forwards", {}).get(entry["name"])
    if existing and existing.get("tunnel") != tunnel["name"]:
        raise ValidationError("existing forwarding name belongs to a different tunnel")
    if existing and entry["revision"] < existing.get("revision", 1):
        raise ValidationError("forward pairing revision is older than the local configuration")
    return validate_forward(entry, state, existing_name=entry["name"] if existing else None)


def preview_forward(code, state, name=None):
    result = import_forward(code, state, name=name)
    if "token" in result:
        result["token"] = "<redacted>"
        result["contains_secret"] = True
    return result
