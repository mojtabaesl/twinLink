"""One bounded authenticated pair bundle; secret data never belongs in argv."""
import base64
import binascii
import gzip
import hashlib
import hmac
import io
import re
import secrets
import struct
import zlib

from .contracts import canonical, digest, strict_json, fields, validate_revision
from .models import ValidationError

MAX_ENCODED, MAX_DECODED = 131072, 65536


def credentials(noise=None):
    out = {"management": secrets.token_hex(32), "rathole": secrets.token_urlsafe(32),
           "paqet": secrets.token_urlsafe(32)}
    if noise:
        out["noise_private"] = noise["noise_private_key"]
    return out


def management_key(value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value):
        raise ValidationError("Management key must be 256-bit hex")
    return bytes.fromhex(value)


def mac(value, key):
    return hmac.new(management_key(key), canonical(value), hashlib.sha256).hexdigest()


def fingerprint(code):
    return hashlib.sha256(code.strip().encode()).hexdigest()


def encode(revision, local_credentials, authenticated=True):
    revision = validate_revision(revision)
    shared = {key: local_credentials[key] for key in ("management", "rathole", "paqet")}
    body = {"schema_version": 2, "sender": "vps1", "recipient": "vps2", "revision": revision,
            "digest": digest(revision), "credentials": shared}
    envelope = {"body": body, "hmac": mac(body, shared["management"]) if authenticated else None}
    data = canonical(envelope)
    if len(data) > MAX_DECODED:
        raise ValidationError("Pair bundle exceeds 64 KiB")
    code = "p2." + base64.urlsafe_b64encode(struct.pack(">I", zlib.crc32(data)) + gzip.compress(data, mtime=0)).decode().rstrip("=")
    if len(code) > MAX_ENCODED:
        raise ValidationError("Pair bundle exceeds 128 KiB")
    return code


def decode(code, expected_fingerprint=None, stored_management_key=None):
    if not isinstance(code, str) or len(code) > MAX_ENCODED:
        raise ValidationError("Invalid or oversized pair bundle")
    code = code.strip()
    if not code.startswith("p2.") or not re.fullmatch(r"[A-Za-z0-9_-]+", code[3:]):
        raise ValidationError("Expected a p2. bundle; legacy codes are migration inputs only")
    if stored_management_key is None:
        if not isinstance(expected_fingerprint, str) or not hmac.compare_digest(fingerprint(code), expected_fingerprint.lower()):
            raise ValidationError("Compare the complete bundle SHA256 over an independently trusted channel; expected fingerprint required")
    try:
        framed = base64.b64decode(code[3:] + "=" * (-len(code[3:]) % 4), altchars=b"-_", validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(framed[4:])) as stream:
            data = stream.read(MAX_DECODED + 1)
        if len(data) > MAX_DECODED or len(framed) < 5 or zlib.crc32(data) != struct.unpack(">I", framed[:4])[0]:
            raise ValueError()
        envelope = strict_json(data)
    except (ValueError, OSError, EOFError, binascii.Error, struct.error, zlib.error):
        raise ValidationError("Corrupt or oversized pair bundle") from None
    fields(envelope, ("body", "hmac"))
    body = envelope["body"]
    fields(body, ("schema_version", "sender", "recipient", "revision", "digest", "credentials"))
    if type(body["schema_version"]) is not int or body["schema_version"] != 2 or body["sender"] != "vps1" or body["recipient"] != "vps2":
        raise ValidationError("Invalid pair bundle roles or schema")
    revision = validate_revision(body["revision"])
    if body["digest"] != digest(revision):
        raise ValidationError("Pair revision digest mismatch")
    creds = body["credentials"]
    fields(creds, ("management", "rathole", "paqet"))
    management_key(creds["management"])
    for key in ("rathole", "paqet"):
        if not isinstance(creds[key], str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", creds[key]):
            raise ValidationError("Invalid transport credential")
    if stored_management_key:
        if creds["management"] != stored_management_key or not isinstance(envelope["hmac"], str) or not hmac.compare_digest(
                envelope["hmac"], mac(body, stored_management_key)):
            raise ValidationError("Pair bundle authentication failed")
    return revision, creds
