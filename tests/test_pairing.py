import base64
import gzip
import json
import struct
import unittest
import zlib

from twinlink.models import ValidationError, empty_state, validate_forward, validate_tunnel
from twinlink.pairing import (decode_forward, decode_tunnel, export_forward,
                              export_tunnel, import_forward, import_tunnel,
                              preview_forward, preview_tunnel)


def source_tunnel():
    return validate_tunnel(dict(name="edge", side="vps1", local_public="198.51.100.1",
                                remote_public="203.0.113.2", local_private="10.77.0.1/30",
                                remote_private="10.77.0.2/30", key=42, verified=True), empty_state())


def frame(body, prefix="v1."):
    return prefix + base64.urlsafe_b64encode(struct.pack(">I", zlib.crc32(body)) + gzip.compress(body)).decode().rstrip("=")


class TunnelPairingTests(unittest.TestCase):
    def test_roundtrip_swaps_exact_addresses_side_and_resets_runtime(self):
        original = source_tunnel()
        original.update(token="must-never-export", enabled=True, running=True)
        code = export_tunnel(original)
        source = decode_tunnel(code)
        self.assertNotIn("token", source)
        peer = import_tunnel(code, name="renamed")
        self.assertEqual(peer["side"], "vps2")
        self.assertEqual(peer["local_public"], original["remote_public"])
        self.assertEqual(peer["remote_private"], original["local_private"])
        for field in ("enabled", "running", "verified"):
            self.assertFalse(peer[field])
        restored = import_tunnel(export_tunnel(peer), name="edge")
        for field in ("local_public", "remote_public", "local_private", "remote_private", "key", "mtu", "ttl", "interface"):
            self.assertEqual(restored[field], original[field])
        self.assertEqual(preview_tunnel(code), import_tunnel(code))

    def test_corruption_bad_prefix_and_invalid_base64_rejected(self):
        code = export_tunnel(source_tunnel())
        framed = bytearray(base64.urlsafe_b64decode(code[3:] + "=" * (-len(code[3:]) % 4)))
        framed[0] ^= 1
        corrupt = "v1." + base64.urlsafe_b64encode(framed).decode().rstrip("=")
        for candidate in ("", "v2." + code[3:], "v1.!!", code[:-10], corrupt):
            with self.subTest(candidate=candidate[:20]), self.assertRaises(ValidationError):
                import_tunnel(candidate)

    def test_padded_codes_and_clipboard_whitespace(self):
        code = export_tunnel(source_tunnel())
        self.assertEqual(import_tunnel("\n" + code + "=" * (-len(code[3:]) % 4) + "\n"), import_tunnel(code))

    def test_size_duplicate_field_and_secret_field_rejection(self):
        huge = frame(b" " * 65537)
        with self.assertRaisesRegex(ValidationError, "safety limit"):
            decode_tunnel(huge)
        duplicate = frame(b'{"version":1,"version":1,"kind":"tunnel","tunnel":{}}')
        with self.assertRaises(ValidationError):
            decode_tunnel(duplicate)
        payload = {"version": 1, "kind": "tunnel", "tunnel": {**source_tunnel(), "token": "secret"}}
        with self.assertRaisesRegex(ValidationError, "unknown or secret"):
            decode_tunnel(frame(json.dumps(payload).encode()))
        with self.assertRaisesRegex(ValidationError, "too large"):
            decode_tunnel("v1." + "A" * 131073)


class ForwardPairingTests(unittest.TestCase):
    def setup_pair(self, mode="rathole"):
        source = source_tunnel()
        source_state = empty_state()
        source_state["tunnels"][source["name"]] = source
        entry = validate_forward(dict(name="web", tunnel="edge", mode=mode, bind_port="8080",
                                      destination_address="10.1.2.3", destination_port="80", revision=3), source_state)
        peer = import_tunnel(export_tunnel(source), name="peer-name")
        peer["verified"] = True
        state = empty_state()
        state["tunnels"][peer["name"]] = peer
        return source, entry, state

    def test_secure_token_and_service_identity_match_on_peer(self):
        source, entry, state = self.setup_pair()
        code = export_forward(entry, source)
        peer = import_forward(code, state)
        for field in ("name", "token", "transport_port", "bind_address", "bind_port", "destination_address", "destination_port", "revision"):
            self.assertEqual(peer[field], entry[field])
        self.assertEqual(peer["tunnel"], "peer-name")
        self.assertEqual(peer["side"], "vps2")
        self.assertEqual(peer["peer_revision"], 3)
        self.assertFalse(peer["enabled"])
        self.assertFalse(peer["running"])
        self.assertEqual(preview_forward(code, state)["token"], "<redacted>")
        self.assertTrue(preview_forward(code, state)["contains_secret"])

    def test_kernel_relay_port_is_preserved(self):
        source, entry, state = self.setup_pair(mode="kernel")
        peer = import_forward(export_forward(entry, source), state)
        self.assertEqual(peer["relay_port"], entry["relay_port"])
        self.assertNotIn("token", decode_forward(export_forward(entry, source))["forward"])

    def test_missing_unverified_or_wrong_tunnel_refused(self):
        source, entry, state = self.setup_pair()
        code = export_forward(entry, source)
        with self.assertRaisesRegex(ValidationError, "matching GRE"):
            import_forward(code, empty_state())
        state["tunnels"]["peer-name"]["verified"] = False
        with self.assertRaisesRegex(ValidationError, "verify GRE"):
            import_forward(code, state)
        state["tunnels"]["peer-name"]["verified"] = True
        state["tunnels"]["peer-name"]["key"] = 999
        with self.assertRaisesRegex(ValidationError, "matching GRE"):
            import_forward(code, state)

    def test_revision_updates_and_stale_import_rejected(self):
        source, entry, state = self.setup_pair()
        state["forwards"]["web"] = import_forward(export_forward(entry, source), state)
        entry.update(revision=4, destination_port="81")
        replacement = import_forward(export_forward(entry, source), state)
        self.assertEqual(replacement["destination_port"], "81")
        self.assertEqual(replacement["peer_revision"], 4)
        state["forwards"]["web"] = replacement
        entry["revision"] = 3
        with self.assertRaisesRegex(ValidationError, "older"):
            import_forward(export_forward(entry, source), state)


if __name__ == "__main__":
    unittest.main()
