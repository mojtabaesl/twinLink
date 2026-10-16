import base64
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import zipfile

from twinlink import pairing, rathole, render
from twinlink.engine import redacted
from twinlink.host import redact
from twinlink.models import ValidationError, empty_state, validate_forward, validate_state
from twinlink.store import StateError
from tests.test_models import tunnel

PRIVATE = base64.b64encode(bytes(range(1, 33))).decode()
PUBLIC = base64.b64encode(bytes(range(33, 65))).decode()
KEYS = {"noise_private_key": PRIVATE, "noise_public_key": PUBLIC}


def noise_pair():
    source = empty_state()
    source["tunnels"]["edge"] = tunnel(running=True, enabled=True)
    for name, public, destination in (("web", "8080", "80"), ("tls", "8443", "443")):
        entry = validate_forward({"name": name, "tunnel": "edge", "mode": "rathole", "bind_port": public,
                                  "destination_address": "127.0.0.1", "destination_port": destination,
                                  "rathole_transport": "noise", **KEYS}, source)
        source["forwards"][name] = entry
    peer = empty_state()
    peer_tunnel = pairing.import_tunnel(pairing.export_tunnel(source["tunnels"]["edge"]))
    peer_tunnel.update(verified=True, running=True, enabled=True)
    peer["tunnels"]["edge"] = peer_tunnel
    return source, peer


class NoisePairingTests(unittest.TestCase):
    def test_single_code_roundtrip_several_ports_without_private_key(self):
        source, peer = noise_pair()
        entries = list(source["forwards"].values())
        code = pairing.export_rathole(entries, source)
        self.assertTrue(code.startswith("r1."))
        wire = pairing._decode(code, "rathole")
        for item in wire["forwards"]:
            self.assertNotIn(PRIVATE, json.dumps(pairing._decode(item, "forward")))
        imported = pairing.import_rathole("\n" + code + "\n", peer)
        self.assertEqual([entry["bind_port"] for entry in imported], ["8080", "8443"])
        for entry in imported:
            original = source["forwards"][entry["name"]]
            self.assertEqual(entry["token"], original["token"])
            self.assertEqual(entry["noise_public_key"], PUBLIC)
            self.assertNotIn("noise_private_key", entry)
            self.assertEqual(entry["rathole_transport"], "noise")
            self.assertFalse(entry["running"])
            peer["forwards"][entry["name"]] = entry
        self.assertEqual(validate_state(peer), peer)
        # Re-exporting client changes preserves the original server identity.
        returned = pairing.import_rathole(pairing.export_rathole(imported, peer), source)
        self.assertEqual(returned[0]["noise_private_key"], PRIVATE)

    def test_noise_rendering_and_all_preview_redaction(self):
        source, peer = noise_pair()
        server = source["forwards"]["web"]
        imported = pairing.import_forward(pairing.export_forward(server, source["tunnels"]["edge"]), peer)
        server_text = render.render_rathole(server, source["tunnels"]["edge"])
        client_text = render.render_rathole(imported, peer["tunnels"]["edge"])
        self.assertIn('[server.transport]\ntype = "noise"', server_text)
        self.assertIn('local_private_key = "' + PRIVATE + '"', server_text)
        self.assertIn('remote_public_key = "' + PUBLIC + '"', client_text)
        self.assertNotIn(PRIVATE, client_text)
        for sanitized in (redacted({"entry": server, "config": server_text}),
                          redact({"entry": server, "config": server_text, "log": PRIVATE}, (PRIVATE,))):
            self.assertNotIn(PRIVATE, json.dumps(sanitized))
            self.assertNotIn(server["token"], json.dumps(sanitized))

    def test_rejects_bad_codes_duplicates_and_unverified_peers(self):
        source, peer = noise_pair()
        entries = list(source["forwards"].values())
        code = pairing.export_rathole(entries, source)
        for candidate in ("", "r2." + code[3:], "r1.!!", code[:-12], pairing.export_tunnel(source["tunnels"]["edge"])):
            with self.subTest(candidate=candidate[:12]), self.assertRaises(ValidationError):
                pairing.import_rathole(candidate, peer)
        forward_code = pairing.export_forward(entries[0], source["tunnels"]["edge"])
        duplicate = pairing._encode("rathole", {"forwards": [forward_code, forward_code]})
        with self.assertRaisesRegex(ValidationError, "duplicate"):
            pairing.import_rathole(duplicate, peer)
        peer["tunnels"]["edge"]["verified"] = False
        with self.assertRaisesRegex(ValidationError, "verify GRE"):
            pairing.import_rathole(code, peer)

    def test_noise_requires_keys_and_client_cannot_replace_server_identity(self):
        source, peer = noise_pair()
        entry = source["forwards"]["web"]
        for field in KEYS:
            for value in (None, "bad", base64.b64encode(bytes(32)).decode()):
                changed = {**entry, field: value}
                with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                    validate_forward(changed, source, existing_name="web")
        imported = pairing.import_rathole(pairing.export_rathole([entry], source), peer)[0]
        peer["forwards"]["web"] = imported
        imported["noise_public_key"] = PRIVATE
        with self.assertRaisesRegex(ValidationError, "private key never leaves"):
            pairing.import_rathole(pairing.export_rathole([imported], peer), source)

    def test_legacy_tcp_is_preserved(self):
        source, _ = noise_pair()
        entry = source["forwards"]["web"]
        entry.pop("rathole_transport")
        normalized = validate_forward(entry, source, existing_name="web")
        self.assertNotIn("noise_private_key", normalized)
        self.assertNotIn("transport.noise", render.render_rathole(normalized, source["tunnels"]["edge"]))


class RatholeInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").exists() else None)
        self.addCleanup(self.temp.cleanup)
        self.binary = Path(self.temp.name) / "bin" / "rathole"

    def archive(self, filename="rathole"):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as package:
            package.writestr(filename, b"trusted-test-executable")
        return output.getvalue()

    def native(self, argv, **kwargs):
        output = "rathole 0.5.0" if argv[1] == "--version" else f"Private Key:\n{PRIVATE}\nPublic Key:\n{PUBLIC}"
        return subprocess.CompletedProcess(argv, 0, output, "")

    def response(self, archive):
        response = io.BytesIO(archive)
        response.geturl = lambda: "https://release-assets.githubusercontent.com/test"
        return response

    def test_preview_selects_official_architecture_without_download_or_writes(self):
        for architecture, asset in (("x86_64", "x86_64-unknown-linux-gnu"), ("aarch64", "aarch64-unknown-linux-musl")):
            with patch.object(rathole.platform, "machine", return_value=architecture), patch.object(rathole.urllib.request, "urlopen") as download:
                plan = rathole.install_plan(str(self.binary))
            self.assertTrue(plan["url"].endswith("rathole-" + asset + ".zip"))
            download.assert_not_called()
            self.assertFalse(self.binary.parent.exists())

    def test_installs_verified_binary_then_reuses_it_without_download(self):
        archive = self.archive()
        checksum = hashlib.sha256(archive).hexdigest()
        with patch.object(rathole.platform, "machine", return_value="x86_64"), patch.object(rathole.urllib.request, "urlopen", return_value=self.response(archive)) as download, patch.object(rathole.subprocess, "run", side_effect=self.native):
            result = rathole.install(str(self.binary), checksum)
            self.assertEqual(self.binary.read_bytes(), b"trusted-test-executable")
            self.assertEqual(self.binary.stat().st_mode & 0o777, 0o755)
            self.assertTrue(result["installed"])
            self.assertTrue(rathole.install(str(self.binary))["already_installed"])
            self.assertEqual(download.call_count, 1)
            self.assertEqual(sorted(path.name for path in self.binary.parent.iterdir()), ["rathole"])

    def test_checksum_archive_and_native_failures_do_not_install(self):
        scenarios = [(self.archive(), "a" * 64, False), (self.archive("../../rathole"), None, False),
                     (b"not a zip", None, False), (self.archive(), None, True)]
        for archive, checksum, fail_native in scenarios:
            native = (lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1, PRIVATE, PRIVATE)) if fail_native else self.native
            with patch.object(rathole.platform, "machine", return_value="x86_64"), patch.object(rathole.urllib.request, "urlopen", return_value=self.response(archive)), patch.object(rathole.subprocess, "run", side_effect=native):
                with self.assertRaises(ValidationError) as error:
                    rathole.install(str(self.binary), checksum)
                self.assertNotIn(PRIVATE, str(error.exception))
            self.assertFalse(self.binary.exists())

    def test_download_failure_is_actionable_and_leaves_destination_absent(self):
        with patch.object(rathole.platform, "machine", return_value="x86_64"), patch.object(rathole.urllib.request, "urlopen", side_effect=urllib.error.URLError("blocked")):
            with self.assertRaisesRegex(ValidationError, "copy its binary securely"):
                rathole.install(str(self.binary))
        self.assertFalse(self.binary.exists())

    def test_refuses_symlinks_unsupported_architectures_and_bad_existing_version(self):
        self.binary.parent.mkdir()
        self.binary.symlink_to(self.binary.parent / "elsewhere")
        with self.assertRaises(StateError):
            rathole.install_plan(str(self.binary))
        self.binary.unlink()
        with patch.object(rathole.platform, "machine", return_value="unknown"):
            with self.assertRaisesRegex(ValidationError, "No automatic"):
                rathole.install_plan(str(self.binary))
        self.binary.write_bytes(b"foreign")
        self.binary.chmod(0o755)
        with patch.object(rathole.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "rathole 0.6.0", "")):
            with self.assertRaisesRegex(ValidationError, "never overwritten"):
                rathole.install(str(self.binary))
        self.assertEqual(self.binary.read_bytes(), b"foreign")

    def test_native_key_generation_accepts_upstream_format_and_redacts_failure(self):
        with patch.object(rathole.subprocess, "run", side_effect=self.native):
            self.assertEqual(rathole.generate_keypair("/opt/rathole"), KEYS)
        with patch.object(rathole.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, PRIVATE, PRIVATE)):
            with self.assertRaises(ValidationError) as error:
                rathole.generate_keypair("/opt/rathole")
            self.assertNotIn(PRIVATE, str(error.exception))

    def test_port_mappings_are_bounded_and_reject_duplicate_public_ports(self):
        self.assertEqual(rathole.port_mappings("8080:80, 8443:443,9000"), [(8080, 80), (8443, 443), (9000, 9000)])
        for value in ("", "0", "65536", "8080:80,8080:81", "80-90", "1:2:3", "8080;reboot"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                rathole.port_mappings(value)


if __name__ == "__main__":
    unittest.main()
