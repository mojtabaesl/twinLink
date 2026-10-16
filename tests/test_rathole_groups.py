"""Shared process lifecycle, migration, pairing and failure recovery."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from twinlink import cli, pairing, render
from twinlink.engine import ApplyError, Engine
from twinlink.models import ValidationError, validate_forward, validate_state
from twinlink.rathole_groups import groups
from twinlink.store import Store
from tests.test_engine import MemoryHost, active_state
from tests.test_rathole import KEYS, PRIVATE, noise_pair


class SharedRatholeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").exists() else None)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / "state")
        self.host = MemoryHost(self.store.directory, self.root / "units")
        self.engine = Engine(self.store, self.host, unit_dir=self.host.unit_dir, systemd=True)
        self.apply(active_state())

    def apply(self, candidate, boot=False):
        old = self.store.read()
        plan = self.engine.plan(old, candidate, "test shared Rathole")
        with self.store.lock():
            return self.engine.apply(old, candidate, plan, boot=boot)

    def prepare(self, *arguments):
        args = cli.build_parser().parse_args(list(arguments))
        with patch.object(cli.rathole, "generate_keypair", return_value=KEYS) as generate:
            candidate = cli.prepare(args, self.store.read())
        return candidate, generate.call_count

    def install_group(self):
        candidate, count = self.prepare("rathole", "add", "shared", "--tunnel", "edge", "--transport-port", "2444", "--ports", "8080:80,8443:443")
        self.assertEqual(count, 1)
        self.apply(candidate)
        return self.store.read()

    def test_one_file_unit_port_token_and_keypair_for_multiple_services(self):
        state = self.install_group()
        entries = list(state["forwards"].values())
        self.assertEqual({entry["transport_port"] for entry in entries}, {2444})
        self.assertEqual(len({entry["token"] for entry in entries}), 1)
        self.assertEqual([path.name for path in (self.store.directory / "rathole").glob("*.toml")], ["shared.toml"])
        config = (self.store.directory / "rathole/shared.toml").read_text()
        self.assertEqual(config.count("local_private_key ="), 1)
        self.assertEqual(config.count("default_token ="), 1)
        self.assertEqual(config.count('[server.services.'), 2)
        self.assertEqual({row["port"] for row in self.host.listeners()}, {2444, 8080, 8443})
        self.assertEqual([name for name in self.host.services if name.startswith("twinlink-rathole-")], ["twinlink-rathole-shared.service"])
        self.assertEqual(validate_state(state), {key: value for key, value in state.items() if not key.startswith("_")})

    def test_stop_and_delete_one_service_preserve_other_listener_and_shared_unit(self):
        self.install_group()
        candidate, _ = self.prepare("forward", "disable", "shared-8080")
        self.apply(candidate)
        self.assertEqual({row["port"] for row in self.host.listeners()}, {2444, 8443})
        self.assertTrue(self.host.services["twinlink-rathole-shared.service"]["active"])
        self.assertTrue(self.host.services["twinlink-rathole-shared.service"]["enabled"])
        state = self.store.read()
        status = self.host.forward_status(state["forwards"]["shared-8080"], state["tunnels"]["edge"], probe=False)
        self.assertFalse(status["drift"])
        candidate, _ = self.prepare("forward", "delete", "shared-8080")
        self.apply(candidate)
        self.assertTrue((self.store.directory / "rathole/shared.toml").exists())
        self.assertEqual({row["port"] for row in self.host.listeners()}, {2444, 8443})
        candidate, _ = self.prepare("forward", "delete", "shared-8443")
        self.apply(candidate)
        self.assertFalse((self.store.directory / "rathole/shared.toml").exists())
        self.assertFalse(self.host.listeners())

    def test_restart_is_once_per_group_and_boot_omits_disabled_service(self):
        self.install_group()
        self.host.commands.clear()
        candidate, _ = self.prepare("forward", "restart", "shared-8080")
        self.engine.force = ("forward", "shared-8080", "restart")
        self.apply(candidate)
        restarts = [argv for argv, _ in self.host.commands if argv == ["systemctl", "restart", "twinlink-rathole-shared.service"]]
        self.assertEqual(len(restarts), 1)
        del self.engine.force
        candidate, _ = self.prepare("forward", "disable", "shared-8080")
        self.apply(candidate)
        self.apply(self.store.read(), boot=True)
        self.assertEqual({row["port"] for row in self.host.listeners()}, {2444, 8443})

    def test_failed_group_restart_restores_original_config_listeners_and_state(self):
        old = self.install_group()
        config = self.store.directory / "rathole/shared.toml"
        original = config.read_bytes()
        candidate, count = self.prepare("rathole", "add", "shared", "--tunnel", "edge", "--ports", "9000:90")
        self.assertEqual(count, 0)
        self.host.fail_once.append(lambda argv, text: argv == ["systemctl", "restart", "twinlink-rathole-shared.service"])
        with self.assertRaises(ApplyError) as error:
            self.apply(candidate)
        self.assertFalse(error.exception.rollback_errors)
        self.assertEqual(self.store.read(), old)
        self.assertEqual(config.read_bytes(), original)
        self.assertEqual({row["port"] for row in self.host.listeners()}, {2444, 8080, 8443})
        self.assertFalse(self.store.journal.exists())

    def test_consolidation_removes_old_units_and_peer_import_replaces_all_records(self):
        source, peer = noise_pair()
        legacy = list(source["forwards"].values())
        old_code = pairing.export_rathole(legacy, source)
        for record in pairing.import_rathole(old_code, peer):
            peer["forwards"][record["name"]] = record
        candidate = self.store.read()
        candidate["forwards"] = source["forwards"]
        for entry in candidate["forwards"].values():
            entry.update(running=True, enabled=True)
        self.apply(candidate)
        candidate, count = self.prepare("rathole", "consolidate", "shared", "--tunnel", "edge", "--transport-port", "2333")
        self.assertEqual(count, 1)
        self.apply(candidate)
        self.assertEqual([path.name for path in (self.store.directory / "rathole").glob("*.toml")], ["shared.toml"])
        for name in ("web", "tls"):
            self.assertFalse((self.host.unit_dir / f"twinlink-rathole-{name}.service").exists())
            self.assertFalse(self.host.services[f"twinlink-rathole-{name}.service"]["active"])
            self.assertFalse(self.host.services[f"twinlink-rathole-{name}.service"]["enabled"])
        saved = self.store.read()
        code = pairing.export_rathole(list(saved["forwards"].values()), saved)
        imported = pairing.import_rathole(code, peer)
        for record in imported:
            peer["forwards"][record["name"]] = record
            self.assertNotIn("noise_private_key", record)
        files = render.render_files(validate_state(peer))
        self.assertEqual(len([path for path in files if path.endswith(".toml")]), 1)
        client = files["/var/lib/twinlink/rathole/shared.toml"]["content"]
        self.assertNotIn(PRIVATE, client)
        self.assertIn("remote_public_key", client)
        returned = pairing.import_rathole(pairing.export_rathole(imported, peer), saved)
        self.assertEqual({record["noise_private_key"] for record in returned}, {PRIVATE})

    def test_export_one_group_member_includes_whole_group(self):
        saved = self.install_group()
        code = pairing.export_rathole([saved["forwards"]["shared-8080"]], saved)
        self.assertEqual(len(pairing._decode(code, "rathole")["forwards"]), 2)
        _, peer = noise_pair()
        records = pairing.import_rathole(code, peer)
        self.assertEqual({record["rathole_group"] for record in records}, {"shared"})

    def test_peer_import_changes_shared_connection_port_for_all_existing_members(self):
        saved = self.install_group()
        _, peer = noise_pair()
        for record in pairing.import_rathole(pairing.export_rathole(list(saved["forwards"].values()), saved), peer):
            peer["forwards"][record["name"]] = record
        candidate, _ = self.prepare("rathole", "consolidate", "shared", "--tunnel", "edge", "--transport-port", "2555")
        self.apply(candidate)
        saved = self.store.read()
        updated = pairing.import_rathole(pairing.export_rathole(list(saved["forwards"].values()), saved), peer)
        self.assertEqual({record["transport_port"] for record in updated}, {2555})
        for record in updated:
            peer["forwards"][record["name"]] = record
        validate_state(peer)

    def test_shared_settings_mismatch_and_port_conflicts_are_rejected(self):
        saved = self.install_group()
        original = saved["forwards"]["shared-8080"]
        for change in ({"transport_port": 2555}, {"noise_public_key": PRIVATE}, {"rathole_group": "another"}):
            changed = {**original, **change}
            with self.subTest(change=change), self.assertRaises(ValidationError):
                validate_forward(changed, saved, existing_name=original["name"])
        with self.assertRaisesRegex(ValidationError, "consolidate"):
            self.prepare("forward", "edit", "shared-8080", "--transport-port", "2555")


if __name__ == "__main__":
    unittest.main()
