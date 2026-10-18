"""Inject local Linux resource behavior; no test changes the host network."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from twinlink.profile_runtime import ProfileRuntime, nft_expectation
from twinlink.profiles import gre_record, table_name
from twinlink.cleanup import delete_pair
from twinlink.store import StateError, Store
from twinlink.coordination import Coordinator, steps
from tests.test_v2 import V2Fixture, FakeRuntime


class SystemHost:
    def __init__(self, unit_dir):
        self.unit_dir = Path(unit_dir)
        self.commands, self.link_rows, self.addr_rows, self.route_rows = [], [], [], []
        self.tables, self.enabled, self.active = {}, set(), set()
        self.forwarding = "0"

    def require_linux_root(self):
        pass

    def run(self, argv, check=True, input=None, timeout=15):
        self.commands.append(list(argv))
        out, err, code = "", "", 0
        if argv[:4] == ["ip", "-j", "route", "get"]:
            found = [row for row in self.route_rows if row.get("dst") != "default" and ipaddress.IPv4Address(argv[4]) in ipaddress.IPv4Network(row["dst"])]
            out = json.dumps(found[:1])
        elif argv[:3] == ["nft", "-j", "list"]:
            if argv[-1] in self.tables:
                out = json.dumps(self.tables[argv[-1]])
            else:
                code, err = 1, "No such file or directory"
        elif argv[:3] == ["nft", "--file", "-"]:
            spec = nft_expectation(input)
            table = spec["table"]
            rows = [{"table": {"name": table, "family": "ip", "comment": spec["comment"]}}]
            for name, contract in spec["chains"].items():
                rows.append({"chain": {"name": name, "family": "ip", "table": table, **contract}})
                rows.extend({"rule": {"family": "ip", "table": table, "chain": name, **r}} for r in spec["rules"][name])
            self.tables[table] = {"nftables": rows}
        elif argv[:3] == ["nft", "delete", "table"]:
            self.tables.pop(argv[-1], None)
        elif argv[:3] in (["ip", "tunnel", "add"], ["ip", "link", "add"]):
            name = argv[argv.index("name") + 1] if "name" in argv else argv[3]
            row = {"ifname": name, "mtu": 1476, "flags": [], "linkinfo": {"info_kind": "gre", "info_data": {
                "local": argv[argv.index("local") + 1], "remote": argv[argv.index("remote") + 1], "ttl": int(argv[argv.index("ttl") + 1])}}}
            if "key" in argv:
                row["linkinfo"]["info_data"].update(ikey=int(argv[-1]), okey=int(argv[-1]))
            if "alias" in argv:
                row["ifalias"] = argv[argv.index("alias") + 1]
            if "mtu" in argv:
                row["mtu"] = int(argv[argv.index("mtu") + 1])
            self.link_rows.append(row)
        elif argv[:3] == ["ip", "link", "set"]:
            name = argv[argv.index("dev") + 1]
            row = next(row for row in self.link_rows if row["ifname"] == name)
            if "alias" in argv:
                row["ifalias"] = argv[-1]
            if "mtu" in argv:
                row["mtu"] = int(argv[argv.index("mtu") + 1])
                row["flags"] = ["UP"]
        elif argv[:3] == ["ip", "address", "replace"]:
            address = ipaddress.IPv4Interface(argv[3])
            self.addr_rows = [r for r in self.addr_rows if r["ifname"] != argv[-1]]
            self.addr_rows.append({"ifname": argv[-1], "addr_info": [{"family": "inet", "local": str(address.ip), "prefixlen": address.network.prefixlen}]})
            self.route_rows = [r for r in self.route_rows if r.get("dev") != argv[-1]]
            self.route_rows.append({"dst": str(address.network), "dev": argv[-1], "protocol": "kernel"})
        elif argv[:3] == ["ip", "link", "delete"]:
            self.link_rows = [r for r in self.link_rows if r["ifname"] != argv[-1]]
            self.addr_rows = [r for r in self.addr_rows if r["ifname"] != argv[-1]]
            self.route_rows = [r for r in self.route_rows if r.get("dev") != argv[-1]]
        elif argv[0] == "sysctl":
            if argv[1] == "-w":
                self.forwarding = argv[-1].split("=")[-1]
            out = self.forwarding
        elif argv[0] == "systemctl" and len(argv) > 2:
            action, name = argv[1], argv[2]
            if action == "enable":
                self.enabled.add(name)
            if action == "disable":
                self.enabled.discard(name)
            if action == "start":
                self.active.add(name)
            if action == "stop":
                self.active.discard(name)
        return {"returncode": code, "stdout": out, "stderr": err}

    def links(self):
        return copy.deepcopy(self.link_rows)

    def addresses(self):
        return [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "198.51.100.1", "prefixlen": 24}]}] + copy.deepcopy(self.addr_rows)

    def routes(self):
        return copy.deepcopy(self.route_rows)

    def listeners(self):
        return []

    def unit_status(self, name):
        path = self.unit_dir / name
        return {"active": name in self.active, "enabled": name in self.enabled,
                "exists": path.exists(), "properties": {"FragmentPath": str(path), "DropInPaths": ""}}


class ProfileRuntimeTests(V2Fixture):
    def setUp(self):
        super().setUp()
        self.state = self.stage()
        self.host = SystemHost(self.root / "units")
        self.runtime = ProfileRuntime(self.store, self.host, str(self.root / "units"))

    def test_kernel_prepare_start_quiesce_restores_setting(self):
        c = self.state["pairs"]["edge"]
        tx = {"previous": None}
        self.runtime.prepare(self.r, "vps1", "gre-kernel", c, tx)
        self.runtime.start(self.r, "vps1", "gre-kernel", c, tx)
        self.assertEqual(self.host.forwarding, "1")
        self.assertTrue(self.host.tables)
        # Exact step retries are idempotent and require no binaries/downloads.
        self.runtime.prepare(self.r, "vps1", "gre-kernel", c, tx)
        self.runtime.start(self.r, "vps1", "gre-kernel", c, tx)
        self.runtime.quiesce(self.r, "vps1", "gre-kernel", c, tx)
        self.assertFalse(self.host.tables)
        self.assertFalse(self.host.link_rows)
        self.assertEqual(self.host.forwarding, "0")
        self.runtime.quiesce(self.r, "vps1", "gre-kernel", c, tx)

    def test_foreign_table_interface_and_manual_sysctl_changes_preserved(self):
        t = gre_record(self.r, "vps1")
        self.host.link_rows = [{"ifname": t["interface"], "mtu": 1500, "linkinfo": {"info_kind": "dummy"}}]
        with self.assertRaises(StateError):
            self.runtime.prepare(self.r, "vps1", "gre-kernel", self.state["pairs"]["edge"], {"previous": None})
        self.host.link_rows = []
        self.runtime.prepare(self.r, "vps1", "gre-kernel", self.state["pairs"]["edge"], {"previous": None})
        self.runtime.start(self.r, "vps1", "gre-kernel", self.state["pairs"]["edge"], {"previous": None})
        self.host.tables[table_name("edge")]["nftables"].append({"foreign": True})
        with self.assertRaises(StateError):
            self.runtime.quiesce(self.r, "vps1", "gre-kernel", self.state["pairs"]["edge"], {"previous": None})
        self.assertTrue(self.host.tables)

    def test_pair_deletion_scrubs_credentials_and_preserves_foreign_files(self):
        foreign = self.store.directory / "revisions" / "edge" / "notes"
        foreign.write_text("operator-owned")
        with self.assertRaises(StateError):
            delete_pair(self.store, self.runtime, "edge")
        self.assertTrue(self.store.credential_path("edge", 1).exists())
        foreign.unlink()
        delete_pair(self.store, self.runtime, "edge")
        self.assertFalse(self.store.read()["pairs"])
        for path in self.store.directory.rglob("*"):
            if path.is_file():
                self.assertNotIn(self.creds["paqet"], path.read_text(), str(path))

    def test_coordinated_recovery_to_off_after_partial_target_start(self):
        peer = Store(self.root / "peer")
        self.stage("vps2", peer)
        a, b = FakeRuntime(), FakeRuntime()
        incoming = None
        for role, action in steps("direct-rathole"):
            store, rt = (self.store, a) if role == "vps1" else (peer, b)
            if action == "start":
                rt.fail = "start"
                with self.assertRaises(RuntimeError):
                    Coordinator(store, rt, lambda: 100).advance("edge", self.r, "direct-rathole", incoming)
                break
            incoming = Coordinator(store, rt, lambda: 100).advance("edge", self.r, "direct-rathole", incoming)["receipt"]
        a.fail = b.fail = None
        coord = Coordinator(self.store, a, lambda: 101)
        old, target = coord.begin_recovery("edge")
        self.assertIsNone(target)
        incoming = None
        for role, action in steps(None):
            store, rt = (self.store, a) if role == "vps1" else (peer, b)
            result = Coordinator(store, rt, lambda: 101).advance("edge", old, None, incoming)
            incoming = result["receipt"]
        result = Coordinator(peer, b, lambda: 101).advance("edge", old, None, incoming)
        self.assertEqual(result["status"], "complete")
        self.assertIsNone(peer.read()["pairs"]["edge"]["active"])
        self.assertIsNone(self.store.read()["pairs"]["edge"]["transition"])

    def test_boot_ephemeral_resources_can_be_recreated_without_losing_baseline(self):
        control = self.state["pairs"]["edge"]
        control.update(active={"profile": "gre-kernel", "revision": 1, "epoch": 1}, epoch=1)
        self.store.write(self.state)
        with patch.object(self.runtime.ledger, "boot_id", return_value="boot-one"):
            self.runtime.prepare(self.r, "vps1", "gre-kernel", control, {"previous": None})
            self.runtime.start(self.r, "vps1", "gre-kernel", control, {"previous": None})
        self.host.link_rows, self.host.addr_rows, self.host.tables, self.host.forwarding = [], [], {}, "0"
        with patch.object(self.runtime.ledger, "boot_id", return_value="boot-two"):
            self.runtime.prepare(self.r, "vps1", "gre-kernel", control, {"previous": control["active"]})
            self.runtime.start(self.r, "vps1", "gre-kernel", control, {"previous": control["active"]})
        row = self.runtime.ledger.read()["resources"]["sysctl:net.ipv4.ip_forward"]
        self.assertEqual(row["before"], "0")
        self.assertEqual(self.host.forwarding, "1")

    def test_purge_resumes_after_partial_file_deletion(self):
        ledger = self.runtime.ledger
        original = ledger.remove_file
        count = [0]
        def interrupted(path, owner):
            original(path, owner)
            count[0] += 1
            if count[0] == 3:
                raise OSError("simulated interrupted unlink")
        with patch.object(Ownership, "remove_file", side_effect=interrupted):
            with self.assertRaises(OSError):
                delete_pair(self.store, self.runtime, "edge")
        self.assertTrue((self.store.directory / "journals" / "purge-edge.json").exists())
        delete_pair(self.store, self.runtime, "edge")
        self.assertFalse(self.store.read()["pairs"])

    def test_sysctl_third_party_change_is_preserved(self):
        control = self.state["pairs"]["edge"]
        self.runtime.prepare(self.r, "vps1", "gre-kernel", control, {"previous": None})
        self.runtime.start(self.r, "vps1", "gre-kernel", control, {"previous": None})
        self.host.forwarding = "2"
        with self.assertRaises(StateError):
            self.runtime.quiesce(self.r, "vps1", "gre-kernel", control, {"previous": None})
        self.assertEqual(self.host.forwarding, "2")

    def test_full_program_removal_checks_manifest_and_removes_owned_directories_last(self):
        from twinlink.cleanup import remove_program
        from twinlink.store import atomic_write
        delete_pair(self.store, self.runtime, "edge")
        prefix = self.root / "prefix"
        launcher, binary = prefix / "bin/twinlink", prefix / "libexec/twinlink-runtime"
        atomic_write(launcher, "owned launcher", 0o755)
        atomic_write(binary, "owned runtime", 0o755)
        manifest = {"owner": "twinlink", "version": 1, "files": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (launcher, binary)}}
        atomic_write(binary.parent / "twinlink-install.json", json.dumps(manifest), 0o644)
        baseline = {"version": 1, "historical_baseline": "recorded", "package_delta": {},
                    "directories": {str(p): {"existed": False} for p in (self.store.directory, prefix, launcher.parent, binary.parent)}}
        atomic_write(self.store.directory / "baseline.json", json.dumps(baseline))
        self.runtime.executable = str(binary)
        launcher.write_text("externally modified")
        with self.assertRaises(StateError):
            remove_program(self.store, self.runtime)
        self.assertTrue(self.store.path.exists())
        self.assertTrue(binary.exists())
        launcher.write_text("owned launcher")
        result = remove_program(self.store, self.runtime)
        self.assertEqual(result["status"], "complete")
        self.assertFalse(prefix.exists())
        self.assertFalse(self.store.directory.exists())


from twinlink.ownership import Ownership
