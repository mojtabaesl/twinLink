"""Transaction tests with a stateful fake kernel, not success-only command stubs."""
import copy
import ipaddress
import itertools
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from twinlink.engine import ApplyError, Engine
from twinlink.host import Host, HostError, _rendered_rule_expressions
from twinlink.models import empty_state, validate_forward, validate_tunnel
from twinlink.store import StateError, Store, atomic_write


def active_state(mode=None):
    state = empty_state()
    state["tunnels"]["edge"] = validate_tunnel({
        "name": "edge", "side": "vps1", "local_public": "198.51.100.1",
        "remote_public": "203.0.113.2", "local_private": "10.77.0.1/30",
        "remote_private": "10.77.0.2/30", "key": 41,
        "enabled": True, "running": True, "verified": True}, state)
    if mode:
        state["forwards"]["web"] = validate_forward({
            "name": "web", "tunnel": "edge", "mode": mode, "protocol": "tcp",
            "bind_port": "8080", "destination_address": "10.20.30.40",
            "destination_port": "80", "enabled": True, "running": True,
            **({"token": "a" * 43} if mode == "rathole" else {})}, state)
    return state


class MemoryHost(Host):
    """Simulate live command effects and their read-back state."""
    def __init__(self, state_dir, unit_dir):
        self.state_dir, self.unit_dir = Path(state_dir), Path(unit_dir)
        self.events = []
        self.commands = []
        self.link_data = []
        self.address_data = [{"ifname": "eth0", "addr_info": [
            {"family": "inet", "local": "198.51.100.1", "prefixlen": 24}]}]
        self.route_data = [{"dst": "default", "dev": "eth0"}]
        self.nft = None
        self.nft_text = None
        self.foreign_firewall = {"inet ssh": "accept tcp dport 22"}
        self.services = {}
        self.listener_data = []
        self.connection_data = []
        self.rathole_public_listener = True
        self.ip_forward = "0"
        self.fail_once = []
        self.ignore_mtu = False
        self.ignore_delete = False
        self.corrupt_nft = False
        self.foreign_fragments = {}

    def require_linux_root(self):
        self.events.append("root-check")

    def links(self):
        return copy.deepcopy(self.link_data)

    def addresses(self):
        return copy.deepcopy(self.address_data)

    def routes(self):
        return copy.deepcopy(self.route_data)

    def listeners(self):
        return copy.deepcopy(self.listener_data)

    def connections(self):
        return copy.deepcopy(self.connection_data)

    def nft_snapshot(self):
        return copy.deepcopy(self.nft or {"available": True, "nftables": []})

    def _result(self, argv, code=0, stdout="", stderr="", check=True):
        if code and check:
            raise HostError(f"{argv[0]} failed ({code}): {stderr}")
        return {"returncode": code, "stdout": stdout, "stderr": stderr}

    def _load_nft(self, script):
        if "table ip twinlink {" not in script:
            self.nft, self.nft_text = None, None
            return
        self.nft_text = script[script.index("table ip twinlink {"):]
        records = [{"table": {"family": "ip", "name": "twinlink", "comment": "twinlink-owned"}}]
        chain = None
        priorities = {"prerouting": -100, "output": -100, "postrouting": 100, "forward": 0}
        for line in self.nft_text.splitlines():
            match = re.match(r"\s*chain (\w+) \{", line)
            if match:
                chain = match.group(1)
                records.append({"chain": {"family": "ip", "table": "twinlink", "name": chain,
                    "hook": chain, "type": "filter" if chain == "forward" else "nat",
                    "prio": priorities[chain], "policy": "accept"}})
            elif 'comment "twinlink:' in line:
                comment, expressions = _rendered_rule_expressions(line)
                if self.corrupt_nft:
                    for expression in expressions:
                        if "dnat" in expression:
                            expression["dnat"]["port"] = 9
                records.append({"rule": {"family": "ip", "table": "twinlink", "chain": chain,
                                          "comment": comment, "expr": expressions}})
        self.nft = {"nftables": records}

    def run(self, argv, check=True, input=None, timeout=15):
        argv = list(argv)
        self.commands.append((argv, input))
        self.events.append("command:" + " ".join(argv))
        for index, predicate in enumerate(self.fail_once):
            if predicate(argv, input):
                self.fail_once.pop(index)
                return self._result(argv, 1, stderr="injected command failure", check=check)
        if argv[0] == "nft":
            if "list" in argv:
                if self.nft is None:
                    return self._result(argv, 1, stderr="No such file or directory", check=check)
                return self._result(argv, stdout=json.dumps(self.nft) if "-j" in argv else self.nft_text, check=check)
            if "--check" not in argv:
                self._load_nft(input or "")
            return self._result(argv)
        if argv[0] == "sysctl":
            if "-w" in argv:
                self.ip_forward = argv[-1].split("=", 1)[1]
            return self._result(argv, stdout=self.ip_forward + "\n")
        if argv[0] == "conntrack":
            return self._result(argv)
        if argv[0] == "ip":
            if argv[1:3] in (["tunnel", "add"], ["tunnel", "change"]):
                name = argv[3]
                link = next((row for row in self.link_data if row["ifname"] == name), None)
                if link is None:
                    link = {"ifname": name, "flags": [], "mtu": 1476, "operstate": "UNKNOWN",
                            "linkinfo": {"info_kind": "gre", "info_data": {}}}
                    self.link_data.append(link)
                data = link["linkinfo"]["info_data"]
                for field in ("local", "remote", "ttl", "key", "ikey", "okey"):
                    if field in argv:
                        value = argv[argv.index(field) + 1]
                        if field == "key":
                            data.update(ikey=int(value), okey=int(value))
                        else:
                            data[field] = int(value) if field in ("ttl", "ikey", "okey") else value
            elif argv[1:3] == ["link", "delete"]:
                name = argv[-1]
                if not self.ignore_delete:
                    self.link_data = [row for row in self.link_data if row["ifname"] != name]
                    self.address_data = [row for row in self.address_data if row["ifname"] != name]
            elif argv[1:3] == ["link", "set"]:
                name = argv[argv.index("dev") + 1]
                link = next(row for row in self.link_data if row["ifname"] == name)
                if "alias" in argv:
                    link["ifalias"] = argv[argv.index("alias") + 1]
                if "mtu" in argv and not self.ignore_mtu:
                    link["mtu"] = int(argv[argv.index("mtu") + 1])
                if "up" in argv:
                    link["flags"] = ["UP"]
                if "down" in argv:
                    link["flags"] = []
            elif argv[1] in ("address", "addr"):
                name = argv[argv.index("dev") + 1]
                row = next((row for row in self.address_data if row["ifname"] == name), None)
                if row is None:
                    row = {"ifname": name, "addr_info": []}
                    self.address_data.append(row)
                if argv[2] == "flush":
                    row["addr_info"] = []
                else:
                    address = ipaddress.ip_interface(argv[3])
                    item = {"family": "inet", "local": str(address.ip), "prefixlen": address.network.prefixlen}
                    row["addr_info"] = [old for old in row["addr_info"] if old["local"] != str(address.ip)]
                    if argv[2] != "delete":
                        row["addr_info"].append(item)
            else:
                raise AssertionError("Unmodeled ip command: " + str(argv))
            return self._result(argv)
        if argv[0] == "systemctl":
            argv = [word for word in argv if word != "--no-block"]
            operation = argv[1]
            if operation == "daemon-reload":
                return self._result(argv)
            unit = argv[2]
            service = self.services.setdefault(unit, {"active": False, "enabled": False})
            if operation in ("is-active", "is-enabled"):
                key = "active" if operation == "is-active" else "enabled"
                return self._result(argv, 0 if service[key] else 3,
                                    (key if service[key] else "inactive" if key == "active" else "disabled") + "\n", check=check)
            if operation == "show":
                fragment = self.foreign_fragments.get(unit)
                own = self.unit_dir / unit
                fragment = fragment or (str(own) if own.exists() else "")
                return self._result(argv, stdout="\n".join([
                    "LoadState=" + ("loaded" if fragment else "not-found"),
                    "ActiveState=" + ("active" if service["active"] else "inactive"),
                    "UnitFileState=" + ("enabled" if service["enabled"] else "disabled"),
                    "FragmentPath=" + fragment, "MainPID=123"]))
            if operation == "cat":
                fragment = Path(self.foreign_fragments.get(unit, str(self.unit_dir / unit)))
                return self._result(argv, stdout=fragment.read_text() if fragment.exists() else "")
            if operation in ("enable", "disable"):
                service["enabled"] = operation == "enable"
            elif operation in ("start", "restart", "stop"):
                service["active"] = operation != "stop"
                if unit.startswith("twinlink-rathole-"):
                    name = unit.removeprefix("twinlink-rathole-").removesuffix(".service")
                    self.listener_data = [row for row in self.listener_data if row.get("managed") != name]
                    if service["active"]:
                        config = (self.state_dir / "rathole" / (name + ".toml")).read_text()
                        for index, endpoint in enumerate(re.findall(r'^bind_addr = "([^"]+)"', config, re.M)):
                            if index > 0 and not self.rathole_public_listener:
                                continue
                            address, port = endpoint.split(":")
                            self.listener_data.append({"address": address, "port": int(port), "protocol": "tcp", "managed": name})
            else:
                raise AssertionError("Unmodeled systemctl command: " + str(argv))
            return self._result(argv)
        if argv[0] == "ping":
            return self._result(argv, stdout="3 packets transmitted, 3 received, 0% packet loss\nrtt min/avg/max/mdev = 1/2/3/1 ms")
        if argv[0] == "rathole" or "rathole" in Path(argv[0]).name:
            return self._result(argv, stdout="rathole 0.5.0\n")
        raise AssertionError("Unmodeled command: " + str(argv))


class TrackingStore(Store):
    def __init__(self, directory, events):
        super().__init__(directory)
        self.events = events

    def write(self, state):
        self.events.append("state-commit")
        super().write(state)


class TrackingEngine(Engine):
    def _verify(self, old, new, boot=False):
        self.host.events.append("verify-start")
        super()._verify(old, new, boot)
        self.host.events.append("verify-success")


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").exists() else None)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.host = MemoryHost(self.directory / "state", self.directory / "units")
        self.store = TrackingStore(self.host.state_dir, self.host.events)
        self.engine = TrackingEngine(self.store, self.host, unit_dir=self.host.unit_dir, systemd=False)

    def apply(self, new, action="test", boot=False):
        old = self.store.read()
        plan = self.engine.plan(old, new, action)
        with self.store.lock():
            return self.engine.apply(old, new, plan, boot=boot)

    def install(self, mode):
        self.apply(active_state())
        self.host.events.clear()
        state = self.store.read()
        state["forwards"] = active_state(mode)["forwards"]
        return self.apply(state)

    def test_preview_has_no_files_commands_or_state_effects(self):
        state = active_state("rathole")
        plan = self.engine.plan(empty_state(), state, "preview")
        self.assertFalse(self.host.commands)
        self.assertFalse(self.host.state_dir.exists())
        self.assertTrue(plan["verification"])
        self.assertTrue(plan["rollback"])
        self.assertNotIn(state["forwards"]["web"]["token"], json.dumps(plan))
        self.assertTrue(any("<redacted>" in spec.get("content", "") for spec in plan["files"]))

    def test_commit_follows_actual_kernel_readback_and_journal_is_removed(self):
        result = self.install("kernel")
        self.assertTrue(result["committed"])
        self.assertLess(self.host.events.index("verify-success"), self.host.events.index("state-commit"))
        self.assertFalse(self.store.journal.exists())
        self.assertEqual(self.host.tunnel_status(self.store.read()["tunnels"]["edge"], probe=False)["drift"], [])
        self.assertEqual(self.host.ip_forward, "1")
        self.assertEqual(os.stat(self.store.path).st_mode & 0o777, 0o600)

    def test_stale_preview_is_rejected_before_host_mutation(self):
        old, candidate = empty_state(), active_state()
        plan = self.engine.plan(old, candidate, "stale")
        other = active_state()
        self.store.write(other)
        with self.assertRaisesRegex(StateError, "changed since preview"):
            self.engine.apply(old, candidate, plan)
        self.assertFalse(self.host.commands)

    def test_command_failure_rolls_back_interface_files_rules_and_state(self):
        self.host.fail_once.append(lambda argv, _: argv[:3] == ["ip", "address", "replace"])
        with self.assertRaisesRegex(ApplyError, "rollback completed"):
            self.apply(active_state())
        self.assertFalse(self.host.link_data)
        self.assertIsNone(self.host.nft)
        self.assertEqual(self.store.read(), empty_state())
        self.assertFalse(self.store.journal.exists())
        self.assertFalse(list(self.host.unit_dir.glob("*.service")))

    def test_readback_failure_never_commits_candidate(self):
        self.apply(active_state())
        old = self.store.read()
        self.host.events.clear()
        candidate = copy.deepcopy(old)
        candidate["tunnels"]["edge"]["mtu"] = 1400
        self.host.ignore_mtu = True
        with self.assertRaisesRegex(ApplyError, "GRE verification failed"):
            self.apply(candidate)
        self.assertEqual(self.store.read(), old)
        self.assertNotIn("verify-success", self.host.events)
        self.assertEqual(self.host.link_data[0]["mtu"], 1476)

    def test_partial_rollback_keeps_journal_and_recovery_retries(self):
        self.host.fail_once.extend([
            lambda argv, _: argv[:3] == ["ip", "address", "replace"],
            lambda argv, _: argv[:3] == ["ip", "link", "delete"],
        ])
        with self.assertRaises(ApplyError) as error:
            self.apply(active_state())
        self.assertTrue(error.exception.rollback_errors)
        self.assertTrue(self.store.journal.exists())
        self.assertTrue(self.host.link_data)
        with self.store.lock():
            result = self.engine.recover()
        self.assertTrue(result["recovered"])
        self.assertFalse(self.store.journal.exists())
        self.assertFalse(self.host.link_data)
        self.assertEqual(self.store.read(), empty_state())

    def test_rollback_reads_back_cleanup_before_claiming_success(self):
        self.host.fail_once.append(lambda argv, _: argv[:3] == ["ip", "address", "replace"])
        self.host.ignore_delete = True
        with self.assertRaises(ApplyError) as error:
            self.apply(active_state())
        self.assertTrue(error.exception.rollback_errors)
        self.assertTrue(self.store.journal.exists())
        self.host.ignore_delete = False
        with self.store.lock():
            self.engine.recover()
        self.assertFalse(self.host.link_data)
        self.assertFalse(self.store.journal.exists())

    def test_unfinished_journal_blocks_next_apply(self):
        atomic_write(self.store.journal, "{}")
        with self.assertRaisesRegex(StateError, "Unfinished transaction"):
            self.apply(active_state())
        self.assertFalse(self.host.commands)

    def test_kernel_disable_removes_owned_exposure_without_touching_foreign_rules(self):
        self.install("kernel")
        candidate = self.store.read()
        candidate["forwards"]["web"].update(enabled=False, running=False)
        self.apply(candidate, "disable")
        rules = [record for record in self.host.nft["nftables"] if "rule" in record]
        self.assertFalse(rules)
        self.assertEqual(self.host.foreign_firewall, {"inet ssh": "accept tcp dport 22"})
        scripts = [text for argv, text in self.host.commands if argv[0] == "nft" and text]
        self.assertTrue(all("flush ruleset" not in text and "delete table inet" not in text for text in scripts))
        self.assertTrue(any(argv[0] == "conntrack" for argv, _ in self.host.commands))

    def test_forward_disable_cleans_exposure_even_when_gre_is_missing(self):
        self.install("kernel")
        self.host.link_data = []
        self.host.address_data = [row for row in self.host.address_data if row["ifname"] == "eth0"]
        candidate = self.store.read()
        candidate["forwards"]["web"].update(enabled=False, running=False)
        self.apply(candidate, "disable")
        self.assertFalse(self.host.link_data)
        self.assertFalse(self.store.read()["forwards"]["web"]["running"])
        self.assertFalse(any("rule" in row for row in self.host.nft["nftables"]))
        self.assertFalse(self.store.journal.exists())

    def test_foreign_table_is_rejected_before_any_mutation(self):
        self.host.nft = {"nftables": [{"table": {"family": "ip", "name": "twinlink", "comment": "foreign"}}]}
        with self.assertRaisesRegex(ApplyError, "Foreign"):
            self.apply(active_state())
        self.assertFalse(self.host.link_data)
        self.assertFalse(self.store.journal.exists())

    def test_foreign_unit_file_is_never_overwritten(self):
        self.host.unit_dir.mkdir()
        foreign = self.host.unit_dir / "twinlink-gre-edge.service"
        foreign.write_text("[Service]\nExecStart=/usr/bin/foreign\n")
        with self.assertRaisesRegex(ApplyError, "foreign file"):
            self.apply(active_state())
        self.assertIn("/usr/bin/foreign", foreign.read_text())
        self.assertFalse(self.host.link_data)

    def test_vendor_unit_with_same_managed_name_is_protected(self):
        self.engine.systemd = True
        vendor = self.directory / "vendor.service"
        vendor.write_text("[Service]\nExecStart=/usr/bin/foreign\n")
        self.host.foreign_fragments["twinlink-gre-edge.service"] = str(vendor)
        with self.assertRaisesRegex(ApplyError, "foreign"):
            self.apply(active_state())
        self.assertFalse(self.host.link_data)
        self.assertIn("/usr/bin/foreign", vendor.read_text())

    def test_symlink_managed_file_is_rejected(self):
        self.host.unit_dir.mkdir()
        foreign = self.directory / "foreign.service"
        foreign.write_text("leave me alone")
        (self.host.unit_dir / "twinlink-gre-edge.service").symlink_to(foreign)
        with self.assertRaisesRegex(StateError, "symlink"):
            self.apply(active_state())
        self.assertEqual(foreign.read_text(), "leave me alone")

    def test_foreign_interface_is_never_changed(self):
        state = active_state()
        self.host.link_data = [{"ifname": state["tunnels"]["edge"]["interface"],
                               "ifalias": "foreign", "linkinfo": {"info_kind": "gre"}}]
        with self.assertRaisesRegex(HostError, "foreign interface"):
            self.apply(state)
        self.assertEqual(self.host.link_data[0]["ifalias"], "foreign")

    def test_live_listener_conflict_aborts_before_creating_forward(self):
        self.apply(active_state())
        old = self.store.read()
        candidate = copy.deepcopy(old)
        candidate["forwards"] = active_state("kernel")["forwards"]
        self.host.listener_data = [{"address": "0.0.0.0", "port": 8080, "protocol": "tcp"}]
        with self.assertRaisesRegex(ValueError, "host listener"):
            self.apply(candidate)
        self.assertEqual(self.store.read(), old)
        self.assertFalse(self.store.journal.exists())

    def test_secondary_assigned_public_bind_is_supported(self):
        self.apply(active_state())
        self.host.address_data[0]["addr_info"].append({"family": "inet", "local": "198.51.100.9", "prefixlen": 24})
        candidate = self.store.read()
        candidate["forwards"]["web"] = validate_forward({
            **active_state("kernel")["forwards"]["web"], "bind_address": "198.51.100.9"}, candidate)
        self.apply(candidate)
        self.assertEqual(self.store.read()["forwards"]["web"]["bind_address"], "198.51.100.9")
        self.assertIn("ip daddr 198.51.100.9", self.host.nft_text)

    def test_unassigned_public_bind_is_rejected_before_exposure(self):
        self.apply(active_state())
        old = self.store.read()
        candidate = copy.deepcopy(old)
        candidate["forwards"]["web"] = validate_forward({
            **active_state("kernel")["forwards"]["web"], "bind_address": "198.51.100.9"}, candidate)
        with self.assertRaisesRegex(ApplyError, "not assigned on VPS1"):
            self.apply(candidate)
        self.assertEqual(self.store.read(), old)
        self.assertFalse(self.store.journal.exists())

    def test_conntrack_wildcard_cleanup_always_includes_translated_tuple(self):
        old = active_state()
        old["forwards"]["web"] = validate_forward({
            **active_state("kernel")["forwards"]["web"], "bind_address": "0.0.0.0",
            "bind_port": "8080-8081", "relay_port": "31000-31001", "destination_port": "80-81"}, old)
        new = copy.deepcopy(old)
        new["forwards"]["web"]["running"] = False
        commands = self.engine.flow_commands(old, new)
        self.assertEqual(len(commands), 2)
        for offset, command in enumerate(sorted(commands, key=lambda argv: int(argv[argv.index("--orig-port-dst") + 1]))):
            self.assertEqual(command[:4], ["conntrack", "-D", "-p", "tcp"])
            self.assertEqual(command[command.index("--orig-port-dst") + 1], str(8080 + offset))
            self.assertEqual(command[command.index("--reply-src") + 1], "10.77.0.2")
            self.assertEqual(command[command.index("--reply-port-src") + 1], str(31000 + offset))
            self.assertNotIn("-F", command)
        # The second NAT hop also constrains the source and backend reply tuple.
        peer = copy.deepcopy(old)
        tunnel = peer["tunnels"]["edge"]
        tunnel.update(side="vps2", local_public="203.0.113.2", remote_public="198.51.100.1",
                      local_private="10.77.0.2/30", remote_private="10.77.0.1/30")
        peer["forwards"]["web"]["side"] = "vps2"
        stopped = copy.deepcopy(peer)
        stopped["forwards"]["web"]["running"] = False
        for command in self.engine.flow_commands(peer, stopped):
            self.assertEqual(command[command.index("--orig-src") + 1], "10.77.0.1")
            self.assertEqual(command[command.index("--orig-dst") + 1], "10.77.0.2")
            self.assertEqual(command[command.index("--reply-src") + 1], "10.20.30.40")
            self.assertIn("--reply-port-src", command)

    def test_foreign_dropin_on_owned_unit_is_refused(self):
        self.engine.systemd = True
        self.apply(active_state())
        original = self.host.unit_status
        def with_dropin(name):
            status = original(name)
            if name == "twinlink-gre-edge.service":
                status["properties"]["DropInPaths"] = "/etc/systemd/system/twinlink-gre-edge.service.d/foreign.conf"
            return status
        with patch.object(self.host, "unit_status", side_effect=with_dropin):
            with self.assertRaisesRegex(ApplyError, "external drop-ins"):
                self.apply(self.store.read())
        self.assertFalse(self.store.journal.exists())

    def test_missing_stopped_tunnel_can_be_committed_idempotently(self):
        candidate = active_state()
        candidate["tunnels"]["edge"].update(running=False, enabled=False)
        self.apply(candidate)
        self.apply(self.store.read())
        self.assertFalse(self.host.link_data)

    def test_delete_refuses_default_route_even_for_owned_gre(self):
        self.apply(active_state())
        self.host.route_data[0]["dev"] = self.store.read()["tunnels"]["edge"]["interface"]
        with self.assertRaisesRegex(HostError, "default route"):
            self.apply(empty_state())
        self.assertTrue(self.host.link_data)

    def test_clearing_gre_key_explicitly_clears_live_key(self):
        self.apply(active_state())
        candidate = self.store.read()
        candidate["tunnels"]["edge"]["key"] = None
        self.host.commands.clear()
        self.apply(candidate)
        data = self.host.link_data[0]["linkinfo"]["info_data"]
        self.assertNotIn("ikey", data)
        self.assertNotIn("okey", data)
        deletes = [argv for argv, _ in self.host.commands if argv[:3] == ["ip", "link", "delete"]]
        creates = [argv for argv, _ in self.host.commands if argv[:3] == ["ip", "tunnel", "add"]]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(len(creates), 1)
        self.assertNotIn("key", creates[0])
        self.assertEqual(self.host.link_data[0]["ifalias"], "twinlink:edge")

    def test_reapply_repairs_actual_link_and_firewall_drift(self):
        self.install("kernel")
        self.host.link_data[0]["mtu"] = 1400
        rule = next(record["rule"] for record in self.host.nft["nftables"] if "rule" in record)
        next(expr["dnat"] for expr in rule["expr"] if "dnat" in expr)["port"] = 9
        self.engine.force = ("tunnel", "edge")
        self.apply(self.store.read(), "reapply")
        state = self.store.read()
        self.assertEqual(self.host.link_data[0]["mtu"], state["tunnels"]["edge"]["mtu"])
        self.assertEqual(self.host.kernel_forward_drift(state["forwards"]["web"], state["tunnels"]["edge"]), [])

    def test_semantically_wrong_rules_cannot_be_committed_using_matching_comments(self):
        self.apply(active_state())
        old = self.store.read()
        candidate = copy.deepcopy(old)
        candidate["forwards"] = active_state("kernel")["forwards"]
        self.host.corrupt_nft = True
        with self.assertRaisesRegex(ApplyError, "expressions differ"):
            self.apply(candidate)
        self.assertEqual(self.store.read(), old)

    def test_forward_failure_does_not_recreate_unmodified_tunnel(self):
        self.install("kernel")
        old = self.store.read()
        candidate = copy.deepcopy(old)
        candidate["forwards"]["web"]["destination_port"] = "81"
        self.host.commands.clear()
        self.host.fail_once.append(lambda argv, text: argv[:2] == ["nft", "--file"]
                                  and text is not None and 'dnat to 10.77.0.2:' in text)
        with self.assertRaises(ApplyError):
            self.apply(candidate)
        self.assertEqual(self.store.read(), old)
        self.assertFalse(any(argv[:3] == ["ip", "link", "delete"] for argv, _ in self.host.commands))

    def test_combined_create_and_forward_cannot_skip_live_gre_verification(self):
        with self.assertRaisesRegex(ApplyError, "GRE peer must be reachable"):
            self.apply(active_state("kernel"))
        self.assertFalse(self.host.link_data)

    def test_fingerprint_ignores_counters_but_detects_changed_match(self):
        self.install("kernel")
        initial = self.engine.nft_fingerprint()
        rule = next(record["rule"] for record in self.host.nft["nftables"] if "rule" in record)
        rule["handle"] = 99
        rule["expr"].insert(0, {"counter": {"packets": 900, "bytes": 45000}})
        # Counters themselves are part of the rendered rules. Add the same
        # zero-counter expression to model the initial kernel's normal output.
        initial_with_counter = self.engine.nft_fingerprint()
        rule["expr"][0]["counter"].update(packets=1000, bytes=99999)
        self.assertEqual(initial_with_counter, self.engine.nft_fingerprint())
        next(expression["dnat"] for expression in rule["expr"] if "dnat" in expression)["port"] = 9
        self.assertNotEqual(initial, self.engine.nft_fingerprint())

    def test_ip_forward_restores_after_failed_rule_install(self):
        self.apply(active_state())
        old = self.store.read()
        candidate = copy.deepcopy(old)
        candidate["forwards"] = active_state("kernel")["forwards"]
        self.host.fail_once.append(lambda argv, text: argv[:2] == ["nft", "--file"]
                                  and text is not None and 'comment "twinlink:web:' in text)
        with self.assertRaises(ApplyError):
            self.apply(candidate)
        self.assertEqual(self.host.ip_forward, "0")
        self.assertEqual(self.store.read(), old)

    def test_rathole_apply_disable_delete_manage_listeners_and_secret_modes(self):
        self.engine.systemd = True
        self.install("rathole")
        self.assertTrue(any(row["port"] == 8080 for row in self.host.listeners()))
        config = self.host.state_dir / "rathole" / "web.toml"
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        candidate = self.store.read()
        candidate["forwards"]["web"].update(enabled=False, running=False)
        self.apply(candidate, "disable")
        self.assertFalse(self.host.listeners())
        candidate = self.store.read()
        del candidate["forwards"]["web"]
        self.apply(candidate, "delete")
        self.assertFalse(config.exists())
        self.assertFalse(self.host.services["twinlink-rathole-web.service"]["enabled"])

    def test_rathole_server_bootstrap_commits_private_listener_pending_peer(self):
        self.engine.systemd = True
        self.host.rathole_public_listener = False
        result = self.install("rathole")
        self.assertTrue(result["committed"])
        self.assertIn("web", result["pending_peer"])
        self.assertEqual(result["health"], "not_verified")
        entry = self.store.read()["forwards"]["web"]
        self.assertTrue(entry["running"])
        self.assertTrue(any(row["address"] == "10.77.0.1" and row["port"] == entry["transport_port"]
                            for row in self.host.listeners()))
        self.assertFalse(any(row["port"] == 8080 for row in self.host.listeners()))
        self.assertTrue((self.host.state_dir / "rathole" / "web.toml").exists())
        self.assertFalse(self.store.journal.exists())

    def test_rathole_connected_peer_without_public_listener_fails_and_rolls_back(self):
        self.engine.systemd = True
        self.apply(active_state())
        old = self.store.read()
        candidate = copy.deepcopy(old)
        candidate["forwards"] = active_state("rathole")["forwards"]
        self.host.rathole_public_listener = False
        transport = candidate["forwards"]["web"]["transport_port"]
        self.host.connection_data = [{"address": "10.77.0.1", "port": transport,
                                      "peer_address": "10.77.0.2", "peer_port": 55000}]
        # The real verifier waits briefly for rathole's authenticated registration
        # to create the listener. Advance only the clock so this regression is bounded.
        with patch("twinlink.engine.time.monotonic", side_effect=itertools.count(0, 10).__next__), patch("twinlink.engine.time.sleep", return_value=None):
            with self.assertRaises(ApplyError) as error:
                self.apply(candidate)
        self.assertIn("listener", str(error.exception).lower())
        self.assertFalse(error.exception.rollback_errors)
        self.assertEqual(self.store.read(), old)
        self.assertFalse(self.store.journal.exists())
        self.assertFalse(self.host.listeners())
        self.assertFalse((self.host.state_dir / "rathole" / "web.toml").exists())

    def test_rathole_bootstrap_cannot_commit_without_private_transport_listener(self):
        self.engine.systemd = True
        self.apply(active_state())
        old = self.store.read()
        candidate = copy.deepcopy(old)
        candidate["forwards"] = active_state("rathole")["forwards"]
        with patch.object(self.host, "listeners", return_value=[]), patch("twinlink.engine.time.monotonic", side_effect=itertools.count(0, 10).__next__), patch("twinlink.engine.time.sleep", return_value=None):
            with self.assertRaisesRegex(ApplyError, "listener verification failed"):
                self.apply(candidate)
        self.assertEqual(self.store.read(), old)
        self.assertFalse(self.store.journal.exists())

    def test_boot_restore_recreates_missing_runtime(self):
        self.install("kernel")
        candidate = self.store.read()
        self.host.link_data = []
        self.host.address_data = [row for row in self.host.address_data if row["ifname"] == "eth0"]
        self.host.nft = None
        self.host.nft_text = None
        self.host.ip_forward = "0"
        self.apply(candidate, "boot restore", boot=True)
        self.assertTrue(self.host.link_data)
        self.assertEqual(self.host.ip_forward, "1")
        self.assertTrue(any("rule" in row for row in self.host.nft["nftables"]))

    def test_failed_boot_restore_removes_newly_recreated_link_and_restores_missing_snapshot(self):
        self.install("kernel")
        old = self.store.read()
        self.host.link_data = []
        self.host.address_data = [row for row in self.host.address_data if row["ifname"] == "eth0"]
        self.host.nft, self.host.nft_text = None, None
        self.host.ip_forward = "0"
        self.host.fail_once.append(lambda argv, text: argv[:2] == ["nft", "--file"]
                                  and bool(self.host.link_data) and text is not None
                                  and 'comment "twinlink:web:' in text)
        with self.assertRaisesRegex(ApplyError, "rollback completed"):
            self.apply(copy.deepcopy(old), "boot restore", boot=True)
        self.assertFalse(self.host.link_data)
        self.assertIsNone(self.host.nft)
        self.assertEqual(self.host.ip_forward, "0")
        self.assertEqual(self.store.read(), old)
        self.assertFalse(self.store.journal.exists())

    def test_boot_restore_stops_disabled_rathole_before_replacing_config(self):
        self.engine.systemd = True
        self.install("rathole")
        config = self.host.state_dir / "rathole" / "web.toml"
        config.unlink()  # Process can remain live after an external file removal.
        candidate = self.store.read()
        candidate["forwards"]["web"].update(enabled=False, running=False)
        self.host.events.clear()
        def record_write(path, content, mode=0o600):
            if Path(path) == config:
                self.host.events.append("write-rathole-config")
            return atomic_write(path, content, mode)
        with patch("twinlink.engine.atomic_write", side_effect=record_write):
            self.apply(candidate, "boot restore", boot=True)
        stopped = self.host.events.index("command:systemctl stop twinlink-rathole-web.service")
        written = self.host.events.index("write-rathole-config")
        self.assertLess(stopped, written)
        self.assertFalse(self.host.services["twinlink-rathole-web.service"]["active"])
        self.assertFalse(self.host.listeners())

    def test_recovery_rejects_path_tampering(self):
        snapshot = {"old": empty_state(), "candidate": active_state(),
                    "files": {str(self.directory / "unrelated"): None}}
        atomic_write(self.store.journal, json.dumps(snapshot))
        with self.assertRaisesRegex(StateError, "ownership validation"):
            self.engine.recover()


if __name__ == "__main__":
    unittest.main()
