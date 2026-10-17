"""Real packet-path tests, isolated from the host's network and firewall.

Run as root on a disposable Linux host with:
  TWINLINK_INTEGRATION=1 python3 -m unittest tests.integration.test_netns -v
Set TWINLINK_RATHOLE_BINARY to a tested rathole executable for TCP proxy tests.

Topology: external -> VPS1 -- GRE over separate WAN -- VPS2 -> backend.
No backend route back to the GRE subnet exists, so kernel success also proves
the required return-path masquerading. Engine mutations use the real nft/ip
commands and file transactions through a namespace-scoped Host. Tests do not
run systemd or claim to prove physical reboot/provider-firewall behavior.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from twinlink.engine import ApplyError, Engine
from twinlink.host import Host, HostError
from twinlink.models import validate_forward, validate_tunnel
from twinlink.render import rathole_config_path
from twinlink.store import Store


_SERVER = r"""
import socket, sys
address, port, protocol, marker = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4].encode()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == 'udp' else socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((address, port))
if protocol == 'tcp': sock.listen(32)
print('READY', flush=True)
while True:
    if protocol == 'udp':
        data, peer = sock.recvfrom(4096)
        sock.sendto(marker + b'|' + data, peer)
    else:
        conn, peer = sock.accept()
        try:
            conn.settimeout(2)
            data = conn.recv(4096)
            if data: conn.sendall(marker + b'|' + data)
        except OSError: pass
        finally: conn.close()
"""

_CLIENT = r"""
import socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if sys.argv[3] == 'udp' else socket.SOCK_STREAM)
sock.settimeout(0.7)
sock.connect((sys.argv[1], int(sys.argv[2])))
sock.sendall(b'twinlink-packet-path')
print(sock.recv(4096).decode())
"""


def _prerequisites():
    if os.environ.get("TWINLINK_INTEGRATION") != "1":
        return "set TWINLINK_INTEGRATION=1 to opt in to Linux packet-path tests"
    if platform.system() != "Linux" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return "network namespace tests require Linux and root"
    missing = [name for name in ("ip", "nft", "ss", "ping", "sysctl", "conntrack") if not shutil.which(name)]
    if missing:
        return "missing integration dependencies: " + ", ".join(missing)
    return ""


class NamespaceHost(Host):
    """Scope every host command, including injected faults, to one namespace."""

    def __init__(self, namespace):
        self.namespace = namespace
        self.fail_nft_matching = None

    def run(self, argv, check=True, input=None, timeout=15):
        if self.fail_nft_matching and argv[:3] == ["nft", "--file", "-"] and self.fail_nft_matching in (input or ""):
            self.fail_nft_matching = None
            raise HostError("injected one-shot nft apply failure")
        return super().run(["ip", "netns", "exec", self.namespace, *argv], check=check, input=input, timeout=timeout)


@unittest.skipIf(bool(_prerequisites()), _prerequisites())
class NetworkNamespaceIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="twinlink-netns-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.namespaces = {}
        self.processes = []
        self.logs = []
        self.addCleanup(self._cleanup_network)
        unique = "tltest-" + str(os.getpid()) + "-" + uuid.uuid4().hex[:5]
        for role in ("external", "vps1", "vps2", "backend"):
            ns = unique + "-" + role
            self._root(["ip", "netns", "add", ns])
            self.namespaces[role] = ns
            self._ns(role, ["ip", "link", "set", "lo", "up"])
        self._wire("vps1", "wan", "198.18.0.1/30", "vps2", "wan", "198.18.0.2/30")
        self._wire("external", "wan", "198.19.0.2/30", "vps1", "public", "198.19.0.1/30")
        self._wire("vps2", "lan", "10.81.0.1/30", "backend", "wan", "10.81.0.2/30")
        self._ns("external", ["ip", "route", "add", "198.18.0.0/30", "via", "198.19.0.1"])
        self._ns("vps1", ["ip", "route", "add", "default", "via", "198.18.0.2", "dev", "wan"])
        self._ns("vps2", ["ip", "route", "add", "default", "via", "198.18.0.1", "dev", "wan"])
        self.default_routes = {role: self._ns(role, ["ip", "-j", "route", "show", "default"]).stdout for role in ("vps1", "vps2")}
        self.hosts = {role: NamespaceHost(self.namespaces[role]) for role in ("vps1", "vps2")}
        self.stores = {role: Store(self.directory / role) for role in self.hosts}
        binary = os.environ.get("TWINLINK_RATHOLE_BINARY") or shutil.which("rathole") or "/usr/local/bin/rathole"
        self.engines = {role: Engine(self.stores[role], self.hosts[role], unit_dir=self.directory / (role + "-units"), rathole_binary=binary, systemd=False) for role in self.hosts}
        for side in ("vps1", "vps2"):
            self._ns(side, ["nft", "add", "table", "ip", "twinlink_foreign_test"])
            self._ns(side, ["nft", "add", "chain", "ip", "twinlink_foreign_test", "sentinel"])
        self.foreign = {side: self._ns(side, ["nft", "-j", "list", "table", "ip", "twinlink_foreign_test"]).stdout for side in self.hosts}
        for side in ("vps1", "vps2"):
            old = self.stores[side].read()
            public = ("198.18.0.1", "198.18.0.2") if side == "vps1" else ("198.18.0.2", "198.18.0.1")
            private = ("10.80.0.1/30", "10.80.0.2/30") if side == "vps1" else ("10.80.0.2/30", "10.80.0.1/30")
            spec = validate_tunnel({"name": "edge", "side": side, "local_public": public[0], "remote_public": public[1], "local_private": private[0], "remote_private": private[1], "key": 61723, "mtu": 1400, "ttl": 64, "enabled": True, "running": True}, old)
            new = copy.deepcopy(old)
            new["tunnels"]["edge"] = spec
            self._apply(side, new, "create GRE")
        # The verified flag is earned from real GRE peer probes on each host.
        for side in self.hosts:
            new = self.stores[side].read()
            status = self.hosts[side].tunnel_status(new["tunnels"]["edge"], probe=True)
            self.assertTrue(status["peer_reachable"], status)
            self.assertFalse(status["drift"], status)
            new["tunnels"]["edge"]["verified"] = True
            self._apply(side, new, "record measured GRE verification")

    def _root(self, argv, check=True, **kwargs):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=20, **kwargs)
        if check and result.returncode:
            self.fail("Command failed: " + repr(argv) + "\n" + result.stderr)
        return result

    def _ns(self, role, argv, **kwargs):
        return self._root(["ip", "netns", "exec", self.namespaces[role], *argv], **kwargs)

    def _wire(self, left, left_name, left_cidr, right, right_name, right_cidr):
        # Names are unique and short; only the two ends briefly exist in the
        # initial namespace before being moved to the isolated test topology.
        suffix = uuid.uuid4().hex[:8]
        endpoints = ("tl" + suffix + "a", "tl" + suffix + "b")
        self._root(["ip", "link", "add", endpoints[0], "type", "veth", "peer", "name", endpoints[1]])
        for original, role, name, cidr in ((endpoints[0], left, left_name, left_cidr), (endpoints[1], right, right_name, right_cidr)):
            self._root(["ip", "link", "set", original, "netns", self.namespaces[role]])
            self._ns(role, ["ip", "link", "set", original, "name", name])
            self._ns(role, ["ip", "address", "add", cidr, "dev", name])
            self._ns(role, ["ip", "link", "set", name, "up"])

    def _cleanup_network(self):
        for process in reversed(self.processes):
            self._stop(process)
        for handle in self.logs:
            handle.close()
        for namespace in reversed(list(self.namespaces.values())):
            subprocess.run(["ip", "netns", "delete", namespace], capture_output=True, timeout=10)

    @staticmethod
    def _stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    def _apply(self, side, new, action, boot=False):
        store = self.stores[side]
        with store.lock():
            old = store.read()
            plan = self.engines[side].plan(old, new, action)
            return self.engines[side].apply(old, new, plan, boot=boot)

    def _add_forward(self, mode="kernel", protocol="tcp", public="18080", destination="28080", noise=False):
        credentials = {}
        if noise:
            from twinlink.rathole import generate_keypair
            credentials = {"rathole_transport": "noise", **generate_keypair(self.engines["vps1"].rathole_binary)}
        for side in self.hosts:
            new = self.stores[side].read()
            spec = validate_forward({"name": "web", "tunnel": "edge", "side": side, "mode": mode, "protocol": protocol, "bind_address": "198.18.0.1", "bind_port": public, "destination_address": "10.81.0.2", "destination_port": destination, "relay_port": "31000", "transport_port": 24001, "token": "integration-secret-service-0123456789", "enabled": True, "running": True, **credentials}, new)
            new["forwards"]["web"] = spec
            self._apply(side, new, "add forwarding")

    def _edit(self, side, **changes):
        new = self.stores[side].read()
        entry = dict(new["forwards"]["web"], **changes)
        entry["revision"] += 1
        new["forwards"]["web"] = validate_forward(entry, new, existing_name="web")
        self._apply(side, new, "edit forwarding")

    def _start_process(self, role, argv):
        log_path = self.directory / ("process-" + str(len(self.processes)) + ".log")
        log = log_path.open("w+")
        self.logs.append(log)
        process = subprocess.Popen(["ip", "netns", "exec", self.namespaces[role], *argv], stdout=log, stderr=subprocess.STDOUT, text=True)
        self.processes.append(process)
        return process, log_path

    def _echo(self, protocol="tcp", port=28080, marker="first"):
        process, log_path = self._start_process("backend", [sys.executable, "-u", "-c", _SERVER, "10.81.0.2", str(port), protocol, marker])
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if "READY" in log_path.read_text():
                return process
            if process.poll() is not None:
                break
            time.sleep(0.05)
        self.fail("Backend did not start: " + log_path.read_text())

    def _request(self, port=18080, protocol="tcp"):
        return self._ns("external", [sys.executable, "-c", _CLIENT, "198.18.0.1", str(port), protocol], check=False)

    def _assert_reaches(self, marker="first", port=18080, protocol="tcp"):
        deadline = time.monotonic() + 6
        while True:
            result = self._request(port, protocol)
            if result.returncode == 0 and result.stdout.strip() == marker + "|twinlink-packet-path":
                return
            if time.monotonic() >= deadline:
                logs = "\n".join(path.read_text() for path in self.directory.glob("process-*.log"))
                self.fail("External packet path failed: " + result.stderr + "\n" + logs)
            time.sleep(0.15)

    def _assert_closed(self, port=18080, protocol="tcp"):
        result = self._request(port, protocol)
        self.assertNotEqual(result.returncode, 0, "disabled/deleted public port still exposed: " + result.stdout)

    def _assert_foreign_unchanged(self):
        for side in self.hosts:
            self.assertEqual(self.foreign[side], self._ns(side, ["nft", "-j", "list", "table", "ip", "twinlink_foreign_test"]).stdout)
            self.assertEqual(self.default_routes[side], self._ns(side, ["ip", "-j", "route", "show", "default"]).stdout)

    def test_kernel_tcp_edit_disable_restart_delete_and_no_foreign_changes(self):
        self._echo()
        self._add_forward()
        self._assert_reaches()
        self._echo(port=28081, marker="edited")
        for side in self.hosts:
            self._edit(side, destination_port="28081")
        self._assert_reaches("edited")
        self._edit("vps1", enabled=False, running=False)
        self._assert_closed()
        self._edit("vps1", enabled=True, running=True)
        self._assert_reaches("edited")
        # Runtime stop/start exercises restart without losing persisted config.
        self._edit("vps1", running=False)
        self._assert_closed()
        self._edit("vps1", running=True)
        self._assert_reaches("edited")
        for side in self.hosts:
            new = self.stores[side].read()
            del new["forwards"]["web"]
            self._apply(side, new, "delete forwarding")
        self._assert_closed()
        self._assert_foreign_unchanged()
        for side in self.hosts:
            new = self.stores[side].read()
            interface = new["tunnels"]["edge"]["interface"]
            del new["tunnels"]["edge"]
            self._apply(side, new, "delete tunnel after its dependents")
            self.assertNotIn(interface, {link["ifname"] for link in self.hosts[side].links()})

    def test_kernel_udp_external_request_and_disable(self):
        self._echo(protocol="udp")
        self._add_forward(protocol="udp")
        self._assert_reaches(protocol="udp")
        self._edit("vps1", enabled=False, running=False)
        self._assert_closed(protocol="udp")
        self._edit("vps1", enabled=True, running=True)
        self._assert_reaches(protocol="udp")

    def test_gre_key_removal_and_endpoint_settings_reapply(self):
        for key, mtu in ((None, 1300), (61724, 1400)):
            for side in self.hosts:
                new = self.stores[side].read()
                new["tunnels"]["edge"].update(key=key, mtu=mtu, verified=False)
                self._apply(side, new, "edit GRE key and MTU")
            for side in self.hosts:
                saved = self.stores[side].read()
                status = self.hosts[side].tunnel_status(saved["tunnels"]["edge"], probe=True)
                self.assertTrue(status["peer_reachable"], status)
                self.assertFalse(status["drift"], status)
        self._assert_foreign_unchanged()

    def test_kernel_detects_and_repairs_nft_and_gre_drift_and_boot_restore(self):
        self._echo()
        self._add_forward()
        self._assert_reaches()
        side = "vps1"
        saved = self.stores[side].read()
        self._ns(side, ["nft", "flush", "chain", "ip", "twinlink", "prerouting"])
        self.assertTrue(self.hosts[side].kernel_forward_drift(saved["forwards"]["web"], saved["tunnels"]["edge"]))
        self._assert_closed()
        self._apply(side, saved, "reapply rules", boot=True)
        self._assert_reaches()
        interface = saved["tunnels"]["edge"]["interface"]
        self._ns(side, ["ip", "link", "set", "dev", interface, "mtu", "1200"])
        self.assertTrue(self.hosts[side].tunnel_status(saved["tunnels"]["edge"], probe=False)["drift"])
        self._apply(side, self.stores[side].read(), "reapply GRE", boot=True)
        self.assertFalse(self.hosts[side].tunnel_status(saved["tunnels"]["edge"], probe=False)["drift"])
        # Delete only runtime resources, retaining enabled persisted state.
        for side in self.hosts:
            saved = self.stores[side].read()
            self._ns(side, ["ip", "link", "delete", "dev", saved["tunnels"]["edge"]["interface"]])
            self._ns(side, ["nft", "delete", "table", "ip", "twinlink"])
        self._assert_closed()
        for side in self.hosts:
            self._apply(side, self.stores[side].read(), "restore persisted enabled state", boot=True)
        self._assert_reaches()
        self._assert_foreign_unchanged()

    def test_kernel_failed_apply_rolls_back_working_packet_path(self):
        self._echo()
        self._add_forward()
        self._assert_reaches()
        previous = self.stores["vps1"].read()
        new = copy.deepcopy(previous)
        new["forwards"]["web"]["bind_port"] = "18081"
        new["forwards"]["web"]["revision"] += 1
        self.hosts["vps1"].fail_nft_matching = "tcp dport 18081 counter dnat"
        with self.assertRaises(ApplyError):
            self._apply("vps1", new, "inject failure after removal of old exposure")
        self.assertEqual(previous, self.stores["vps1"].read())
        self.assertFalse(self.stores["vps1"].journal.exists())
        self._assert_reaches()
        self._assert_closed(port=18081)
        self._assert_foreign_unchanged()

    def test_rathole_tcp_external_request_edit_disable_restart_delete_and_restore(self):
        self._rathole_lifecycle()

    def test_rathole_noise_external_request_edit_disable_restart_delete_and_restore(self):
        self._rathole_lifecycle(noise=True)

    def test_v2_direct_rathole_delivers_with_gre_down(self):
        binary = os.environ.get("TWINLINK_RATHOLE_BINARY") or shutil.which("rathole")
        if not binary or not Path(binary).is_file():
            self.skipTest("set TWINLINK_RATHOLE_BINARY to the pinned executable")
        from twinlink.contracts import new_revision
        from twinlink.pair_bundle import credentials
        from twinlink.profiles import render_rathole
        from twinlink.rathole import check_version, generate_keypair
        from twinlink.store import atomic_write
        check_version(binary)
        noise = generate_keypair(binary)
        r = new_revision("direct", {"vps1": "198.18.0.1", "vps2": "198.18.0.2"}, 3456,
            [{"id": "web", "bind": "198.18.0.1", "protocol": "tcp", "ports": "18080",
              "backend": {"address": "10.81.0.2", "ports": "28080"}, "probe": None}])
        r["public_keys"]["noise"] = noise["noise_public_key"]
        creds = credentials(noise)
        self._echo()
        processes = []
        for role in self.hosts:
            self._ns(role, ["ip", "link", "set", self.stores[role].read()["tunnels"]["edge"]["interface"], "down"])
            path = self.directory / (role + "-direct.toml")
            atomic_write(path, render_rathole(r, role, "direct-rathole", creds))
            processes.append(self._start_process(role, [binary, str(path)])[0])
        self._assert_reaches()
        for process in processes:
            self._stop(process)
        self._assert_closed()
        self._assert_foreign_unchanged()

    def test_v2_paqet_candidate_tcp_and_udp_packet_qualification(self):
        """Candidate evidence only; qualification is reviewed before enabling it."""
        import hashlib
        from twinlink import paqet
        from twinlink.contracts import new_revision
        from twinlink.pair_bundle import credentials
        from twinlink.profiles import table_name
        from twinlink.store import atomic_write
        binary = os.environ.get("TWINLINK_PAQET_BINARY")
        expected = os.environ.get("TWINLINK_PAQET_SHA256")
        if not binary or not expected:
            self.skipTest("Paqet candidate requires TWINLINK_PAQET_BINARY and independently trusted TWINLINK_PAQET_SHA256")
        self.assertEqual(hashlib.sha256(Path(binary).read_bytes()).hexdigest(), expected)
        version = subprocess.run([binary, "version"], text=True, capture_output=True, timeout=3, check=True)
        self.assertIn(paqet.VERSION, version.stdout + version.stderr)
        for protocol in ("tcp", "udp"):
            with self.subTest(protocol=protocol):
                self._echo(protocol=protocol)
                r = new_revision("candidate", {"vps1": "198.18.0.1", "vps2": "198.18.0.2"}, 3456,
                    [{"id": "echo", "bind": "198.18.0.1", "protocol": protocol, "ports": "18080",
                      "backend": {"address": "10.81.0.2", "ports": "28080"}, "probe": None}])
                creds = credentials()
                processes = []
                for role in ("vps2", "vps1"):
                    peer = "vps1" if role == "vps2" else "vps2"
                    link = json.loads(self._ns(peer, ["ip", "-j", "link", "show", "wan"]).stdout)[0]
                    facts = {"interface": "wan", "source": r["public_endpoints"][role], "gateway": r["public_endpoints"][peer],
                             "router_mac": link["address"], "ephemeral_range": [32768, 60999]}
                    if role == "vps2":
                        rules = paqet.packet_exceptions(r, facts, table_name("candidate"), "00000000-0000-0000-0000-000000000001")
                        self._ns(role, ["nft", "--check", "--file", "-"], input=rules)
                        self._ns(role, ["nft", "--file", "-"], input=rules)
                    path = self.directory / (role + "-candidate.yaml")
                    atomic_write(path, paqet.render_config(r, role, facts, creds["paqet"]))
                    processes.append(self._start_process(role, [binary, "run", "-c", str(path)])[0])
                self._assert_reaches(protocol=protocol)
                for process in processes:
                    self._stop(process)
                self._assert_closed(protocol=protocol)
                self._ns("vps2", ["nft", "delete", "table", "ip", table_name("candidate")])
        self._assert_foreign_unchanged()

    def test_rathole_shared_noise_config_two_ports_and_independent_stop(self):
        binary = os.environ.get("TWINLINK_RATHOLE_BINARY") or shutil.which("rathole")
        if not binary or not Path(binary).is_file() or not os.access(binary, os.X_OK):
            self.skipTest("set TWINLINK_RATHOLE_BINARY to an executable rathole binary")
        from twinlink.rathole import generate_keypair
        keys = generate_keypair(binary)
        self._echo()
        self._echo(port=28081, marker="second")
        for side in self.hosts:
            candidate = self.stores[side].read()
            for public, destination in ((18080, 28080), (18081, 28081)):
                entry = validate_forward({"name": f"shared-{public}", "tunnel": "edge", "mode": "rathole",
                                          "protocol": "tcp", "bind_address": "198.18.0.1", "bind_port": str(public),
                                          "destination_address": "10.81.0.2", "destination_port": str(destination),
                                          "rathole_group": "shared", "transport_port": 2444,
                                          "token": "integration-shared-service-0123456789", "rathole_transport": "noise",
                                          "enabled": True, "running": True, **keys}, candidate)
                candidate["forwards"][entry["name"]] = entry
            self._apply(side, candidate, "add shared Noise config")

        def start_pair():
            return [self._start_process(side, [binary, rathole_config_path("shared", str(self.stores[side].directory))])[0]
                    for side in self.hosts]

        pair = start_pair()
        self._assert_reaches()
        self._assert_reaches("second", port=18081)
        for process in pair:
            self._stop(process)
        for side in self.hosts:
            candidate = self.stores[side].read()
            candidate["forwards"]["shared-18080"].update(enabled=False, running=False)
            self._apply(side, candidate, "disable only the first shared service")
        start_pair()
        self._assert_reaches("second", port=18081)
        self._assert_closed(port=18080)
        self._assert_foreign_unchanged()

    def _rathole_lifecycle(self, noise=False):
        binary = os.environ.get("TWINLINK_RATHOLE_BINARY") or shutil.which("rathole")
        if not binary or not Path(binary).is_file() or not os.access(binary, os.X_OK):
            self.skipTest("set TWINLINK_RATHOLE_BINARY to an executable rathole binary")
        self._echo()
        self._add_forward(mode="rathole", noise=noise)

        def start_pair():
            pair = []
            for side in self.hosts:
                config = rathole_config_path("web", str(self.stores[side].directory))
                process, _ = self._start_process(side, [binary, config])
                pair.append(process)
            return pair

        # Process management is explicit here because namespaces do not run
        # systemd. Real systemd boot/restart must also be tested on two VPSs.
        pair = start_pair()
        self._assert_reaches()
        for process in pair:
            self._stop(process)
        self._assert_closed()
        pair = start_pair()
        self._assert_reaches()
        for process in pair:
            self._stop(process)
        self._echo(port=28081, marker="edited")
        for side in self.hosts:
            self._edit(side, destination_port="28081")
        pair = start_pair()
        self._assert_reaches("edited")
        for process in pair:
            self._stop(process)
        for side in self.hosts:
            self._edit(side, enabled=False, running=False)
        self._assert_closed()
        for side in self.hosts:
            self._edit(side, enabled=True, running=True)
            saved = self.stores[side].read()
            self._ns(side, ["ip", "link", "delete", "dev", saved["tunnels"]["edge"]["interface"]])
            self._apply(side, saved, "restore persisted GRE and proxy config", boot=True)
        pair = start_pair()
        self._assert_reaches("edited")
        for process in pair:
            self._stop(process)
        for side in self.hosts:
            new = self.stores[side].read()
            del new["forwards"]["web"]
            self._apply(side, new, "delete forwarding")
            self.assertFalse(Path(rathole_config_path("web", str(self.stores[side].directory))).exists())
        self._assert_closed()
        self._assert_foreign_unchanged()


if __name__ == "__main__":
    unittest.main()
