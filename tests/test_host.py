import copy
import json
import subprocess
import unittest
from unittest.mock import patch

from twinlink.host import (Host, HostError, _nft_signature, _rendered_rule_expressions,
                           parse_ping, parse_ss, redact, require_linux_root)


TUNNEL = {"name": "test", "side": "vps1", "interface": "tl123abc", "local_public": "192.0.2.1",
          "remote_public": "192.0.2.2", "local_private": "10.88.0.1/30",
          "remote_private": "10.88.0.2/30", "mtu": 1476, "ttl": 64,
          "key": 123, "enabled": True, "running": True}
LINK = {"ifname": "tl123abc", "ifalias": "twinlink:test", "flags": ["POINTOPOINT", "UP"],
        "mtu": 1476, "operstate": "UNKNOWN", "linkinfo": {"info_kind": "gre", "info_data":
        {"local": "192.0.2.1", "remote": "192.0.2.2", "ttl": 64, "ikey": "0.0.0.123", "okey": 123}}}
ADDRESSES = [{"ifname": "eth0", "addr_info": [{"local": "192.0.2.1", "prefixlen": 24}]},
             {"ifname": "tl123abc", "addr_info": [{"local": "10.88.0.1", "prefixlen": 30}]}]
GOOD_PING = {"returncode": 0, "stdout": "3 packets transmitted, 3 received, 0% packet loss, time 2002ms\n"
             "rtt min/avg/max/mdev = 2.000/4.500/8.000/1.000 ms", "stderr": ""}
FORWARD = {"name": "web", "side": "vps1", "mode": "rathole", "protocol": "tcp",
           "tunnel": "test", "relay_port": "40000",
           "bind_address": "0.0.0.0", "bind_port": "8080", "destination_address": "127.0.0.1",
           "destination_port": "80", "transport_port": 2333, "enabled": True,
           "running": True, "token": "super-secret-test-token"}


class NftTableCommentTests(unittest.TestCase):
    def test_snapshot_recovers_legacy_table_comment(self):
        host = Host()
        snapshot = {"nftables": [{"table": {"family": "ip", "name": "twinlink"}}]}
        with patch.object(host, "run", side_effect=[
                {"returncode": 0, "stdout": json.dumps(snapshot), "stderr": ""},
                {"returncode": 0, "stdout": 'table ip twinlink {\n\tcomment "twinlink-owned"\n}\n', "stderr": ""}]):
            self.assertEqual(host.nft_snapshot()["nftables"][0]["table"]["comment"], "twinlink-owned")

    def test_fallback_never_infers_ownership_from_untrusted_evidence(self):
        for code, text in [(0, 'table ip twinlink { chain x { comment "twinlink-owned" } }'),
                           (0, 'table ip other { comment "twinlink-owned" }'),
                           (0, 'table ip twinlink { comment "foreign" }'),
                           (1, 'table ip twinlink { comment "twinlink-owned" }')]:
            with self.subTest(code=code, text=text):
                snapshot = {"nftables": [{"table": {"family": "ip", "name": "twinlink"}}]}
                with patch.object(Host, "run", return_value={"returncode": code, "stdout": text, "stderr": ""}):
                    self.assertNotIn("comment", Host().nft_table_comments(snapshot)["nftables"][0]["table"])

    def test_explicit_foreign_json_marker_is_not_overridden(self):
        snapshot = {"nftables": [{"table": {"family": "ip", "name": "twinlink", "comment": "foreign"}}]}
        with patch.object(Host, "run") as run:
            Host().nft_table_comments(snapshot)
            run.assert_not_called()


class FakeHost(Host):
    def __init__(self):
        self.link_data = [copy.deepcopy(LINK)]
        self.address_data = copy.deepcopy(ADDRESSES)
        self.route_data = [{"dst": "default", "dev": "eth0", "gateway": "192.0.2.254"}]
        self.ping = copy.deepcopy(GOOD_PING)
        self.calls = []
        self.active = True
        self.listener_data = [{"protocol": "tcp", "address": "0.0.0.0", "port": 8080}]
        self.connection_data = [{"address": "10.88.0.1", "port": 2333,
                                 "peer_address": "10.88.0.2", "peer_port": 50000}]
        self.nft_data = {"available": True, "nftables": []}
        self.destination_up = True

    def links(self):
        return self.link_data

    def addresses(self):
        return self.address_data

    def routes(self):
        return self.route_data

    def unit_status(self, name):
        return {"name": name, "active": self.active, "exists": self.active}

    def listeners(self):
        return self.listener_data

    def connections(self):
        return self.connection_data

    def nft_snapshot(self):
        return self.nft_data

    def tcp_probe(self, address, port, timeout=2):
        self.calls.append(["tcp_probe", address, port])
        return {"reachable": self.destination_up}

    def run(self, argv, check=True, input=None, timeout=15):
        self.calls.append(argv)
        if argv[0] == "ping":
            return self.ping
        return {"returncode": 0, "stdout": "token = \"super-secret-test-token\"", "stderr": ""}


class CommandTests(unittest.TestCase):
    @patch("twinlink.host.platform.system", return_value="Darwin")
    def test_host_commands_and_root_guard_reject_non_linux(self, _):
        with self.assertRaisesRegex(HostError, "Linux"):
            Host().run(["ip", "link"])
        with self.assertRaisesRegex(HostError, "Linux"):
            require_linux_root()

    @patch("twinlink.host.platform.system", return_value="Linux")
    @patch("twinlink.host.os.geteuid", return_value=501)
    def test_live_mutations_require_root(self, *_):
        with self.assertRaisesRegex(HostError, "root"):
            require_linux_root()

    @patch("twinlink.host.platform.system", return_value="Linux")
    @patch("twinlink.host.subprocess.run")
    def test_runner_never_uses_a_shell(self, runner, _):
        runner.return_value = subprocess.CompletedProcess([], 0, "output", "")
        result = Host().run(["printf", "$(touch /tmp/nope)"])
        self.assertEqual(result["stdout"], "output")
        self.assertFalse(runner.call_args.kwargs["shell"])
        self.assertEqual(runner.call_args.args[0][1], "$(touch /tmp/nope)")
        self.assertEqual(runner.call_args.kwargs["env"]["LC_ALL"], "C")

    @patch("twinlink.host.platform.system", return_value="Linux")
    @patch("twinlink.host.subprocess.run", side_effect=FileNotFoundError)
    def test_missing_command_is_reported_or_raised(self, *_):
        self.assertEqual(Host().run(["absent"], check=False)["returncode"], 127)
        with self.assertRaisesRegex(HostError, "Dependency not found"):
            Host().run(["absent"])

    @patch("twinlink.host.platform.system", return_value="Linux")
    @patch("twinlink.host.subprocess.run", side_effect=subprocess.TimeoutExpired(["ping"], 2, b"partial", b"wait"))
    def test_timeouts_have_bounded_failure_result(self, *_):
        result = Host().run(["ping"], check=False, timeout=2)
        self.assertEqual(result["returncode"], 124)
        self.assertEqual(result["stdout"], "partial")
        self.assertIn("timed out", result["stderr"])

    def test_systemd_name_cannot_be_an_option(self):
        with self.assertRaises(HostError):
            Host().unit_status("--root=/tmp/evil.service")


class ParsingTests(unittest.TestCase):
    def test_ss_ipv4_ipv6_and_established_formats(self):
        rows = parse_ss("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                        "udp UNCONN 0 0 [::]:53 [::]:*\n"
                        "0 0 10.88.0.1:2333 10.88.0.2:52153\n"
                        "ESTAB 0 0 [fe80::1%eth0]:2345 [fe80::2%eth0]:9999")
        self.assertEqual([(row["address"], row["port"]) for row in rows],
                         [("0.0.0.0", 22), ("::", 53), ("10.88.0.1", 2333), ("fe80::1", 2345)])
        self.assertEqual(rows[2]["peer_port"], 52153)
        self.assertEqual(rows[1]["protocol"], "udp")

    @patch("twinlink.host.Path.read_text", return_value="0::/system.slice/twinlink-rathole-web.service\n")
    def test_listener_ownership_uses_socket_process_cgroup(self, _):
        host = Host()
        with patch.object(host, "run", return_value={"stdout": 'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("rathole",pid=123,fd=3))'}):
            self.assertEqual(host.listeners()[0]["managed"], "web")

    @patch("twinlink.host.Path.read_text", return_value="0::/system.slice/foreign.service\n")
    def test_foreign_listener_is_not_marked_managed(self, _):
        host = Host()
        with patch.object(host, "run", return_value={"stdout": 'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("rathole",pid=123,fd=3))'}):
            self.assertNotIn("managed", host.listeners()[0])

    def test_ping_reports_average_and_loss(self):
        result = parse_ping(GOOD_PING)
        self.assertEqual(result["health"], "up")
        self.assertEqual(result["latency_ms"], 4.5)
        self.assertEqual(result["loss_percent"], 0)

    def test_total_loss_and_unmeasurable_probe_differ(self):
        lost = parse_ping({"returncode": 1, "stdout": "3 packets transmitted, 0 received, 100% packet loss", "stderr": ""})
        unknown = parse_ping({"returncode": 127, "stdout": "", "stderr": "ping missing"})
        self.assertEqual(lost["health"], "down")
        self.assertEqual(unknown["health"], "degraded")
        self.assertIsNone(unknown["loss_percent"])

    def test_redacts_known_secrets_and_assignments_recursively(self):
        payload = {"token": "abc", "nested": ["token = \"another secret\"", "log abc", "password=other"]}
        rendered = json.dumps(redact(payload, ("abc",)))
        for secret in ("abc", "another secret", "other"):
            self.assertNotIn(secret, rendered)

    def test_nft_semantically_equivalent_fib_flag_and_masquerade_forms(self):
        expected = [{"match": {"op": "==", "left": {"fib": {"result": "type", "flags": ["daddr"]}}, "right": "local"}},
                    {"masquerade": None}]
        actual = copy.deepcopy(expected)
        actual[0]["match"]["left"]["fib"]["flags"] = "daddr"
        actual[1]["masquerade"] = {}
        self.assertEqual(_nft_signature(expected), _nft_signature(actual))
        actual[1]["masquerade"] = {"flags": ["random"]}
        self.assertNotEqual(_nft_signature(expected), _nft_signature(actual))

    def test_nft_ct_state_array_and_set_have_same_membership(self):
        # nftables 1.0.2 tests/py/any/ct.t.json uses a bare array for
        # `ct state new,established`, and a set for `ct state {new,established}`.
        for states in (["new", "established"], ["established", "related"]):
            expected = [{"match": {"left": {"ct": {"key": "state"}},
                                   "op": "==", "right": {"set": states}}}, {"accept": None}]
            actual = copy.deepcopy(expected)
            actual[0]["match"].update(op="in", right=list(reversed(states)))
            self.assertEqual(_nft_signature(expected), _nft_signature(actual))
            actual[0]["match"]["right"].append("invalid")
            self.assertNotEqual(_nft_signature(expected), _nft_signature(actual))
            actual[0]["match"].update(op="!=", right=states)
            self.assertNotEqual(_nft_signature(expected), _nft_signature(actual))

    def test_nft_ct_state_normalization_does_not_change_other_arrays(self):
        expected = [{"match": {"left": {"payload": {"protocol": "tcp", "field": "dport"}},
                               "op": "==", "right": {"set": [80, 443]}}}]
        actual = copy.deepcopy(expected)
        actual[0]["match"].update(op="in", right=[80, 443])
        self.assertNotEqual(_nft_signature(expected), _nft_signature(actual))


class TunnelTests(unittest.TestCase):
    def test_up_unknown_operstate_requires_reachable_peer(self):
        host = FakeHost()
        healthy = host.tunnel_status(TUNNEL)
        self.assertEqual(healthy["health"], "up")
        self.assertFalse(healthy["drift"])
        host.ping = {"returncode": 1, "stdout": "3 packets transmitted, 0 received, 100% packet loss", "stderr": ""}
        self.assertEqual(host.tunnel_status(TUNNEL)["health"], "down")

    def test_status_without_probe_never_claims_peer_up(self):
        result = FakeHost().tunnel_status(TUNNEL, probe=False)
        self.assertEqual(result["health"], "degraded")
        self.assertIsNone(result["peer_reachable"])

    def test_probe_source_is_private_address(self):
        host = FakeHost()
        host.tunnel_status(TUNNEL)
        self.assertEqual(host.calls[0], ["ping", "-n", "-I", "10.88.0.1", "-c", "3", "-W", "1", "10.88.0.2"])

    def test_drift_has_specific_fields_including_ownership(self):
        host = FakeHost()
        host.link_data[0]["mtu"] = 1400
        host.link_data[0]["ifalias"] = "other-owner"
        host.link_data[0]["linkinfo"]["info_data"]["remote"] = "192.0.2.99"
        host.link_data[0]["linkinfo"]["info_data"]["okey"] = 999
        result = host.tunnel_status(TUNNEL)
        self.assertEqual(result["health"], "degraded")
        self.assertEqual({item["field"] for item in result["drift"]}, {"mtu", "alias", "remote_public", "okey"})

    def test_zero_key_header_flag_differs_from_unkeyed_gre(self):
        host = FakeHost()
        host.link_data[0]["linkinfo"]["info_data"].update(ikey=0, okey=0)
        result = host.tunnel_status({**TUNNEL, "key": None})
        self.assertEqual({item["field"] for item in result["drift"]}, {"ikey", "okey"})
        host.link_data[0]["linkinfo"]["info_data"].pop("ikey")
        host.link_data[0]["linkinfo"]["info_data"].pop("okey")
        self.assertEqual(host.tunnel_status({**TUNNEL, "key": None})["drift"], [])

    def test_admin_down_does_not_probe(self):
        host = FakeHost()
        host.link_data[0]["flags"] = []
        self.assertEqual(host.tunnel_status(TUNNEL)["health"], "down")
        self.assertFalse(host.calls)

    def test_missing_interface_has_drift(self):
        host = FakeHost()
        host.link_data = []
        result = host.tunnel_status(TUNNEL)
        self.assertEqual(result["health"], "down")
        self.assertEqual(result["drift"][0]["field"], "interface")

    def test_missing_stopped_interface_is_in_sync(self):
        host = FakeHost()
        host.link_data = []
        result = host.tunnel_status({**TUNNEL, "running": False})
        self.assertEqual(result["drift"], [])

    def test_safety_rejects_physical_foreign_default_route_and_unbound_public(self):
        for mutation, fragment in ((lambda h: h.link_data[0]["linkinfo"].update(info_kind="ether"), "non-GRE"),
                                   (lambda h: h.link_data[0].update(ifalias="foreign"), "foreign"),
                                   (lambda h: h.route_data[0].update(dev=TUNNEL["interface"]), "default route"),
                                   (lambda h: h.address_data.clear(), "not assigned")):
            host = FakeHost()
            mutation(host)
            with self.assertRaisesRegex(HostError, fragment):
                host.assert_tunnel_safe(TUNNEL)

    def test_safety_accepts_owned_tunnel_and_missing_recovery_link(self):
        host = FakeHost()
        host.assert_tunnel_safe(TUNNEL)
        host.link_data = []
        host.assert_tunnel_safe(TUNNEL, existing=True)

    def test_delete_guard_can_allow_missing_public_but_still_protects_default(self):
        host = FakeHost()
        host.address_data = []
        host.assert_tunnel_safe(TUNNEL, require_public=False)
        host.route_data[0]["dev"] = TUNNEL["interface"]
        with self.assertRaisesRegex(HostError, "default route"):
            host.assert_tunnel_safe(TUNNEL, require_public=False)

    def test_private_subnet_cannot_steal_live_physical_network_or_route(self):
        host = FakeHost()
        host.address_data.append({"ifname": "mgmt0", "addr_info": [{"family": "inet", "local": "10.88.0.20", "prefixlen": 24}]})
        with self.assertRaisesRegex(HostError, "overlaps an address network"):
            host.assert_tunnel_safe(TUNNEL)
        host.assert_tunnel_safe(TUNNEL, require_public=False)
        host.address_data.pop()
        host.route_data.append({"dst": "10.88.0.0/16", "dev": "mgmt0"})
        with self.assertRaisesRegex(HostError, "overlaps an existing host route"):
            host.assert_tunnel_safe(TUNNEL)
        host.assert_tunnel_safe(TUNNEL, require_public=False)

    @patch.dict("twinlink.host.os.environ", {"SSH_CONNECTION": "10.88.0.2 50000 192.0.2.1 2222"})
    def test_private_subnet_cannot_redirect_current_ssh_peer(self):
        with self.assertRaisesRegex(HostError, "SSH client's address"):
            FakeHost().assert_tunnel_safe(TUNNEL)


class ForwardTests(unittest.TestCase):
    def test_rathole_connection_missing_listener_and_unit_have_distinct_issues(self):
        host = FakeHost()
        host.connection_data = []
        host.listener_data = []
        host.active = False
        result = host.forward_status(FORWARD, TUNNEL)
        self.assertEqual(result["health"], "down")
        self.assertTrue({"rathole_unit_failure", "rathole_connection_failure", "missing_public_listener"}.issubset(result["issues"]))

    def test_vps1_does_not_probe_vps2_loopback_destination(self):
        host = FakeHost()
        result = host.forward_status(FORWARD, TUNNEL)
        self.assertEqual(result["health"], "degraded")
        self.assertIsNone(result["destination"]["reachable"])
        self.assertFalse(any(call[0] == "tcp_probe" for call in host.calls))

    def test_tcp_destination_failure_checked_on_vps2(self):
        host = FakeHost()
        entry = {**FORWARD, "side": "vps2"}
        host.destination_up = False
        result = host.forward_status(entry, TUNNEL)
        self.assertIn("destination_unreachable", result["issues"])
        self.assertFalse(result["destination"]["reachable"])

    def test_udp_destination_stays_unknown(self):
        host = FakeHost()
        host.connection_data[0]["peer_port"] = 2333
        result = host.forward_status({**FORWARD, "side": "vps2", "protocol": "udp"}, TUNNEL)
        self.assertIsNone(result["destination"]["reachable"])
        self.assertEqual(result["health"], "degraded")

    def test_destination_range_probes_are_bounded_and_interior_stays_unknown(self):
        host = FakeHost()
        host.kernel_forward_drift = lambda *args: []
        result = host.forward_status({**FORWARD, "side": "vps2", "mode": "kernel", "destination_port": "80-200"}, TUNNEL)
        self.assertEqual(len(result["destination"]["checks"]), 2)
        self.assertTrue(result["destination"]["range_sampled"])
        self.assertIn("destination_range_sampled", result["issues"])
        self.assertEqual(result["health"], "degraded")

    def test_tunnel_failure_is_identified_first(self):
        host = FakeHost()
        host.link_data = []
        result = host.forward_status(FORWARD, TUNNEL)
        self.assertEqual(result["issues"], ["tunnel_failure"])
        self.assertNotIn("unit", result)

    def test_kernel_rule_absence_is_drift(self):
        result = FakeHost().forward_status({**FORWARD, "mode": "kernel"}, TUNNEL)
        self.assertIn("missing_firewall_rule", result["issues"])
        self.assertTrue(result["drift"])

    def test_stopped_rathole_status_detects_live_owned_exposure(self):
        host = FakeHost()
        host.listener_data[0]["managed"] = "web"
        result = host.forward_status({**FORWARD, "running": False, "enabled": False}, TUNNEL)
        self.assertEqual(result["health"], "degraded")
        self.assertTrue(result["public_listener"])
        self.assertIn("stopped_forward_exposed", result["issues"])

    def test_stopped_kernel_status_detects_leftover_managed_rule(self):
        host = FakeHost()
        host.nft_data["nftables"] = [{"rule": {"family": "ip", "table": "twinlink", "comment": "twinlink:web:dnat:0"}}]
        result = host.forward_status({**FORWARD, "mode": "kernel", "running": False}, TUNNEL)
        self.assertEqual(result["health"], "degraded")
        self.assertIn("stopped_forward_exposed", result["issues"])

    def test_kernel_semantic_comparison_detects_edited_dnat_with_intact_comment(self):
        from twinlink.render import render_nft_entry
        entry = {**FORWARD, "mode": "kernel"}
        snapshot = {"available": True, "nftables": [{"table": {
            "family": "ip", "name": "twinlink", "comment": "twinlink-owned"}}]}
        for chain, (kind, priority) in {"prerouting": ("nat", -100), "output": ("nat", -100),
                                      "postrouting": ("nat", 100), "forward": ("filter", 0)}.items():
            snapshot["nftables"].append({"chain": {"family": "ip", "table": "twinlink", "name": chain,
                "hook": chain, "type": kind, "prio": priority, "policy": "accept"}})
        for chain, lines in render_nft_entry(entry, TUNNEL).items():
            for line in lines:
                comment, expressions = _rendered_rule_expressions(line)
                expressions.insert(0, {"counter": {"bytes": 999, "packets": 5}})
                snapshot["nftables"].append({"rule": {"family": "ip", "table": "twinlink",
                    "chain": chain, "comment": comment, "expr": expressions}})
        host = FakeHost()
        self.assertEqual(host.kernel_forward_drift(entry, TUNNEL, snapshot), [])
        for expression in snapshot["nftables"][5]["rule"]["expr"]:
            if "dnat" in expression:
                expression["dnat"]["port"] = 80
        drift = host.kernel_forward_drift(entry, TUNNEL, snapshot)
        self.assertEqual(drift[0]["field"], "twinlink:web:dnat:0")

    def test_kernel_semantic_comparison_rejects_foreign_table_and_duplicates(self):
        host = FakeHost()
        snapshot = {"nftables": [{"table": {"family": "ip", "name": "twinlink", "comment": "foreign"}}]}
        drift = host.kernel_forward_drift({**FORWARD, "mode": "kernel"}, TUNNEL, snapshot)
        self.assertEqual(drift[0]["field"], "firewall_ownership")

    def test_diagnostics_redact_tokens_from_logs(self):
        result = FakeHost().diagnose_forward(FORWARD, TUNNEL)
        self.assertNotIn(FORWARD["token"], json.dumps(result))
        self.assertIn("[REDACTED]", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
