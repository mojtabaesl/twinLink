"""Configuration contract tests. Kernel/network behavior is integration-tested separately."""

import copy
import unittest

from twinlink import render


def tunnel(side="vps1"):
    private = ("10.77.0.1/30", "10.77.0.2/30")
    if side == "vps2":
        private = private[::-1]
    return {"name": "edge", "side": side, "local_public": "192.0.2.10", "remote_public": "198.51.100.10", "local_private": private[0], "remote_private": private[1], "interface": "tl123456789abc", "mtu": 1476, "ttl": 64, "enabled": True, "running": True, "verified": True}


def forward(side="vps1", mode="kernel"):
    return {"name": "web", "tunnel": "edge", "side": side, "mode": mode, "protocol": "tcp", "bind_address": "192.0.2.10", "bind_port": "8080", "destination_address": "10.77.0.2", "destination_port": "80", "relay_port": "31000", "transport_port": 24001, "token": "a-long-per-service-secret-token-0123456789", "enabled": True, "running": True, "revision": 1}


def state(side="vps1", mode="kernel"):
    return {"version": 1, "tunnels": {"edge": tunnel(side)}, "forwards": {"web": forward(side, mode)}}


class RenderTests(unittest.TestCase):
    def test_units_invoke_engine_without_shell_or_secret(self):
        unit = render.render_tunnel_unit(tunnel())
        self.assertIn(render.OWNERSHIP_MARKER, unit)
        self.assertIn('ExecStart="/usr/local/bin/twinlink" "internal" "tunnel-up" "edge"', unit)
        self.assertIn('ExecStop="/usr/local/bin/twinlink" "internal" "tunnel-down" "edge"', unit)
        self.assertIn("RemainAfterExit=yes", unit)
        self.assertIn("After=network-online.target twinlink-restore.service", unit)
        self.assertNotIn("/bin/sh", unit)
        self.assertNotIn("Restart=", unit)

    def test_systemd_arguments_escape_specifiers_and_environment(self):
        unit = render.render_tunnel_unit(tunnel(), '/opt/a %i $VALUE/bin/twinlink')
        self.assertIn('"/opt/a %%i $$VALUE/bin/twinlink"', unit)
        for bad in ("relative/bin", "/tmp/a\nExecStart=/bin/false", "/tmp/../etc/twinlink"):
            with self.assertRaises(ValueError):
                render.render_tunnel_unit(tunnel(), bad)

    def test_rathole_matching_service_and_token_over_private_gre(self):
        server = render.render_rathole(forward(mode="rathole"), tunnel())
        client = render.render_rathole(forward("vps2", "rathole"), tunnel("vps2"))
        self.assertIn('bind_addr = "10.77.0.1:24001"', server)
        self.assertIn('remote_addr = "10.77.0.1:24001"', client)
        self.assertIn('[server.services."web"]', server)
        self.assertIn('[client.services."web"]', client)
        self.assertIn('bind_addr = "192.0.2.10:8080"', server)
        self.assertIn('local_addr = "10.77.0.2:80"', client)
        secret_line = next(line for line in server.splitlines() if line.startswith("token = "))
        self.assertIn(secret_line, client)
        self.assertNotIn("192.0.2.10:24001", server)

    def test_rathole_rejects_unverified_udp_ranges_and_weak_secrets(self):
        for change in ({"protocol": "udp"}, {"bind_port": "8080-8081"}, {"destination_port": "80-81"}, {"token": "weak"}, {"token": "x" * 32 + "\n"}):
            item = forward(mode="rathole")
            item.update(change)
            with self.assertRaises(ValueError):
                render.render_rathole(item, tunnel())

    def test_rathole_units_harden_and_order_gre_without_secret_argv(self):
        item = forward(mode="rathole")
        unit = render.render_rathole_unit(item, tunnel())
        self.assertIn("twinlink-gre-edge.service", unit)
        self.assertIn("twinlink-restore.service", unit)
        self.assertIn('ExecStart="/usr/local/bin/rathole" "/var/lib/twinlink/rathole/web.toml"', unit)
        self.assertIn("Restart=always", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertNotIn(item["token"], unit)
        # Boot restore owns startup sequencing and may itself start this unit.
        self.assertNotIn("Requires=", unit)

    def test_kernel_vps1_uses_relay_and_snat_for_return_path(self):
        rules = render.render_nft(state())
        self.assertIn('ip daddr 192.0.2.10 tcp dport 8080 counter dnat to 10.77.0.2:31000', rules)
        self.assertIn('oifname "tl123456789abc" ip daddr 10.77.0.2 tcp dport 31000 counter snat to 10.77.0.1', rules)
        self.assertIn("ct state established,related counter accept", rules)
        self.assertNotIn("dnat to 10.77.0.2:80", rules)

    def test_kernel_vps2_second_stage_is_tunnel_and_peer_restricted(self):
        data = state("vps2")
        data["forwards"]["web"]["destination_address"] = "10.90.0.10"
        rules = render.render_nft(data)
        self.assertIn('iifname "tl123456789abc" ip saddr 10.77.0.1 ip daddr 10.77.0.2 tcp dport 31000 counter dnat to 10.90.0.10:80', rules)
        self.assertIn('iifname "tl123456789abc" ip saddr 10.77.0.1 ip daddr 10.90.0.10 tcp dport 80 counter masquerade', rules)
        self.assertIn('oifname "tl123456789abc" ip daddr 10.77.0.1 ct state established,related counter accept', rules)

    def test_kernel_vps2_local_service_still_maps_relay_port(self):
        rules = render.render_nft(state("vps2"))
        self.assertIn("tcp dport 31000 counter dnat to 10.77.0.2:80", rules)
        self.assertNotIn("masquerade", rules)
        self.assertNotIn("peer-forward", rules)

    def test_kernel_udp_ranges_preserve_port_offset_both_sides(self):
        for side in ("vps1", "vps2"):
            data = state(side)
            data["forwards"]["web"].update(protocol="udp", bind_port="8080-8082", relay_port="31000-31002", destination_port="80-82")
            rules = render.render_nft(data)
            if side == "vps1":
                for offset in range(3):
                    self.assertIn(f"udp dport {8080 + offset} counter dnat to 10.77.0.2:{31000 + offset}", rules)
            else:
                for offset in range(3):
                    self.assertIn(f"udp dport {31000 + offset} counter dnat to 10.77.0.2:{80 + offset}", rules)

    def test_kernel_ranges_are_bounded_and_equal_width(self):
        for change in ({"bind_port": "1-257"}, {"destination_port": "80-81"}, {"relay_port": "31000-31001"}, {"bind_port": "65536"}, {"bind_port": "90-80"}):
            data = state()
            data["forwards"]["web"].update(change)
            with self.assertRaises(ValueError):
                render.render_nft(data)

    def test_kernel_range_can_fan_in_to_one_backend_port(self):
        data = state("vps2")
        data["forwards"]["web"].update(bind_port="8080-8082", relay_port="31000-31002", destination_port="80")
        rules = render.render_nft(data)
        for port in range(31000, 31003):
            self.assertIn(f"tcp dport {port} counter dnat to 10.77.0.2:80", rules)

    def test_disabled_does_not_mean_stopped_but_stopped_has_no_rules(self):
        data = state()
        data["forwards"]["web"]["enabled"] = False
        self.assertIn("twinlink:web:dnat", render.render_nft(data))
        data["forwards"]["web"]["running"] = False
        self.assertNotIn("twinlink:web:", render.render_nft(data))
        data["forwards"]["web"]["running"] = True
        data["tunnels"]["edge"]["running"] = False
        self.assertNotIn("twinlink:web:", render.render_nft(data))

    def test_namespace_is_exclusive_and_does_not_flush(self):
        rules = render.render_nft(state())
        self.assertIn("table ip twinlink {", rules)
        self.assertIn('comment "twinlink-owned"', rules)
        for line in rules.splitlines():
            if not line.lstrip().startswith("#"):
                self.assertNotIn("flush", line)
                self.assertNotIn("delete table", line)
        self.assertIn("policy accept", rules)
        self.assertIn("does not override drops", rules)

    def test_wildcard_only_matches_local_destination_addresses(self):
        data = state()
        data["forwards"]["web"]["bind_address"] = "0.0.0.0"
        self.assertIn("fib daddr type local tcp dport 8080", render.render_nft(data))

    def test_stable_identities_and_deterministic_render(self):
        data = state()
        second = copy.deepcopy(data["forwards"]["web"])
        second.update(name="api", bind_port="8081", relay_port="31001")
        data["forwards"]["api"] = second
        reversed_state = copy.deepcopy(data)
        reversed_state["forwards"] = dict(reversed(list(data["forwards"].items())))
        self.assertEqual(render.render_nft(data), render.render_nft(reversed_state))
        self.assertEqual(len(render.expected_nft_comments(state())), 5)
        self.assertIn("twinlink:web:snat", render.expected_nft_comments(state()))

    def test_render_files_modes_paths_and_no_input_mutation(self):
        data = state(mode="rathole")
        before = copy.deepcopy(data)
        files = render.render_files(data, "/var/lib/twinlink", "/etc/systemd/system", "/opt/bin/twinlink", "/opt/bin/rathole")
        self.assertEqual(data, before)
        self.assertEqual(files["/var/lib/twinlink/rathole/web.toml"]["mode"], 0o600)
        self.assertEqual(files["/var/lib/twinlink/managed.nft"]["mode"], 0o600)
        self.assertEqual(files["/etc/systemd/system/twinlink-gre-edge.service"]["mode"], 0o644)
        self.assertIn("/etc/systemd/system/twinlink-rathole-web.service", files)
        self.assertIn("/etc/systemd/system/twinlink-restore.service", files)
        for spec in files.values():
            self.assertTrue(spec["content"].startswith(render.OWNERSHIP_MARKER))

    def test_unit_callbacks_preserve_custom_state_and_runtime_paths(self):
        files = render.render_files(state(), "/srv/private twinlink", "/opt/units", "/opt/twinlink-runtime", "/opt/rathole")
        for path in ("/opt/units/twinlink-gre-edge.service", "/opt/units/twinlink-restore.service"):
            unit = files[path]["content"]
            self.assertIn('"/opt/twinlink-runtime" "--state-dir" "/srv/private twinlink" "--unit-dir" "/opt/units" "--runtime-path" "/opt/twinlink-runtime" "--rathole-binary" "/opt/rathole" "internal"', unit)

    def test_rejects_names_sides_addresses_and_missing_tunnel(self):
        for invalid in ("../web", "web\nExecStart=/bin/sh", "-bad", ""):
            with self.assertRaises(ValueError):
                render.tunnel_unit_name(invalid)
        for change in ({"side": "vps2"}, {"bind_address": "::1"}, {"protocol": "tcp; accept"}):
            data = state()
            data["forwards"]["web"].update(change)
            with self.assertRaises(ValueError):
                render.render_nft(data)
        data = state()
        data["tunnels"].clear()
        with self.assertRaises(ValueError):
            render.render_nft(data)

    def test_restore_revalidates_configuration_at_boot(self):
        unit = render.render_restore_unit()
        self.assertIn('ExecStart="/usr/local/bin/twinlink" "internal" "restore"', unit)
        self.assertIn("WantedBy=multi-user.target", unit)
        self.assertIn("After=network-online.target", unit)


if __name__ == "__main__":
    unittest.main()
