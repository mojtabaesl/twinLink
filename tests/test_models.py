import copy
import unittest

from twinlink.models import (ValidationError, empty_state, interface_name, ports,
                             validate_forward, validate_state, validate_tunnel)


def tunnel(**changes):
    entry = dict(name="edge", side="vps1", local_public="198.51.100.1",
                 remote_public="203.0.113.2", local_private="10.77.0.1/30",
                 remote_private="10.77.0.2/30", verified=True, key=41)
    entry.update(changes)
    return validate_tunnel(entry, empty_state())


def populated_state():
    state = empty_state()
    state["tunnels"]["edge"] = tunnel()
    return state


def forward(**changes):
    entry = dict(name="web", tunnel="edge", mode="kernel", protocol="tcp",
                 bind_port="8080", destination_address="10.20.30.40", destination_port="80")
    entry.update(changes)
    return entry


class TunnelValidationTests(unittest.TestCase):
    def test_interface_stable_and_owned(self):
        self.assertEqual(interface_name("edge"), interface_name("edge"))
        self.assertTrue(interface_name("edge").startswith("tl"))
        self.assertEqual(len(interface_name("edge")), 15)
        self.assertNotEqual(interface_name("edge"), interface_name("other"))
        with self.assertRaises(ValidationError):
            tunnel(interface="eth0")

    def test_defaults_and_integer_bounds(self):
        normalized = tunnel(key="4294967295", ttl="255", mtu="576")
        self.assertEqual(normalized["key"], 4294967295)
        self.assertFalse(normalized["running"])
        self.assertEqual(tunnel(key=42)["mtu"], 1472)
        self.assertEqual(tunnel(key=None)["mtu"], 1476)
        for changes in ({"key": 0}, {"key": 4294967296}, {"ttl": 0}, {"ttl": True},
                        {"mtu": 1500}, {"enabled": "false"}, {"name": "../../eth0"}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                tunnel(**changes)

    def test_private_addresses_must_be_distinct_same_rfc1918_subnet(self):
        bad = [dict(local_private="8.8.8.8/30", remote_private="8.8.8.9/30"),
               dict(local_private="10.77.0.0/30"), dict(remote_private="10.77.0.1/30"),
               dict(remote_private="10.77.1.2/30"), dict(local_private="100.64.0.1/30"),
               dict(local_private="10.77.0.1"), dict(remote_private="10.77.0.3/30")]
        for changes in bad:
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                tunnel(**changes)

    def test_point_to_point_31_accepted(self):
        normalized = tunnel(local_private="10.1.0.0/31", remote_private="10.1.0.1/31")
        self.assertEqual(normalized["local_private"], "10.1.0.0/31")

    def test_endpoints_cannot_be_wildcard_multicast_loopback_or_equal(self):
        for value in ("0.0.0.0", "224.0.0.1", "127.0.0.1", "255.255.255.255", "203.0.113.2", "::1"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                tunnel(local_public=value)

    def test_conflicts_include_disabled_tunnels_and_reversed_tuple(self):
        state = populated_state()
        other = tunnel(name="second", local_private="10.78.0.1/30", remote_private="10.78.0.2/30")
        with self.assertRaisesRegex(ValidationError, "endpoints and key"):
            validate_tunnel(other, state)
        other.update(key=42, local_private="10.77.0.5/29", remote_private="10.77.0.6/29")
        with self.assertRaisesRegex(ValidationError, "overlaps"):
            validate_tunnel(other, state)
        original = state["tunnels"]["edge"]
        self.assertEqual(validate_tunnel(original, state, existing_name="edge"), original)


class ForwardValidationTests(unittest.TestCase):
    def test_ports_are_strict_and_bounded(self):
        self.assertEqual(ports("8000-8010"), (8000, 8010))
        self.assertEqual(ports(80), (80, 80))
        for value in ("0", "65536", "2-1", "1:2", "80; reboot", " 80", True, None):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                ports(value)

    def test_verified_gre_gate_and_load_of_degraded_config(self):
        state = populated_state()
        state["tunnels"]["edge"]["verified"] = False
        with self.assertRaisesRegex(ValidationError, "verify GRE"):
            validate_forward(forward(), state)
        normalized = validate_forward(forward(), state, existing_name="web")
        state["forwards"]["web"] = normalized
        self.assertEqual(validate_state(state), state)

    def test_same_protocol_public_conflicts_reserve_disabled_ports(self):
        state = populated_state()
        state["forwards"]["web"] = validate_forward(forward(), state)
        with self.assertRaisesRegex(ValidationError, "overlaps"):
            validate_forward(forward(name="other", bind_port="8079-8081", destination_port="80-82"), state)
        self.assertEqual(validate_forward(forward(name="udp", protocol="udp"), state)["protocol"], "udp")

    def test_wildcard_listener_conflicts_and_own_managed_listener_skip(self):
        state = populated_state()
        listeners = [dict(address="0.0.0.0", port="8080", protocol="tcp")]
        with self.assertRaisesRegex(ValidationError, "host listener"):
            validate_forward(forward(), state, listeners=listeners)
        listeners[0]["managed"] = "web"
        self.assertEqual(validate_forward(forward(), state, existing_name="web", listeners=listeners)["name"], "web")

    def test_protected_ports_bind_selection_and_range_limit(self):
        state = populated_state()
        for changes in (dict(bind_port="20-25", destination_port="80"),
                        dict(bind_address="127.0.0.1"), dict(bind_port="8000-8256"),
                        dict(bind_port="8000-8002", destination_port="90-91"),
                        dict(destination_address="127.0.0.1")):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                validate_forward(forward(**changes), state)
        with self.assertRaisesRegex(ValidationError, "management"):
            validate_forward(forward(bind_port="2222"), state, protected_ports=(2222,))
        self.assertEqual(validate_forward(forward(bind_address="192.0.2.9"), state)["bind_address"], "192.0.2.9")

    def test_rathole_uses_unique_strong_token_single_tcp_port(self):
        state = populated_state()
        a = validate_forward(forward(mode="rathole", destination_address="127.0.0.1"), state)
        b = validate_forward(forward(mode="rathole", destination_address="127.0.0.1"), state)
        self.assertGreaterEqual(len(a["token"]), 43)
        self.assertNotEqual(a["token"], b["token"])
        for changes in (dict(protocol="udp"), dict(bind_port="8000-8001"), dict(token="weak")):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                validate_forward(forward(mode="rathole", **changes), state)

    def test_relay_ranges_reserved_and_bounded(self):
        state = populated_state()
        state["forwards"]["web"] = validate_forward(forward(bind_port="8000-8002", destination_port="80-82", relay_port="30000-30002"), state)
        with self.assertRaisesRegex(ValidationError, "relay/transport"):
            validate_forward(forward(name="other", bind_port="9000", relay_port="30001"), state)
        with self.assertRaisesRegex(ValidationError, "relay range"):
            validate_forward(forward(name="other", bind_port="9000-9001", relay_port="30010"), state)

    def test_vps2_keeps_vps1_public_bind_and_ignores_vps2_public_listeners(self):
        state = populated_state()
        state["tunnels"]["edge"] = tunnel(side="vps2", local_public="203.0.113.2", remote_public="198.51.100.1", local_private="10.77.0.2/30", remote_private="10.77.0.1/30")
        normalized = validate_forward(forward(), state, listeners=[dict(address="0.0.0.0", port="8080", protocol="tcp")])
        self.assertEqual(normalized["bind_address"], "198.51.100.1")

    def test_validation_does_not_mutate_inputs(self):
        state, entry = populated_state(), forward()
        snapshot = copy.deepcopy((state, entry))
        validate_forward(entry, state)
        self.assertEqual((state, entry), snapshot)


if __name__ == "__main__":
    unittest.main()
