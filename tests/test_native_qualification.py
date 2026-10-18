"""Harness readiness regressions only; these are not native packet evidence."""
import subprocess
import unittest
from unittest.mock import Mock, patch

from tests.integration import test_netns as native


class CandidateReadinessTests(unittest.TestCase):
    def candidate(self):
        return native.NetworkNamespaceIntegrationTests("test_v2_paqet_candidate_tcp_and_udp_packet_qualification")

    def listener(self, protocol="tcp", pid=1234):
        state = "LISTEN" if protocol == "tcp" else "UNCONN"
        return subprocess.CompletedProcess([], 0,
            f'{protocol} {state} 0 128 198.18.0.1:18080 0.0.0.0:* users:(("paqet",pid={pid},fd=3))\n', "")

    def test_delayed_tcp_and_udp_listener_is_awaited(self):
        for protocol in ("tcp", "udp"):
            case = self.candidate()
            process = Mock(pid=1234)
            process.poll.return_value = None
            with self.subTest(protocol=protocol), patch.object(case, "_ns", side_effect=[subprocess.CompletedProcess([], 0, "", ""), self.listener(protocol)]) as read, \
                 patch("tests.integration.test_netns.time.sleep") as sleep:
                case._assert_client_ready(process, protocol=protocol)
                self.assertEqual(read.call_count, 2)
                sleep.assert_called_once()

    def test_foreign_listener_does_not_establish_client_readiness(self):
        case = self.candidate()
        process = Mock(pid=1234)
        process.poll.return_value = None
        with patch.object(case, "_ns", side_effect=[self.listener(pid=5678), self.listener()]) as read, patch("tests.integration.test_netns.time.sleep"):
            case._assert_client_ready(process)
            self.assertEqual(read.call_count, 2)

    def test_failed_startup_is_not_key_rejection_evidence(self):
        case = self.candidate()
        process = Mock(pid=1234)
        process.poll.return_value = 1
        with patch.object(case, "_ns") as read, self.assertRaisesRegex(AssertionError, "exited before listener readiness"):
            case._assert_client_ready(process)
        read.assert_not_called()

    def test_missing_listener_times_out_instead_of_passing(self):
        case = self.candidate()
        process = Mock(pid=1234)
        process.poll.return_value = None
        with patch.object(case, "_ns", return_value=subprocess.CompletedProcess([], 0, "", "")), \
             patch("tests.integration.test_netns.time.sleep"), patch("tests.integration.test_netns.time.monotonic", side_effect=[0, 0, 0.1, 0.2]), \
             self.assertRaisesRegex(AssertionError, "never owned"):
            case._assert_client_ready(process, timeout=0.15)
