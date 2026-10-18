#!/usr/bin/env python3
"""Fetch a pinned candidate or record native namespace evidence on disposable Linux.

This never changes release qualification policy. Systemd/physical-host acceptance
must be recorded separately before an architecture/protocol is approved.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import unittest
import urllib.request

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
from twinlink import paqet
from twinlink.contracts import KCP_DEFAULTS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--fetch-only", action="store_true")
    parser.add_argument("--output", default="paqet-evidence.json")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("Native qualification/fetch requires Linux; do not run on a development Mac")
    binary = Path(args.binary).absolute()
    if args.fetch_only:
        plan = paqet.install_plan(str(binary))
        if not plan["already_installed"]:
            with urllib.request.urlopen(plan["url"], timeout=30) as response:
                if not response.geturl().startswith("https://"):
                    parser.error("Non-HTTPS release redirect")
                payload = paqet._install_payload(response.read(paqet.MAX_INSTALL_BYTES + 1), plan)
            with binary.open("xb") as stream:
                stream.write(payload)
                os.fchmod(stream.fileno(), 0o755)
        paqet.check_installed_version(binary)
        print(str(binary))
        return 0
    if os.geteuid() != 0 or os.environ.get("TWINLINK_INTEGRATION") != "1":
        parser.error("Use Linux root and TWINLINK_INTEGRATION=1 on a disposable host")
    expected = paqet.binary_pin(platform.machine())
    actual = hashlib.sha256(binary.read_bytes()).hexdigest()
    if actual != expected["sha256"]:
        parser.error("Binary differs from this architecture's reviewed release hash")
    paqet.check_installed_version(binary)
    os.environ["TWINLINK_PAQET_BINARY"] = str(binary)
    os.environ["TWINLINK_PAQET_SHA256"] = actual
    from tests.integration.test_netns import NetworkNamespaceIntegrationTests
    names = ("test_v2_paqet_candidate_tcp_and_udp_packet_qualification",
             "test_v2_paqet_native_mixed_ranges_local_remote_and_off",
             "test_v2_kernel_host_local_tcp_and_udp_coordinated_delivery",
             "test_v2_kernel_loopback_only_backend_rejected_without_standby_gre")
    suite = unittest.TestSuite(NetworkNamespaceIntegrationTests(name) for name in names)
    started = time.time()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    tools = {}
    for name, argv in (("ip", ["ip", "-Version"]), ("nft", ["nft", "--version"]),
                       ("conntrack", ["conntrack", "-V"])):
        value = subprocess.run(argv, capture_output=True, text=True, timeout=3)
        tools[name] = (value.stdout + value.stderr)[:4096]
    passed = result.wasSuccessful() and not result.skipped and result.testsRun == len(names)
    evidence = {"version": paqet.VERSION, "commit": paqet.COMMIT, "architecture": expected["architecture"],
                "sha256": actual, "kernel": platform.release(), "tools": tools, "started_at": started,
                "ended_at": time.time(), "renderer_version": 2, "settings": {"conn": 4, "local_flag": ["SA"], "remote_flag": ["SA"], "kcp": KCP_DEFAULTS},
                "tests": names, "tests_run": result.testsRun, "skipped": [(str(test), reason) for test, reason in result.skipped],
                "failures": len(result.failures), "errors": len(result.errors), "namespace_passed": passed,
                "systemd_vm_acceptance": "pending", "independent_two_host_acceptance": "pending",
                "release_qualification": "pending review; no policy updated"}
    output = Path(args.output)
    with output.open("x") as stream:
        json.dump(evidence, stream, indent=2)
        stream.write("\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
