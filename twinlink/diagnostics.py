"""Read-only bounded evidence collectors. No install, repair or sysctl writes."""
import concurrent.futures
import datetime
import errno
import json
import os
from pathlib import Path
import platform
import re
import selectors
import ipaddress
import subprocess
import time
import uuid

from .redaction import Redactor, secret_values

MAX_COMMAND_BYTES = 65536
MAX_SAMPLES = 100000
MAX_REPORT_BYTES = 10 * 1024 * 1024


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def bounded_command(argv, timeout=3, output_limit=MAX_COMMAND_BYTES):
    """Drain incrementally; stop at limits instead of buffering arbitrary logs."""
    started = time.monotonic()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = False
    try:
        with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              start_new_session=True) as child:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ, "stdout")
                    selector.register(child.stderr, selectors.EVENT_READ, "stderr")
                    while selector.get_map():
                        remaining = timeout - (time.monotonic() - started)
                        if remaining <= 0:
                            raise TimeoutError("Command timed out")
                        for key, _ in selector.select(min(remaining, 0.1)):
                            data = os.read(key.fileobj.fileno(), 8192)
                            if not data:
                                selector.unregister(key.fileobj)
                                continue
                            used = sum(len(v) for v in buffers.values())
                            buffers[key.data].extend(data[:max(0, output_limit - used)])
                            if used + len(data) > output_limit:
                                truncated = True
                                raise OverflowError("Command output truncated")
                    child.wait(timeout=max(0.01, timeout - (time.monotonic() - started)))
            finally:
                # The session's descendants can retain our pipes after their
                # parent exits. Always terminate the owned group on leaving.
                import signal
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
            return {"returncode": child.returncode, **{k: bytes(v).decode(errors="replace") for k, v in buffers.items()},
                    "error": None, "truncated": truncated}
    except (OSError, TimeoutError, OverflowError, subprocess.SubprocessError) as exc:
        return {"returncode": None, **{k: bytes(v).decode(errors="replace") for k, v in buffers.items()},
                "error": type(exc).__name__, "truncated": truncated}


def read_sample(root=Path("/proc")):
    names = {"cpu": "stat", "load": "loadavg", "memory": "meminfo", "vm": "vmstat", "sockets": "net/sockstat",
             "tcp": "net/snmp", "netstat": "net/netstat", "interfaces": "net/dev", "fd": "sys/fs/file-nr",
             "conntrack_count": "sys/net/netfilter/nf_conntrack_count", "conntrack_max": "sys/net/netfilter/nf_conntrack_max",
             "cpu_psi": "pressure/cpu", "memory_psi": "pressure/memory", "io_psi": "pressure/io", "boot_id": "sys/kernel/random/boot_id"}
    values, errors = {}, []
    for name, relative in names.items():
        try:
            with (root / relative).open() as stream:
                data = stream.read(MAX_COMMAND_BYTES + 1)
            if len(data) > MAX_COMMAND_BYTES:
                raise ValueError("Sample truncated")
            values[name] = data.strip()
        except (OSError, ValueError):
            errors.append({"collector": name, "result": "unknown", "error": "Unavailable proc evidence"})
    for name in ("cpu.max", "memory.current", "memory.max", "pids.current", "pids.max", "io.stat"):
        try:
            values["cgroup_" + name.replace(".", "_")] = (Path("/sys/fs/cgroup") / name).read_text()[:MAX_COMMAND_BYTES]
        except OSError:
            errors.append({"collector": "cgroup:" + name, "result": "unknown", "error": "Unavailable cgroup evidence"})
    try:
        stat = os.statvfs("/")
        values["disk"] = {"available_bytes": stat.f_bavail * stat.f_frsize, "available_inodes": stat.f_favail}
    except OSError:
        errors.append({"collector": "disk", "result": "unknown", "error": "Unavailable disk evidence"})
    return values, errors


def evidence(source, result, value, offset, role=None, error=None):
    return {"id": str(uuid.uuid4()), "role": role, "observed_at_utc": utc(), "monotonic_offset": offset,
            "source": source, "probe_definition": source, "result": result, "value": value,
            "unit": None, "expected_or_baseline": None, "error": error}


def probe_definitions(revision, role, profile):
    from .profiles import expanded_services
    definitions = []
    for service in expanded_services(revision):
        public = revision["public_endpoints"]["vps1"] if service["bind"] == "0.0.0.0" else service["bind"]
        for kind, address, port in (("service", public, service["port"]),
                                    ("backend", service["backend"]["address"], service["target_port"])):
            if kind == "backend" and role != "vps2":
                continue
            definitions.append({"id": f"{kind}:{service['id']}:{service['port']}", "kind": kind,
                "address": address, "port": port, "protocol": service["protocol"], "exchange": service["probe"]})
    return definitions


def application_probe(definition, timeout=3):
    """Only an explicitly configured exchange proves application delivery."""
    import socket
    exchange = definition["exchange"]
    if exchange is None:
        return {"result": "unknown", "error": "No safe application exchange configured", "latency_ms": None}
    start = time.monotonic()
    deadline = start + timeout
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if definition["protocol"] == "tcp" else socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((definition["address"], definition["port"]))
            if time.monotonic() >= deadline:
                raise TimeoutError("Application probe budget expired")
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            sock.sendall(bytes.fromhex(exchange["request_hex"]))
            expected = bytes.fromhex(exchange["response_hex"])
            received = b""
            while len(received) < len(expected):
                if time.monotonic() >= deadline:
                    raise TimeoutError("Application probe budget expired")
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                chunk = sock.recv(65536 if definition["protocol"] == "udp" else len(expected) - len(received))
                if not chunk:
                    break
                received += chunk
                if definition["protocol"] == "udp" or time.monotonic() >= deadline:
                    break
            return {"result": "pass" if received == expected else "fail", "error": None if received == expected else "Application response mismatch",
                    "latency_ms": (time.monotonic() - start) * 1000}
    except OSError as exc:
        traffic_errors = {errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED, errno.ETIMEDOUT,
                          errno.EPIPE, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN}
        failed = isinstance(exc, (TimeoutError, ConnectionError)) or exc.errno in traffic_errors
        return {"result": "fail" if failed else "unknown", "error": type(exc).__name__,
                "latency_ms": (time.monotonic() - start) * 1000 if failed else None}


def readiness(store, revision, role):
    """Artifact evidence only: never claim standby runtime or peer readiness."""
    from .contracts import digest
    from .profiles import manifests
    from .store import reject_symlink
    facts = store.facts(revision["pair_id"], revision["revision"])
    rendered = manifests(revision, role, store.credentials(revision["pair_id"], revision["revision"]), facts, store.read()["installation_id"])
    prepared_path = store.preparation_path(revision["pair_id"], revision["revision"])
    prepared = store.private_read(prepared_path) if prepared_path.exists() else {}
    prepared_matches = prepared.get("config_digest") == digest(revision) and prepared.get("facts_digest") == digest(facts)
    binary_matches = {}
    import hashlib
    for kind, pin in prepared.get("binaries", {}).items():
        path = Path(pin["path"])
        reject_symlink(path)
        matching = False
        if path.is_file() and path.stat().st_size <= 256 * 1024 * 1024:
            checksum = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(65536), b""):
                    checksum.update(chunk)
            matching = checksum.hexdigest() == pin["sha256"]
        binary_matches[kind] = matching
    rows = []
    for profile, manifest in rendered.items():
        root = store.revision_path(revision["pair_id"], revision["revision"]) / role / profile
        matching = True
        for name, content in manifest["files"].items():
            path = root / name
            reject_symlink(path)
            expected = content.encode()
            if not path.is_file() or path.stat().st_size != len(expected) or path.stat().st_mode & 0o077:
                matching = False
                continue
            with path.open("rb") as stream:
                if stream.read(len(expected) + 1) != expected:
                    matching = False
        rows.append({"profile": profile, "revision": revision["revision"], "config_digest": digest(revision),
            "compatible": manifest["compatible"], "missing_services": manifest["missing_services"],
            "preparation_errors": manifest["preparation_errors"], "artifacts_match": matching,
            "preparation_matches": prepared_matches,
            "prepared_binary_matches": binary_matches.get("paqet" if profile == "direct-paqet" else "rathole") if profile != "gre-kernel" else None,
            "result": "unknown", "local_preflight": "not run", "peer_readiness": "unknown"})
    return rows


def investigate(report, definitions):
    """Findings cite observations and counterevidence; correlation is not cause."""
    def finding(observation, inference, cause, support, counter=(), confidence="medium"):
        if len(report["findings"]) >= 128:
            if "Findings limit" not in report["truncation"]:
                report["truncation"].append("Findings limit")
            return
        report["findings"].append({"observation": observation, "inference": inference, "likely_cause": cause,
            "evidence_ids": [e["id"] for e in support[:64]], "counterevidence_ids": [e["id"] for e in counter[:64]],
            "confidence": confidence, "suggested_next_checks": ["Compare peer evidence and repeat the configured application exchange from an independent client"]})
    failed, successful, covered = [], [], set()
    for definition in definitions:
        samples = [p for p in report["probes"] if p["probe_definition"] == definition["id"]]
        bad = [p for p in samples if p["result"] == "fail"]
        good = [p for p in samples if p["result"] == "pass"]
        if definition["kind"] == "service":
            failed.extend(bad)
            successful.extend(good)
            if good and not bad and all(p["result"] == "pass" for p in samples):
                covered.add(definition["id"])
        latencies = sorted(p["value"]["latency_ms"] for p in good if p["value"].get("latency_ms") is not None)
        longest = run = 0
        for p in samples:
            run = run + 1 if p["result"] == "fail" else 0
            longest = max(run, longest)
        stats = {"probe": definition["id"], "pass": len(good), "fail": len(bad), "unknown": len(samples) - len(good) - len(bad),
            "longest_failure_run": longest, "outage_offsets": [p["monotonic_offset"] for p in bad[:1024]],
            "recovery_offsets": [b["monotonic_offset"] for a, b in zip(samples, samples[1:]) if a["result"] == "fail" and b["result"] == "pass"][:1024],
            "latency_p50_ms": latencies[len(latencies) // 2] if latencies else None,
            "latency_p95_ms": latencies[min(len(latencies) - 1, int(len(latencies) * .95))] if latencies else None,
            "latency_spread_ms": max(latencies) - min(latencies) if latencies else None}
        report["profile_evidence"].append(evidence("probe-statistics", "pass", stats, 0, report["host"]["role"]))
        if bad:
            finding(("Intermittent " if good else "Failed ") + definition["id"],
                "Configured application delivery failed at this vantage", "Path, listener, transport or backend failure; cause not isolated", bad, good, "high")
    if failed:
        backend = [p for p in report["probes"] if p["value"].get("kind") == "backend" and p["result"] == "pass"]
        if backend:
            finding("Service exchange failures while backend exchanges succeeded", "At least one backend was reachable during this window",
                    "Public listener or transport path warrants investigation; timing and service identity still apply", failed + backend)
        for source in ("route", "listeners", "unit"):
            rows = [p for p in report["interface_route_samples"] + report["processes_systemd"] if p["source"] == source and p["result"] == "pass"]
            changes = [(a, b) for a, b in zip(rows, rows[1:]) if a["value"] != b["value"]]
            for a, b in changes[:8]:
                near = [p for p in failed if a["monotonic_offset"] <= p["monotonic_offset"] <= b["monotonic_offset"] + 1]
                if near:
                    finding(source + " changed near a failed exchange", "The events overlap in the sampled window; causation is unproved",
                            "Route/listener/process churn may affect delivery", [a, b] + near, confidence="low")
        links = [p for p in report["interface_route_samples"] if p["source"] == "link" and p["result"] == "pass"]
        for a, b in zip(links, links[1:]):
            old = {r.get("ifindex"): r for r in a["value"] if r.get("ifindex") is not None}
            for row in b["value"]:
                before = old.get(row.get("ifindex"))
                if not before or before.get("ifname") != row.get("ifname"):
                    continue
                x, y = before.get("stats64", before.get("stats", {})), row.get("stats64", row.get("stats", {}))
                rx0, rx1 = x.get("rx", {}).get("packets"), y.get("rx", {}).get("packets")
                tx0, tx1 = x.get("tx", {}).get("packets"), y.get("tx", {}).get("packets")
                if all(type(v) is int for v in (rx0, rx1, tx0, tx1)) and rx1 == rx0 and tx1 > tx0:
                    finding("Interface transmitted without observed receive progress", "Possible one-way failure; aggregate interface counters are not flow proof",
                            "Return path, peer, capture vantage or idle ingress; filtering is unproved", [a, b] + failed[:4], confidence="low")
        for a, b in zip(report["host_samples"], report["host_samples"][1:]):
            near = [p for p in failed if a["monotonic_offset"] <= p["monotonic_offset"] <= b["monotonic_offset"] + 1]
            if not near:
                continue
            signals = []
            for name in ("cpu_psi", "memory_psi", "io_psi"):
                old = re.search(r"some avg10=([0-9.]+)", a["value"].get(name, ""))
                new = re.search(r"some avg10=([0-9.]+)", b["value"].get(name, ""))
                if old and new and float(new[1]) >= 10 and float(new[1]) > float(old[1]):
                    signals.append(name + " increased")
            current = b["value"]
            count, maximum = current.get("conntrack_count", ""), current.get("conntrack_max", "")
            if str(count).isdigit() and str(maximum).isdigit() and int(maximum) > 0 and int(count) / int(maximum) >= .9:
                signals.append("conntrack occupancy >=90%")
            if signals:
                finding("Host pressure overlapped failed exchanges: " + ", ".join(signals),
                        "Local contention or conntrack capacity may affect delivery; correlation is not causation",
                        "Inspect peer timing and local workload/conntrack failures", [a, b] + near, confidence="low")
    unit_failures = [p for p in report["processes_systemd"] if p["source"] == "unit" and p["result"] == "fail"]
    if unit_failures:
        finding("Selected transport unit was not active", "Local transport process outage observed", "Inspect bounded unit logs and restart counters", unit_failures, confidence="high")
    resource_failures = [p for p in report["profile_evidence"] if p["source"] == "profile-resources" and p["result"] == "fail"]
    if resource_failures:
        finding("Selected profile resources differ from configuration", "Local resource drift observed", "Inspect owned GRE/nft/listeners", resource_failures, confidence="high")
    required = {d["id"] for d in definitions if d["kind"] == "service"}
    if report["active_profile"] is not None:
        report["overall_status"] = ("degraded" if successful else "failed") if failed or unit_failures or resource_failures else "unknown"
        core = report["processes_systemd"] + report["interface_route_samples"]
        needed = {"route", "link", "listeners"} | ({"unit"} if report["active_profile"] != "gre-kernel" else set())
        known = {p["source"] for p in core if p["result"] == "pass"}
        resource_checks = [p for p in report["profile_evidence"] if p["source"] == "profile-resources"]
        incomplete = any(p["result"] != "pass" and p["source"] in needed for p in core)
        if required and required <= covered and needed <= known and not incomplete and resource_checks and all(p["result"] == "pass" for p in resource_checks) and not failed and not unit_failures:
            report["overall_status"] = "healthy"


def profile_resources(revision, role, profile, observations, installation_id):
    """Compare observed local resources; successful sockets still need exchanges."""
    from .profiles import gre_record, expanded_services, render_kernel
    from .profile_runtime import nft_matches
    checks = {}
    if profile.startswith("gre-"):
        t = gre_record(revision, role)
        link = next((r for r in observations.get("link", []) if r.get("ifname") == t["interface"]), None)
        if "link" in observations:
            data = (link or {}).get("linkinfo", {}).get("info_data", {})
            def key(v):
                return int(ipaddress.IPv4Address(v)) if isinstance(v, str) and "." in v else int(v or 0)
            checks["gre_link"] = bool(link and link.get("mtu") == t["mtu"] and "UP" in link.get("flags", [])
                and link.get("ifalias") == "twinlink:" + installation_id + ":" + revision["pair_id"]
                and link.get("linkinfo", {}).get("info_kind") == "gre"
                and all(data.get(k) == t[v] for k, v in (("local", "local_public"), ("remote", "remote_public"), ("ttl", "ttl")))
                and all(key(data.get(k)) == (t["key"] or 0) for k in ("ikey", "okey")))
            if link and link.get("linkinfo", {}).get("info_kind") == "gre" and "info_data" not in link.get("linkinfo", {}):
                checks["gre_link"] = None
        if "address" in observations:
            own = ipaddress.IPv4Interface(t["local_private"])
            addresses = [a for r in observations["address"] if r.get("ifname") == t["interface"] for a in r.get("addr_info", []) if a.get("family") == "inet"]
            checks["gre_address"] = len(addresses) == 1 and addresses[0].get("local") == str(own.ip) and addresses[0].get("prefixlen") == own.network.prefixlen
    if profile == "gre-kernel" and "nft" in observations:
        script, snapshot = render_kernel(revision, role, installation_id), observations["nft"]
        checks["owned_nft"] = nft_matches(script, snapshot)
        if checks["owned_nft"] is False and observations.get("nft_comment_available") is False:
            # Compare all other observed fields without treating unavailable
            # comment proof as drift. This temporary header is never evidence
            # of ownership and must not appear in the collected snapshot.
            without_missing_proof = {**snapshot, "nftables": [
                {**row, "table": {**row["table"], "comment": "twinlink:" + installation_id}}
                if "table" in row and "comment" not in row["table"] else row
                for row in snapshot.get("nftables", [])]}
            if nft_matches(script, without_missing_proof):
                checks["owned_nft"] = None
    if role == "vps1" and profile != "gre-kernel" and "listeners" in observations:
        required = [(s["bind"], s["port"], s["protocol"]) for s in expanded_services(revision)]
        if "rathole" in profile:
            address = str(ipaddress.IPv4Interface(revision["gre"]["addresses"]["vps1"]).ip) if profile == "gre-rathole" else revision["public_endpoints"]["vps1"]
            required.append((address, revision["transport"]["port"], "tcp"))
        checks["listeners"] = all(any(r.get("port") == port and r.get("protocol") == protocol and r.get("address") in (address, "0.0.0.0", "::", "*") for r in observations["listeners"]) for address, port, protocol in required)
    expected = ({"gre_link", "gre_address"} if profile.startswith("gre-") else set()) | ({"owned_nft"} if profile == "gre-kernel" else set()) | ({"listeners"} if role == "vps1" and profile != "gre-kernel" else set())
    return {"result": "fail" if False in checks.values() else "pass" if expected <= checks.keys() and None not in checks.values() else "unknown", "checks": checks}


def collect(store, pair_id=None, deep=False, duration=0, interval=1, redaction="share", clock=time.monotonic, sleep=time.sleep, redactor=None,
            probe_fn=None, command_fn=None, sample_fn=None):
    if not 0 <= duration <= 3600 or not 0.25 <= interval <= 3600:
        raise ValueError("Watch duration <=1h; sampling interval >=250ms")
    from .contracts import digest
    from .profiles import table_name
    from .profile_runtime import ProfileRuntime
    from .redaction import stored_secrets
    command_fn, probe_fn, sample_fn = command_fn or bounded_command, probe_fn or application_probe, sample_fn or read_sample
    start, start_utc = clock(), utc()
    state = store.read()
    control = state.get("pairs", {}).get(pair_id) if pair_id else None
    active = control["active"] if control else None
    staged = store.revision(pair_id, control["staged_revision"]) if control else None
    revision = store.revision(pair_id, active["revision"]) if active else None
    role = control["role"] if control else None
    report = {"schema_version": 1, "report_id": str(uuid.uuid4()), "created_at_utc": utc(),
        "collection_window": {"start": start_utc, "end": None, "monotonic": {"start": start, "end": None}},
        "collector_version": 2, "versions": {"os": platform.system(), "kernel": platform.release(), "tools": {}},
        "host": {"role": role, "pair_id": pair_id, "boot_id": None, "clock": "unmeasured peer skew"},
        "active_profile": active["profile"] if active else None,
        "revisions": {"staged": control["staged_revision"], "active": active, "staged_configuration": {
            "config_digest": digest(staged), "service_mappings": staged["services"], "differs_from_active": not revision or digest(staged) != digest(revision)}} if control else {},
        "config_digest": digest(revision) if revision else None, "service_mappings": revision["services"] if revision else [],
        "probes": [], "host_samples": [], "interface_route_samples": [], "firewall_conntrack": [], "processes_systemd": [],
        "profile_evidence": [], "log_events": [], "inactive_readiness": readiness(store, staged, role) if staged else [],
        "overall_status": "off" if control and not active and not control["transition"] else "unknown", "findings": [], "collection_errors": [],
        "unknowns": ["Independent Internet vantage not collected", "Peer state is not live", "Standby readiness requires explicit preflight"],
        "redaction_summary": {"level": redaction, "context": "private per-report context; equality only within this report"}, "truncation": []}
    definitions = probe_definitions(revision, role, active["profile"]) if revision else []
    pending = list(definitions)
    commands = [("route", ["ip", "-j", "route", "show"]), ("link", ["ip", "-j", "-d", "-s", "link", "show"]), ("listeners", ["ss", "-H", "-lntup"])]
    if active:
        unit = ProfileRuntime(store, None).runtime_unit(revision, active["profile"])
        if active["profile"] != "gre-kernel":
            commands += [("unit", ["systemctl", "show", unit, "--no-pager", "--property=ActiveState,SubState,MainPID,NRestarts"]),
                         ("journal", ["journalctl", "--no-pager", "-o", "json", "-n", "200", "-u", unit])]
        if active["profile"] == "gre-kernel" or active["profile"] == "direct-paqet" and role == "vps2":
            commands.append(("nft", ["nft", "-j", "list", "table", "ip", table_name(pair_id)]))
        if active["profile"].startswith("gre-"):
            commands.append(("address", ["ip", "-j", "address", "show"]))
        peer = "vps2" if role == "vps1" else "vps1"
        commands.append(("public-peer", ["ping", "-n", "-c", "1", "-W", "1", revision["public_endpoints"][peer]]))
        facts = store.facts(pair_id, revision["revision"])
        if facts:
            commands.append(("gateway", ["ping", "-n", "-c", "1", "-W", "1", facts["gateway"]]))
        if active["profile"].startswith("gre-"):
            commands.append(("gre-peer", ["ping", "-n", "-c", "1", "-W", "1", "-I",
                str(ipaddress.IPv4Interface(revision["gre"]["addresses"][role]).ip),
                str(ipaddress.IPv4Interface(revision["gre"]["addresses"][peer]).ip)]))
    if deep:
        commands.append(("conntrack", ["conntrack", "-S"]))
    deadline, next_sample = start + (duration or (60 if deep else 15)), start
    seen_logs, seen_errors, size, count = set(), set(), len(json.dumps(report)), 0
    probe_starts = []
    def reserve_probes(number):
        # A sliding one-second window, shared by ICMP and application probes.
        now = clock()
        probe_starts[:] = [t for t in probe_starts if t > now - 1]
        if len(probe_starts) + number > 20:
            wait = probe_starts[len(probe_starts) + number - 21] + 1 - now
            sleep(max(0, min(wait, deadline - now)))
        if clock() >= deadline:
            return False
        probe_starts.extend([clock()] * number)
        return True
    def append(bucket, item):
        nonlocal size, count
        size += len(json.dumps(item))
        count += 1
        if size < MAX_REPORT_BYTES // 2 and count <= MAX_SAMPLES:
            report[bucket].append(item)
        elif "Evidence/report limit" not in report["truncation"]:
            report["truncation"].append("Evidence/report limit")
    def nft_comment_command(argv):
        # The compatibility read shares the collection deadline and the normal
        # command output cap; partial text cannot establish ownership.
        timeout = min(3, deadline - clock())
        value = command_fn(argv, timeout=timeout) if timeout > 0 else {
            "returncode": None, "stdout": "", "error": "Collection budget exhausted"}
        observations["nft_comment_available"] = value["returncode"] == 0 and not value.get("error") and not value.get("truncated")
        if not observations["nft_comment_available"]:
            if "nft-comment" not in seen_errors:
                report["collection_errors"].append({"collector": "nft-comment", "result": "unknown",
                    "error": value.get("error") or "Table comment evidence unavailable"})
                seen_errors.add("nft-comment")
            if value.get("truncated") and "nft-comment" not in report["truncation"]:
                report["truncation"].append("nft-comment")
        return value
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        while True:
            if report["host_samples"] and clock() >= deadline:
                break
            observations = {}
            observed = clock()
            values, errors = sample_fn()
            item = evidence("proc/sys", "pass" if values else "unknown", values, clock() - start, role)
            item["scheduling_gap"] = max(0, clock() - next_sample)
            append("host_samples", item)
            report["host"]["boot_id"] = values.get("boot_id")
            for error in errors:
                signature = json.dumps(error, sort_keys=True)
                if signature not in seen_errors:
                    report["collection_errors"].append(error)
                    seen_errors.add(signature)
            for i in range(0, len(commands), 4):
                batch = commands[i:i + 4]
                icmp = sum(name in ("public-peer", "gateway", "gre-peer") for name, _ in batch)
                if icmp and not reserve_probes(icmp):
                    break
                timeout = min(3, deadline - clock())
                if timeout <= 0:
                    break
                futures = [(name, pool.submit(command_fn, argv, timeout=timeout)) for name, argv in batch]
                for name, future in futures:
                    value = future.result()
                    known = value["returncode"] == 0 and not value.get("error") and not value.get("truncated")
                    collected, result = value.get("stdout", ""), "pass" if known else "unknown"
                    try:
                        if known and name in ("route", "link", "address"):
                            allowed = {"dst", "gateway", "prefsrc", "src", "dev", "ifname", "ifindex", "mtu", "flags", "operstate", "stats64", "stats", "link_index", "ifalias", "linkinfo", "addr_info"}
                            collected = [{k: v for k, v in row.items() if k in allowed} for row in json.loads(collected)]
                        elif known and name == "listeners":
                            from .host import parse_ss
                            collected = [{k: row[k] for k in ("address", "port", "protocol", "pids") if k in row} for row in parse_ss(collected)]
                        elif known and name == "unit":
                            collected = dict(line.split("=", 1) for line in collected.splitlines() if "=" in line)
                            result = "pass" if collected.get("ActiveState") == "active" else "fail" if collected.get("ActiveState") in ("failed", "inactive", "deactivating") else "unknown"
                        elif known and name == "journal":
                            for line in collected.splitlines()[:200]:
                                row = json.loads(line)
                                safe = {k: row[k] for k in ("MESSAGE", "PRIORITY", "__REALTIME_TIMESTAMP") if k in row}
                                signature = json.dumps(safe, sort_keys=True)
                                if signature not in seen_logs and len(report["log_events"]) < 800:
                                    append("log_events", safe)
                                    seen_logs.add(signature)
                            continue
                        elif known and name == "nft":
                            from .host import recover_nft_table_comments
                            collected = recover_nft_table_comments(json.loads(collected), {
                                table_name(pair_id): "twinlink:" + state["installation_id"]}, nft_comment_command)
                    except (ValueError, TypeError, AttributeError):
                        known, result, collected = False, "unknown", None
                    if known:
                        observations[name] = collected
                    if name in ("public-peer", "gateway", "gre-peer"):
                        result = "pass" if known else "fail" if value["returncode"] == 1 else "unknown"
                    bucket = "interface_route_samples" if name in ("route", "link", "address") else "firewall_conntrack" if name in ("nft", "conntrack") else "profile_evidence" if name in ("public-peer", "gateway", "gre-peer") else "processes_systemd"
                    append(bucket, evidence(name, result, collected, clock() - start, role, value.get("error") or ("Command failed/unparseable" if not known else None)))
                    if not known and name not in seen_errors:
                        report["collection_errors"].append({"collector": name, "result": "unknown", "error": value.get("error") or "Command failed/unparseable"})
                        seen_errors.add(name)
                    if value.get("truncated") and name not in report["truncation"]:
                        report["truncation"].append(name)
            if active:
                try:
                    resources = profile_resources(revision, role, active["profile"], observations, state["installation_id"])
                except (ValueError, TypeError, KeyError, AttributeError):
                    resources = {"result": "unknown", "checks": {}, "error": "Unparseable profile resource observation"}
                append("profile_evidence", evidence("profile-resources", resources["result"], resources, clock() - start, role))
            # Rotate bounded batches across watch rounds; quick mode continues
            # through all definitions while its global time budget permits.
            rounds = 1 if duration else (len(pending) + 3) // 4
            for _ in range(rounds):
                timeout = min(3, deadline - clock())
                if timeout <= 0 or not pending:
                    break
                batch, pending = pending[:4], pending[4:]
                if not reserve_probes(len(batch)):
                    pending = batch + pending
                    break
                timeout = min(3, deadline - clock())
                futures = [(definition, pool.submit(probe_fn, definition, timeout=timeout)) for definition in batch]
                for definition, future in futures:
                    outcome = future.result()
                    detail = {k: v for k, v in definition.items() if k != "exchange"}
                    detail["latency_ms"] = outcome.get("latency_ms")
                    item = evidence("application-exchange", outcome["result"], detail, clock() - start, role, outcome.get("error"))
                    item["probe_definition"] = definition["id"]
                    append("probes", item)
            if not duration or clock() >= deadline or report["truncation"] and "Evidence/report limit" in report["truncation"]:
                break
            if not pending:
                pending = list(definitions)
            next_sample = observed + interval
            sleep(max(0, min(next_sample, deadline) - clock()))
    sampled = {p["probe_definition"] for p in report["probes"]}
    for definition in definitions:
        if definition["id"] not in sampled:
            report["unknowns"].append("Probe not sampled within budget: " + definition["id"])
    investigate(report, definitions)
    report["collection_window"]["end"] = utc()
    report["collection_window"]["monotonic"]["end"] = clock()
    report = (redactor or Redactor(redaction, stored_secrets(store))).scrub(report)
    return cap_report(report)


def cap_report(report, *, envelope=None):
    """Bound final UTF-8 JSON, including paired reports and optional CLI framing.

    Keep configuration/provenance intact. Remove oldest evidence from the
    largest collection and prune references only in the affected source report.
    """
    from .models import ValidationError
    buckets = ("probes", "host_samples", "interface_route_samples", "firewall_conntrack", "processes_systemd", "profile_evidence", "log_events",
               "findings", "collection_errors", "unknowns", "inactive_readiness")
    sources = report["reports"] if report.get("kind") == "paired-evidence" else [report]
    marker = "Export size limit; oldest evidence removed"
    def size():
        value = {**envelope, "report": report} if envelope is not None else report
        return len(json.dumps(value, indent=2).encode()) + (1 if envelope is not None else 0)
    while size() > MAX_REPORT_BYTES:
        candidates = [(source, name) for source in sources for name in buckets if source.get(name)]
        if not candidates:
            raise ValidationError("Report metadata exceeds the export size limit; reduce report configuration or metadata")
        source, bucket = max(candidates, key=lambda item: len(json.dumps(item[0][item[1]])))
        count = max(1, len(source[bucket]) // 4)
        removed = {e["id"] for e in source[bucket][:count] if isinstance(e, dict) and isinstance(e.get("id"), str)}
        del source[bucket][:count]
        for original in (source, report):
            if marker not in original.setdefault("truncation", []):
                original["truncation"].append(marker)
            if original.get("overall_status") == "healthy":
                original["overall_status"] = "unknown"
        for finding in source.get("findings", []):
            for field in ("evidence_ids", "counterevidence_ids"):
                finding[field] = [value for value in finding[field] if value not in removed]
        if removed:
            source["findings"] = [f for f in source["findings"] if f["evidence_ids"]]
    return report


def capture_metadata(interface, peer, port, direction="inout"):
    """Explicit scoped opt-in. No pcap file, payload formatting or raw output."""
    import ipaddress
    import re
    from .models import ValidationError, _integer
    if not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface):
        raise ValidationError("Capture requires an explicit --capture-interface")
    try:
        ipaddress.IPv4Address(peer)
    except (ValueError, TypeError):
        raise ValidationError("Capture requires an explicit IPv4 --capture-peer") from None
    port = _integer(port, "capture port", 1, 65535)
    if direction not in ("in", "out", "inout"):
        raise ValidationError("Invalid capture direction")
    result = bounded_command(["tcpdump", "-n", "-q", "-tt", "-l", "-i", interface, "-Q", direction,
        "-c", "1000", "-s", "64", "ip", "and", "host", peer, "and", "tcp", "and", "port", str(port)], timeout=10)
    # Parse only timestamps and IP/port/length metadata; discard everything
    # else, including native diagnostics and any unrecognized dissection.
    records = []
    pattern = re.compile(r"^(\d+(?:\.\d+)?) IP ((?:\d+\.){3}\d+)\.(\d+) > ((?:\d+\.){3}\d+)\.(\d+): tcp (\d+)")
    for line in result["stdout"].splitlines()[:1000]:
        match = pattern.match(line)
        if match:
            records.append({"time": float(match[1]), "source": match[2], "source_port": int(match[3]),
                            "destination": match[4], "destination_port": int(match[5]), "length": int(match[6])})
    losses = re.findall(r"(?m)^(\d+) packets (?:dropped by kernel|received by filter)$", result["stderr"])
    return {"records": records, "capture_statistics": [int(x) for x in losses],
            "result": "pass" if records else "unknown", "truncated": result["truncated"],
            "limits": {"seconds": 10, "packets": 1000, "metadata_only": True},
            "unknowns": ["Absence does not prove filtering; capture loss, offload and vantage apply"]}
