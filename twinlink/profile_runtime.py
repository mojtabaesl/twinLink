"""Local v2 profile resources. Coordination, not this class, orders hosts."""
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import time
import re

from .contracts import digest, canonical, PROFILES
from .coordination import Pending
from .engine import Engine, _canonical_nft
from .models import ValidationError, _listener_conflict, ports
from .ownership import Ownership
from .profiles import manifests, gre_record, table_name, kernel_state, expanded_services
from .render import _command
from .store import StateError, reject_symlink
from . import paqet, rathole
from .backends import readiness as backend_readiness


def nft_expectation(script):
    """Semantic contract for the generated kernel nft subset, including order."""
    from .host import _rendered_rule_expressions
    table = re.search(r"table ip (\w+) \{", script)
    marker = re.search(r'^\s*comment "([^"]+)"', script, re.M)
    if not table or not marker:
        raise StateError("Missing nft ownership contract")
    chains, rules, current = {}, {}, None
    priorities = {"dstnat": -100, "srcnat": 100, "filter": 0, "raw": -300}
    for raw in script.splitlines():
        line = raw.strip()
        chain = re.fullmatch(r"chain (\w+) \{", line)
        if chain:
            current = chain[1]
            rules[current] = []
        hook = re.fullmatch(r"type (nat|filter) hook (\w+) priority (-?\d+|\w+); policy (\w+);", line)
        if hook and current:
            priority = priorities.get(hook[3], hook[3])
            chains[current] = {"type": hook[1], "hook": hook[2], "prio": int(priority), "policy": hook[4]}
        elif current and ' comment "' in line:
            comment, expressions = _rendered_rule_expressions(line)
            rules[current].append({"comment": comment, "expr": expressions})
        if line == "}":
            current = None
    return {"table": table[1], "comment": marker[1], "chains": chains, "rules": rules}


def nft_matches(script, snapshot):
    from .host import _nft_signature
    expected = nft_expectation(script)
    rows = snapshot.get("nftables", [])
    if any(set(row) - {"metainfo", "table", "chain", "rule"} for row in rows):
        return False
    tables = [r["table"] for r in rows if "table" in r]
    chains = [r["chain"] for r in rows if "chain" in r]
    rules = [r["rule"] for r in rows if "rule" in r]
    if len(tables) != 1 or tables[0].get("name") != expected["table"] or tables[0].get("family") != "ip" or tables[0].get("comment") != expected["comment"] or tables[0].get("flags"):
        return False
    if len(chains) != len(expected["chains"]) or any(r.get("family") != "ip" or r.get("table") != expected["table"] for r in chains + rules):
        return False
    for chain, contract in expected["chains"].items():
        actual = [r for r in chains if r.get("name") == chain]
        if len(actual) != 1 or any(actual[0].get(k) != v for k, v in contract.items()):
            return False
        actual_rules = [r for r in rules if r.get("chain") == chain]
        intended = expected["rules"][chain]
        if len(actual_rules) != len(intended) or any(a.get("comment") != e["comment"] or _nft_signature(a.get("expr", [])) != _nft_signature(e["expr"]) for a, e in zip(actual_rules, intended)):
            return False
    return len(rules) == sum(len(r) for r in expected["rules"].values())


class ProfileRuntime:
    def __init__(self, store, host, unit_dir="/etc/systemd/system", executable="/usr/local/libexec/twinlink-runtime",
                 rathole_binary="/usr/local/bin/rathole", paqet_binary="/usr/local/bin/paqet"):
        self.store, self.host = store, host
        self.unit_dir, self.executable = Path(unit_dir), executable
        self.binaries = {"rathole": rathole_binary, "paqet": paqet_binary}
        self.ledger = Ownership(store)

    def unit(self, pair_id, profile):
        return "twinlink-v2-" + hashlib.sha256(pair_id.encode()).hexdigest()[:16] + "-" + profile + ".service"

    def root(self, revision, role, profile):
        return self.store.revision_path(revision["pair_id"], revision["revision"]) / role / profile

    def discover(self, revision, role):
        peer = revision["public_endpoints"]["vps2" if role == "vps1" else "vps1"]
        route = self.host.run(["ip", "-j", "route", "get", peer], timeout=3)
        rows = json.loads(route["stdout"])
        if len(rows) != 1:
            raise ValidationError("Cannot discover a unique peer route")
        row = rows[0]
        gateway = row.get("gateway")
        neighbors = json.loads(self.host.run(["ip", "-j", "neigh", "show", "to", gateway or peer,
                                              "dev", row["dev"]], timeout=3)["stdout"])
        if len(neighbors) != 1 or not neighbors[0].get("lladdr"):
            raise ValidationError("Gateway MAC unknown; resolve the gateway neighbor outside diagnostics and regenerate")
        ephemeral = self.host.run(["sysctl", "-n", "net.ipv4.ip_local_port_range"], timeout=3)["stdout"].split()
        return paqet.validate_facts({"interface": row["dev"], "source": row.get("prefsrc", row.get("src")),
            "gateway": gateway or peer, "router_mac": neighbors[0]["lladdr"], "ephemeral_range": [int(v) for v in ephemeral]})

    def materialize(self, revision, role):
        """Explicit preparation only: never called from switch/start."""
        pair = revision["pair_id"]
        facts = self.store.facts(pair, revision["revision"])
        rendered = manifests(revision, role, self.store.credentials(pair, revision["revision"]), facts, self.store.read()["installation_id"])
        for profile, manifest in rendered.items():
            if profile == "gre-kernel" or manifest["preparation_errors"]:
                continue
            binary = self.binaries["paqet" if profile == "direct-paqet" else "rathole"]
            root = self.root(revision, role, profile)
            args = ("run", "-c", str(root / "config.yaml")) if profile == "direct-paqet" else (str(root / "config.toml"),)
            guard = _command(self.executable, "--state-dir", str(self.store.directory), "--unit-dir", str(self.unit_dir),
                             "--runtime-path", self.executable, "--rathole-binary", self.binaries["rathole"],
                             "--paqet-binary", self.binaries["paqet"], "internal", "profile-guard",
                             pair, "--profile", profile, "--revision", str(revision["revision"]))
            content = f'''# twinlink-owned v2 pair={pair}
[Unit]
Description=Twinlink {pair} {profile}
After=network-online.target
[Service]
Type=simple
ExecCondition={guard}
ExecStart={_command(binary, *args)}
Restart=on-failure
RestartSec=3
TimeoutStopSec=15
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
'''
            # A separate unit per revision avoids rewriting active units while staging.
            self.ledger.write_file(self.unit_dir / self.unit(pair + "-r" + str(revision["revision"]), profile), content, pair, 0o644)
        globals_ = ("--state-dir", str(self.store.directory), "--unit-dir", str(self.unit_dir),
                    "--runtime-path", self.executable, "--rathole-binary", self.binaries["rathole"], "--paqet-binary", self.binaries["paqet"])
        content = f'''# twinlink-owned v2 restore coordinator
[Unit]
Description=Twinlink selected pair profiles
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
ExecStart={_command(self.executable, *globals_, "internal", "restore")}
RemainAfterExit=yes
UMask=0077
[Install]
WantedBy=multi-user.target
'''
        self.ledger.write_file(self.unit_dir / "twinlink-v2-restore.service", content, pair, 0o644)
        expiry_service, expiry_timer = self.expiry_units(pair)
        content = f'''# twinlink-owned v2 pair={pair}
[Unit]
Description=Twinlink {pair} verification expiry withdrawal
StartLimitIntervalSec=0
[Service]
Type=oneshot
ExecStart={_command(self.executable, *globals_, "internal", "verification-expire", pair)}
Restart=on-failure
RestartSec=1
UMask=0077
'''
        self.ledger.write_file(self.unit_dir / expiry_service, content, pair, 0o644)
        content = f'''# twinlink-owned v2 pair={pair}
[Unit]
Description=Twinlink {pair} verification deadline
[Timer]
OnActiveSec=60s
OnUnitActiveSec=1s
AccuracySec=1s
Unit={expiry_service}
'''
        self.ledger.write_file(self.unit_dir / expiry_timer, content, pair, 0o644)
        self.host.run(["systemctl", "daemon-reload"])
        self.set_enablement("twinlink-v2-restore.service", pair, True)
        # Check exact binary hash/version now and bind to prepared metadata.
        prepared = {}
        for kind, binary in self.binaries.items():
            path = Path(binary)
            reject_symlink(path)
            if not path.is_file() or not os.access(path, os.X_OK):
                continue
            checksum = hashlib.sha256(path.read_bytes()).hexdigest()
            if kind == "rathole":
                try:
                    rathole.check_version(path)
                except ValidationError:
                    continue
            else:
                try:
                    pin = paqet.binary_pin(paqet.platform.machine())
                    if checksum != pin["sha256"]:
                        continue
                    paqet.check_installed_version(path)
                except ValidationError:
                    continue
            prepared[kind] = {"path": str(path), "sha256": checksum}
        self.ledger.write_file(self.store.preparation_path(pair, revision["revision"]), canonical({
            "config_digest": digest(revision), "facts_digest": digest(facts), "binaries": prepared,
            "prepared_at": time.time(), "units": True,
            "renderer_version": 2 if revision["schema_version"] >= 3 else 1}).decode(), pair)
        return prepared

    def set_enablement(self, unit, owner, enabled):
        before = self.host.unit_status(unit)["enabled"]
        resource = "unit-enable:" + unit
        self.ledger.begin(resource, "unit-enable", owner, before, enabled, "restore-unit-enablement")
        self.host.run(["systemctl", "enable" if enabled else "disable", unit])
        self.ledger.complete(resource, self.host.unit_status(unit)["enabled"])

    def assert_unit_safe(self, unit, *, allow_restoring=False):
        path = self.unit_dir / unit
        self.ledger.check("file:" + str(path), self.ledger.file_value(path), allow_restoring=allow_restoring)
        status = self.host.unit_status(unit)
        props = status.get("properties", {})
        if props.get("DropInPaths", "").strip() or (props.get("FragmentPath") and Path(props["FragmentPath"]) != path):
            raise StateError("Unit has foreign fragment or drop-ins: " + unit)
        return status

    def runtime_unit(self, revision, profile):
        return self.unit(revision["pair_id"] + "-r" + str(revision["revision"]), profile)

    def check_prepared_binary(self, prepared, profile):
        kind = "paqet" if profile == "direct-paqet" else "rathole"
        pins = prepared.get("binaries", {})
        pin = pins.get(kind) if isinstance(pins, dict) else None
        if not isinstance(pin, dict) or pin.get("path") != self.binaries[kind]:
            raise StateError("Pinned binary not prepared")
        path = Path(pin["path"])
        reject_symlink(path)
        if not path.is_file() or not os.access(path, os.X_OK) or path.stat().st_size > 256 * 1024 * 1024:
            raise StateError("Prepared binary is missing, nonexecutable or oversized")
        checksum = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                checksum.update(chunk)
        if checksum.hexdigest() != pin.get("sha256"):
            raise StateError("Prepared binary changed")
        if profile == "direct-paqet" and pin.get("sha256") != paqet.binary_pin(paqet.platform.machine())["sha256"]:
            raise StateError("Prepared Paqet binary does not match this architecture's release identity")

    def check_prepared_launch(self, revision, role, profile):
        """Read-only launch checks; no mutation lock, probes or binary execution."""
        if profile == "gre-kernel":
            raise StateError("Kernel profiles do not have a process launch unit")
        pair, number = revision["pair_id"], revision["revision"]
        facts = self.store.facts(pair, number)
        prepared = self.store.private_read(self.store.preparation_path(pair, number))
        if (not isinstance(prepared, dict) or prepared.get("config_digest") != digest(revision)
                or prepared.get("facts_digest") != digest(facts) or prepared.get("units") is not True):
            raise StateError("Preparation is stale; config regenerate required")
        if revision["schema_version"] >= 3 and prepared.get("renderer_version") != 2:
            raise StateError("Renderer preparation is stale; config regenerate required")
        prepared_path = self.store.preparation_path(pair, number)
        self.ledger.check("file:" + str(prepared_path), self.ledger.file_value(prepared_path))
        generated = manifests(revision, role, self.store.credentials(pair, number), facts, self.store.read()["installation_id"])[profile]
        if not generated["compatible"] or generated["preparation_errors"]:
            raise StateError("Profile is incompatible or unprepared")
        for filename, expected in generated["files"].items():
            path = self.root(revision, role, profile) / filename
            reject_symlink(path)
            data = expected.encode()
            if not path.is_file() or path.stat().st_size != len(data) or path.stat().st_mode & 0o077:
                raise StateError("Prepared artifact drift; config regenerate required")
            with path.open("rb") as stream:
                if stream.read(len(data) + 1) != data:
                    raise StateError("Prepared artifact drift; config regenerate required")
            self.ledger.check("file:" + str(path), self.ledger.file_value(path))
        self.check_prepared_binary(prepared, profile)
        if profile == "direct-paqet" and self.discover(revision, role) != facts:
            raise StateError("Paqet local route/NIC/MAC facts changed; config regenerate required")
        self.assert_unit_safe(self.runtime_unit(revision, profile))

    def expiry_units(self, pair):
        service = self.unit(pair, "verification-expiry")
        return service, service.removesuffix(".service") + ".timer"

    def arm_verification_expiry(self, revision, role, profile, control, tx):
        """Arm before exposure; systemd enforces withdrawal after CLI exit."""
        service, timer = self.expiry_units(revision["pair_id"])
        self.assert_unit_safe(service)
        status = self.assert_unit_safe(timer)
        if status["enabled"]:
            raise StateError("Verification timer must not be enabled at boot")
        # A start retry must not reset the original timer's monotonic budget.
        if not status["active"]:
            self.host.run(["systemctl", "start", timer])
        if not self.host.unit_status(timer)["active"]:
            raise StateError("Verification expiry timer did not start")

    def disarm_verification_expiry(self, revision, role, profile, control, tx):
        _, timer = self.expiry_units(revision["pair_id"])
        if self.ledger.read()["resources"].get("file:" + str(self.unit_dir / timer)):
            self.assert_unit_safe(timer)
            self.host.run(["systemctl", "stop", timer])
            if self.host.unit_status(timer)["active"]:
                raise StateError("Verification timer remains active")

    def verification_expiry_armed(self, revision, role, profile, control, tx):
        _, timer = self.expiry_units(revision["pair_id"])
        if not self.ledger.read()["resources"].get("file:" + str(self.unit_dir / timer)):
            return False
        return self.assert_unit_safe(timer)["active"]

    def preflight(self, revision, role, profile, control, tx):
        if profile is None:
            return
        pair = revision["pair_id"]
        facts = self.store.facts(pair, revision["revision"])
        generated = manifests(revision, role, self.store.credentials(pair, revision["revision"]), facts, self.store.read()["installation_id"])[profile]
        if not generated["compatible"] or generated["preparation_errors"]:
            raise ValidationError("Profile incompatible/unprepared: " + json.dumps(generated["missing_services"] + generated["preparation_errors"]))
        if profile == "direct-paqet" and (not facts or facts["source"] != revision["public_endpoints"][role]):
            raise ValidationError("Paqet NAT topology is not qualified; local route source must equal its public endpoint")
        missing_probes = [service["id"] for service in revision["services"] if service["probe"] is None]
        if missing_probes:
            raise ValidationError("Configure a safe application exchange probe before cutover for: " + ", ".join(missing_probes))
        for filename, expected in generated["files"].items():
            path = self.root(revision, role, profile) / filename
            reject_symlink(path)
            if not path.is_file() or path.read_text() != expected or path.stat().st_mode & 0o077:
                raise StateError("Prepared artifact drift; config regenerate required")
        protected = {22}
        connection = os.environ.get("SSH_CONNECTION", "").split()
        if len(connection) == 4 and connection[3].isdigit():
            protected.add(int(connection[3]))
        if revision["transport"]["port"] in protected:
            raise ValidationError("Shared transport conflicts with the management connection")
        for service in revision["services"]:
            first, last = ports(service["ports"])
            if any(first <= p <= last for p in protected):
                raise ValidationError("Service overlaps a protected management port")
        assigned = {a["local"] for row in self.host.addresses() for a in row.get("addr_info", []) if a.get("family") == "inet"}
        if revision["public_endpoints"][role] not in assigned:
            raise ValidationError("Local pair endpoint is not assigned to this host")
        if profile.startswith("gre-"):
            tunnel = gre_record(revision, role)
            existing = self._link_value(tunnel["interface"])
            if existing is not None:
                row = self.ledger.read()["resources"].get("link:" + tunnel["interface"])
                partial = row and row["status"] == "pending" and isinstance(row["after"], dict) and "config" in row["after"]
                # The old profile may still own this link during preflight.
                # A proven interrupted creation remains pending until prepare
                # resumes it; preflight must not finalize a partial snapshot.
                self._recover_link(tunnel["interface"], existing, bind=False)
                if not partial:
                    self.ledger.check("link:" + tunnel["interface"], existing)
            network = ipaddress.IPv4Interface(tunnel["local_private"]).network
            for route in self.host.routes():
                if route.get("dst", "default") == "default" or route.get("dev") == tunnel["interface"]:
                    continue
                try:
                    other = ipaddress.ip_network(route["dst"], strict=False)
                except ValueError:
                    continue
                if other.version == 4 and network.overlaps(other):
                    raise ValidationError("GRE subnet conflicts with an existing host route")
        table = table_name(pair)
        observed = self._table_value(table)
        if observed is not None:
            self._recover_table(table, observed)
            self.ledger.check("nft:" + table, observed)
        if "rules.nft" in generated["files"]:
            script = ("delete table ip " + table + "\n" if observed is not None else "") + generated["files"]["rules.nft"]
            self.host.run(["nft", "--check", "--file", "-"], input=script)
        prepared_path = self.store.preparation_path(pair, revision["revision"])
        reject_symlink(prepared_path)
        if not prepared_path.exists():
            raise StateError("Boot coordinator is not prepared; config regenerate required")
        prepared = self.store.private_read(prepared_path)
        if prepared.get("config_digest") != digest(revision) or prepared.get("facts_digest") != digest(facts) or not prepared.get("units"):
            raise StateError("Preparation is stale; config regenerate required")
        if revision["schema_version"] >= 3 and prepared.get("renderer_version") != 2:
            raise StateError("Renderer preparation is stale; config regenerate required")
        coordinator = "twinlink-v2-restore.service"
        status = self.assert_unit_safe(coordinator)
        if not status["enabled"] or status.get("properties", {}).get("UnitFileState", "enabled") != "enabled":
            raise StateError("Boot coordinator is disabled; config regenerate required")
        self.ledger.check("unit-enable:" + coordinator, True)
        if not tx.get("boot_restore"):
            for unit in self.expiry_units(pair):
                if self.assert_unit_safe(unit)["enabled"]:
                    raise StateError("Verification expiry units must remain disabled at boot")
        if profile != "gre-kernel":
            self.check_prepared_binary(prepared, profile)
            self.ledger.check("file:" + str(self.unit_dir / self.runtime_unit(revision, profile)),
                              self.ledger.file_value(self.unit_dir / self.runtime_unit(revision, profile)))
            self.assert_unit_safe(self.runtime_unit(revision, profile))
        # Discovering facts never sends neighbor probes or changes host configuration.
        if facts is not None and self.discover(revision, role) != facts:
            raise StateError("Local NIC/source/gateway facts changed; explicitly regenerate")
        listeners = self.host.listeners()
        if role == "vps2" and profile == "gre-kernel":
            t = gre_record(revision, role)
            private = str(ipaddress.IPv4Interface(t["local_private"]).ip)
            entries = list(kernel_state(revision, role)["forwards"].values())
            local_backends = {(entry["protocol"], port) for entry in entries
                              if entry["destination_address"] == private
                              for port in range(ports(entry["destination_port"])[0], ports(entry["destination_port"])[1] + 1)}
            # Any declared local backend can overlap another mapping's relay.
            # The application exchanges below must still prove those sockets;
            # undeclared relay listeners remain conflicts.
            relay_listeners = [listener for listener in listeners if not (
                (listener.get("protocol", "tcp"), listener.get("port")) in local_backends
                and listener.get("address", "0.0.0.0") in (private, "0.0.0.0"))]
            for entry in entries:
                first, last = ports(entry["relay_port"])
                if any(first <= p <= last for p in protected):
                    raise ValidationError("Kernel relay conflicts with a management port")
                _listener_conflict(private, entry["relay_port"], entry["protocol"], relay_listeners, None)
        for listener in listeners:
            # Only cgroup + exact managed unit ownership can excuse an old socket.
            pids = listener.get("pids", [])
            if control["active"] and pids:
                old = self.store.revision(pair, control["active"]["revision"])
                name = self.runtime_unit(old, control["active"]["profile"])
                if all(re.search(r"(?:^|/)" + re.escape(name) + r"(?:/|$)", Path(f"/proc/{pid}/cgroup").read_text(), re.M) for pid in pids):
                    listener = {**listener, "managed": pair}
            if role == "vps1":
                for s in revision["services"]:
                    _listener_conflict(s["bind"], s["ports"], s["protocol"], [listener], pair)
            if (role == "vps1" and "rathole" in profile) or (role == "vps2" and profile == "direct-paqet"):
                ip = revision["public_endpoints"][role]
                if profile == "gre-rathole":
                    ip = str(ipaddress.IPv4Interface(revision["gre"]["addresses"][role]).ip)
                _listener_conflict(ip, revision["transport"]["port"], "tcp", [listener], pair)
        if role == "vps1":
            assigned = {a["local"] for row in self.host.addresses() for a in row.get("addr_info", []) if a.get("family") == "inet"}
            for service in revision["services"]:
                if service["bind"] != "0.0.0.0" and service["bind"] not in assigned:
                    raise ValidationError("Public service bind is not assigned locally")
        else:
            return {"backend_checks": self.probe_backends(revision, profile=profile), "service_path": "pending peer activation and exact application verification",
                    "host_policy": "unknown until service-path exchange; owned ACCEPT does not override foreign DROP"}
        return {"service_path": "pending peer activation and exact application verification", "host_policy": "unknown until service-path exchange"}

    def probe_backends(self, revision, budget=60, profile="gre-kernel", allow_deferred=True):
        """Prove the proposed VPS2 backend bytes before withdrawing runtime."""
        from .diagnostics import application_probe
        deadline, checked, results = time.monotonic() + budget, set(), []
        assigned = {a["local"] for row in self.host.addresses() for a in row.get("addr_info", []) if a.get("family") == "inet"}
        listeners = self.host.listeners()
        for service in expanded_services(revision):
            probe = service["probe"]
            if probe is None:
                raise StateError("Application exchange recipe is missing for " + service["id"])
            readiness = backend_readiness(revision, service, profile, assigned, listeners, allow_deferred=allow_deferred)
            if readiness["result"] == "fail":
                raise StateError(readiness["reason"] + ": " + service["id"])
            identity = (service["protocol"], readiness["probe_address"], service["target_port"],
                        probe["request_hex"], probe["response_hex"])
            if identity in checked:
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StateError("Backend preflight exceeded its 60-second budget")
            definition = {"address": identity[1], "port": identity[2], "protocol": identity[0], "exchange": probe}
            outcome = application_probe(definition, timeout=min(3, remaining))
            if outcome["result"] != "pass":
                raise StateError("Backend preflight exchange failed for " + service["id"] + ":" + str(service["target_port"]) + ": " + str(outcome.get("error") or outcome["result"]))
            if time.monotonic() >= deadline:
                raise StateError("Backend preflight exceeded its 60-second budget")
            checked.add(identity)
            results.append({**readiness, "application": outcome["result"], "port": service["target_port"]})
        return results

    def _table_value(self, table):
        snapshot = self._table_snapshot(table)
        return digest(_canonical_nft(snapshot)) if snapshot is not None else None

    def _table_snapshot(self, table):
        result = self.host.run(["nft", "-j", "list", "table", "ip", table], check=False)
        if result["returncode"]:
            if "No such file" in result["stderr"] or "does not exist" in result["stderr"]:
                return None
            raise StateError("Cannot inspect nft table ownership")
        from .host import Host
        # The parser needs only run(), keeping injected host implementations
        # usable while sharing the legacy serializer compatibility checks.
        markers = {"twinlink": "twinlink-owned"} if table == "twinlink" else {
            table: "twinlink:" + self.store.read()["installation_id"]}
        return Host.nft_table_comments(self.host, json.loads(result["stdout"]), markers)

    def _recover_table(self, table, observed):
        resource = "nft:" + table
        row = self.ledger.read()["resources"].get(resource)
        if row and row["status"] == "pending" and isinstance(row["after"], dict) and "script" in row["after"]:
            script = row["after"]["script"]
            snapshot = self._table_snapshot(table)
            if snapshot is None or digest(script) != row["after"]["script_digest"] or digest(_canonical_nft(snapshot)) != observed or not nft_matches(script, snapshot):
                raise StateError("Pending nft intent does not match installed expressions; preserving " + table)
            self.ledger.bind_expected(resource, observed, digest({"table": table, "script": script}))

    def _install_table(self, revision, role, profile):
        pair, table = revision["pair_id"], table_name(revision["pair_id"])
        resource = "nft:" + table
        before = self._table_value(table)
        path = self.root(revision, role, profile) / "rules.nft"
        script = path.read_text()
        if before is not None:
            self._recover_table(table, before)
            row = self.ledger.check(resource, before)
            if row["ownership_proof"] == digest({"table": table, "script": script}):
                return
            raise StateError("Quiesce the previous owned table before target start")
        self.host.run(["nft", "--check", "--file", "-"], input=script)
        # Expected JSON cannot be computed portably from nft text. Record a
        # pending ownership intent before apply, then bind the exact read-back.
        self.ledger.begin(resource, "nft", pair, None, {"script_digest": digest(script), "script": script}, "delete-table")
        self.host.run(["nft", "--file", "-"], input=script)
        observed = self._table_value(table)
        self._recover_table(table, observed)

    def _link_value(self, interface):
        matches = [l for l in self.host.links() if l["ifname"] == interface]
        if not matches:
            return None
        link = matches[0]
        value = {k: copy.deepcopy(link.get(k)) for k in ("ifname", "ifalias", "mtu", "linkinfo")}
        value["addresses"] = sorted([{k: a.get(k) for k in ("family", "local", "prefixlen", "scope", "label")}
            for row in self.host.addresses() if row["ifname"] == interface for a in row.get("addr_info", [])], key=lambda a: json.dumps(a, sort_keys=True))
        value["routes"] = sorted([{k: v for k, v in row.items() if k not in ("cache", "expires")}
            for row in self.host.routes() if row.get("dev") == interface], key=lambda a: json.dumps(a, sort_keys=True))
        return value

    def prepare(self, revision, role, profile, control, tx):
        if not profile or not profile.startswith("gre-"):
            return
        t = gre_record(revision, role)
        resource = "link:" + t["interface"]
        before = self._link_value(t["interface"])
        pending = self.ledger.read()["resources"].get(resource, {}).get("status") == "pending"
        if before is not None:
            self._recover_link(t["interface"], before, bind=False)
            if not pending:
                self.ledger.check(resource, before)
                self._verify_gre(revision, role)
                return
        owner = "twinlink:" + self.store.read()["installation_id"] + ":" + revision["pair_id"]
        # Alias and MTU are part of link creation: a crash cannot leave an
        # unmarked GRE link that could be confused with a foreign interface.
        create = ["ip", "link", "add", "name", t["interface"], "alias", owner, "mtu", str(t["mtu"]), "type", "gre",
                  "local", t["local_public"], "remote", t["remote_public"], "ttl", str(t["ttl"])]
        if t["key"] is not None:
            create += ["key", str(t["key"])]
        commands = ([] if before is not None else [create]) + Engine.tunnel_commands(t)[2:]
        if not pending or before is None:
            self.ledger.begin(resource, "link", revision["pair_id"], before, {"alias": owner, "config": t}, "delete-link")
        for command in commands:
            self.host.run(command)
        value = self._link_value(t["interface"])
        if value is None or value["ifalias"] != owner or value["linkinfo"]["info_kind"] != "gre":
            raise StateError("GRE ownership verification failed")
        self._recover_link(t["interface"], value)
        self.ledger.complete(resource, value)
        self._verify_gre(revision, role)

    def _recover_link(self, interface, value, bind=True):
        resource = "link:" + interface
        row = self.ledger.read()["resources"].get(resource)
        if not row or row["status"] != "pending" or not isinstance(row["after"], dict) or "config" not in row["after"]:
            return
        intent, t = row["after"], row["after"]["config"]
        data = (value or {}).get("linkinfo", {}).get("info_data", {})
        valid = bool(value and value.get("ifalias") == intent["alias"] and value.get("mtu") == t["mtu"] and value.get("linkinfo", {}).get("info_kind") == "gre")
        valid = valid and all(data.get(k) == t[f] for k, f in (("local", "local_public"), ("remote", "remote_public"), ("ttl", "ttl")))
        def key_value(v):
            return int(ipaddress.IPv4Address(v)) if isinstance(v, str) and "." in v else int(v or 0)
        valid = valid and all(key_value(data.get(k)) == (t["key"] or 0) for k in ("ikey", "okey"))
        own = ipaddress.IPv4Interface(t["local_private"])
        for address in (value or {}).get("addresses", []):
            if address["family"] == "inet":
                valid = valid and address["local"] == str(own.ip) and address["prefixlen"] == own.network.prefixlen
            else:
                valid = valid and address.get("scope") == "link" and ipaddress.ip_address(address["local"]).is_link_local
        for route in (value or {}).get("routes", []):
            destination = ipaddress.ip_network(route.get("dst", "0.0.0.0/0"), strict=False)
            valid = valid and route.get("protocol") == "kernel" and (destination == own.network or destination.version == 4 and destination.prefixlen == 32 and destination.subnet_of(own.network)
                or destination.version == 6 and destination == ipaddress.ip_network("fe80::/64"))
        if not valid:
            raise StateError("Pending GRE intent differs from live resources; preserving " + interface)
        if bind:
            self.ledger.bind_expected(resource, value)

    def _verify_gre(self, revision, role):
        t = gre_record(revision, role)
        value = self._link_value(t["interface"])
        data = (value or {}).get("linkinfo", {}).get("info_data", {})
        expected = {"local": t["local_public"], "remote": t["remote_public"], "ttl": t["ttl"]}
        if value is None or value["mtu"] != t["mtu"] or any(data.get(k) != v for k, v in expected.items()):
            raise StateError("GRE endpoint/TTL/MTU drift")
        def key_value(value):
            if value is None:
                return 0
            return int(ipaddress.IPv4Address(value)) if isinstance(value, str) and "." in value else int(value)
        if any(key_value(data.get(k)) != (t["key"] or 0) for k in ("ikey", "okey")):
            raise StateError("GRE key drift")
        found = {a["local"] + "/" + str(a["prefixlen"]) for row in self.host.addresses() if row["ifname"] == t["interface"]
                 for a in row.get("addr_info", []) if a.get("family") == "inet"}
        if found != {t["local_private"]}:
            raise StateError("GRE address drift")
        if not any(l["ifname"] == t["interface"] and "UP" in l.get("flags", []) for l in self.host.links()):
            raise StateError("GRE link is down")
        from .backends import local
        if role == "vps2" and any(local(s) for s in revision["services"]):
            network = str(ipaddress.IPv4Interface(t["local_private"]).network)
            if not any(route.get("dst") == network and route.get("dev") == t["interface"] for route in self.host.routes()):
                raise StateError("GRE connected return route is missing for the VPS2-local backend")
            peer = str(ipaddress.IPv4Interface(t["remote_private"]).ip)
            try:
                selected = json.loads(self.host.run(["ip", "-j", "route", "get", peer], timeout=3)["stdout"])
            except (ValueError, KeyError):
                raise StateError("GRE backend return-route lookup unavailable") from None
            if len(selected) != 1 or selected[0].get("dev") != t["interface"]:
                raise StateError("GRE backend replies would use a different return route")

    def start(self, revision, role, profile, control, tx):
        if profile == "gre-kernel":
            if role == "vps2":
                self._verify_gre(revision, role)
                self.probe_backends(revision, profile=profile, allow_deferred=False)
            resource, owner = "sysctl:net.ipv4.ip_forward", revision["pair_id"]
            before = self.host.run(["sysctl", "-n", "net.ipv4.ip_forward"])["stdout"].strip()
            self.ledger.begin(resource, "sysctl", owner, before, "1", "restore-sysctl")
            self.host.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
            self.ledger.complete(resource, self.host.run(["sysctl", "-n", "net.ipv4.ip_forward"])["stdout"].strip())
            self._install_table(revision, role, profile)
        else:
            if profile == "direct-paqet" and role == "vps2":
                self._install_table(revision, role, profile)
            name = self.runtime_unit(revision, profile)
            self.assert_unit_safe(name)
            self.host.run(["systemctl", "start", name])
            if not self.host.unit_status(name)["active"]:
                raise StateError("Target process did not start")

    def quiesce(self, revision, role, profile, control, tx):
        pair = revision["pair_id"]
        errors = []
        def attempt(operation):
            try:
                return operation()
            except Exception as exc:
                errors.append(exc)
                return None
        revisions = {revision["revision"]}
        for selection in (tx["previous"], control.get("active")):
            if selection:
                revisions.add(selection["revision"])
        # A recovery transaction must also withdraw an interrupted target
        # revision, even when commit selected only one of the two hosts.
        if tx.get("recovery_of") or profile is None:
            base = self.store.directory / "revisions" / pair
            for entry in attempt(lambda: list(base.iterdir())) or []:
                def revision_number():
                    reject_symlink(entry)
                    return int(entry.name) if entry.is_dir() and entry.name.isdigit() else None
                number = attempt(revision_number)
                if number is not None:
                    revisions.add(number)
        # Inspect the selected/target processes first and stop proven active
        # ones immediately. Defer all inactive artifact checks until afterward.
        names = []
        for selection in (control.get("active"), {"profile": profile, "revision": revision["revision"]}, tx["previous"]):
            if selection and selection["profile"] in PROFILES:
                names.append(self.runtime_unit({"pair_id": pair, "revision": selection["revision"]}, selection["profile"]))
        names.extend(self.runtime_unit({"pair_id": pair, "revision": number}, p)
                     for number in sorted(revisions) for p in PROFILES)
        def stop_unit(name):
            path = self.unit_dir / name
            row = self.ledger.read()["resources"]["file:" + str(path)]
            if row["status"] == "restored" and self.ledger.file_value(path) is None and not self.host.unit_status(name)["active"]:
                return
            self.assert_unit_safe(name)
            self.host.run(["systemctl", "stop", name])
            self.host.run(["systemctl", "disable", name])
            if self.host.unit_status(name)["active"]:
                raise StateError("Inactive profile process remains active: " + name)
        inactive = []
        for name in dict.fromkeys(names):
            if self.ledger.read()["resources"].get("file:" + str(self.unit_dir / name)):
                status = attempt(lambda: self.host.unit_status(name))
                if status is not None:
                    if status["active"]:
                        attempt(lambda: stop_unit(name))
                    else:
                        inactive.append(name)
        for name in inactive:
            attempt(lambda: stop_unit(name))
        def withdraw_table():
            table, resource = table_name(pair), "nft:" + table_name(pair)
            observed = self._table_value(table)
            if observed is not None:
                self._recover_table(table, observed)
                def restore_table(before):
                    if before is not None:
                        raise StateError("Cannot reconstruct an unowned baseline table")
                    self.host.run(["nft", "delete", "table", "ip", table])
                    return self._table_value(table)
                self.ledger.release(resource, pair, observed, restore_table)
            else:
                self.ledger.retire_absent(resource, pair)
        attempt(withdraw_table)
        # Clear only tuples translated by this pair's private GRE endpoints.
        for number in sorted(revisions):
            r = attempt(lambda: self.store.revision(pair, number))
            if r is None:
                continue
            old = kernel_state(r, role)
            off = {"version": 1, "tunnels": {}, "forwards": {}}
            if (tx["previous"] and tx["previous"]["profile"] == "gre-kernel") or profile in (None, "gre-kernel") or tx.get("recovery_of"):
                for command in Engine(self.store, self.host).flow_commands(old, off):
                    def expire_flow():
                        result = self.host.run(command, check=False)
                        if result["returncode"] not in (0, 1) or (result["returncode"] == 1 and "0 flow entries" not in result["stdout"] + result["stderr"]):
                            raise StateError("Cannot expire owned translated flows")
                    attempt(expire_flow)
            interface = gre_record(r, role)["interface"]
            def withdraw_link():
                observed = self._link_value(interface)
                if observed is not None:
                    self._recover_link(interface, observed)
                    def restore_link(before):
                        if before is not None:
                            raise StateError("Foreign GRE baseline cannot be deleted")
                        self.host.run(["ip", "link", "delete", "dev", interface])
                        return self._link_value(interface)
                    self.ledger.release("link:" + interface, pair, observed, restore_link)
                else:
                    self.ledger.retire_absent("link:" + interface, pair)
            attempt(withdraw_link)
        def restore_forwarding():
            resource = "sysctl:net.ipv4.ip_forward"
            row = self.ledger.read()["resources"].get(resource)
            if row and pair in row["owners"]:
                observed = self.host.run(["sysctl", "-n", "net.ipv4.ip_forward"])["stdout"].strip()
                def restore_sysctl(before):
                    self.host.run(["sysctl", "-w", "net.ipv4.ip_forward=" + before])
                    return self.host.run(["sysctl", "-n", "net.ipv4.ip_forward"])["stdout"].strip()
                self.ledger.release(resource, pair, observed, restore_sysctl)
        attempt(restore_forwarding)
        if errors:
            if len(errors) == 1:
                raise errors[0]
            raise StateError("Withdrawal conflicts: " + "; ".join(str(exc) for exc in errors))
        # Keep expiry enforcement available until withdrawal has succeeded.
        self.disarm_verification_expiry(revision, role, profile, control, tx)

    def verify_local(self, revision, role, profile):
        if profile and profile.startswith("gre-"):
            self._verify_gre(revision, role)
            interface = gre_record(revision, role)["interface"]
            self.ledger.check("link:" + interface, self._link_value(interface))
        if profile == "gre-kernel" or profile == "direct-paqet" and role == "vps2":
            self.ledger.check("nft:" + table_name(revision["pair_id"]), self._table_value(table_name(revision["pair_id"])))
        if profile and profile != "gre-kernel":
            if not self.assert_unit_safe(self.runtime_unit(revision, profile))["active"]:
                raise StateError("Transport process stopped during verification")

    def revalidate(self, revision, role, profile, control, tx):
        action = tx["refresh_step"]
        if action == "preflight":
            return self.preflight(revision, role, profile, control, tx)
        if action == "quiesce" or profile is None:
            local_tx = {**tx, "previous": tx.get("local_previous", tx["previous"])} if profile is None else tx
            return self.quiesce(revision, role, profile, control, local_tx)
        if action == "prepare":
            self._verify_gre(revision, role)
            interface = gre_record(revision, role)["interface"]
            return self.ledger.check("link:" + interface, self._link_value(interface))
        if action == "verify":
            return self.verify(revision, role, profile, control, tx)
        if action in ("commit", "acknowledge") and control["active"] != {"profile": profile, "revision": tx["revision"], "epoch": tx["epoch"]}:
            raise StateError("Committed selection changed; cannot refresh receipt")
        self.verify_local(revision, role, profile)

    def verify(self, revision, role, profile, control, tx):
        # Every explicit request/response proves bytes across the service path;
        # accepting TCP or sending UDP alone is never a success criterion.
        self.verify_local(revision, role, profile)
        if role != "vps2":
            # The preceding VPS2 verification receipt proves its vantage only.
            return
        budget = min(60, tx.get("verification_deadline", time.time() + 60) - time.time())
        boot = self.ledger.boot_id()
        if boot is not None and boot == tx.get("verification_boot_id"):
            budget = min(budget, tx.get("verification_monotonic_deadline", time.monotonic() + 60) - time.monotonic())
        deadline = time.monotonic() + budget
        for service in expanded_services(revision):
            probe = service["probe"]
            if probe is None:
                raise Pending("Pending verification: configure a safe application exchange probe for every service")
            address = revision["public_endpoints"]["vps1"] if service["bind"] == "0.0.0.0" else service["bind"]
            from .diagnostics import application_probe
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StateError("Application verification exceeded 60 seconds")
            result = application_probe({"address": address, "port": service["port"],
                "protocol": service["protocol"], "exchange": probe}, timeout=min(3, remaining))
            if result["result"] != "pass":
                raise StateError("Application response mismatch or failed exchange for " + service["id"] + ": " + str(result.get("error")))

    def boot(self):
        state = self.store.read()
        results = []
        for pair, c in state["pairs"].items():
            tx = c["transition"]
            preflight_only = tx and tx.get("target") is not None and tx["phase"] == "preflight" and not tx.get("recovery_of")
            if (tx and not preflight_only) or c.get("commit_pending") or c["active"] is None:
                results.append({"pair": pair, "status": "off-pending-recovery" if c["transition"] else "off"})
                continue
            tx = {"previous": c["active"], "boot_restore": True}
            phase, r = "preflight", None
            try:
                r = self.store.revision(pair, c["active"]["revision"])
                self.preflight(r, c["role"], c["active"]["profile"], c, tx)
                phase = "prepare"
                self.prepare(r, c["role"], c["active"]["profile"], c, tx)
                phase = "start"
                self.start(r, c["role"], c["active"]["profile"], c, tx)
            except Exception as exc:
                result = {"pair": pair, "status": "failed", "phase": phase, "error": str(exc)}
                if phase != "preflight" and r is not None:
                    try:
                        self.quiesce(r, c["role"], c["active"]["profile"], c, tx)
                    except Exception as cleanup:
                        result.update(status="recovery-required", withdrawal_error=str(cleanup))
                results.append(result)
            else:
                results.append({"pair": pair, "status": "active-unverified"})
        return results
