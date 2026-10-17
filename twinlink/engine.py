"""Validate -> preview -> apply -> read back -> commit, with durable rollback."""
import base64
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import time

from .store import StateError, atomic_write, reject_symlink
from .rathole_groups import group_name, groups, unit_name, units


class ApplyError(RuntimeError):
    def __init__(self, message, rollback_errors=()):
        super().__init__(message)
        self.rollback_errors = list(rollback_errors)


def redacted(value):
    if isinstance(value, dict):
        return {k: ("<redacted>" if k in {"token", "password", "secret", "noise_private_key", "local_private_key", "credentials", "management", "noise_private"} else redacted(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redacted(v) for v in value]
    if isinstance(value, str):
        return re.sub(r'(?m)^(\s*(?:token|default_token|noise_private_key|local_private_key)\s*=\s*).+$', r'\1"<redacted>"', value)
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _canonical_nft(value):
    """Ignore runtime counters/handles, retain rule order and all match expressions."""
    if isinstance(value, list):
        return [_canonical_nft(v) for v in value if not (isinstance(v, dict) and "metainfo" in v)]
    if isinstance(value, dict):
        return {k: _canonical_nft(v) for k, v in value.items() if k not in {"handle", "packets", "bytes", "index"}}
    return value


class Engine:
    def __init__(self, store, host, unit_dir="/etc/systemd/system", executable="/usr/local/bin/twinlink",
                 rathole_binary="/usr/local/bin/rathole", systemd=True):
        self.store, self.host = store, host
        self.unit_dir, self.executable = str(unit_dir), str(executable)
        self.rathole_binary, self.systemd = str(rathole_binary), systemd
        self.pending_peer = []

    def files(self, state):
        from .render import render_files
        if not state["tunnels"] and not state["forwards"]:
            return {}
        return render_files(state, str(self.store.directory), self.unit_dir, self.executable, self.rathole_binary)

    @staticmethod
    def changed(old, new, key):
        return {name for name in old[key].keys() | new[key].keys() if old[key].get(name) != new[key].get(name)}

    def affected(self, old, new):
        tunnels = self.changed(old, new, "tunnels")
        forwards = self.changed(old, new, "forwards")
        force = getattr(self, "force", None)
        if force:
            (tunnels if force[0] == "tunnel" else forwards).add(force[1])
        forwards |= {n for state in (old, new) for n, f in state["forwards"].items() if f["tunnel"] in tunnels}
        shared = {group_name(entry) for state in (old, new) for name, entry in state["forwards"].items()
                  if name in forwards and entry["mode"] == "rathole"}
        forwards |= {name for state in (old, new) for name, entry in state["forwards"].items()
                     if entry["mode"] == "rathole" and group_name(entry) in shared}
        return tunnels, forwards

    def plan(self, old, new, action):
        from .render import render_nft
        before, after = self.files(old), self.files(new)
        changes = []
        for path in sorted(before.keys() | after.keys()):
            target = Path(path)
            reject_symlink(target)
            expected = after.get(path)
            drifted = expected and target.is_file() and (target.read_bytes() != expected["content"].encode() or target.stat().st_mode & 0o777 != expected["mode"])
            if before.get(path) != expected or not target.exists() or drifted:
                changes.append({"path": path, "action": "write" if path in after else "remove",
                                **redacted(after.get(path, {}))})
        commands = []
        changed_t, changed_f = self.affected(old, new)
        try:
            live_links = {l["ifname"]: l for l in self.host.links()}
        except RuntimeError:
            live_links = None
        for name in sorted(changed_t):
            tunnel = new["tunnels"].get(name)
            if tunnel and tunnel.get("running"):
                steps = self.tunnel_commands(tunnel)
                exists = tunnel["interface"] in live_links if live_links is not None else old["tunnels"].get(name, {}).get("running")
                key_clear = tunnel.get("key") is None and (old["tunnels"].get(name, {}).get("key") is not None or
                            (live_links is not None and any(live_links.get(tunnel["interface"], {}).get("linkinfo", {}).get("info_data", {}).get(k) is not None for k in ("ikey", "okey"))))
                restart = getattr(self, "force", ()) == ("tunnel", name, "restart")
                if exists and (key_clear or restart):
                    commands.append(["ip", "link", "delete", "dev", tunnel["interface"]])
                elif exists:
                    steps[0][2] = "change"
                commands += steps
            else:
                previous = old["tunnels"].get(name)
                if previous:
                    commands.append(["ip", "link", "delete", "dev", previous["interface"]])
        commands += [["nft", "--check", "--file", "<managed rules>"], ["nft", "--file", "<atomic managed table replacement>"]]
        if any(f.get("running") and f["mode"] == "kernel" for f in new["forwards"].values()):
            commands.append(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        if self.systemd:
            for unit in sorted(units(old, changed_f)):
                commands.append(["systemctl", "stop", unit])
            commands.append(["systemctl", "daemon-reload"])
            commands += self.service_commands(new)
            for name, entries in sorted(groups(new).items()):
                if any(entry["name"] in changed_f for entry in entries) and any(entry["running"] for entry in entries):
                    commands.append(["systemctl", "restart", unit_name(entries[0])])
        commands += self.flow_commands(old, new)
        if not new["tunnels"]:
            commands.append(["nft", "delete", "table", "ip", "twinlink"])
        return {"action": action, "base_digest": digest(old), "configuration": redacted(new),
                "files": changes, "commands": commands, "rules": render_nft(new),
                "execution_order": ["Journal prior runtime and managed files", "Stop affected rathole processes before writing configurations",
                                    "Write generated files", "Temporarily withdraw affected NAT exposure and expire only its translated conntrack tuples",
                                    "Reconcile GRE and IP forwarding", "Atomically install final managed table", "Reconcile managed systemd services",
                                    "Read back and verify", "Remove obsolete owned files and commit state"],
                "verification": ["Read GRE kind, ownership, endpoints, key, TTL, MTU, flags and addresses from kernel",
                                 "Compare nftables table ownership, rule comments and read-back fingerprint",
                                 "Verify rathole process and private GRE listener; public listener is required after a peer registers",
                                 "Check stopped/deleted entries have no public listener or owned forwarding rule"],
                "rollback": ["Stop affected managed rathole services", "Restore previous managed files and unit enablement",
                             "Restore saved GRE interfaces and addresses", "Restore prior nftables table atomically",
                             "Restore prior ip_forward value", "Retain journal and repair instructions if any rollback step fails"],
                "notes": ["No peer is changed automatically. Transfer a fresh forwarding export after shared configuration edits.",
                          "Existing conntrack flows for changed/stopped kernel entries are removed; active connections will end.",
                          "GRE offers no encryption. Permit IP protocol 47 and private-GRE ICMP on both providers/hosts."]
                         + [f"Updating Rathole {name} restarts its shared process; all {len(entries)} configured services reconnect."
                            for name, entries in groups(new).items() if len(entries) > 1 and any(entry["name"] in changed_f for entry in entries)]}

    @staticmethod
    def tunnel_commands(tunnel):
        command = ["ip", "tunnel", "add", tunnel["interface"], "mode", "gre", "local", tunnel["local_public"],
                   "remote", tunnel["remote_public"], "ttl", str(tunnel["ttl"])]
        if tunnel.get("key") is not None:
            command += ["key", str(tunnel["key"])]
        return [command, ["ip", "link", "set", "dev", tunnel["interface"], "alias", "twinlink:" + tunnel["name"]],
                ["ip", "address", "replace", tunnel["local_private"], "dev", tunnel["interface"]],
                ["ip", "link", "set", "dev", tunnel["interface"], "mtu", str(tunnel["mtu"]), "up"]]

    def service_commands(self, state):
        commands = [["systemctl", "enable" if state["tunnels"] else "disable", "twinlink-restore.service"]]
        for name, tunnel in sorted(state["tunnels"].items()):
            commands.append(["systemctl", "enable" if tunnel["enabled"] else "disable", f"twinlink-gre-{name}.service"])
        for entries in groups(state).values():
            commands.append(["systemctl", "enable" if any(entry["enabled"] for entry in entries) else "disable", unit_name(entries[0])])
        return commands

    def _run(self, args, **kwargs):
        return self.host.run(args, **kwargs)

    def _table(self):
        result = self._run(["nft", "-j", "list", "table", "ip", "twinlink"], check=False)
        if result["returncode"]:
            # A missing table is normal. A permission/backend error is not.
            if any(s in result["stderr"].lower() for s in ("no such file", "does not exist")):
                return None
            raise ApplyError("Cannot inspect nftables: " + result["stderr"])
        table = self.host.nft_table_comments(json.loads(result["stdout"]))
        records = table.get("nftables", [])
        owned = any("table" in r and r["table"].get("family") == "ip"
                    and r["table"].get("name") == "twinlink"
                    and r["table"].get("comment") == "twinlink-owned" for r in records)
        if not owned:
            raise ApplyError("Foreign ip twinlink table exists; refusing takeover")
        return table

    def nft_fingerprint(self):
        value = self._table()
        return digest(_canonical_nft(value)) if value is not None else None

    def _replace_nft(self, content):
        prefix = "delete table ip twinlink\n" if self._table() is not None else ""
        # render_nft declares exactly one application-owned table; no global flush.
        script = prefix + content
        self._run(["nft", "--check", "--file", "-"], input=script)
        self._run(["nft", "--file", "-"], input=script)

    def _files_safe(self, paths):
        for path in paths:
            reject_symlink(path)
            target = Path(path)
            if target.exists():
                if not target.is_file() or "twinlink-owned" not in target.read_text()[:512]:
                    raise ApplyError("Refusing to replace foreign file: " + path)

    def _snapshot(self, old, new, boot=False):
        paths = self.files(old).keys() | self.files(new).keys()
        self._files_safe(paths)
        table = self._table()
        nft_text = None
        if table is not None:
            nft_text = self._run(["nft", "--stateless", "list", "table", "ip", "twinlink"])["stdout"]
        links, addresses = self.host.links(), self.host.addresses()
        names = {t["interface"] for s in (old, new) for t in s["tunnels"].values()}
        units = set()
        if self.systemd:
            for state in (old, new):
                units.update(f"twinlink-gre-{n}.service" for n in state["tunnels"])
                units.update(unit_name(entry) for entry in state["forwards"].values() if entry["mode"] == "rathole")
            units.add("twinlink-restore.service")
        services = {u: {"active": self._run(["systemctl", "is-active", u], check=False)["stdout"].strip() == "active",
                        "enabled": self._run(["systemctl", "is-enabled", u], check=False)["stdout"].strip() == "enabled"}
                    for u in units}
        affected_t, affected_f = self.affected(old, new)
        if boot:
            affected_t |= old["tunnels"].keys() | new["tunnels"].keys()
            affected_f |= old["forwards"].keys() | new["forwards"].keys()
        return {"old": old, "candidate": new, "affected_tunnels": sorted(affected_t), "affected_forwards": sorted(affected_f),
                "files": {p: {"data": base64.b64encode(Path(p).read_bytes()).decode(),
                 "mode": Path(p).stat().st_mode & 0o777} if Path(p).exists() else None for p in paths},
                "nft": nft_text, "nft_json": table, "links": [l for l in links if l.get("ifname") in names],
                "addresses": [a for a in addresses if a.get("ifname") in names],
                "ip_forward": self._run(["sysctl", "-n", "net.ipv4.ip_forward"])["stdout"].strip(),
                "services": services, "time": time.time()}

    def _tunnel_up(self, tunnel):
        self.host.assert_tunnel_safe(tunnel, existing=True)
        link = next((l for l in self.host.links() if l.get("ifname") == tunnel["interface"]), None)
        commands = self.tunnel_commands(tunnel)
        if link and tunnel.get("key") is None:
            data = link.get("linkinfo", {}).get("info_data", {})
            if data.get("ikey") is not None or data.get("okey") is not None:
                # ip tunnel change key 0 still sets GRE_KEY. Recreating this
                # positively owned interface removes the optional key header.
                self._tunnel_down(tunnel)
                link = None
        if link:
            # Change parameters in place; never delete physical/foreign interfaces.
            commands[0][2] = "change"
            self._run(commands[0])
            actual = next((a for a in self.host.addresses() if a.get("ifname") == tunnel["interface"]), {})
            for address in actual.get("addr_info", []):
                if address.get("family") == "inet":
                    cidr = f"{address['local']}/{address['prefixlen']}"
                    if cidr != tunnel["local_private"]:
                        self._run(["ip", "address", "delete", cidr, "dev", tunnel["interface"]])
            commands = commands[1:]
        for command in commands:
            self._run(command)

    def _tunnel_down(self, tunnel):
        self.host.assert_tunnel_safe(tunnel, existing=True, require_public=False)
        link = next((l for l in self.host.links() if l.get("ifname") == tunnel["interface"]), None)
        if not link:
            return
        if link.get("ifalias") != "twinlink:" + tunnel["name"] or link.get("linkinfo", {}).get("info_kind") != "gre":
            raise ApplyError("Refusing to delete foreign interface " + tunnel["interface"])
        self._run(["ip", "link", "delete", "dev", tunnel["interface"]])

    def flow_commands(self, old, new):
        # Delete only original public tuples belonging to changed entries, including
        # UDP and established TCP. Otherwise removing DNAT leaves conntrack exposure.
        from .models import ports
        commands = []
        _, changed_f = self.affected(old, new)
        for name in changed_f:
            entry = old["forwards"].get(name)
            if not entry or entry["mode"] != "kernel" or not entry.get("running"):
                continue
            lo, hi = ports(entry["bind_port"])
            for port in range(lo, hi + 1):
                tunnel = old["tunnels"][entry["tunnel"]]
                rlo, _ = ports(entry["relay_port"])
                # Both original and translated tuples restrict deletion to this
                # managed NAT flow, even when the public bind is wildcard.
                args = ["conntrack", "-D", "-p", entry["protocol"], "--orig-port-dst", str(port)]
                if entry["side"] == "vps1" and entry["bind_address"] != "0.0.0.0":
                    args += ["--orig-dst", entry["bind_address"]]
                if entry["side"] == "vps1":
                    args += ["--reply-src", str(ipaddress.ip_interface(tunnel["remote_private"]).ip),
                             "--reply-port-src", str(rlo + port - lo)]
                else:
                    args[args.index("--orig-port-dst") + 1] = str(rlo + port - lo)
                    args += ["--orig-dst", str(ipaddress.ip_interface(tunnel["local_private"]).ip)]
                    dlo, dhi = ports(entry["destination_port"])
                    args += ["--orig-src", str(ipaddress.ip_interface(tunnel["remote_private"]).ip),
                             "--reply-src", entry["destination_address"], "--reply-port-src", str(dlo + (port - lo if dlo != dhi else 0))]
                commands.append(args)
        return commands

    def _expire_flows(self, old, new):
        for args in self.flow_commands(old, new):
            # conntrack returns 1 when zero matching flows were deleted.
            result = self._run(args, check=False)
            if result["returncode"] not in (0, 1) or (result["returncode"] == 1 and
                    not re.search(r"\b0 flow entries", result["stdout"] + result["stderr"])):
                raise ApplyError("Could not expire forwarding connections: " + result["stderr"])

    def _runtime(self, old, new, boot=False):
        from .render import render_nft
        changed_t, changed_f = self.affected(old, new)
        # Remove NAT exposure before changing tunnels or listeners.
        interim = copy.deepcopy(new)
        for name in changed_f:
            if name in interim["forwards"]:
                interim["forwards"][name]["running"] = False
        self._replace_nft(render_nft(interim))
        self._expire_flows(old, new)
        for name in sorted(old["tunnels"]):
            if (name in changed_t or boot) and (name not in new["tunnels"] or not new["tunnels"][name].get("running")):
                if self.systemd and not boot:
                    self._run(["systemctl", "--no-block", "stop", f"twinlink-gre-{name}.service"])
                self._tunnel_down(old["tunnels"][name])
        for name, tunnel in sorted(new["tunnels"].items()):
            if tunnel.get("running") and (name in changed_t or boot):
                if getattr(self, "force", ()) == ("tunnel", name, "restart"):
                    self._tunnel_down(tunnel)
                self._tunnel_up(tunnel)
        if any(f.get("running") and f["mode"] == "kernel" for f in new["forwards"].values()):
            self._run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        self._replace_nft(render_nft(new))
        if self.systemd and not boot:
            self._run(["systemctl", "daemon-reload"])
            for command in self.service_commands(new):
                self._run(command)
            for entries in groups(new).values():
                if any(entry["name"] in changed_f for entry in entries) and any(entry["running"] for entry in entries):
                    self._run(["systemctl", "restart", unit_name(entries[0])])
            for unit in units(old) - units(new):
                self._run(["systemctl", "disable", unit])
            for name in old["tunnels"].keys() - new["tunnels"].keys():
                self._run(["systemctl", "disable", f"twinlink-gre-{name}.service"])
            if not new["tunnels"]:
                self._run(["systemctl", "stop", "twinlink-restore.service"])
        elif self.systemd and boot:
            self._run(["systemctl", "daemon-reload"])
            for entries in groups(new).values():
                if any(entry["running"] for entry in entries):
                    # These units are ordered after the restore callback itself.
                    self._run(["systemctl", "--no-block", "restart", unit_name(entries[0])])

    def _verify(self, old, new, boot=False):
        from .render import render_nft
        affected_t, affected_f = self.affected(old, new)
        relevant_t = affected_t | {f["tunnel"] for n, f in new["forwards"].items() if n in affected_f and f.get("running")}
        for name, tunnel in new["tunnels"].items():
            if not boot and name not in relevant_t:
                continue
            status = self.host.tunnel_status(tunnel, probe=False)
            if status.get("drift"):
                raise ApplyError("GRE verification failed for " + name + ": " + json.dumps(status["drift"]))
        live_names = {l.get("ifname") for l in self.host.links()}
        for name in old["tunnels"].keys() - new["tunnels"].keys():
            if old["tunnels"][name]["interface"] in live_names:
                raise ApplyError("Deleted GRE interface remains: " + name)
        table = self._table()
        expected = re.findall(r'comment\s+"(twinlink:[^"]+)"', render_nft(new))
        actual = [r["rule"].get("comment") for r in (table or {}).get("nftables", []) if "rule" in r]
        if sorted(expected) != sorted(actual):
            raise ApplyError("Installed nftables rules do not match the generated rule identifiers")
        for entry in new["forwards"].values():
            if entry["mode"] == "kernel" and entry.get("running"):
                drift = self.host.kernel_forward_drift(entry, new["tunnels"][entry["tunnel"]], snapshot=table)
                if drift:
                    raise ApplyError("Installed nftables expressions differ: " + json.dumps(drift))
        if boot and self.systemd:
            listeners = self.host.listeners()
            for name, previous in old["forwards"].items():
                current = new["forwards"].get(name)
                if previous["mode"] == "rathole" and not (current and current.get("running")):
                    unit = unit_name(previous)
                    shared_running = any(entry["running"] for entry in groups(new).get(group_name(previous), []))
                    exposed = previous["side"] == "vps1" and any(l.get("managed") == group_name(previous)
                              and l.get("port") == int(previous["bind_port"]) for l in listeners)
                    if (not shared_running and self._run(["systemctl", "is-active", unit], check=False)["stdout"].strip() == "active") or exposed:
                        raise ApplyError("Stopped rathole entry remains active during restore: " + name)
        if not boot:
            listeners = self.host.listeners()
            from .models import ports
            _, affected = self.affected(old, new)
            for name in affected:
                entry = new["forwards"].get(name)
                previous = old["forwards"].get(name)
                if entry and entry["mode"] == "rathole" and entry.get("running") and self.systemd:
                    unit = unit_name(entry)
                    deadline = time.monotonic() + 5
                    while True:
                        active = self._run(["systemctl", "is-active", unit], check=False)["stdout"].strip() == "active"
                        current = self.host.listeners()
                        port = ports(entry["bind_port"])[0] if entry["side"] == "vps1" else None
                        transport = entry["transport_port"]
                        private = str(ipaddress.ip_interface(new["tunnels"][entry["tunnel"]]["local_private"]).ip)
                        required = ((transport, private),) if port else ()
                        exposed = all(any(l["protocol"] == "tcp" and l["port"] == p and l["address"] == address for l in current)
                                      for p, address in required)
                        if active and exposed:
                            public = not port or any(l["protocol"] == "tcp" and l["port"] == port and l["address"] == entry["bind_address"] for l in current)
                            if public:
                                break
                            peer = str(ipaddress.ip_interface(new["tunnels"][entry["tunnel"]]["remote_private"]).ip)
                            connected = any(c.get("address") == private and c.get("port") == transport and c.get("peer_address") == peer
                                            for c in self.host.connections())
                            awaiting_pair = ("rathole_group" in entry and
                                             (not previous or not previous.get("running") or previous.get("revision") != entry.get("revision")
                                              or group_name(previous) != group_name(entry)))
                            if not connected or awaiting_pair:
                                # v0.5.0 binds its public service only after an
                                # authenticated client registers. Commit the local
                                # listener setup so its credentials can be exported.
                                self.pending_peer.append(name)
                                break
                        if time.monotonic() >= deadline:
                            raise ApplyError("Rathole process/listener verification failed for " + name)
                        time.sleep(0.15)
                if previous and previous["mode"] == "rathole" and previous["side"] == "vps1" and not (entry and entry.get("running")):
                    if any(l["protocol"] == previous["protocol"] and l["port"] == ports(previous["bind_port"])[0]
                           and l["address"] in {previous["bind_address"], "0.0.0.0", "::"} for l in listeners):
                        raise ApplyError("Public listener still exposed after stop/delete: " + name)
        new["_nft_fingerprint"] = self.nft_fingerprint()
        new["_rules_digest"] = hashlib.sha256(render_nft(new).encode()).hexdigest()

    def safety(self, old, new, boot=False):
        from .models import validate_tunnel, validate_forward
        listeners = self.host.listeners()
        owned_groups = groups(old)
        free = [l for l in listeners if not (l.get("managed") in owned_groups and self.systemd)]
        protected = {22}
        connection = os.environ.get("SSH_CONNECTION", "").split()
        if len(connection) == 4 and connection[3].isdigit():
            protected.add(int(connection[3]))
        affected_t, affected_f = self.affected(old, new)
        required_t = affected_t | {f["tunnel"] for n, f in new["forwards"].items() if n in affected_f and f.get("running")}
        for name, tunnel in new["tunnels"].items():
            validate_tunnel(tunnel, new, existing_name=name)
            if not boot and name not in required_t:
                continue
            self.host.assert_tunnel_safe(tunnel, existing=name in old["tunnels"], require_public=bool(tunnel.get("running")))
            if not tunnel.get("running"):
                continue
            private = ipaddress.ip_interface(tunnel["local_private"]).network
            for endpoint in (tunnel["local_public"], tunnel["remote_public"]):
                if ipaddress.ip_address(endpoint) in private:
                    raise ApplyError("GRE private subnet would route its public endpoint into itself")
            for route in self.host.routes():
                destination = route.get("dst", "default")
                if destination == "default" or route.get("dev") == tunnel["interface"]:
                    continue
                try:
                    network = ipaddress.ip_network(destination, strict=False)
                except ValueError:
                    continue
                if network.version == 4 and private.overlaps(network):
                    raise ApplyError("GRE private subnet overlaps an existing host route: " + destination)
        for name in old["tunnels"].keys() - new["tunnels"].keys():
            self.host.assert_tunnel_safe(old["tunnels"][name], existing=True, require_public=False)
        for name, entry in new["forwards"].items():
            prior = old["forwards"].get(name)
            check_listeners = not prior or entry.get("running")
            validate_forward(entry, new, existing_name=name, listeners=free if check_listeners else (), protected_ports=protected)
            if entry.get("running") and entry["side"] == "vps1" and entry["bind_address"] != "0.0.0.0":
                if not any(a.get("local") == entry["bind_address"] for row in self.host.addresses() for a in row.get("addr_info", [])):
                    raise ApplyError("Public bind address is not assigned on VPS1: " + entry["bind_address"])
            if not boot and entry.get("running") and (name not in old["forwards"] or not old["forwards"][name].get("running")):
                status = self.host.tunnel_status(new["tunnels"][entry["tunnel"]], probe=True)
                if status.get("health") != "up" or status.get("drift"):
                    raise ApplyError("GRE peer must be reachable before enabling forwarding: " + str(status.get("reason")))
            if entry["mode"] == "rathole" and entry.get("running"):
                result = self._run([self.rathole_binary, "--version"])
                output = result["stdout"] + "\n" + result["stderr"]
                version = re.search(r"(?m)^rathole[ \t]+(\S+)", output)
                # Upstream source builds put the version in a separate field.
                if version is None and re.search(r"(?m)^rathole[ \t]*$", output):
                    version = re.search(r"(?m)^Build Version:[ \t]+(\S+)[ \t]*$", output)
                if version is None or version.group(1) != "0.5.0":
                    raise ApplyError("Supported rathole version is 0.5.0 (TCP); supply --rathole-binary")
        self._files_safe(self.files(old).keys() | self.files(new).keys())
        self._units_safe(old, new)
        self._table()

    def _units_safe(self, old, new):
        if not self.systemd:
            return
        units = {Path(p).name for state in (old, new) for p in self.files(state) if p.endswith(".service")}
        for unit in units:
            info = self.host.unit_status(unit)
            fragment = info.get("properties", {}).get("FragmentPath")
            if info.get("exists") and fragment:
                self._files_safe([fragment])
                if Path(fragment).absolute() != (Path(self.unit_dir) / unit).absolute():
                    raise ApplyError("Managed unit name is loaded from a foreign path: " + fragment)
                if info.get("properties", {}).get("DropInPaths", "").strip():
                    raise ApplyError("Managed unit has external drop-ins; refusing to operate it: " + unit)

    def apply(self, old, new, plan, boot=False):
        self.host.require_linux_root()
        self.pending_peer = []
        if digest(self.store.read()) != plan["base_digest"]:
            raise StateError("Configuration changed since preview; create a new plan")
        if self.store.journal.exists():
            raise StateError("Unfinished transaction. Run twinlink recover --apply before mutating")
        self.safety(old, new, boot=boot)
        snapshot = self._snapshot(old, new, boot=boot)
        atomic_write(self.store.journal, json.dumps(snapshot, sort_keys=True))
        try:
            if self.systemd:
                # rathole watches its TOML. Stop before atomically replacing it,
                # so hot reload cannot expose a new port before verification.
                old_groups, new_groups = groups(old), groups(new)
                for unit in sorted(units(old, snapshot["affected_forwards"])):
                    group = unit.removeprefix("twinlink-rathole-").removesuffix(".service")
                    entries = new_groups.get(group, [])
                    if not boot or not any(entry["running"] for entry in entries) or entries != old_groups.get(group):
                        self._run(["systemctl", "stop", unit])
            files = self.files(new)
            for path, spec in files.items():
                target = Path(path)
                if not target.exists() or target.read_bytes() != spec["content"].encode() or target.stat().st_mode & 0o777 != spec["mode"]:
                    atomic_write(path, spec["content"], spec["mode"])
            self._runtime(old, new, boot=boot)
            self._verify(old, new, boot=boot)
            if not new["tunnels"]:
                if self._table() is not None:
                    self._run(["nft", "delete", "table", "ip", "twinlink"])
                if self._table() is not None:
                    raise ApplyError("Owned firewall table remained after purge")
                new["_nft_fingerprint"] = None
            # Remove stale owned files only after dependent processes have stopped.
            for path in self.files(old).keys() - files.keys():
                self._files_safe([path])
                if Path(path).exists():
                    Path(path).unlink()
            if self.systemd and not boot:
                self._run(["systemctl", "daemon-reload"])
            self.store.write(new)
            self.store.journal.unlink()
            result = {"committed": True, "action": plan["action"], "state_digest": digest(new)}
            if self.pending_peer:
                result["pending_peer"] = self.pending_peer
                result["health"] = "not_verified"
                result["next"] = "Transfer/import the matching forwarding configuration and start VPS2, then run forward check on both hosts and test from an external client"
            return result
        except BaseException as exc:
            # A failure after atomic commit but before journal unlink is recovered
            # conservatively to the prior state. A kill leaves the journal intact.
            errors = self.rollback(snapshot)
            raise ApplyError("Apply failed: " + str(exc) + "; " + ("rollback completed" if not errors else
                             "rollback incomplete; run twinlink recover --apply and inspect diagnose output"), errors) from exc

    def rollback(self, snapshot):
        errors = []
        def attempt(label, callback):
            try:
                callback()
            except BaseException as exc:
                errors.append(label + ": " + str(exc))
        if self.systemd:
            for unit in snapshot["services"]:
                affected_forwards = snapshot.get("affected_forwards", list(snapshot["candidate"]["forwards"]))
                if unit in units(snapshot["old"], affected_forwards) | units(snapshot["candidate"], affected_forwards):
                    attempt("stop " + unit, lambda u=unit: self._run(["systemctl", "stop", u]))
                if snapshot["files"].get(str(Path(self.unit_dir) / unit)) is None and (Path(self.unit_dir) / unit).exists():
                    attempt("disable new " + unit, lambda u=unit: self._run(["systemctl", "disable", u]))
        for path, value in snapshot["files"].items():
            def restore(p=path, value=value):
                self._files_safe([p])
                if value is None:
                    if Path(p).exists():
                        Path(p).unlink()
                else:
                    atomic_write(p, base64.b64decode(value["data"]), value["mode"])
            attempt("restore " + path, restore)
        affected_t = set(snapshot.get("affected_tunnels", self.affected(snapshot["old"], snapshot["candidate"])[0]))
        actual = {l["ifname"]: l for l in snapshot["links"] if any(
                  t["interface"] == l["ifname"] and n in affected_t for s in (snapshot["old"], snapshot["candidate"])
                  for n, t in s["tunnels"].items())}
        tunnels = dict(snapshot["candidate"]["tunnels"])
        tunnels.update(snapshot["old"]["tunnels"])
        for name, tunnel in tunnels.items():
            if name not in affected_t:
                continue
            attempt("remove candidate GRE " + tunnel["name"], lambda t=tunnel: self._tunnel_down(t))
        for name, link in actual.items():
            def restore_link(link=link, name=name):
                data = link.get("linkinfo", {}).get("info_data", {})
                tunnel = next(t for t in tunnels.values() if t["interface"] == name)
                saved = dict(tunnel, local_public=data.get("local", tunnel["local_public"]),
                             remote_public=data.get("remote", tunnel["remote_public"]), mtu=link["mtu"], ttl=data.get("ttl", 64))
                key = data.get("ikey", data.get("key"))
                if key is not None:
                    try:
                        saved["key"] = int(key)
                    except ValueError:
                        saved["key"] = int(ipaddress.IPv4Address(key))
                self._tunnel_up(saved)
                for field in ("ikey", "okey"):
                    if data.get(field) is not None:
                        value = data[field]
                        try:
                            value = int(value)
                        except ValueError:
                            value = int(ipaddress.IPv4Address(value))
                        self._run(["ip", "tunnel", "change", name, field, str(value)])
                # Restore the exact previous IPv4 address set and admin flag.
                self._run(["ip", "address", "flush", "dev", name, "scope", "global"])
                for row in snapshot["addresses"]:
                    if row.get("ifname") == name:
                        for address in row.get("addr_info", []):
                            if address.get("family") == "inet":
                                self._run(["ip", "address", "add", f"{address['local']}/{address['prefixlen']}", "dev", name])
                self._run(["ip", "link", "set", "dev", name, "up" if "UP" in link.get("flags", []) else "down"])
            attempt("restore GRE " + name, restore_link)
        def restore_nft():
            current = self._table()
            prefix = "delete table ip twinlink\n" if current is not None else ""
            text = prefix + (snapshot["nft"] or "")
            if text:
                self._run(["nft", "--file", "-"], input=text)
        attempt("restore nftables", restore_nft)
        attempt("restore ip_forward", lambda: self._run(["sysctl", "-w", "net.ipv4.ip_forward=" + snapshot["ip_forward"]]))
        if self.systemd:
            attempt("reload units", lambda: self._run(["systemctl", "daemon-reload"]))
            for unit, status in snapshot["services"].items():
                def restore_unit(u=unit, s=status):
                    # Missing units that were absent before need no disable/stop.
                    exists = (Path(self.unit_dir) / u).exists()
                    if exists:
                        self._run(["systemctl", "enable" if s["enabled"] else "disable", u])
                        if u.startswith("twinlink-rathole-"):
                            self._run(["systemctl", "start" if s["active"] else "stop", u])
                attempt("restore service " + unit, restore_unit)
        if not errors:
            attempt("verify rollback", lambda: self._verify_rollback(snapshot))
        if not errors:
            attempt("restore configuration", lambda: self.store.write(snapshot["old"]))
        if not errors and self.store.journal.exists():
            self.store.journal.unlink()
        return errors

    def _verify_rollback(self, snapshot):
        for path, value in snapshot["files"].items():
            target = Path(path)
            reject_symlink(target)
            if value is None:
                if target.exists():
                    raise ApplyError("New managed file remained after rollback: " + path)
            elif not target.exists() or target.read_bytes() != base64.b64decode(value["data"]) or target.stat().st_mode & 0o777 != value["mode"]:
                raise ApplyError("Managed file rollback differs: " + path)
        live = {l["ifname"]: l for l in self.host.links()}
        previous = {l["ifname"]: l for l in snapshot["links"]}
        names = {t["interface"] for s in (snapshot["old"], snapshot["candidate"]) for t in s["tunnels"].values()}
        for name in names:
            before, after = previous.get(name), live.get(name)
            if bool(before) != bool(after):
                raise ApplyError("GRE interface presence differs after rollback: " + name)
            if before:
                for field in ("mtu", "ifalias"):
                    if before.get(field) != after.get(field):
                        raise ApplyError("GRE rollback differs: " + name + " " + field)
                if ("UP" in before.get("flags", [])) != ("UP" in after.get("flags", [])):
                    raise ApplyError("GRE admin state differs after rollback: " + name)
                for field in ("info_kind", "info_data"):
                    if before.get("linkinfo", {}).get(field) != after.get("linkinfo", {}).get(field):
                        raise ApplyError("GRE parameters differ after rollback: " + name)
        def addresses(rows):
            return {(r["ifname"], a["local"], a["prefixlen"]) for r in rows if r.get("ifname") in names
                    for a in r.get("addr_info", []) if a.get("family") == "inet"}
        if addresses(snapshot["addresses"]) != addresses(self.host.addresses()):
            raise ApplyError("GRE addresses differ after rollback")
        if "nft_json" in snapshot and _canonical_nft(self._table()) != _canonical_nft(snapshot["nft_json"]):
            raise ApplyError("Firewall differs after rollback")
        if self._run(["sysctl", "-n", "net.ipv4.ip_forward"])["stdout"].strip() != snapshot["ip_forward"]:
            raise ApplyError("IP forwarding differs after rollback")
        if self.systemd:
            affected = snapshot.get("affected_forwards", list(snapshot["candidate"]["forwards"]))
            for unit, status in snapshot["services"].items():
                if unit in units(snapshot["old"], affected) | units(snapshot["candidate"], affected):
                    active = self._run(["systemctl", "is-active", unit], check=False)["stdout"].strip() == "active"
                    if active != status["active"]:
                        raise ApplyError("Service runtime differs after rollback: " + unit)
                enabled = self._run(["systemctl", "is-enabled", unit], check=False)["stdout"].strip() == "enabled"
                if enabled != status["enabled"]:
                    raise ApplyError("Service enablement differs after rollback: " + unit)

    def recover(self):
        self.host.require_linux_root()
        reject_symlink(self.store.journal)
        if not self.store.journal.exists():
            return {"recovered": False, "reason": "No unfinished transaction"}
        snapshot = json.loads(self.store.journal.read_text())
        # Journals are private, but still bound recovery to generated managed paths.
        allowed = self.files(snapshot["old"]).keys() | self.files(snapshot["candidate"]).keys()
        if set(snapshot["files"]) != allowed:
            raise StateError("Journal paths fail ownership validation")
        errors = self.rollback(snapshot)
        if errors:
            raise ApplyError("Recovery incomplete; journal retained", errors)
        return {"recovered": True}
