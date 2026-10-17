"""Read Linux state and collect bounded, non-mutating health evidence.

The command runner deliberately accepts argv only.  No command in this module
changes networking, files, firewall rules, or systemd state.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import shlex
import socket
import subprocess
import time
from typing import Any

from .rathole_groups import group_name, unit_name


class HostError(RuntimeError):
    """A Linux prerequisite, command, or live safety check failed."""


def require_linux_root() -> None:
    if platform.system() != "Linux":
        raise HostError("Live network operations require Linux; omit --apply to inspect a plan.")
    if os.geteuid() != 0:
        raise HostError("Live network operations require root; run with sudo.")


def _ip(value: str) -> str:
    return str(ipaddress.ip_interface(value).ip)


def _key(value: Any) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, str) and "." in value:
        return int(ipaddress.IPv4Address(value))
    return int(value)


def _endpoint(value: str) -> tuple[str, int | None]:
    """Parse ss's IPv4, IPv6, wildcard and scoped local endpoint forms."""
    address, _, port = value.rpartition(":")
    address = address.strip("[]").split("%", 1)[0]
    return address or "*", int(port) if port.isdigit() else None


def parse_ss(text: str, default_protocol: str = "tcp") -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        columns = line.split()
        if not columns:
            continue
        if columns[0].lower() in {"tcp", "udp", "tcp6", "udp6"}:
            if len(columns) < 6:
                continue
            protocol, state, local, peer = columns[0], columns[1], columns[4], columns[5]
        elif len(columns) >= 5 and not columns[0].isdigit():
            protocol, state, local, peer = default_protocol, columns[0], columns[3], columns[4]
        elif len(columns) >= 4:
            protocol, state, local, peer = default_protocol, "ESTAB", columns[2], columns[3]
        else:
            continue
        address, port = _endpoint(local)
        peer_address, peer_port = _endpoint(peer)
        rows.append({"protocol": protocol.removesuffix("6"), "state": state,
                     "address": address, "port": port,
                     "peer_address": peer_address, "peer_port": peer_port,
                     "pids": sorted({int(pid) for pid in re.findall(r"\bpid=(\d+)\b", line)})})
    return rows


def parse_ping(result: dict[str, Any]) -> dict[str, Any]:
    output = result.get("stdout", "") + "\n" + result.get("stderr", "")
    loss = re.search(r"([\d.]+)%\s+packet loss", output)
    latency = re.search(r"(?:rtt|round-trip)[^=]*=\s*[\d.]+/([\d.]+)/", output)
    loss_percent = float(loss.group(1)) if loss else None
    latency_ms = float(latency.group(1)) if latency else None
    if loss_percent == 100:
        health, reason = "down", "No GRE peer ping replies (100% packet loss)."
    elif loss_percent is None:
        health, reason = "degraded", "GRE peer reachability could not be measured."
    elif loss_percent > 0:
        health, reason = "degraded", "GRE peer responds with packet loss."
    elif result.get("returncode", 1) != 0:
        health, reason = "degraded", "GRE probe reported an error despite received replies."
    else:
        health, reason = "up", "GRE peer answered all probes."
    return {"health": health, "reason": reason, "loss_percent": loss_percent,
            "latency_ms": latency_ms, "returncode": result.get("returncode")}


def redact(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    """Redact both known secrets and token/password assignments in evidence."""
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if any(word in key.lower() for word in
                     ("token", "password", "secret", "private_key")) else redact(item, secrets))
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    if not isinstance(value, str):
        return value
    for secret in secrets:
        if secret:
            value = value.replace(secret, "[REDACTED]")
    return re.sub(r'(?im)((?:token|password|secret|private_key)\s*[=:]\s*)("[^"\n]*"|\x27[^\x27\n]*\x27|[^\s,\n]+)',
                  r'\1"[REDACTED]"', value)


def _nft_signature(expressions: list[dict[str, Any]]) -> str:
    """Canonicalize semantic expressions, ignoring mutable packet counters."""
    def normalize(value: Any) -> Any:
        if isinstance(value, dict):
            normalized = {key: normalize(item) for key, item in value.items()}
            if "set" in normalized:
                normalized["set"] = sorted(normalized["set"], key=lambda item: json.dumps(item, sort_keys=True))
            if "match" in normalized:
                match = normalized["match"]
                flags = {"payload": {"protocol": "tcp", "field": "flags"}}
                bits = {"fin": 1, "syn": 2, "rst": 4, "psh": 8, "ack": 16, "urg": 32, "ecn": 64, "cwr": 128}
                def flag_value(value):
                    if isinstance(value, str) and value in bits:
                        return bits[value]
                    if isinstance(value, list) and all(isinstance(v, str) and v in bits for v in value):
                        result = 0
                        for v in value:
                            result |= bits[v]
                        return result
                    return value
                left = match.get("left")
                if isinstance(left, dict) and set(left) == {"&"} and isinstance(left["&"], list) and len(left["&"]) == 2 and left["&"][0] == flags:
                    left["&"][1] = flag_value(left["&"][1])
                    match["right"] = flag_value(match.get("right"))
                    if left["&"][1] == 4 and match.get("op") == "!=" and match["right"] == 0:
                        match["op"], match["right"] = "==", 4
                elif left == flags and match.get("op") == "in" and flag_value(match.get("right")) == 4:
                    match.update(left={"&": [flags, 4]}, op="==", right=4)
                # nft 1.0.2 renders comma-separated ct states as an array,
                # while explicit state sets use {"set": [...]}. Both test
                # membership; array ordering does not change the match.
                if match.get("left") == {"ct": {"key": "state"}}:
                    right = match.get("right")
                    if isinstance(right, list):
                        match["right"] = {"set": sorted(right)}
                    if match.get("op") == "in":
                        match["op"] = "=="
                if isinstance(match.get("right"), dict) and "set" in match["right"]:
                    if match.get("op") in ("in", "=="):
                        match["op"] = "=="
            for action in ("dnat", "snat"):
                if isinstance(normalized.get(action), dict):
                    normalized[action].pop("family", None)
            if isinstance(normalized.get("fib"), dict) and "flags" in normalized["fib"]:
                flags = normalized["fib"]["flags"]
                normalized["fib"]["flags"] = sorted([flags] if isinstance(flags, str) else flags)
            if "masquerade" in normalized and normalized["masquerade"] == {}:
                normalized["masquerade"] = None
            return normalized
        if isinstance(value, list):
            return [normalize(item) for item in value]
        return value
    return json.dumps([normalize(expr) for expr in expressions if "counter" not in expr],
                      sort_keys=True, separators=(",", ":"))


def _rendered_rule_expressions(line: str) -> tuple[str, list[dict[str, Any]]]:
    """Interpret only the small, trusted nft DSL produced by render.py."""
    tokens = shlex.split(line)
    expressions = []
    index = 0
    while index < len(tokens):
        word = tokens[index]
        if word == "comment":
            return tokens[index + 1], expressions
        if word == "counter":
            index += 1
            continue
        if word in ("iifname", "oifname"):
            left = {"meta": {"key": word}}
            op = "!=" if tokens[index + 1] == "!=" else "=="
            advance = 3 if op == "!=" else 2
            right = tokens[index + advance - 1]
        elif word == "ip" and tokens[index + 1] in ("saddr", "daddr"):
            left, op, right = {"payload": {"protocol": "ip", "field": tokens[index + 1]}}, "==", tokens[index + 2]
            advance = 3
        elif word in ("tcp", "udp") and tokens[index + 1] in ("dport", "sport"):
            left = {"payload": {"protocol": word, "field": tokens[index + 1]}}
            parts = [int(port) for port in tokens[index + 2].split("-")]
            right, op, advance = (parts[0] if len(parts) == 1 else {"range": parts}), "==", 3
        elif word == "tcp" and tokens[index + 1:index + 6] == ["flags", "&", "rst", "==", "rst"]:
            left = {"&": [{"payload": {"protocol": "tcp", "field": "flags"}}, "rst"]}
            right, op, advance = "rst", "==", 6
        elif word == "fib" and tokens[index + 1:index + 4] == ["daddr", "type", "local"]:
            left = {"fib": {"result": "type", "flags": ["daddr"]}}
            right, op, advance = "local", "==", 4
        elif word == "ct" and tokens[index + 1] == "state":
            left = {"ct": {"key": "state"}}
            states = tokens[index + 2].split(",")
            right = {"set": states} if len(states) > 1 else states[0]
            op, advance = "==", 3
        elif word in ("dnat", "snat") and tokens[index + 1] == "to":
            endpoint = tokens[index + 2]
            action: dict[str, Any] = {"addr": endpoint}
            if ":" in endpoint:
                address, port = _endpoint(endpoint)
                action = {"addr": address, "port": port}
            expressions.append({word: action})
            index += 3
            continue
        elif word in ("accept", "masquerade", "notrack", "drop"):
            expressions.append({word: None})
            index += 1
            continue
        else:
            raise HostError(f"Unsupported generated nft expression: {word}")
        expressions.append({"match": {"op": op, "left": left, "right": right}})
        index += advance
    raise HostError("Generated nft rule has no ownership comment.")


def recover_nft_table_comments(snapshot, expected_comments, run):
    """Recover only an expected leading table marker missing from nft JSON."""
    for item in snapshot.get("nftables", []):
        table = item.get("table", {})
        name = table.get("name")
        if table.get("family") != "ip" or name not in expected_comments or "comment" in table:
            continue
        marker = expected_comments[name]
        result = run(["nft", "list", "table", "ip", name])
        # Match only the table's leading comment, never a chain/rule comment.
        # Missing/unreadable evidence must leave ownership unverified.
        if result["returncode"] == 0 and not result.get("error") and not result.get("truncated") and re.match(
                r'\A\s*table ip ' + re.escape(name) + r'\s*\{\s*comment "' + re.escape(marker) + r'"\s*;?(?=\s|\})',
                result["stdout"] or ""):
            table["comment"] = marker
    return snapshot


class Host:
    """Injectable interface to the current Linux host."""

    def run(self, argv: list[str], check: bool = True, input: str | None = None,
            timeout: float = 15) -> dict[str, Any]:
        if platform.system() != "Linux":
            raise HostError("Executing host commands requires Linux.")
        if not argv or not all(isinstance(arg, str) for arg in argv):
            raise HostError("Commands must be a nonempty list of strings.")
        try:
            completed = subprocess.run(argv, input=input, text=True, capture_output=True,
                                       timeout=timeout, env={**os.environ, "LC_ALL": "C"},
                                       shell=False)
            result = {"returncode": completed.returncode, "stdout": completed.stdout,
                      "stderr": completed.stderr}
        except FileNotFoundError:
            result = {"returncode": 127, "stdout": "", "stderr": f"Dependency not found: {argv[0]}"}
        except subprocess.TimeoutExpired as exc:
            def output_text(item: Any) -> str:
                return item.decode(errors="replace") if isinstance(item, bytes) else (item or "")
            result = {"returncode": 124, "stdout": output_text(exc.stdout),
                      "stderr": output_text(exc.stderr) + f"\nCommand timed out after {timeout}s."}
        except OSError as exc:
            result = {"returncode": 126, "stdout": "", "stderr": str(exc)}
        if check and result["returncode"]:
            raise HostError(f"{argv[0]} failed ({result['returncode']}): {redact(result['stderr'].strip())}")
        return result

    def require_linux_root(self) -> None:
        require_linux_root()

    def _json(self, argv: list[str]) -> Any:
        result = self.run(argv)
        try:
            return json.loads(result["stdout"])
        except (ValueError, TypeError) as exc:
            raise HostError(f"{argv[0]} returned invalid JSON.") from exc

    def links(self) -> list[dict[str, Any]]:
        return self._json(["ip", "-j", "-d", "link", "show"])

    def addresses(self) -> list[dict[str, Any]]:
        return self._json(["ip", "-j", "addr", "show"])

    def routes(self) -> list[dict[str, Any]]:
        return self._json(["ip", "-j", "route", "show", "table", "all"])

    def listeners(self) -> list[dict[str, Any]]:
        rows = parse_ss(self.run(["ss", "-H", "-lntup"])["stdout"])
        # A service merely being active does not prove that it owns a socket.
        # Every reported socket owner must belong to the same systemd cgroup.
        for row in rows:
            owners = []
            for pid in row["pids"]:
                try:
                    cgroups = Path(f"/proc/{pid}/cgroup").read_text()
                except OSError:
                    owners.append(None)
                    continue
                matches = re.findall(r"(?:^|/)twinlink-rathole-([A-Za-z0-9_.-]+)\.service(?:/|$)", cgroups, re.M)
                owners.append(matches[0] if len(set(matches)) == 1 else None)
            if owners and all(owner == owners[0] and owner is not None for owner in owners):
                row["managed"] = owners[0]
        return rows

    def connections(self) -> list[dict[str, Any]]:
        return parse_ss(self.run(["ss", "-H", "-nt", "state", "established"])["stdout"])

    def unit_status(self, name: str) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9_.@:-]+\.(?:service|timer)", name) or name.startswith("-"):
            raise HostError("Invalid systemd unit name.")
        result = self.run(["systemctl", "show", name, "--no-pager",
                           "--property=LoadState,ActiveState,SubState,UnitFileState,Result,ExecMainStatus,FragmentPath,MainPID,DropInPaths"],
                          check=False)
        properties = dict(line.split("=", 1) for line in result["stdout"].splitlines() if "=" in line)
        return {"name": name, "exists": properties.get("LoadState") == "loaded",
                "active": properties.get("ActiveState") == "active",
                "enabled": properties.get("UnitFileState") in {"enabled", "enabled-runtime"},
                "properties": properties, "returncode": result["returncode"],
                "error": redact(result["stderr"].strip())}

    def dependency_report(self) -> dict[str, Any]:
        required = ("ip", "ss", "ping", "nft", "systemctl", "sysctl", "conntrack")
        optional = ("rathole", "tracepath", "journalctl", "modprobe")
        commands = {name: {"path": shutil.which(name), "required": name in required}
                    for name in required + optional}
        linux = platform.system() == "Linux"
        return {"linux": linux, "root": os.geteuid() == 0,
                "supported": linux, "commands": commands,
                "missing_required": [name for name in required if not commands[name]["path"]],
                "systemd_runtime": linux and Path("/run/systemd/system").is_dir(),
                "gre_module_loaded": linux and Path("/sys/module/ip_gre").is_dir()}

    def nft_table_comments(self, snapshot: dict[str, Any], expected_comments=None) -> dict[str, Any]:
        """Recover the table marker omitted by older nft JSON serializers."""
        expected_comments = {"twinlink": "twinlink-owned"} if expected_comments is None else expected_comments
        return recover_nft_table_comments(snapshot, expected_comments, lambda argv: self.run(argv, check=False))

    def nft_snapshot(self) -> dict[str, Any]:
        result = self.run(["nft", "-j", "list", "ruleset"], check=False)
        if result["returncode"]:
            return {"available": False, "error": redact(result["stderr"].strip()), "nftables": []}
        try:
            snapshot = json.loads(result["stdout"])
            if not isinstance(snapshot, dict):
                raise ValueError("not an object")
            snapshot["available"] = True
            return self.nft_table_comments(snapshot)
        except (ValueError, TypeError):
            return {"available": False, "error": "nft returned invalid JSON", "nftables": []}

    def kernel_forward_drift(self, entry: dict[str, Any], tunnel: dict[str, Any],
                             snapshot: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Compare owned rule chains, matches and NAT actions, not just tags."""
        from .render import render_nft_entry

        snapshot = self.nft_snapshot() if snapshot is None else snapshot
        if not snapshot.get("available", True):
            return [{"field": "firewall", "desired": "readable", "actual": snapshot.get("error", "unavailable")}]
        drift = []
        tables = [item["table"] for item in snapshot.get("nftables", []) if "table" in item
                  and item["table"].get("family") == "ip" and item["table"].get("name") == "twinlink"]
        if not tables:
            drift.append({"field": "firewall_table", "desired": "ip twinlink", "actual": "missing"})
        elif tables[0].get("comment") != "twinlink-owned":
            drift.append({"field": "firewall_ownership", "desired": "twinlink-owned", "actual": tables[0].get("comment")})
        chains = {item["chain"].get("name"): item["chain"] for item in snapshot.get("nftables", [])
                  if "chain" in item and item["chain"].get("family") == "ip"
                  and item["chain"].get("table") == "twinlink"}
        hooks = {"prerouting": ("nat", -100), "output": ("nat", -100),
                 "postrouting": ("nat", 100), "forward": ("filter", 0)}
        for name, (kind, priority) in hooks.items():
            chain = chains.get(name, {})
            if (chain.get("hook"), chain.get("type"), chain.get("prio"), chain.get("policy")) != (name, kind, priority, "accept"):
                drift.append({"field": "firewall_chain:" + name, "desired": f"{kind} hook {name} priority {priority} policy accept",
                              "actual": "missing or different hook configuration"})
        rules = [item["rule"] for item in snapshot.get("nftables", []) if "rule" in item
                 and item["rule"].get("family") == "ip" and item["rule"].get("table") == "twinlink"]
        expected = {}
        for chain, lines in render_nft_entry(entry, tunnel).items():
            for line in lines:
                comment, expressions = _rendered_rule_expressions(line)
                expected[comment] = (chain, _nft_signature(expressions))
        for comment, (chain, signature) in expected.items():
            matching = [rule for rule in rules if rule.get("comment") == comment]
            if len(matching) != 1:
                drift.append({"field": comment, "desired": "one managed rule", "actual": len(matching)})
            elif matching[0].get("chain") != chain or _nft_signature(matching[0].get("expr", [])) != signature:
                drift.append({"field": comment, "desired": "configured matches and action in " + chain,
                              "actual": "installed rule differs"})
        unexpected = [rule.get("comment") for rule in rules
                      if str(rule.get("comment", "")).startswith("twinlink:" + entry["name"] + ":")
                      and rule.get("comment") not in expected]
        for comment in unexpected:
            drift.append({"field": comment, "desired": "absent", "actual": "unexpected managed rule"})
        return drift

    def assert_tunnel_safe(self, tunnel: dict[str, Any], existing: bool = False,
                           require_public: bool = True) -> None:
        """Reject a non-owned link, default route interface, or unbound endpoint."""
        name = tunnel["interface"]
        if not re.fullmatch(r"tl[a-z0-9]{1,13}", name):
            raise HostError("Managed GRE interface names must start with tl and fit Linux's 15-byte limit.")
        links = self.links()
        link = next((item for item in links if item.get("ifname") == name), None)
        if link:
            if link.get("linkinfo", {}).get("info_kind") != "gre":
                raise HostError(f"Refusing to touch non-GRE interface {name}.")
            if link.get("ifalias") != "twinlink:" + tunnel["name"]:
                raise HostError(f"Refusing to touch foreign interface {name}; ownership alias does not match.")
        elif existing:
            # Reapply may recover a missing managed interface.  Absence is safe.
            pass
        routes = self.routes()
        for route in routes:
            devices = [route.get("dev")] + [hop.get("dev") for hop in route.get("nexthops", [])]
            if route.get("dst", "default") == "default" and name in devices:
                raise HostError(f"Refusing to alter {name}: it carries a default route.")
        local = tunnel["local_public"]
        addresses = self.addresses()
        configured = any(item.get("local") == local for interface in addresses
                         for item in interface.get("addr_info", []))
        if require_public and not configured:
            raise HostError(f"Local GRE public endpoint {local} is not assigned on this host.")
        if not require_public:
            return
        private = ipaddress.IPv4Interface(tunnel["local_private"]).network
        for field in ("local_public", "remote_public"):
            if ipaddress.IPv4Address(tunnel[field]) in private:
                raise HostError("GRE private subnet would route its public endpoint into itself.")
        for interface in addresses:
            if interface.get("ifname") == name:
                continue
            for address in interface.get("addr_info", []):
                if address.get("family", "inet") != "inet" or "local" not in address or "prefixlen" not in address:
                    continue
                network = ipaddress.IPv4Interface(f"{address['local']}/{address['prefixlen']}").network
                if private.overlaps(network):
                    raise HostError("GRE private subnet overlaps an address network on " + interface.get("ifname", "another interface") + ": " + str(network))
        for route in routes:
            destination = route.get("dst", "default")
            if destination in ("default", "0.0.0.0/0") or route.get("dev") == name:
                continue
            try:
                network = ipaddress.ip_network(destination, strict=False)
            except ValueError:
                continue
            if network.version == 4 and private.overlaps(network):
                raise HostError("GRE private subnet overlaps an existing host route: " + destination)
        connection = os.environ.get("SSH_CONNECTION", "").split()
        if len(connection) == 4:
            try:
                peer = ipaddress.ip_address(connection[0])
            except ValueError:
                peer = None
            if peer is not None and peer.version == 4 and peer in private:
                raise HostError("GRE private subnet would redirect this SSH client's address; choose another subnet.")

    def tunnel_status(self, tunnel: dict[str, Any], probe: bool = True) -> dict[str, Any]:
        status: dict[str, Any] = {"name": tunnel["name"], "interface": tunnel["interface"],
                                  "health": "down", "reason": "GRE interface is missing.",
                                  "drift": [], "actual": None, "loss_percent": None,
                                  "latency_ms": None, "peer_reachable": None}
        try:
            link = next((item for item in self.links() if item.get("ifname") == tunnel["interface"]), None)
            if link is None:
                if tunnel.get("running", tunnel.get("enabled", True)):
                    status["drift"] = [{"field": "interface", "desired": "present", "actual": "missing"}]
                else:
                    status["reason"] = "GRE tunnel is stopped."
                return status
            addresses = next((item.get("addr_info", []) for item in self.addresses()
                              if item.get("ifname") == tunnel["interface"]), [])
        except HostError as exc:
            status["reason"] = str(exc)
            status["inspection_error"] = str(exc)
            return status
        info = link.get("linkinfo", {})
        data = info.get("info_data", {})
        actual_addresses = [f"{item['local']}/{item['prefixlen']}" for item in addresses
                            if "local" in item and "prefixlen" in item]
        actual = {"kind": info.get("info_kind"), "local_public": data.get("local"),
                  "remote_public": data.get("remote"), "mtu": link.get("mtu"),
                  "ttl": data.get("ttl"), "ikey": data.get("ikey"), "okey": data.get("okey"),
                  "alias": link.get("ifalias"), "up": "UP" in link.get("flags", []),
                  "operstate": link.get("operstate"), "addresses": actual_addresses}
        status["actual"] = actual
        expected = {"kind": "gre", "local_public": tunnel["local_public"],
                    "remote_public": tunnel["remote_public"], "mtu": tunnel.get("mtu", 1476),
                    "ttl": tunnel.get("ttl", 64), "alias": "twinlink:" + tunnel["name"],
                    "up": bool(tunnel.get("running", tunnel.get("enabled", True)))}
        for field, want in expected.items():
            if want != actual[field]:
                status["drift"].append({"field": field, "desired": want, "actual": actual[field]})
        for key in ("ikey", "okey"):
            try:
                equal = (actual[key] is None if tunnel.get("key") is None
                         else actual[key] is not None and _key(tunnel["key"]) == _key(actual[key]))
            except (ValueError, TypeError, ipaddress.AddressValueError):
                equal = False
            if not equal:
                status["drift"].append({"field": key, "desired": tunnel.get("key"), "actual": actual[key]})
        if tunnel["local_private"] not in actual_addresses:
            status["drift"].append({"field": "local_private", "desired": tunnel["local_private"],
                                    "actual": actual_addresses})
        for address in actual_addresses:
            if address != tunnel["local_private"] and ":" not in address:
                status["drift"].append({"field": "extra_address", "desired": None, "actual": address})
        if not actual["up"]:
            status["reason"] = "GRE interface is administratively down."
        elif not probe:
            status.update(health="degraded", reason="GRE interface is up; peer reachability has not been probed.")
        else:
            command = ["ping", "-n", "-I", _ip(tunnel["local_private"]), "-c", "3", "-W", "1",
                       _ip(tunnel["remote_private"])]
            try:
                evidence = self.run(command, check=False, timeout=6)
                status.update(parse_ping(evidence))
                status["peer_reachable"] = (status["loss_percent"] is not None and status["loss_percent"] < 100)
            except HostError as exc:
                status.update(health="degraded", reason=str(exc))
        if status["drift"] and status["health"] == "up":
            status.update(health="degraded", reason="GRE peer responds, but live configuration has drifted.")
        return status

    def tcp_probe(self, address: str, port: int, timeout: float = 2) -> dict[str, Any]:
        started = time.monotonic()
        try:
            with socket.create_connection((address, port), timeout=timeout):
                pass
            return {"reachable": True, "latency_ms": round((time.monotonic() - started) * 1000, 3)}
        except OSError as exc:
            return {"reachable": False, "error": str(exc)}

    @staticmethod
    def _port_range(value: Any) -> range:
        parts = str(value).split("-", 1)
        start, end = int(parts[0]), int(parts[-1])
        return range(start, end + 1)

    def forward_status(self, entry: dict[str, Any], tunnel: dict[str, Any],
                       probe: bool = True, group_running: bool | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {"name": entry["name"], "mode": entry["mode"],
                                  "health": "down", "reason": "Forwarding is stopped.", "issues": [],
                                  "destination": {"reachable": None}, "drift": []}
        tunnel_state = self.tunnel_status(tunnel, probe=probe)
        result["tunnel"] = tunnel_state
        running = bool(entry.get("running", entry.get("enabled", True)))
        if not running:
            side = entry.get("side", tunnel.get("side", "vps1"))
            try:
                if entry["mode"] == "rathole":
                    unit = self.unit_status(entry.get("unit", unit_name(entry)))
                    result["unit"] = unit
                    if unit["active"] and ("rathole_group" not in entry or group_running is False):
                        result["drift"].append({"field": "rathole_unit", "desired": "inactive", "actual": "active"})
                    if side == "vps1":
                        owned = [item for item in self.listeners() if item.get("managed") == group_name(entry)
                                 and item.get("protocol") == entry["protocol"]
                                 and item.get("port") in self._port_range(entry["bind_port"])]
                        result["public_listener"] = bool(owned)
                        if owned:
                            result["drift"].append({"field": "public_listener", "desired": "absent", "actual": "owned listener remains"})
                else:
                    snapshot = self.nft_snapshot()
                    result["firewall_available"] = snapshot.get("available", True)
                    for item in snapshot.get("nftables", []):
                        rule = item.get("rule", {})
                        if rule.get("family") == "ip" and rule.get("table") == "twinlink" and str(rule.get("comment", "")).startswith("twinlink:" + entry["name"] + ":"):
                            result["drift"].append({"field": rule["comment"], "desired": "absent", "actual": "managed rule remains"})
                    if not result["firewall_available"]:
                        result["issues"].append("firewall_unknown")
                if result["drift"]:
                    result.update(health="degraded", reason="Forwarding is configured stopped, but managed resources remain active; reapply or diagnose this entry.")
                    result["issues"].append("stopped_forward_exposed")
                elif result["issues"]:
                    result.update(health="degraded", reason="Forwarding is configured stopped; live exposure could not be inspected.")
            except HostError as exc:
                result.update(health="degraded", reason="Forwarding is configured stopped; inspection failed: " + str(exc))
                result["issues"].append("inspection_failed")
            return result
        if tunnel_state["health"] == "down":
            result.update(reason="Tunnel failure: " + tunnel_state["reason"])
            result["issues"].append("tunnel_failure")
            return result
        if tunnel_state.get("peer_reachable") is not True:
            result["issues"].append("tunnel_unverified")
        side = entry.get("side", tunnel.get("side", "vps1"))
        if entry["mode"] == "rathole":
            unit = self.unit_status(entry.get("unit", unit_name(entry)))
            result["unit"] = unit
            if not unit["active"]:
                result["issues"].append("rathole_unit_failure")
            try:
                connections = self.connections()
                server_address = _ip(tunnel["local_private"] if side == "vps1" else tunnel["remote_private"])
                port = int(entry["transport_port"])
                connected = any((item["address"] == server_address and item["port"] == port)
                                or (item["peer_address"] == server_address and item["peer_port"] == port)
                                for item in connections)
                result["rathole_connected"] = connected
                if not connected:
                    result["issues"].append("rathole_connection_failure")
            except HostError as exc:
                result["issues"].append("rathole_connection_unknown")
                result["connection_error"] = str(exc)
            if side == "vps1":
                try:
                    listeners = self.listeners()
                    ports = self._port_range(entry["bind_port"])
                    listening = all(any(item["protocol"] == entry["protocol"] and item["port"] == port
                                        and item["address"] in {entry["bind_address"], "*", "0.0.0.0", "::"}
                                        for item in listeners) for port in ports)
                    result["public_listener"] = listening
                    if not listening:
                        result["issues"].append("missing_public_listener")
                except HostError as exc:
                    result["issues"].append("public_listener_unknown")
                    result["listener_error"] = str(exc)
        elif entry["mode"] == "kernel":
            snapshot = self.nft_snapshot()
            result["firewall_available"] = snapshot.get("available", True)
            if not result["firewall_available"]:
                result["issues"].append("firewall_unknown")
                result["firewall_error"] = snapshot.get("error")
            else:
                result["drift"] = self.kernel_forward_drift(entry, tunnel, snapshot)
                if result["drift"]:
                    missing = any(item.get("actual") in (0, "missing") for item in result["drift"])
                    result["issues"].append("missing_firewall_rule" if missing else "firewall_rule_drift")
        if side == "vps2":
            if entry["protocol"] == "udp":
                result["destination"] = {"reachable": None,
                                         "reason": "UDP reachability requires a protocol-aware end-to-end request."}
                result["issues"].append("udp_destination_unknown")
            elif probe:
                ports = self._port_range(entry["destination_port"])
                # Probe the first and last endpoints of ranges to keep checks bounded.
                checks = [{"port": port, **self.tcp_probe(entry["destination_address"], port)}
                          for port in sorted({ports.start, ports.stop - 1})]
                result["destination"] = {"reachable": all(item["reachable"] for item in checks),
                                         "checks": checks,
                                         "range_sampled": len(ports) > 2}
                if not result["destination"]["reachable"]:
                    result["issues"].append("destination_unreachable")
                elif len(ports) > 2:
                    result["issues"].append("destination_range_sampled")
            else:
                result["issues"].append("destination_unverified")
        else:
            result["destination"] = {"reachable": None,
                                     "reason": "Destination reachability must be checked on VPS2."}
        hard = {"rathole_unit_failure", "rathole_connection_failure", "missing_public_listener",
                "missing_firewall_rule", "firewall_rule_drift", "destination_unreachable"}
        if hard.intersection(result["issues"]):
            result["health"] = "down"
        elif result["issues"] or tunnel_state["health"] != "up" or side == "vps1":
            result["health"] = "degraded"
        else:
            result["health"] = "up"
        descriptions = {"tunnel_unverified": "GRE peer reachability is unverified",
                        "rathole_unit_failure": "rathole systemd unit is inactive or missing",
                        "rathole_connection_failure": "rathole has no established private GRE transport connection",
                        "missing_public_listener": "public service listener is missing",
                        "missing_firewall_rule": "managed forwarding firewall rule is missing",
                        "firewall_rule_drift": "managed forwarding firewall rules differ from the desired configuration",
                        "destination_unreachable": "destination TCP service is unreachable",
                        "destination_range_sampled": "destination range endpoints respond; interior ports have not been probed",
                        "udp_destination_unknown": "UDP destination reachability is unknown",
                        "destination_unverified": "destination reachability is unverified"}
        result["reason"] = "; ".join(descriptions.get(issue, issue.replace("_", " "))
                                         for issue in result["issues"])
        if not result["reason"]:
            result["reason"] = ("Local forwarding checks passed; run check on VPS2 and send an external request to verify end to end."
                                if side == "vps1" else "GRE and local forwarding checks passed; end-to-end traffic is not yet proven.")
        return result

    def _evidence(self, argv: list[str], timeout: float = 10) -> dict[str, Any]:
        try:
            return {"command": argv, **self.run(argv, check=False, timeout=timeout)}
        except HostError as exc:
            return {"command": argv, "returncode": 126, "stdout": "", "stderr": str(exc)}

    def diagnose_tunnel(self, tunnel: dict[str, Any]) -> dict[str, Any]:
        source, peer = _ip(tunnel["local_private"]), _ip(tunnel["remote_private"])
        unit = tunnel.get("unit", f"twinlink-gre-{tunnel['name']}.service")
        commands = [
            ["ip", "-j", "-d", "link", "show", "dev", tunnel["interface"]],
            ["ip", "-j", "addr", "show", "dev", tunnel["interface"]],
            ["ip", "-j", "route", "get", peer, "from", source],
            ["ping", "-n", "-I", source, "-c", "3", "-W", "1", peer],
            ["ping", "-n", "-I", source, "-M", "do", "-s", str(max(0, int(tunnel.get("mtu", 1476)) - 28)),
             "-c", "2", "-W", "1", peer],
            ["tracepath", "-n", "-m", "8", peer],
            ["systemctl", "show", unit, "--no-pager"],
            ["systemctl", "cat", unit, "--no-pager"],
            ["journalctl", "-u", unit, "--no-pager", "-n", "60"],
        ]
        return redact({"name": tunnel["name"], "status": self.tunnel_status(tunnel),
                       "evidence": [self._evidence(command) for command in commands]})

    def diagnose_forward(self, entry: dict[str, Any], tunnel: dict[str, Any],
                         config_path: str | None = None, group_running: bool | None = None) -> dict[str, Any]:
        unit = entry.get("unit", unit_name(entry))
        commands = [["ss", "-H", "-lntu"], ["ss", "-H", "-nt", "state", "established"],
                    ["nft", "-j", "list", "ruleset"]]
        if entry["mode"] == "rathole":
            commands += [["systemctl", "show", unit, "--no-pager"],
                         ["systemctl", "cat", unit, "--no-pager"],
                         ["journalctl", "-u", unit, "--no-pager", "-n", "60"]]
        result = {"name": entry["name"], "status": self.forward_status(entry, tunnel, group_running=group_running),
                  "tunnel": self.diagnose_tunnel(tunnel),
                  "evidence": [self._evidence(command) for command in commands]}
        if config_path:
            try:
                result["generated_config"] = Path(config_path).read_text()
            except OSError as exc:
                result["generated_config_error"] = str(exc)
        return redact(result, (str(entry.get("token", "")), str(entry.get("noise_private_key", ""))))
