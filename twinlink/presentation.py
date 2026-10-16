"""Terminal presentation only; detailed payloads remain owned by their producers."""
import json
import os
import re
import sys

from .engine import redacted
from .rathole_groups import groups


def style(text, status="title", stream=None):
    stream = stream or sys.stdout
    if not stream.isatty() or os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return text
    color = {"title": "1;36", "up": "32", "success": "32", "down": "31", "failure": "31",
             "degraded": "33", "warning": "33"}.get(status)
    return f"\033[{color}m{text}\033[0m" if color else text


def prompt(label, default=None):
    return label + (f" [{default}]" if default is not None else "") + ": "


def endpoints(record):
    if "remote_public" in record:
        return f"Peer: {record['remote_public']} | GRE: {record['local_private']} -> {record['remote_private']}"
    return (f"{record.get('protocol', 'tcp').upper()} {record.get('bind_address', '*')}:{record.get('bind_port', '?')} -> "
            f"{record.get('destination_address', '?')}:{record.get('destination_port', '?')} | {record.get('mode', 'unknown').title()}")


def changed_settings(before, after):
    """Describe initial or changed public settings, excluding credentials/metadata."""
    fields = (("side", "Server role"), ("local_public", "Local public endpoint"),
              ("remote_public", "Peer public endpoint"), ("local_private", "Local GRE address"),
              ("remote_private", "Peer GRE address"), ("key", "GRE key"),
              ("mtu", "MTU"), ("ttl", "TTL"), ("tunnel", "Tunnel"), ("mode", "Method"),
              ("protocol", "Protocol"), ("bind_address", "Public bind address"),
              ("bind_port", "Public port"), ("destination_address", "Backend address"),
              ("destination_port", "Backend port"), ("relay_port", "Relay port"),
              ("transport_port", "Rathole transport port"),
              ("rathole_transport", "Rathole transport"), ("rathole_group", "Rathole group"))
    defaults = {"rathole_transport": "tcp"}
    initial = before is None
    before = before or {}
    endpoint_fields = {"remote_public", "local_private", "remote_private", "protocol", "mode",
                       "bind_address", "bind_port", "destination_address", "destination_port"}
    lines = []
    for field, label in fields:
        previous = before.get(field, defaults.get(field))
        current = after.get(field, defaults.get(field))
        if initial:
            if field not in endpoint_fields and (field in after or
                    (field == "rathole_transport" and after.get("mode") == "rathole")):
                lines.append(f"{label}: {current if current is not None else 'none'}")
        elif previous != current:
            lines.append(f"    {label}: {previous if previous is not None else 'none'} -> "
                         f"{current if current is not None else 'none'}")
    if initial:
        return ["    " + " | ".join(lines[index:index + 3]) for index in range(0, len(lines), 3)]
    return lines


def tunnel_setup_action(action, record, existing):
    name = record["name"]
    if action == "pair-import":
        pairing = "confirm the source server has the matching GRE configuration"
    else:
        replace = " --name <peer-local-name> --replace" if existing else ""
        pairing = (f"export {'fresh ' if existing else ''}GRE pairing text with sudo twinlink tunnel pair-export {name}; "
                   f"import it on the peer with sudo twinlink tunnel pair-import --file <pairing-file>{replace} --apply")
    start = (f"start the tunnel with sudo twinlink tunnel start {name} --apply on both hosts; "
             if not record.get("running") else "ensure the matching tunnel is running on both hosts; ")
    return (f"{pairing}; {start}then run sudo twinlink tunnel check {name} --record --apply "
            "on both hosts (using each host's local tunnel name).")


def peer_update_action(names):
    name = names[0] if len(names) == 1 else "NAME"
    each = " for each listed forwarding entry" if len(names) > 1 else ""
    return (f"export fresh pairing text with sudo twinlink forward pair-export {name}{each}; "
            f"import it on the peer, then run sudo twinlink forward enable {name} --apply on both hosts.")


def record_lines(item, compact=False):
    record, observed = item.get("configuration", {}), item.get("operational", {})
    health = observed.get("health", "unknown")
    title = style(f"{record.get('name', '?')}: {health}", health)
    if compact:
        lines = ["  " + title + " | " + endpoints(record)]
        if health != "up" and observed.get("reason"):
            lines.append("    " + observed["reason"])
        if item.get("peer_transfer_required"):
            lines.append("    Peer setup required; transfer matching configuration.")
        return lines
    lines = [title, "  " + endpoints(record),
             "  Saved intent: " + ("running" if record.get("running") else "stopped") + "; " +
             ("enabled at boot" if record.get("enabled") else "disabled at boot")]
    if observed.get("reason"):
        lines.append("  " + observed["reason"])
    if item.get("peer_transfer_required"):
        lines.append("  Peer setup required; transfer the matching forwarding configuration.")
    return lines


def render(value, context, phase=None, old=None, candidate=None, affected=None):
    """Render an explicit command family, never infer operations from payload keys."""
    group, action, name = context
    label = " ".join(part for part in (action, group, name) if part)
    if isinstance(value, dict) and "error" in value:
        # Strip serialized diagnostic objects after a reason, preserving ordinary
        # brackets such as the leading [Errno 13] in OS errors and file paths.
        summary = re.split(r":\s*(?=\[\s*\{|\{\s*[\"'])", value["error"], maxsplit=1)[0]
        reason = (summary.splitlines() or ["Operation failed; inspect status before retrying."])[0]
        lines = [style("Cancelled" if "Cancelled" in value["error"] else "Failed", "failure", sys.stderr), "  " + reason]
        if value.get("rollback_errors"):
            lines += [style("  Rollback incomplete; unfinished transaction requires recovery.", "failure", sys.stderr), "Next: run sudo twinlink recover --apply."]
        elif "rollback completed" in value["error"]:
            lines.append("  Rollback completed.")
        if reason != value["error"] and not value.get("rollback_errors"):
            lines.append("Next: use --verbose for technical details; inspect status before retrying.")
        return lines
    if phase in ("preview", "applied") and candidate is not None:
        lines = [style(("Preview: " if phase == "preview" else "Applied: ") + label, "title" if phase == "preview" else "success")]
        if affected is None:
            affected = tuple({n for n in old[key].keys() | candidate[key].keys() if old[key].get(n) != candidate[key].get(n)} for key in ("tunnels", "forwards"))
        for key, names in zip(("tunnels", "forwards"), affected):
            after = candidate[key]
            for resource in sorted(names):
                record = after.get(resource)
                if record is None:
                    lines.append("  Delete " + key[:-1] + " " + resource)
                else:
                    lines.append("  " + resource + " | " + endpoints(record))
                    lines.extend(changed_settings(old[key].get(resource), record))
                    lines += ["  " +
                              ("Start now" if record.get("running") else "Stop now") + "; " +
                              ("enable at boot" if record.get("enabled") else "disable at boot")]
        for shared, entries in sorted(groups(candidate).items()):
            if any(e["name"] in affected[1] for e in entries) and any(e["running"] for e in entries):
                lines.append("  Shared Rathole service restart: " + shared + " (" + ", ".join(e["name"] for e in entries) + ")")
        if any(old["forwards"].get(n, {}).get("mode") == "kernel" and old["forwards"][n].get("running") for n in affected[1]):
            lines.append("  Existing connections on affected Kernel forwards will end.")
        peer_updates = sorted(n for n in affected[1] if n in old["forwards"] and n in candidate["forwards"]
                              and old["forwards"][n].get("revision") != candidate["forwards"][n].get("revision")
                              and candidate["forwards"][n].get("peer_revision") != candidate["forwards"][n].get("revision"))
        if peer_updates:
            lines.append(style("  Peer update required: " + ", ".join(peer_updates), "warning"))
        tunnel_setup = []
        if group == "tunnel" and action in ("create", "pair-import", "edit"):
            for tunnel_name in sorted(affected[0]):
                record = candidate["tunnels"].get(tunnel_name)
                if record and not record.get("verified"):
                    lines.append(style("  GRE unverified: " + tunnel_name + "; forwarding requires recorded verification.", "warning"))
                    tunnel_setup.append(tunnel_setup_action(action, record, tunnel_name in old["tunnels"]))
        if phase == "preview":
            if peer_updates:
                lines.append("  After applying: " + peer_update_action(peer_updates))
            for guidance in tunnel_setup:
                lines.append("  After applying: " + guidance)
            lines.append("No changes applied. Repeat with --apply.")
        else:
            lines.append("  Configuration committed; connectivity not verified.")
            if value.get("pending_peer"):
                lines.append("  Pending peer: " + ", ".join(value["pending_peer"]))
            if value.get("pairing_code"):
                lines += ["Pairing code:", value["pairing_code"], "  Transfer privately; Rathole codes contain service tokens.", "Next: run sudo twinlink forward setup on the peer."]
            elif peer_updates:
                lines.append("Next: " + peer_update_action(peer_updates))
            elif tunnel_setup:
                lines.append("Next: " + " ".join(tunnel_setup))
            else:
                lines.append("Next: " + value.get("next", "run sudo twinlink status and check the affected resources."))
        return lines
    if group == "status" or action == "list":
        lines = [style("Status" if group == "status" else group.title() + " list")]
        if group == "status" and value.get("unfinished_transaction"):
            lines += [style("  Unfinished transaction; recover before making changes.", "warning"), "Next: run sudo twinlink recover --apply."]
        sections = (("tunnels", value["tunnels"]), ("forwards", value["forwards"])) if group == "status" else ((group + "s", value),)
        empty_action = None
        for title, items in sections:
            lines.append(f"{title.title()}: {len(items)}")
            for item in items:
                lines.extend(record_lines(item, compact=True))
            if not items and empty_action is None:
                empty_action = "tunnel create --help" if title == "tunnels" else "forward setup"
        if empty_action and not (group == "status" and value.get("unfinished_transaction")):
            lines.append("Next: run sudo twinlink " + empty_action + ".")
        return lines
    if action in ("show", "check"):
        return record_lines(value)
    if action == "diagnose":
        status = value.get("status", {})
        lines = [style(f"Diagnosis: {name} | {status.get('health', 'unknown')}", status.get("health")), "  " + status.get("reason", "Health unknown; run check on both peers.")]
        for issue in status.get("issues", []):
            if isinstance(issue, str):
                lines.append("  " + issue.replace("_", " "))
        for check in value.get("evidence", []):
            if check.get("returncode"):
                command = check.get("command", ["check"])
                lines.append("  Failed/unknown check: " + command[0] + "; inspect with --verbose.")
        tunnel_status = value.get("tunnel", {}).get("status", {})
        if tunnel_status and tunnel_status.get("health") != "up":
            lines.append("  GRE: " + tunnel_status.get("health", "unknown") + "; " + tunnel_status.get("reason", "Check the GRE peer."))
        lines.append(f"Next: run sudo twinlink {group} check {name}; use --verbose for evidence.")
        return lines
    if group == "doctor":
        missing = value.get("missing_required", [])
        lines = [style("Dependency check")]
        if value.get("platform") != "Linux":
            lines.append("  Linux is required.")
        if not value.get("systemd_runtime"):
            lines.append("  systemd runtime unavailable; run on a host with systemd.")
        lines.extend("  Missing required dependency: " + item for item in missing)
        lines.append("Next: install missing dependencies and rerun sudo twinlink doctor." if missing else "  Required dependency checks complete; use --verbose for inventory.")
        return lines
    if group == "recover":
        pending = value.get("pending", value.get("recovered"))
        return [style("Recovery: " + ("completed" if value.get("recovered") else "pending" if pending else "no unfinished transaction")),
                "  Restore saved configuration, managed files and network resources." if pending and phase != "applied" else "  Recovery state inspected.",
                "Next: run sudo twinlink recover --apply --yes." if pending and phase != "applied" else "  Inspect status before continuing."]
    if action == "config":
        return [style("Rathole config: " + name), "  " + value["path"], "  " + value["note"], "Next: " + value["edit_with_nano"]]
    if action == "export":
        return [style("Exported: " + value["exported"], "success"), "  Private transfer required. " + value["transfer"]]
    if action in ("install", "install-rathole"):
        return [style("Rathole installation: " + ("already installed" if value.get("already_installed") else "preview" if phase == "preview" else "completed")),
                "  " + str(value.get("path", value.get("binary", ""))),
                "No changes applied. Repeat with --apply." if phase == "preview" else "Next: run sudo twinlink forward setup."]
    if group == "uninstall":
        return [style("Uninstall: managed resources retained"), "  Tunnels: " + ", ".join(value["managed_tunnels"]),
                "  Forwards: " + ", ".join(value["managed_forwards"]), "Next: " + value["program_only"], "  " + value["purge"]]
    raise ValueError("Missing presentation for " + group + " " + action)


def output(value, as_json=False, *, verbose=False, context=None, phase=None, old=None, candidate=None, affected=None):
    value = redacted(value)
    if as_json or verbose or context is None:
        stream = sys.stderr if context is not None and not as_json and isinstance(value, dict) and "error" in value else sys.stdout
        print(json.dumps(value, indent=2, sort_keys=True) if not isinstance(value, str) or as_json else value, file=stream)
        return
    stream = sys.stderr if isinstance(value, dict) and "error" in value else sys.stdout
    for line in render(value, context, phase, redacted(old), redacted(candidate), affected):
        print(line, file=stream)
