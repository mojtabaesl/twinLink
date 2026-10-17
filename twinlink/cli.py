"""Scriptable CLI and interactive operator menu."""
import argparse
import copy
import json
import os
from pathlib import Path
import platform
import shlex
import sys

from . import __version__
from .engine import ApplyError, Engine, redacted
from .host import Host, HostError
from .models import ValidationError, validate_tunnel, validate_forward
from . import pairing, rathole
from .presentation import output
from .render import rathole_config_path
from .rathole_groups import group_name, groups
from .store import Store, StateError, reject_symlink


LIFECYCLE = ("enable", "disable", "start", "stop", "restart", "reapply", "delete")
TUNNEL_FIELDS = ("side", "local_public", "remote_public", "local_private", "remote_private", "key", "mtu", "ttl")
FORWARD_FIELDS = ("tunnel", "mode", "protocol", "bind_address", "bind_port", "destination_address", "destination_port", "relay_port", "transport_port", "rathole_transport", "rathole_group")


def mutation_flags(parser):
    parser.add_argument("--apply", action="store_true", help="Apply this preview after validation (default: preview only)")
    parser.add_argument("--yes", action="store_true", help="Skip the apply confirmation; requires --apply")
    parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="Machine-readable output")


def build_parser():
    parser = argparse.ArgumentParser(prog="twinlink", description="Two steps: create a GRE tunnel, then forward ports using Kernel or Rathole. Run 'twinlink menu' for guided setup. Mutations preview unless --apply is supplied.")
    parser.add_argument("--version", action="version", version="twinlink " + __version__)
    parser.add_argument("--json", action="store_true", help="Machine-readable output; secrets are redacted")
    parser.add_argument("--state-dir", default="/var/lib/twinlink", help="Private configuration and journal directory")
    parser.add_argument("--unit-dir", default="/etc/systemd/system", help="Managed unit directory")
    parser.add_argument("--runtime-path", default="/usr/local/libexec/twinlink-runtime", help="Absolute installed runtime used by units")
    parser.add_argument("--rathole-binary", default="/usr/local/bin/rathole", help="Rathole 0.5.0 executable/install path")
    parser.add_argument("--paqet-binary", default="/usr/local/bin/paqet", help="Pinned prepared Paqet executable path")
    parser.add_argument("--no-systemd", action="store_true", help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="group", required=True)
    from .v2_cli import register
    register(commands, mutation_flags)
    for group in ("tunnel", "forward"):
        group_parser = commands.add_parser(group, help="1. Create and manage GRE tunnels" if group == "tunnel" else "2. Set up and manage port forwarding (Kernel or Rathole)")
        actions = group_parser.add_subparsers(dest="action", required=True)
        for action in ("list", "show", "check", "diagnose"):
            leaf = actions.add_parser(action)
            if action != "list":
                leaf.add_argument("name")
            leaf.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
            if action in ("list", "show"):
                leaf.add_argument("--no-probe", action="store_true", help="Skip peer probe; reachability remains unknown")
            if action == "check" and group == "tunnel":
                leaf.add_argument("--record", action="store_true", help="Record successful peer verification (requires --apply)")
                leaf.add_argument("--apply", action="store_true")
                leaf.add_argument("--yes", action="store_true")
        for action in LIFECYCLE:
            leaf = actions.add_parser(action)
            leaf.add_argument("name")
            if action == "delete" and group == "tunnel":
                choice = leaf.add_mutually_exclusive_group()
                choice.add_argument("--cascade", action="store_true", help="Delete the listed dependent forwarding entries")
                choice.add_argument("--no-cascade", action="store_true", help="Refuse deletion if any forwarding entries exist")
            mutation_flags(leaf)
        for action in (("create", "edit") if group == "tunnel" else ("add", "edit")):
            leaf = actions.add_parser(action)
            leaf.add_argument("name")
            fields = TUNNEL_FIELDS if group == "tunnel" else FORWARD_FIELDS
            for field in fields:
                kwargs = {"type": int} if field in ("key", "mtu", "ttl", "transport_port") else {}
                if field == "side":
                    kwargs["choices"] = ("vps1", "vps2")
                elif field == "mode":
                    kwargs["choices"] = ("kernel", "rathole")
                elif field == "protocol":
                    kwargs["choices"] = ("tcp", "udp")
                elif field == "rathole_transport":
                    kwargs["choices"] = ("noise", "tcp")
                required = action in ("create", "add") and field in (("side", "local_public", "remote_public", "local_private", "remote_private") if group == "tunnel" else ("tunnel", "mode"))
                leaf.add_argument("--" + field.replace("_", "-"), required=required, **kwargs)
            if group == "forward" and action == "add":
                leaf.add_argument("--ports", help="Rathole: PUBLIC:BACKEND pairs in one shared config, e.g. 8080:80,8443:443")
            if action in ("create", "add"):
                leaf.add_argument("--disabled", action="store_true", help="Create a stopped entry, disabled at boot")
            if group == "tunnel" and action == "edit":
                leaf.add_argument("--clear-key", action="store_true")
            mutation_flags(leaf)
        if group == "tunnel":
            export = actions.add_parser("pair-export", help="Export GRE only; never forwarding secrets")
            export.add_argument("name")
            export.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
            imp = actions.add_parser("pair-import", help="Decode, swap sides, and preview before applying")
            source = imp.add_mutually_exclusive_group(required=True)
            source.add_argument("--code")
            source.add_argument("--file")
            imp.add_argument("--name")
            imp.add_argument("--replace", action="store_true", help="Replace an existing named tunnel; stop dependent entries")
            mutation_flags(imp)
        else:
            setup = actions.add_parser("setup", help="Guided port forwarding: choose Kernel or Rathole; reuse saved GRE details")
            setup.add_argument("--mode", choices=("kernel", "rathole"), help="Preselect the forwarding method")
            setup.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
            menu = actions.add_parser("menu", help="Open the forwarding menu")
            menu.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
            config = actions.add_parser("config", help="Print Rathole config paths/editor commands without opening files")
            config.add_argument("name")
            config.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
            install = actions.add_parser("install-rathole", help="Install the optional Rathole forwarding engine (setup handles this automatically)")
            install.add_argument("--sha256")
            mutation_flags(install)
            combine = actions.add_parser("consolidate", help="Combine Rathole forwards on one tunnel into one config/process")
            combine.add_argument("name", help="Shared Rathole name")
            combine.add_argument("--tunnel", required=True)
            combine.add_argument("--transport-port", type=int, default=2333)
            mutation_flags(combine)
            export = actions.add_parser("pair-export", help="Print a pairing code for Kernel forwarding or a Rathole config")
            export.add_argument("names", nargs="+")
            export.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
            imp = actions.add_parser("pair-import", help="Detect Kernel/Rathole pairing text and preview the peer forwarding")
            source = imp.add_mutually_exclusive_group(required=True)
            source.add_argument("--code")
            source.add_argument("--file")
            imp.add_argument("--enable", action="store_true", help="Start imported forwarding and enable at boot")
            mutation_flags(imp)
            export = actions.add_parser("export", help="Explicit secret export to a new private file")
            export.add_argument("name")
            export.add_argument("--output", required=True)
            export.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
            imp = actions.add_parser("import", help="Import a matching forwarding configuration received securely")
            imp.add_argument("--file", required=True)
            imp.add_argument("--name")
            mutation_flags(imp)
    rathole_parser = commands.add_parser("rathole", help="Compatibility commands; use 'forward setup' for Kernel or Rathole")
    rathole_actions = rathole_parser.add_subparsers(dest="action", required=True)
    install = rathole_actions.add_parser("install", help="Install the pinned official release; reuse a compatible binary")
    install.add_argument("--sha256", help="Optional trusted SHA256 of the release ZIP archive")
    mutation_flags(install)
    setup = rathole_actions.add_parser("setup", help="Guided installation, ports, Noise credentials and base64 pairing")
    setup.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    config = rathole_actions.add_parser("config", help="Print config paths/editor commands without launching an editor")
    config.add_argument("name")
    config.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    add = rathole_actions.add_parser("add", help="Create one or more Noise forwards in one transaction on VPS1")
    add.add_argument("name", help="Shared Rathole configuration/process name")
    add.add_argument("--tunnel", required=True)
    add.add_argument("--ports", required=True, help="PUBLIC:DESTINATION pairs, e.g. 8080:80,8443:443; 9000 keeps the same port")
    add.add_argument("--destination-address", default="127.0.0.1")
    add.add_argument("--bind-address")
    add.add_argument("--transport-port", type=int, help="Shared Rathole connection port (default 2333, or reuse the existing group port)")
    add.add_argument("--disabled", action="store_true")
    mutation_flags(add)
    combine = rathole_actions.add_parser("consolidate", help="Combine saved Rathole forwards on one tunnel into one config/process")
    combine.add_argument("name", help="Shared Rathole name")
    combine.add_argument("--tunnel", required=True)
    combine.add_argument("--transport-port", type=int, default=2333)
    mutation_flags(combine)
    export = rathole_actions.add_parser("pair-export", help="Explicitly print a base64 pairing code containing service tokens")
    export.add_argument("names", nargs="+")
    export.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    imp = rathole_actions.add_parser("pair-import", help="Import a base64 Rathole pairing code")
    source = imp.add_mutually_exclusive_group(required=True)
    source.add_argument("--code")
    source.add_argument("--file")
    imp.add_argument("--enable", action="store_true", help="Start imported forwards and enable at boot")
    mutation_flags(imp)
    for name in ("doctor", "status", "menu"):
        leaf = commands.add_parser(name)
        leaf.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        if name in ("doctor", "status"):
            leaf.add_argument("--pair")
        if name == "doctor":
            leaf.add_argument("--deep", action="store_true")
            leaf.add_argument("--watch")
            leaf.add_argument("--interval", type=float, default=1)
            leaf.add_argument("--capture", action="store_true")
            leaf.add_argument("--capture-interface")
            leaf.add_argument("--capture-peer")
            leaf.add_argument("--capture-port", type=int)
            leaf.add_argument("--capture-direction", choices=("in", "out", "inout"), default="inout")
            leaf.add_argument("--preview", action="store_true")
            leaf.add_argument("--redaction", choices=("share", "secrets"), default="share")
            leaf.add_argument("--export")
            leaf.add_argument("--merge", nargs=2)
            leaf.add_argument("--compare")
    recover = commands.add_parser("recover", help="Roll back an interrupted journalled transaction")
    recover.add_argument("--pair")
    recover.add_argument("--rollback", action="store_true", help="Coordinate v2 rollback through both-host quiescence")
    recover.add_argument("--cancel-preflight", action="store_true")
    recover.add_argument("--receipt-file")
    recover.add_argument("--output")
    recover.add_argument("--step")
    recover.add_argument("--transaction")
    recover.add_argument("--refresh-receipt", action="store_true")
    mutation_flags(recover)
    uninstall = commands.add_parser("uninstall", help="Preview resource removal; program-only removal is scripts/uninstall.sh")
    uninstall.add_argument("--pair")
    uninstall.add_argument("--plan", action="store_true")
    uninstall.add_argument("--purge", action="store_true")
    uninstall.add_argument("--purge-managed", action="store_true", help="Delete every managed tunnel and forwarding entry")
    uninstall.add_argument("--cascade", action="store_true")
    mutation_flags(uninstall)
    internal = commands.add_parser("internal", help="Boot callbacks used by managed units")
    internal.add_argument("operation", choices=("restore", "tunnel-up", "tunnel-down", "profile-guard", "verification-expire"))
    internal.add_argument("name", nargs="?")
    internal.add_argument("--profile", choices=("gre-kernel", "gre-rathole", "direct-rathole", "direct-paqet"))
    internal.add_argument("--revision", type=int)
    def add_verbose(current):
        current.add_argument("--verbose", action="store_true", default=argparse.SUPPRESS,
                             help="Detailed redacted output (--json takes precedence)")
        for entry in current._actions:
            if isinstance(entry, argparse._SubParsersAction):
                for child in entry.choices.values():
                    add_verbose(child)
    add_verbose(parser)
    return parser


def _read_transfer(path, secret=False):
    target = Path(path).absolute()
    reject_symlink(target)
    if not target.is_file() or target.stat().st_size > pairing.MAX_CODE_SIZE:
        raise ValidationError("Transfer file is missing, not a regular file, or exceeds the size limit")
    if secret and target.stat().st_mode & 0o077:
        raise ValidationError("Forwarding transfer contains credentials; chmod 600 " + str(target))
    return target.read_text().strip()


def _get(state, group, name):
    key = "tunnels" if group == "tunnel" else "forwards"
    try:
        return state[key][name]
    except KeyError:
        raise ValidationError(f"Unknown {group} {name!r}") from None


def _stop_dependents(state, name, disable=False):
    for entry in state["forwards"].values():
        if entry["tunnel"] == name:
            entry["running"] = False
            if disable:
                entry["enabled"] = False


def _forward_command(args):
    """Reuse the Rathole implementation behind the public forwarding commands."""
    if args.group != "forward":
        return args
    action = getattr(args, "action", "")
    if action == "add":
        if getattr(args, "ports", None) is None:
            missing = [field for field in ("bind_port", "destination_address", "destination_port")
                       if getattr(args, field, None) is None]
            if missing:
                raise ValidationError("Forward add requires " + ", ".join("--" + field.replace("_", "-") for field in missing) + "; Rathole can instead use --ports PUBLIC:BACKEND")
            return args
        if args.mode != "rathole":
            raise ValidationError("Kernel forwarding uses --bind-port and --destination-port (single ports or ranges); --ports is for Rathole")
        if any(getattr(args, field, None) is not None for field in ("bind_port", "destination_port", "relay_port", "rathole_group")):
            raise ValidationError("Use the forwarding NAME and --ports for a shared Rathole config; omit --bind-port, --destination-port, --relay-port and --rathole-group")
        if getattr(args, "protocol", None) not in (None, "tcp") or getattr(args, "rathole_transport", None) not in (None, "noise"):
            raise ValidationError("Shared Rathole forwarding uses TCP with Noise")
        return argparse.Namespace(**{**vars(args), "group": "rathole", "destination_address": args.destination_address or "127.0.0.1"})
    aliases = {"config": "config", "install-rathole": "install", "consolidate": "consolidate"}
    if action in aliases:
        return argparse.Namespace(**{**vars(args), "group": "rathole", "action": aliases[action]})
    return args


def prepare(args, old):
    """Prepare desired state; native key generation changes no networking/files."""
    args = _forward_command(args)
    new = copy.deepcopy(old)
    group, action = args.group, getattr(args, "action", "")
    if group == "forward" and action == "pair-import":
        code = (args.code if args.code is not None else _read_transfer(args.file, secret=True)).strip()
        records = pairing.import_rathole(code, new) if code.startswith(pairing.RATHOLE_PREFIX) else [pairing.import_forward(code, new)]
        for record in records:
            if args.enable:
                if not new["tunnels"][record["tunnel"]]["running"]:
                    raise ValidationError("Start the GRE tunnel before enabling imported forwarding")
                record.update(enabled=True, running=True)
            new["forwards"][record["name"]] = record
        return new
    if group == "rathole":
        if action == "add":
            mappings = rathole.port_mappings(args.ports)
            names = rathole.forward_names(args.name, mappings)
            members = groups(new).get(args.name, [])
            transport_port = args.transport_port if args.transport_port is not None else (members[0]["transport_port"] if members else 2333)
            for name, (public, destination) in zip(names, mappings):
                options = argparse.Namespace(**{**vars(args), "group": "forward", "action": "add", "name": name, "ports": None,
                                               "mode": "rathole", "protocol": "tcp", "rathole_transport": "noise",
                                               "rathole_group": args.name, "transport_port": transport_port,
                                               "bind_port": str(public), "destination_port": str(destination)})
                new = prepare(options, new)
            return new
        if action == "consolidate":
            entries = [entry for entry in new["forwards"].values() if entry["mode"] == "rathole" and entry["tunnel"] == args.tunnel]
            if not entries or len(entries) > 64:
                raise ValidationError("Consolidation requires 1–64 Rathole forwards on the selected tunnel")
            if new["tunnels"][args.tunnel]["side"] != "vps1":
                raise ValidationError("Consolidate on VPS1, then import the new pairing code on VPS2")
            credentials = rathole.generate_keypair(args.rathole_binary)
            selected = {entry["name"] for entry in entries}
            for name in selected:
                del new["forwards"][name]
            for entry in entries:
                entry.update(rathole_group=args.name, transport_port=args.transport_port,
                             rathole_transport="noise", revision=entry["revision"] + 1, peer_revision=None, **credentials)
                new["forwards"][entry["name"]] = validate_forward(entry, new, existing_name=entry["name"])
            return new
        if action == "pair-import":
            code = args.code if args.code is not None else _read_transfer(args.file, secret=True)
            records = pairing.import_rathole(code, new)
            for record in records:
                if args.enable:
                    if not new["tunnels"][record["tunnel"]]["running"]:
                        raise ValidationError("Start the GRE tunnel before enabling imported forwarding")
                    record.update(enabled=True, running=True)
                new["forwards"][record["name"]] = record
            return new
    if group == "uninstall":
        if not args.purge_managed:
            raise ValidationError("Program-only removal: run scripts/uninstall.sh; --purge-managed explicitly removes network resources")
        if not args.cascade and old["forwards"]:
            raise ValidationError("Purge includes forwarding entries; pass --cascade explicitly")
        new["forwards"], new["tunnels"] = {}, {}
        return new
    key = "tunnels" if group == "tunnel" else "forwards"
    if action in ("create", "add", "edit"):
        existing = _get(old, group, args.name) if action == "edit" else {}
        record = dict(existing, name=args.name)
        fields = TUNNEL_FIELDS if group == "tunnel" else FORWARD_FIELDS
        for field in fields:
            value = getattr(args, field, None)
            if value is not None:
                record[field] = value
        if action in ("create", "add"):
            record.update(enabled=not args.disabled, running=not args.disabled)
        if group == "tunnel":
            if getattr(args, "clear_key", False):
                record["key"] = None
            if action == "edit" and any(record.get(f) != existing.get(f) for f in TUNNEL_FIELDS):
                if record["side"] != existing["side"] and any(f["tunnel"] == args.name for f in new["forwards"].values()):
                    raise ValidationError("Cannot change tunnel side while forwarding entries depend on it")
                record["verified"] = False
                _stop_dependents(new, args.name, disable=True)
            value = validate_tunnel(record, new, existing_name=args.name if existing else None)
        else:
            if record.get("mode") == "rathole":
                if action == "edit" and "rathole_group" in existing and any(
                        record.get(field) != existing.get(field) for field in ("rathole_group", "transport_port", "rathole_transport")):
                    raise ValidationError("Shared Rathole name/port/transport changes require forward consolidate on VPS1, then pairing again")
                if action == "add":
                    record.setdefault("rathole_transport", "noise")
                    if record.get("rathole_group") is not None:
                        members = groups(new).get(record["rathole_group"], [])
                        if members:
                            shared = members[0]
                            if shared["tunnel"] != record["tunnel"]:
                                raise ValidationError("This Rathole name belongs to another GRE tunnel")
                            for field in ("token", "noise_private_key", "noise_public_key"):
                                if field in shared:
                                    record[field] = shared[field]
                if record.get("rathole_transport") == "noise" and not record.get("noise_public_key"):
                    validated = validate_forward({**record, "rathole_transport": "tcp"}, new,
                                                 existing_name=args.name if existing else None)
                    if validated["side"] != "vps1":
                        raise ValidationError("Create Noise forwarding on VPS1, then import its pairing code on VPS2")
                    record["token"] = validated["token"]
                    record.update(rathole.generate_keypair(args.rathole_binary))
            if action == "edit":
                if record["tunnel"] != existing["tunnel"] or record["mode"] != existing["mode"]:
                    raise ValidationError("Tunnel association and mode are stable; delete/recreate the entry to change them")
                if any(record.get(f) != existing.get(f) for f in FORWARD_FIELDS):
                    record.update(revision=existing["revision"] + 1, enabled=False, running=False)
            value = validate_forward(record, new, existing_name=args.name if existing else None)
            tunnel = new["tunnels"][value["tunnel"]]
            if value["running"] and not tunnel["running"]:
                raise ValidationError("Start the GRE tunnel before adding active forwarding")
        new[key][args.name] = value
    elif action == "pair-import":
        code = args.code if args.code is not None else _read_transfer(args.file)
        record = pairing.import_tunnel(code, name=args.name)
        name = record["name"]
        exists = name in new["tunnels"]
        if exists and not args.replace:
            raise ValidationError("Tunnel exists; inspect preview with --replace to replace its configuration")
        record.update(enabled=True, running=True)
        new["tunnels"][name] = validate_tunnel(record, new, existing_name=name if exists else None)
        if exists:
            _stop_dependents(new, name, disable=True)
    elif action == "import":
        record = pairing.import_forward(_read_transfer(args.file, secret=True), new, name=args.name)
        new["forwards"][record["name"]] = record
    elif action in LIFECYCLE:
        record = _get(new, group, args.name)
        if action == "delete":
            if group == "tunnel":
                deps = [name for name, f in new["forwards"].items() if f["tunnel"] == args.name]
                if deps and not args.cascade:
                    raise ValidationError("Dependent forwarding entries: " + ", ".join(deps) + "; choose --cascade to remove them or --no-cascade to refuse")
                for name in deps:
                    del new["forwards"][name]
            del new[key][args.name]
        elif action in ("stop", "disable"):
            record["running"] = False
            if action == "disable":
                record["enabled"] = False
            if group == "tunnel":
                _stop_dependents(new, args.name, disable=action == "disable")
        elif action in ("start", "enable", "restart"):
            record["running"] = True
            if action == "enable":
                record["enabled"] = True
            if group == "forward" and not new["tunnels"][record["tunnel"]]["running"]:
                raise ValidationError("Start the GRE tunnel before starting forwarding")
        # reapply uses identical state but force reconciliation is handled engine-side.
    return new


def inspect_record(args, state, host, engine, record):
    try:
        if args.group == "tunnel":
            status = host.tunnel_status(record, probe=not getattr(args, "no_probe", False))
        else:
            shared_running = any(entry["running"] for entry in groups(state).get(group_name(record), [])) if record["mode"] == "rathole" else None
            status = host.forward_status(record, state["tunnels"][record["tunnel"]], probe=not getattr(args, "no_probe", False), group_running=shared_running)
            expected = state.get("_nft_fingerprint")
            if record["mode"] == "kernel" and expected and expected != engine.nft_fingerprint():
                status.setdefault("drift", []).append({"field": "nftables", "reason": "Installed table differs from the verified commit"})
                status.update(health="degraded", reason="Managed firewall rules drifted; run forward reapply " + record["name"])
        result = {"configuration": redacted(record), "operational": status,
                  "peer_transfer_required": args.group == "forward" and record.get("peer_revision") != record.get("revision")}
        if args.group == "forward" and record["mode"] == "rathole":
            result["config"] = config_instructions(args, record["name"], group_name(record))
        return result
    except (HostError, ApplyError, OSError) as exc:
        return {"configuration": redacted(record), "operational": {"health": "unknown", "reason": str(exc)}}


def _confirm(args):
    if args.yes:
        return
    if not sys.stdin.isatty():
        raise ValidationError("Non-interactive apply requires --yes after reviewing the preview")
    if input("Apply this plan? Type apply: ").strip() != "apply":
        raise ValidationError("Cancelled; no changes applied")


def interactive(base_args):
    from .menu import run_menu
    return run_menu(base_args)


def config_instructions(args, name, rathole_name=None):
    rathole_name = rathole_name or name
    path = rathole_config_path(rathole_name, str(Path(args.state_dir).absolute()))
    base = ["sudo", "twinlink", "--state-dir", str(Path(args.state_dir).absolute()),
            "--unit-dir", args.unit_dir, "--runtime-path", args.runtime_path,
            "--rathole-binary", args.rathole_binary]
    return {"path": path, "edit_with_vim": shlex.join(["sudo", "vim", path]),
            "edit_with_nano": shlex.join(["sudo", "nano", path]),
            "restart_after_manual_edit": shlex.join(["sudo", "systemctl", "restart", f"twinlink-rathole-{rathole_name}.service"]),
            "persistent_changes": shlex.join(base + ["forward", "edit", name, "--help"]),
            "note": "Generated TOML: manual edits are overwritten on reapply or boot restore. Use forward edit for persistent port/address changes; export/import shared changes again."}


def _internal(args, store, host, engine):
    host.require_linux_root()
    with store.lock(timeout=45):
        if store.journal.exists():
            raise StateError("Interrupted transaction: run twinlink recover --apply before boot restore")
        state = store.read()
        if args.operation == "restore":
            candidate = copy.deepcopy(state)
            for tunnel in candidate["tunnels"].values():
                tunnel["running"] = tunnel["enabled"]
            for entry in candidate["forwards"].values():
                entry["running"] = entry["enabled"] and candidate["tunnels"][entry["tunnel"]]["running"]
            plan = engine.plan(state, candidate, "boot restore")
            result = engine.apply(state, candidate, plan, boot=True)
            output(result, args.json)
        else:
            if args.operation == "tunnel-down" and args.name not in state["tunnels"]:
                return 0
            tunnel = _get(state, "tunnel", args.name)
            if args.operation == "tunnel-up":
                if tunnel["enabled"] or tunnel["running"]:
                    engine._tunnel_up(tunnel)
                    status = host.tunnel_status(dict(tunnel, running=True), probe=False)
                    if status.get("drift"):
                        raise ApplyError("Systemd GRE start read-back failed: " + json.dumps(status["drift"]))
            else:
                # A stop job queued during a transaction may run after a later
                # start. Respect the latest committed intent under the same lock.
                if not tunnel["running"]:
                    engine._tunnel_down(tunnel)
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    public_context = (args.group, getattr(args, "action", ""), getattr(args, "name", "") or "")
    def emit(value, as_json=False, **kwargs):
        output(value, as_json, verbose=getattr(args, "verbose", False), context=None if args.group == "internal" else public_context, **kwargs)
    try:
        requested_action = args.group + " " + getattr(args, "action", "purge")
        args = _forward_command(args)
        if args.no_systemd and os.environ.get("TWINLINK_TESTING") != "1":
            raise ValidationError("--no-systemd is reserved for isolated integration tests (TWINLINK_TESTING=1)")
        store = Store(args.state_dir)
        host = Host()
        from . import v2_cli
        from .coordination import Pending
        if args.group in v2_cli.GROUPS or args.group == "uninstall" and (store.directory / "uninstall.json").exists():
            if args.group == "setup" and not any((args.file, args.pair, args.vps1, args.vps2)) and sys.stdin.isatty():
                from .menu import run_pair_setup
                return run_pair_setup(args)
            try:
                return v2_cli.handle(args, store, host, _confirm)
            except Pending as exc:
                v2_cli.emit({"status": "pending", "error": str(exc)}, args)
                return 3
            except ValidationError as exc:
                v2_cli.emit({"status": "invalid", "error": str(exc)}, args)
                return 2
            except StateError as exc:
                v2_cli.emit({"status": "conflict", "error": str(exc)}, args)
                return 4
        v2_state = store.read()
        diagnostic_options = args.group == "doctor" and any(getattr(args, k, None) for k in ("deep", "watch", "export", "merge", "compare", "preview", "capture"))
        if args.group == "doctor" and (v2_state["version"] == 2 or diagnostic_options):
            return v2_cli.doctor(args, store)
        if v2_state["version"] == 2:
            if args.group == "menu":
                from .menu import run_v2_menu
                return run_v2_menu(args)
            if args.group in ("status", "recover", "uninstall", "internal"):
                try:
                    return v2_cli.handle(args, store, host, _confirm)
                except Pending as exc:
                    v2_cli.emit({"status": "pending", "error": str(exc)}, args)
                    return 3
                except StateError as exc:
                    v2_cli.emit({"status": "conflict", "error": str(exc)}, args)
                    return 4
            raise ValidationError("Legacy commands are disabled after explicit v2 commit; use pair/profile/service/config commands")
        engine = Engine(store, host, unit_dir=args.unit_dir, executable=args.runtime_path,
                        rathole_binary=args.rathole_binary, systemd=not args.no_systemd)
        if args.group == "menu":
            return interactive(args)
        if args.group == "forward" and args.action in ("setup", "menu"):
            from .menu import run_forward_setup, run_forward_menu
            return run_forward_setup(args) if args.action == "setup" else run_forward_menu(args)
        if args.group == "rathole" and args.action == "setup":
            from .menu import run_rathole_setup
            return run_rathole_setup(args)
        if args.group == "rathole" and args.action == "install":
            plan = rathole.install_plan(args.rathole_binary, args.sha256)
            if not args.apply:
                emit({**plan, "next": "Repeat with --apply to install Rathole"}, args.json, phase="preview")
                return 0
            _confirm(args)
            host.require_linux_root()
            with store.lock():
                if store.journal.exists():
                    raise StateError("Recover the interrupted transaction before installing Rathole")
                emit(rathole.install(args.rathole_binary, args.sha256), args.json)
            return 0
        if args.group == "doctor":
            report = host.dependency_report()
            report["platform"] = platform.system()
            report["rathole"] = {"path": args.rathole_binary, "installed": os.access(args.rathole_binary, os.X_OK), "supported_version": "0.5.0 TCP"}
            report["state_directory"] = str(store.directory)
            emit(report, args.json)
            return 0 if platform.system() == "Linux" and not report.get("missing_required") and report.get("systemd_runtime") else 1
        if args.group == "internal":
            return _internal(args, store, host, engine)
        if args.group == "recover":
            if not args.apply:
                emit({"pending": store.journal.exists(), "preview": "Restore the private journal's old state, managed files, GRE, rules, services, and sysctl", "next": "recover --apply --yes"}, args.json)
                return 0
            _confirm(args)
            with store.lock():
                emit(engine.recover(), args.json, phase="applied")
            return 0
        state = store.read()
        if args.group == "forward" and args.action == "pair-export":
            entries = {}
            for name in args.names:
                for entry in groups(state).get(name) or [_get(state, "forward", name)]:
                    entries[entry["name"]] = entry
            records = list(entries.values())
            if all(entry["mode"] == "rathole" for entry in records):
                code = pairing.export_rathole(records, state)
            elif len(records) == 1 and records[0]["mode"] == "kernel":
                code = pairing.export_forward(records[0], state["tunnels"][records[0]["tunnel"]])
            else:
                raise ValidationError("Export one Kernel forwarding entry or one or more Rathole configs at a time")
            if args.json or getattr(args, "verbose", False):
                emit({"code": code, "contains_secret": records[0]["mode"] == "rathole", "contains_noise_private_key": False}, args.json)
            else:
                print(code)
            return 0
        if args.group == "rathole" and args.action == "config":
            members = groups(state).get(args.name)
            record = members[0] if members else _get(state, "forward", args.name)
            if record["mode"] != "rathole":
                raise ValidationError("This forwarding entry does not use Rathole")
            emit(config_instructions(args, record["name"], group_name(record)), args.json)
            return 0
        if args.group == "rathole" and args.action == "pair-export":
            records = {}
            for name in args.names:
                members = groups(state).get(name)
                for entry in members or [_get(state, "forward", name)]:
                    records[entry["name"]] = entry
            code = pairing.export_rathole(list(records.values()), state)
            if args.json or getattr(args, "verbose", False):
                emit({"code": code, "contains_secret": True, "contains_noise_private_key": False}, args.json)
            else:
                print(code)
            return 0
        if args.group == "status":
            result = {"version": __version__, "unfinished_transaction": store.journal.exists(), "tunnels": [], "forwards": []}
            for group, key in (("tunnel", "tunnels"), ("forward", "forwards")):
                view = copy.copy(args)
                view.group = group
                for record in state[key].values():
                    result[key].append(inspect_record(view, state, host, engine, record))
            emit(result, args.json)
            return 0
        if args.group == "uninstall" and not args.purge_managed:
            emit({"managed_tunnels": list(state["tunnels"]), "managed_forwards": list(state["forwards"]),
                    "program_only": "scripts/uninstall.sh removes the command launcher, retaining the runtime needed by managed units",
                    "purge": "uninstall --purge-managed --cascade --apply --yes removes managed network resources first"}, args.json)
            return 0
        action = getattr(args, "action", "")
        if args.group != "rathole" and action in ("list", "show", "check", "diagnose"):
            if action == "list":
                key = "tunnels" if args.group == "tunnel" else "forwards"
                emit([inspect_record(args, state, host, engine, r) for r in state[key].values()], args.json)
                return 0
            record = _get(state, args.group, args.name)
            if action == "diagnose":
                result = host.diagnose_tunnel(record) if args.group == "tunnel" else host.diagnose_forward(
                    record, state["tunnels"][record["tunnel"]], rathole_config_path(group_name(record), str(store.directory)),
                    group_running=any(entry["running"] for entry in groups(state).get(group_name(record), [])) if record["mode"] == "rathole" else None)
                emit(result, args.json)
                return 0
            result = inspect_record(args, state, host, engine, record)
            if action == "check" and getattr(args, "record", False):
                if result["operational"].get("health") != "up" or result["operational"].get("drift"):
                    raise ValidationError("GRE verification not recorded: peer probe and kernel configuration must both pass; " + str(result["operational"].get("reason")))
                candidate = copy.deepcopy(state)
                candidate["tunnels"][args.name]["verified"] = True
            else:
                emit(result, args.json)
                return 0 if action != "check" or result["operational"].get("health") == "up" else 2
        elif action == "pair-export":
            code = pairing.export_tunnel(_get(state, "tunnel", args.name))
            if args.json or getattr(args, "verbose", False):
                emit({"code": code, "contains_forwarding_secrets": False}, args.json)
            else:
                print(code)
            return 0
        elif action == "export":
            record = _get(state, "forward", args.name)
            target = Path(args.output).absolute()
            reject_symlink(target)
            if target.exists():
                raise ValidationError("Refusing to overwrite export file; choose a new private filename")
            if not target.parent.is_dir():
                raise ValidationError("Create the private export directory first")
            code = pairing.export_forward(record, state["tunnels"][record["tunnel"]])
            # Explicit export is the sole path writing secrets outside app storage.
            fd = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(code + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            emit({"exported": str(target), "mode": "0600", "revision": record["revision"],
                    "transfer": "Copy with scp over a verified SSH connection; import on the peer, inspect, then enable explicitly",
                    "contains_secret": record["mode"] == "rathole"}, args.json)
            return 0
        else:
            candidate = prepare(args, state)
        setup_pairing = None
        setup_names = []
        if args.group == "rathole" and action in ("add", "consolidate"):
            setup_names = [entry["name"] for entry in groups(candidate)[args.name]]
            # Check export bounds before the transaction, so a successful
            # commit cannot subsequently fail to produce its pairing code.
            setup_pairing = pairing.export_rathole([candidate["forwards"][name] for name in setup_names], candidate)
        elif args.group == "forward" and action == "add":
            entry = candidate["forwards"][args.name]
            setup_pairing = (pairing.export_rathole([entry], candidate) if entry["mode"] == "rathole" else
                             pairing.export_forward(entry, candidate["tunnels"][entry["tunnel"]]))
            setup_names = [args.name] if entry["mode"] == "rathole" else []
        force = action in ("reapply", "restart")
        if force:
            # Persisted metadata is excluded from model fields; force runtime diff
            # through a separate engine argument instead of contaminating records.
            engine.force = (args.group, args.name, action)
        plan = engine.plan(state, candidate, requested_action)
        affected = engine.affected(state, candidate)
        if not args.apply:
            plan["next"] = "Repeat with --apply (and --yes for scripts) after reviewing this preview"
            emit(plan, args.json, phase="preview", old=state, candidate=candidate, affected=affected)
            return 0
        if args.json:
            # JSON apply is one document so scripts never have to parse concatenated JSON.
            pass
        else:
            emit(plan, phase="preview", old=state, candidate=candidate, affected=affected)
        _confirm(args)
        with store.lock():
            result = engine.apply(state, candidate, plan)
        if setup_pairing is not None:
            result["pairing_code"] = setup_pairing
            result["pairing_note"] = "Paste into twinlink forward setup on the peer. Rathole codes contain service tokens and Noise public keys; server private keys are excluded. Transfer privately."
            if setup_names:
                result["configs"] = [config_instructions(args, setup_names[0], group_name(candidate["forwards"][setup_names[0]]))]
        emit({**result, "plan": plan} if args.json else result, args.json, phase="applied", old=state, candidate=candidate, affected=affected)
        return 0
    except (ValidationError, StateError, HostError, ApplyError, OSError, ValueError) as exc:
        versioned = args.group in {"setup", "pair", "profile", "service", "config", "system", "logs"} or locals().get("v2_state", {}).get("version") == 2 or locals().get("diagnostic_options", False)
        if versioned:
            from .v2_cli import emit as emit_v2
            code = 2 if isinstance(exc, ValidationError) else 4 if isinstance(exc, StateError) else 1
            emit_v2({"status": "invalid" if code == 2 else "conflict" if code == 4 else "failed", "error": str(exc)}, args)
            return code
        details = {"error": str(exc)}
        if getattr(exc, "rollback_errors", None):
            details["rollback_errors"] = exc.rollback_errors
        emit(details, getattr(args, "json", False))
        return 1
    except KeyboardInterrupt:
        emit({"error": "Interrupted; inspect status and recover any unfinished transaction"}, getattr(args, "json", False))
        return 130
