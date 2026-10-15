"""Scriptable CLI and interactive operator menu."""
import argparse
import copy
import json
import os
from pathlib import Path
import platform
import sys

from . import __version__
from .engine import ApplyError, Engine, redacted
from .host import Host, HostError
from .models import ValidationError, validate_tunnel, validate_forward
from . import pairing
from .store import Store, StateError, reject_symlink


LIFECYCLE = ("enable", "disable", "start", "stop", "restart", "reapply", "delete")
TUNNEL_FIELDS = ("side", "local_public", "remote_public", "local_private", "remote_private", "key", "mtu", "ttl")
FORWARD_FIELDS = ("tunnel", "mode", "protocol", "bind_address", "bind_port", "destination_address", "destination_port", "relay_port", "transport_port")


def output(value, as_json=False):
    value = redacted(value)
    if as_json:
        print(json.dumps(value, indent=2, sort_keys=True))
    elif isinstance(value, str):
        print(value)
    else:
        print(json.dumps(value, indent=2, sort_keys=True))


def mutation_flags(parser):
    parser.add_argument("--apply", action="store_true", help="Apply this preview after validation (default: preview only)")
    parser.add_argument("--yes", action="store_true", help="Skip the apply confirmation; requires --apply")
    parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="Machine-readable output")


def build_parser():
    parser = argparse.ArgumentParser(prog="twinlink", description="Manage GRE first, then rathole or kernel forwarding. Mutations preview unless --apply is supplied.")
    parser.add_argument("--version", action="version", version="twinlink " + __version__)
    parser.add_argument("--json", action="store_true", help="Machine-readable output; secrets are redacted")
    parser.add_argument("--state-dir", default="/var/lib/twinlink", help="Private configuration and journal directory")
    parser.add_argument("--unit-dir", default="/etc/systemd/system", help="Managed unit directory")
    parser.add_argument("--runtime-path", default="/usr/local/libexec/twinlink-runtime", help="Absolute installed runtime used by units")
    parser.add_argument("--rathole-binary", default="/usr/local/bin/rathole", help="Operator-supplied rathole 0.5.0 executable")
    parser.add_argument("--no-systemd", action="store_true", help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="group", required=True)
    for group in ("tunnel", "forward"):
        group_parser = commands.add_parser(group, help="Manage GRE tunnels" if group == "tunnel" else "Manage entries attached to verified GRE")
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
                required = action in ("create", "add") and field in (("side", "local_public", "remote_public", "local_private", "remote_private") if group == "tunnel" else ("tunnel", "mode", "bind_port", "destination_address", "destination_port"))
                leaf.add_argument("--" + field.replace("_", "-"), required=required, **kwargs)
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
            export = actions.add_parser("export", help="Explicit secret export to a new private file")
            export.add_argument("name")
            export.add_argument("--output", required=True)
            export.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
            imp = actions.add_parser("import", help="Import a matching forwarding configuration received securely")
            imp.add_argument("--file", required=True)
            imp.add_argument("--name")
            mutation_flags(imp)
    for name in ("doctor", "status", "menu"):
        leaf = commands.add_parser(name)
        leaf.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    recover = commands.add_parser("recover", help="Roll back an interrupted journalled transaction")
    mutation_flags(recover)
    uninstall = commands.add_parser("uninstall", help="Preview resource removal; program-only removal is scripts/uninstall.sh")
    uninstall.add_argument("--purge-managed", action="store_true", help="Delete every managed tunnel and forwarding entry")
    uninstall.add_argument("--cascade", action="store_true")
    mutation_flags(uninstall)
    internal = commands.add_parser("internal", help="Boot callbacks used by managed units")
    internal.add_argument("operation", choices=("restore", "tunnel-up", "tunnel-down"))
    internal.add_argument("name", nargs="?")
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


def prepare(args, old):
    """Pure desired-state mutation. Never runs commands or stores secrets."""
    new = copy.deepcopy(old)
    group, action = args.group, getattr(args, "action", "")
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
            status = host.forward_status(record, state["tunnels"][record["tunnel"]], probe=not getattr(args, "no_probe", False))
            expected = state.get("_nft_fingerprint")
            if record["mode"] == "kernel" and expected and expected != engine.nft_fingerprint():
                status.setdefault("drift", []).append({"field": "nftables", "reason": "Installed table differs from the verified commit"})
                status.update(health="degraded", reason="Managed firewall rules drifted; run forward reapply " + record["name"])
        return {"configuration": redacted(record), "operational": status,
                "peer_transfer_required": args.group == "forward" and record.get("peer_revision") != record.get("revision")}
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
    try:
        if args.no_systemd and os.environ.get("TWINLINK_TESTING") != "1":
            raise ValidationError("--no-systemd is reserved for isolated integration tests (TWINLINK_TESTING=1)")
        store = Store(args.state_dir)
        host = Host()
        engine = Engine(store, host, unit_dir=args.unit_dir, executable=args.runtime_path,
                        rathole_binary=args.rathole_binary, systemd=not args.no_systemd)
        if args.group == "menu":
            return interactive(args)
        if args.group == "doctor":
            report = host.dependency_report()
            report["platform"] = platform.system()
            report["rathole"] = {"path": args.rathole_binary, "installed": os.access(args.rathole_binary, os.X_OK), "supported_version": "0.5.0 TCP"}
            report["state_directory"] = str(store.directory)
            output(report, args.json)
            return 0 if platform.system() == "Linux" and not report.get("missing_required") and report.get("systemd_runtime") else 1
        if args.group == "internal":
            return _internal(args, store, host, engine)
        if args.group == "recover":
            if not args.apply:
                output({"pending": store.journal.exists(), "preview": "Restore the private journal's old state, managed files, GRE, rules, services, and sysctl", "next": "recover --apply --yes"}, args.json)
                return 0
            _confirm(args)
            with store.lock():
                output(engine.recover(), args.json)
            return 0
        state = store.read()
        if args.group == "status":
            result = {"version": __version__, "unfinished_transaction": store.journal.exists(), "tunnels": [], "forwards": []}
            for group, key in (("tunnel", "tunnels"), ("forward", "forwards")):
                view = copy.copy(args)
                view.group = group
                for record in state[key].values():
                    result[key].append(inspect_record(view, state, host, engine, record))
            output(result, args.json)
            return 0
        if args.group == "uninstall" and not args.purge_managed:
            output({"managed_tunnels": list(state["tunnels"]), "managed_forwards": list(state["forwards"]),
                    "program_only": "scripts/uninstall.sh removes the command launcher, retaining the runtime needed by managed units",
                    "purge": "uninstall --purge-managed --cascade --apply --yes removes managed network resources first"}, args.json)
            return 0
        action = getattr(args, "action", "")
        if action in ("list", "show", "check", "diagnose"):
            if action == "list":
                key = "tunnels" if args.group == "tunnel" else "forwards"
                output([inspect_record(args, state, host, engine, r) for r in state[key].values()], args.json)
                return 0
            record = _get(state, args.group, args.name)
            if action == "diagnose":
                result = host.diagnose_tunnel(record) if args.group == "tunnel" else host.diagnose_forward(
                    record, state["tunnels"][record["tunnel"]], str(store.directory / "rathole" / (record["name"] + ".toml")))
                output(result, args.json)
                return 0
            result = inspect_record(args, state, host, engine, record)
            if action == "check" and getattr(args, "record", False):
                if result["operational"].get("health") != "up" or result["operational"].get("drift"):
                    raise ValidationError("GRE verification not recorded: peer probe and kernel configuration must both pass; " + str(result["operational"].get("reason")))
                candidate = copy.deepcopy(state)
                candidate["tunnels"][args.name]["verified"] = True
            else:
                output(result, args.json)
                return 0 if action != "check" or result["operational"].get("health") == "up" else 2
        elif action == "pair-export":
            code = pairing.export_tunnel(_get(state, "tunnel", args.name))
            if args.json:
                output({"code": code, "contains_forwarding_secrets": False}, True)
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
            output({"exported": str(target), "mode": "0600", "revision": record["revision"],
                    "transfer": "Copy with scp over a verified SSH connection; import on the peer, inspect, then enable explicitly",
                    "contains_secret": record["mode"] == "rathole"}, args.json)
            return 0
        else:
            candidate = prepare(args, state)
        force = action in ("reapply", "restart")
        if force:
            # Persisted metadata is excluded from model fields; force runtime diff
            # through a separate engine argument instead of contaminating records.
            engine.force = (args.group, args.name, action)
        plan = engine.plan(state, candidate, args.group + " " + (action or "purge"))
        if not args.apply:
            plan["next"] = "Repeat with --apply (and --yes for scripts) after reviewing this preview"
            output(plan, args.json)
            return 0
        if args.json:
            # JSON apply is one document so scripts never have to parse concatenated JSON.
            pass
        else:
            output(plan)
        _confirm(args)
        with store.lock():
            result = engine.apply(state, candidate, plan)
        output({**result, "plan": plan} if args.json else result, args.json)
        return 0
    except (ValidationError, StateError, HostError, ApplyError, OSError, ValueError) as exc:
        details = {"error": str(exc)}
        if getattr(exc, "rollback_errors", None):
            details["rollback_errors"] = exc.rollback_errors
        output(details, getattr(args, "json", False))
        return 1
    except KeyboardInterrupt:
        output({"error": "Interrupted; inspect status and recover any unfinished transaction"}, getattr(args, "json", False))
        return 130
