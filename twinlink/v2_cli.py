"""V2 commands share one pair model and default to non-mutating previews."""
import argparse
import copy
import getpass
import json
import os
from pathlib import Path
import re
import sys

from .contracts import (PROFILES, canonical, new_revision, next_revision, validate_revision,
                        strict_json, validate_service, validate_reservations)
from .coordination import Coordinator
from .models import ValidationError, _integer
from .ownership import Ownership
from .pair_bundle import credentials, encode, decode, fingerprint, MAX_ENCODED
from .profile_runtime import ProfileRuntime
from .profiles import manifests
from .redaction import Redactor, secret_values, stored_secrets
from .store import StateError, atomic_write, reject_symlink

GROUPS = frozenset(("setup", "pair", "profile", "service", "config", "system", "logs"))


def register(commands, mutation_flags):
    def leaf(parent, name, mutate=False, pair=True):
        p = parent.add_parser(name)
        if pair:
            p.add_argument("--pair")
        if mutate:
            mutation_flags(p)
        else:
            p.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        return p
    setup = leaf(commands, "setup", True)
    setup.add_argument("--vps1")
    setup.add_argument("--vps2")
    setup.add_argument("--transport-port", type=int, default=3456)
    setup.add_argument("--file", help="Private complete v2 shared revision JSON; otherwise use endpoint flags")
    for group, actions in (("pair", ("export", "import", "status", "delete")),
                           ("profile", ("list", "check", "switch", "status", "restart", "reapply")),
                           ("service", ("list", "add", "edit", "delete")),
                           ("config", ("show", "set", "regenerate", "migrate")),
                           ("system", ("changes", "restore", "preserve-backups"))):
        parent = commands.add_parser(group)
        subs = parent.add_subparsers(dest="action", required=True)
        for action in actions:
            mutate = action in ("import", "delete", "switch", "restart", "reapply", "add", "edit", "set", "regenerate", "migrate", "restore", "preserve-backups")
            p = leaf(subs, action, mutate)
            if group == "pair" and action == "export":
                p.add_argument("--output")
                p.add_argument("--revision", type=int, help="Export a retained revision to transfer staged edits in order")
            if group == "pair" and action == "import":
                p.add_argument("--file", help="Mode-0600 bundle file, or '-' for stdin; omitted: hidden paste")
                p.add_argument("--expected-fingerprint")
            if group == "profile" and action in ("switch", "check"):
                p.add_argument("profile", choices=(*PROFILES, "off"))
            if group == "profile" and action in ("switch", "restart", "reapply"):
                p.add_argument("--refresh-receipt", action="store_true", help="Revalidate and refresh the last pending local phase receipt")
                p.add_argument("--revision", type=int, help="Pin the revision in a coordinated continuation")
                p.add_argument("--transaction")
                p.add_argument("--step")
                p.add_argument("--receipt-file")
                p.add_argument("--output", help="Private outgoing receipt file")
            if group == "service" and action in ("add", "edit", "delete"):
                p.add_argument("name")
                if action != "delete":
                    p.add_argument("--bind")
                    p.add_argument("--protocol", choices=("tcp", "udp"))
                    p.add_argument("--ports")
                    backend = p.add_mutually_exclusive_group()
                    backend.add_argument("--backend-address")
                    backend.add_argument("--backend-local", action="store_true", help="Target VPS2 itself using the selected profile's address")
                    p.add_argument("--backend-ports")
                    p.add_argument("--probe-request-hex")
                    p.add_argument("--probe-response-hex")
            if group == "config" and action == "set":
                p.add_argument("field", choices=("transport.port", "gre.mtu", "gre.ttl", "gre.key", "gre.addresses", "gre.addresses.vps1", "gre.addresses.vps2", "public_endpoints.vps1", "public_endpoints.vps2"))
                p.add_argument("value")
            if group == "config" and action == "migrate":
                p.add_argument("--transport-port", type=int)
                p.add_argument("--file", help="On VPS2: authenticated pair bundle after offline legacy inventory")
                p.add_argument("--expected-fingerprint")
    logs = leaf(commands, "logs")
    logs.add_argument("--limit", type=int, default=200)


def select_pair(state, pair_id=None):
    if state["version"] != 2:
        raise ValidationError("Set up a new pair or explicitly migrate v1 with config migrate")
    if pair_id is None:
        if len(state["pairs"]) != 1:
            raise ValidationError("Use --pair ID when there are zero or multiple pairs")
        pair_id = next(iter(state["pairs"]))
    if pair_id not in state["pairs"]:
        raise ValidationError("Unknown pair")
    return pair_id, state["pairs"][pair_id]


def read_private(path, limit=MAX_ENCODED):
    target = Path(path).absolute()
    reject_symlink(target)
    if not target.is_file() or target.stat().st_mode & 0o077:
        raise ValidationError("Transfer must be a private regular mode-0600 file")
    with target.open() as stream:
        text = stream.read(limit + 1)
    if len(text) > limit:
        raise ValidationError("Transfer exceeds its size limit")
    return text.strip()


def write_new(path, content):
    path = Path(path).absolute()
    reject_symlink(path)
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(content + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def runtime(args, store, host):
    return ProfileRuntime(store, host, args.unit_dir, args.runtime_path, args.rathole_binary, args.paqet_binary)


def view(store, pair, control):
    r = store.revision(pair, control["staged_revision"])
    rendered = manifests(r, control["role"], store.credentials(pair), store.facts(pair), store.read()["installation_id"])
    return {"pair_id": pair, "role": control["role"], "active": control["active"], "staged_revision": r["revision"],
            "transition": {k: control["transition"][k] for k in ("phase", "transaction_id", "cursor", "error")} if control["transition"] else None,
            "status": "recovery-required" if control["transition"] else "active-unverified" if control["active"] else "off",
            "commit_pending": control.get("commit_pending", False),
            "shared_transport": {"value": r["transport"]["port"], "origin": "transport.port"},
            "profiles": [{k: value[k] for k in ("profile", "configured", "compatible", "missing_services", "preparation_errors", "transport_port", "transport_origin")}
                         for value in rendered.values()], "peer_observations": control["peer_observations"],
            "health": "unknown"}


def emit(value, args):
    # V2 output uses one versioned document for both human/script invocation.
    if value.get("status") == "preview" and getattr(args, "apply", False):
        return
    print(json.dumps({"schema_version": 2, "action": args.group + " " + getattr(args, "action", ""), **value}, indent=2, sort_keys=True))


def handle(args, store, host, confirm):
    uninstall_journal = store.directory / "uninstall.json"
    reject_symlink(uninstall_journal)
    if args.group == "uninstall" and uninstall_journal.exists():
        emit({"status": "preview", "operation": "Resume final local uninstall", "journal": str(uninstall_journal)}, args)
        if getattr(args, "apply", False):
            if not (args.purge or args.purge_managed):
                raise ValidationError("Use uninstall --purge --apply to resume final removal")
            confirm(args)
            host.require_linux_root()
            from .cleanup import remove_program
            with store.lock():
                result = remove_program(store, runtime(args, store, host))
            emit(result, args)
        return 0
    state = store.read()
    applying = getattr(args, "apply", False)
    rt = runtime(args, store, host)
    def commit(fn):
        if not applying:
            return None
        confirm(args)
        host.require_linux_root()
        with store.lock():
            if store.read() != state:
                raise StateError("State changed after preview; rerun command")
            if store.journal.exists():
                raise StateError("Recover legacy transaction before v2 mutations")
            return fn()
    def stage(r, role, creds, facts=None, prepare=False):
        new = store.stage(state, r, role, creds, facts)
        if prepare:
            rt.materialize(r, role)
        return new
    group, action = args.group, getattr(args, "action", "")
    if group == "setup":
        if args.file:
            r = validate_revision(strict_json(read_private(args.file, 65536)))
        else:
            if not args.pair or not args.vps1 or not args.vps2:
                raise ValidationError("Setup requires --pair ID --vps1 ADDRESS --vps2 ADDRESS; add services through service add")
            r = new_revision(args.pair, {"vps1": args.vps1, "vps2": args.vps2}, args.transport_port)
        if state["version"] == 2 and r["pair_id"] in state["pairs"]:
            raise ValidationError("Pair already exists; edit shared configuration instead")
        emit({"status": "preview", "configuration": r, "runtime": "off", "credentials": "Generated only on apply; explicit pair export discloses them"}, args)
        def setup():
            pending = store.pending_stage(r["pair_id"])
            if pending:
                saved = pending["revision_config"]
                if any(saved[k] != r[k] for k in ("public_endpoints", "transport", "gre", "services")):
                    raise StateError("Setup retry differs from interrupted staging configuration")
                return stage(saved, pending["role"], pending["credentials"], pending["facts"])
            from .rathole import generate_keypair
            noise = None
            if Path(args.rathole_binary).is_file():
                from .rathole import check_version
                try:
                    check_version(args.rathole_binary)
                    noise = generate_keypair(args.rathole_binary)
                    r["public_keys"]["noise"] = noise["noise_public_key"]
                except ValidationError:
                    pass
            creds = credentials(noise)
            try:
                facts = rt.discover(r, "vps1")
            except (ValueError, RuntimeError, OSError, KeyError):
                facts = None
            return stage(r, "vps1", creds, facts)
        result = commit(setup)
        if result:
            emit({"status": "complete", "pair_id": r["pair_id"], "runtime": "off", "next": "service add, config regenerate, then pair export"}, args)
        return 0
    if group == "config" and action == "migrate":
        from .migration import plan
        candidate = plan(state, args.transport_port)
        emit({"status": "preview", "migration": candidate}, args)
        if applying:
            if candidate["blockers"]:
                raise ValidationError("Migration blockers require operator review; v1 unchanged")
            imported = None
            if args.file:
                code = read_private(args.file)
                imported = decode(code, args.expected_fingerprint)
            if any(p["role"] == "vps2" for p in candidate["pairs"]) and imported is None:
                raise ValidationError("VPS2 migration requires --file with VPS1's full bundle and --expected-fingerprint")
            if imported and (len(candidate["pairs"]) != 1 or candidate["pairs"][0]["revision"]["pair_id"] != imported[0]["pair_id"]):
                raise ValidationError("Import one unambiguous legacy pair at a time")
            def migrate():
                from .migration import inventory, adopt
                from .rathole_groups import units
                for unit in {"twinlink-restore.service", *units(state), *("twinlink-gre-" + n + ".service" for n in state["tunnels"])}:
                    status = host.unit_status(unit)
                    if status["active"] or (unit != "twinlink-restore.service" and status["enabled"]):
                        raise StateError("Stop/disable legacy units before migration: " + unit)
                live = {row["ifname"] for row in host.links()}
                if any(t["interface"] in live for t in state["tunnels"].values()):
                    raise StateError("Legacy GRE runtime remains; stop it through the v1 CLI first")
                legacy_resources = inventory(store, rt, state)
                Ownership(store).write_file(store.directory / "backups" / "v1-state.json", canonical(state).decode(), "installation")
                from .contracts import empty_v2
                migration_journal = store.directory / "journals" / "migration.json"
                pending = store.private_read(migration_journal, 4 * 1024 * 1024) if migration_journal.exists() else None
                if pending and pending["state_before"] != state:
                    raise StateError("Migration journal differs from v1 state")
                pending = pending or {"state_before": state, "status": "staging", "new": empty_v2(),
                                      "credentials": {item["revision"]["pair_id"]: credentials() for item in candidate["pairs"]}}
                Ownership(store).write_file(migration_journal, canonical(pending).decode(), "installation")
                new = pending["new"]
                # Stage all pair artifacts before committing the final v2 pointer.
                try:
                    for item in candidate["pairs"]:
                        r, role = item["revision"], item["role"]
                        if imported:
                            r, creds = imported
                            role = "vps2"
                        else:
                            creds = pending["credentials"][r["pair_id"]]
                            legacy = [f for f in state["forwards"].values() if f["tunnel"] == r["pair_id"] and f["mode"] == "rathole"]
                            if legacy:
                                creds["rathole"] = legacy[0]["token"]
                                if role == "vps1" and legacy[0].get("noise_private_key"):
                                    creds["noise_private"] = legacy[0]["noise_private_key"]
                        new = store.stage(new, r, role, creds, commit_state=False)
                    adopt(store, rt, legacy_resources)
                    # Legacy boot enablement was managed by v1. Retire it;
                    # historical package/sysctl baselines remain unknown.
                    host.run(["systemctl", "disable", "twinlink-restore.service"])
                    store.write(new)
                    Ownership(store).remove_file(migration_journal, "installation")
                    return new
                except BaseException:
                    # Staging never starts runtime; a local state restoration
                    # remains safe until explicit coordinated activation.
                    store.write(state)
                    raise
            if commit(migrate):
                emit({"status": "complete", "runtime": "off", "backup": str(store.directory / "backups" / "v1-state.json"),
                      "next": "Export/import the pair, prepare both hosts, then coordinated initial activation"}, args)
        return 2 if candidate["blockers"] else 0
    if group == "pair" and action == "import":
        code = read_private(args.file) if args.file and args.file != "-" else sys.stdin.read(MAX_ENCODED + 1).strip() if args.file == "-" else getpass.getpass("Pair bundle (hidden): ")
        # Discover pair identity only after bootstrap fingerprint validation.
        key = None
        if args.pair and state["version"] == 2 and args.pair in state["pairs"]:
            key = store.credentials(args.pair)["management"]
        r, creds = decode(code, args.expected_fingerprint, key)
        if args.pair and args.pair != r["pair_id"]:
            raise ValidationError("Bundle pair does not match --pair")
        if state["version"] == 2 and r["pair_id"] in state["pairs"] and key is None:
            # Existing trust must never be replaced by a new bootstrap fingerprint.
            r, creds = decode(code, stored_management_key=store.credentials(r["pair_id"])["management"])
        emit({"status": "preview", "configuration": r, "fingerprint": fingerprint(code), "runtime": "unchanged"}, args)
        def imp():
            try:
                facts = rt.discover(r, "vps2")
            except (ValueError, RuntimeError, OSError, KeyError):
                facts = None
            return stage(r, "vps2", creds, facts)
        if commit(imp):
            emit({"status": "complete", "pair_id": r["pair_id"], "runtime": "unchanged", "next": "config regenerate --pair " + r["pair_id"]}, args)
        return 0
    if group == "system":
        if action == "preserve-backups":
            from .baseline_backups import plan, preserve
            emit({"status": "preview", "baseline_backups": plan(store),
                  "policy": "Preserve exact contents outside the state directory; purge never deletes retained copies"}, args)
            result = commit(lambda: preserve(store))
            if result is not None:
                emit(result, args)
            return 0
        summary = Ownership(store).summary()
        baseline_path = store.directory / "baseline.json"
        reject_symlink(baseline_path)
        baseline = store.baseline() if baseline_path.exists() else {}
        legacy_backups = [str(path) for path in sorted(store.directory.glob("baseline.json.backup-*"))]
        emit({"status": "preview" if action == "restore" else "complete", "resources": summary,
              **({"legacy_baseline_backups": legacy_backups, "baseline_backup_recovery": "twinlink system preserve-backups --apply --yes (use the same --state-dir)"} if legacy_backups else {}),
              "historical_baseline": baseline.get("historical_baseline", "unknown"),
              "package_delta": baseline.get("package_delta", {}), "python": baseline.get("python", "unknown")}, args)
        if action == "restore" and applying:
            if state["version"] != 2:
                raise ValidationError("V1 settings require legacy recovery or explicit migration; restoration baseline remains unknown")
            if any(c["active"] or c["transition"] for c in state.get("pairs", {}).values()):
                raise StateError("Complete coordinated off before restoration")
            from .cleanup import restore_system
            result = commit(lambda: restore_system(store, rt))
            emit(result, args)
            return 4 if result["conflicts"] else 0
        return 4 if any(row["status"] in ("conflict", "pending", "restoring") for row in summary) else 0
    if group == "status":
        emit({"status": "complete", "pairs": [view(store, p, c) for p, c in state["pairs"].items()]}, args)
        return 0
    if group == "uninstall":
        from .cleanup import delete_pair, restore_system, remove_program
        pending = [p for p, cc in state["pairs"].items() if cc["active"] or cc["transition"] or cc.get("commit_pending")]
        emit({"status": "preview", "pairs": list(state["pairs"]), "requires_off": pending,
              "legacy_baseline_backups": [str(path) for path in sorted(store.directory.glob("baseline.json.backup-*"))],
              "baseline_backup_recovery": "twinlink system preserve-backups --apply --yes (use the same --state-dir)",
              "resources": Ownership(store).summary(), "next": "Complete profile switch off on both hosts; then uninstall --purge --apply --yes",
              "scope": "Local cleanup only; peer must be cleaned separately"}, args)
        purging = args.purge or args.purge_managed
        if applying and not purging:
            raise ValidationError("Use uninstall --purge --apply after coordinated off")
        if applying and purging:
            if pending:
                raise StateError("Complete coordinated off before full local uninstall: " + ", ".join(pending))
            def purge():
                for pair_id in list(state["pairs"]):
                    delete_pair(store, rt, pair_id)
                result = restore_system(store, rt, dependencies=True)
                if result["conflicts"]:
                    return result
                return remove_program(store, rt)
            result = commit(purge)
            emit(result, args)
            return 4 if result.get("conflicts") else 0
        return 0
    if group == "internal":
        if args.operation == "verification-expire":
            pair, _ = select_pair(state, args.name)
            with store.lock():
                emit(Coordinator(store, rt).expire_verification(pair), args)
            return 0
        if args.operation == "restore":
            with store.lock():
                results = rt.boot()
                failed = any(row["status"] in ("failed", "recovery-required") for row in results)
                emit({"status": "failed" if failed else "complete", "pairs": results}, args)
            return 1 if failed else 0
        if args.operation == "profile-guard":
            pair, c = select_pair(state, args.name)
            a, tx = c["active"], c["transition"]
            preflight_only = tx and tx["phase"] == "preflight" and not tx.get("recovery_of")
            allowed = a and a["profile"] == args.profile and a["revision"] == args.revision and (not tx or preflight_only) and not c.get("commit_pending")
            allowed = allowed or tx and tx["phase"] == "target-starting" and tx["target"] == args.profile and tx["revision"] == args.revision
            if not allowed:
                return 1
            # systemctl start may be waiting while the coordinator holds its
            # mutation lock. Validate files without acquiring or changing it.
            rt.ledger = Ownership(store, read_only=True)
            try:
                rt.check_prepared_launch(store.revision(pair, args.revision), c["role"], args.profile)
            except (StateError, ValidationError, OSError) as exc:
                emit({"status": "failed", "error": str(exc)}, args)
                return 1
            return 0
        raise ValidationError("Legacy boot callbacks are disabled for v2")
    if group == "pair" and action == "delete":
        requested = getattr(args, "pair", None)
        if requested:
            from .models import _name
            requested = _name(requested)
        if requested and (store.directory / "journals" / ("purge-" + requested + ".json")).exists():
            pair = requested
        else:
            pair, _ = select_pair(state, requested)
        emit({"status": "preview", "pair_id": pair, "operation": "Delete owned pair artifacts after completed off; foreign changes block cleanup"}, args)
        if applying:
            from .cleanup import delete_pair
            emit(commit(lambda: delete_pair(store, rt, pair)), args)
        return 0
    pair, c = select_pair(state, getattr(args, "pair", None))
    r, creds, facts = store.revision(pair, c["staged_revision"]), store.credentials(pair), store.facts(pair)
    if group in ("pair", "profile") and action in ("status", "list"):
        emit({"status": "complete", **view(store, pair, c)}, args)
        return 0
    if group == "pair" and action == "export":
        if c["role"] != "vps1":
            raise ValidationError("Shared revisions are authored/exported on VPS1")
        if args.revision is not None:
            number = _integer(args.revision, "revision", 1, c["staged_revision"])
            r, creds = store.revision(pair, number), store.credentials(pair, number)
        code = encode(r, creds)
        result = {"status": "complete", "revision": r["revision"], "fingerprint": fingerprint(code), "contains_secret": True}
        if args.output:
            write_new(args.output, code)
            result["file"] = str(Path(args.output).absolute())
        else:
            result["bundle"] = code
        emit(result, args)
        return 0
    if group == "config" and action == "show":
        emit({"status": "complete", "configuration": r}, args)
        return 0
    if group == "config" and action == "regenerate":
        emit({"status": "preview", "pair_id": pair, "resources": "Refresh local facts, manifests, binary fingerprints and guarded disabled units; runtime unchanged"}, args)
        def regenerate():
            prepared_revision, prepared_credentials = r, creds
            if c["transition"] or c.get("commit_pending"):
                raise StateError("Finish transition first")
            pending = store.pending_stage(pair)
            if pending and "revision_config" in pending:
                prepared_revision, prepared_credentials = pending["revision_config"], pending["credentials"]
            elif c["role"] == "vps1" and r["public_keys"]["noise"] is None and Path(args.rathole_binary).is_file():
                from .rathole import check_version, generate_keypair
                check_version(args.rathole_binary)
                noise = generate_keypair(args.rathole_binary)
                prepared_revision = next_revision(r, public_keys={"noise": noise["noise_public_key"]})
                prepared_credentials = {**creds, "noise_private": noise["noise_private_key"]}
            if c["active"] and c["active"]["revision"] == prepared_revision["revision"]:
                raise StateError("Stage a new revision before regenerating active revision artifacts")
            try:
                local = rt.discover(prepared_revision, c["role"])
            except (ValueError, RuntimeError, OSError, KeyError):
                local = None
            stage(prepared_revision, c["role"], prepared_credentials, local)
            return rt.materialize(prepared_revision, c["role"])
        prepared = commit(regenerate)
        if prepared is not None:
            emit({"status": "complete", "prepared_binaries": list(prepared)}, args)
        return 0
    if group == "profile" and action == "check":
        target = None if args.profile == "off" else args.profile
        rt.ledger = Ownership(store, read_only=True)
        readiness = rt.preflight(r, c["role"], target, c, {}) or {}
        deferred = any(check["result"] == "deferred" for check in readiness.get("backend_checks", []))
        emit({"status": "deferred-local" if deferred else "ready-local", "peer": "unknown", "profile": target, **readiness}, args)
        return 0
    if group == "profile" and action in ("switch", "restart", "reapply"):
        off = action == "switch" and args.profile == "off"
        if action != "switch":
            if c["active"] is None:
                raise ValidationError("No active selection to restart/reapply; use profile switch explicitly")
            r = store.revision(pair, c["active"]["revision"])
        elif off and c["active"]:
            r = store.revision(pair, c["active"]["revision"])
        if args.revision is not None and not off:
            number = _integer(args.revision, "revision", 1, 2147483647)
            if action != "switch" and number != r["revision"]:
                raise StateError("Restart/reapply must use the active revision")
            r = store.revision(pair, number)
        target = (None if args.profile == "off" else args.profile) if action == "switch" else c["active"]["profile"] if c["active"] else None
        incoming = strict_json(read_private(args.receipt_file)) if args.receipt_file else None
        emit({"status": "preview", "pair_id": pair, "target": target, "revision": r["revision"],
              "services": r["services"], "outage": "Existing connections end; VPS1 stops first, then VPS2; both receipts required before target starts",
              "recovery": "recover --pair " + pair, "peer": "Manual receipt coordination"}, args)
        result = commit(lambda: Coordinator(store, rt).advance(pair, r, target, incoming, args.transaction, args.step, operation=action, refresh=args.refresh_receipt))
        if result:
            if args.output and result.get("receipt"):
                write_new(args.output, canonical(result["receipt"]).decode())
                result["receipt_file"] = args.output
                del result["receipt"]
            emit(result, args)
            return 0 if result["status"] == "complete" else 3
        return 0
    if group == "service" and action == "list":
        emit({"status": "complete", "services": r["services"]}, args)
        return 0
    if (group == "service" and action in ("add", "edit", "delete")) or (group == "config" and action == "set"):
        if c["role"] != "vps1":
            raise ValidationError("Shared edits must be authored on VPS1")
        changes = copy.deepcopy(r)
        if group == "config":
            parts = args.field.split(".")
            value = args.value if parts[0] == "public_endpoints" or "addresses" in parts else _integer(args.value, args.field, 1, 4294967295)
            if args.field == "gre.addresses":
                value = strict_json(args.value)
            destination = changes
            for part in parts[:-1]:
                destination = destination[part]
            destination[parts[-1]] = value
        else:
            entries = {s["id"]: s for s in changes["services"]}
            if action == "add" and args.name in entries or action != "add" and args.name not in entries:
                raise ValidationError("Service already exists or does not exist for this operation")
            if action == "delete":
                del entries[args.name]
            else:
                s = entries.get(args.name, {"id": args.name, "bind": r["public_endpoints"]["vps1"], "protocol": "tcp", "ports": None,
                                          "backend": {"target": "vps2-local", "ports": None}, "probe": None})
                for field in ("bind", "protocol", "ports"):
                    if getattr(args, field) is not None:
                        s[field] = getattr(args, field)
                if args.backend_address is not None:
                    s["backend"] = {"target": "address", "address": args.backend_address, "ports": s["backend"]["ports"]}
                elif args.backend_local:
                    s["backend"] = {"target": "vps2-local", "ports": s["backend"]["ports"]}
                if args.backend_ports is not None:
                    s["backend"]["ports"] = args.backend_ports
                if args.probe_request_hex or args.probe_response_hex:
                    s["probe"] = {"kind": "exchange", "request_hex": args.probe_request_hex, "response_hex": args.probe_response_hex}
                entries[args.name] = validate_service(s)
            changes["services"] = list(entries.values())
        changes.pop("revision")
        changes.pop("parent_digest")
        updated = next_revision(r, **changes)
        from .backends import effective
        other = [store.revision(p, cc["staged_revision"]) for p, cc in state["pairs"].items()]
        validate_reservations(updated, other)
        emit({"status": "preview", "configuration": updated, "effective_backends": effective(updated), "runtime": "Active revision retained until coordinated activation",
              "next": "One fresh pair export/import, config regenerate on both hosts, then profile switch"}, args)
        if commit(lambda: stage(updated, c["role"], creds, facts)):
            emit({"status": "complete", "staged_revision": updated["revision"], "active": c["active"]}, args)
        return 0
    if group == "logs":
        from .diagnostics import bounded_command
        limit = _integer(args.limit, "log limit", 1, 200)
        rows = []
        if c["active"]:
            active = store.revision(pair, c["active"]["revision"])
            result = bounded_command(["journalctl", "--no-pager", "-o", "json", "-n", str(limit), "-u", rt.runtime_unit(active, c["active"]["profile"])])
            for line in result["stdout"].splitlines():
                try:
                    row = json.loads(line)
                    rows.append({k: row[k] for k in ("MESSAGE", "PRIORITY", "__REALTIME_TIMESTAMP") if k in row})
                except ValueError:
                    continue
        emit({"status": "complete", "events": Redactor("secrets", stored_secrets(store)).scrub(rows)}, args)
        return 0
    if group in ("recover", "uninstall"):
        if group == "recover" and args.cancel_preflight:
            tx = c["transition"]
            if not tx or tx["phase"] != "preflight" or tx.get("recovery_of") or any(
                    item["body"]["step"] != "preflight" for item in tx["local_completed"].values()):
                raise StateError("Only a non-disruptive preflight can be cancelled locally")
            emit({"status": "preview", "operation": "Cancel local preflight; repeat on peer", "runtime": "unchanged"}, args)
            def cancel():
                updated = copy.deepcopy(state)
                updated["pairs"][pair]["transition"] = None
                store.write(updated)
                return True
            if commit(cancel):
                emit({"status": "complete", "runtime": "unchanged"}, args)
            return 0
        if group == "recover" and args.rollback:
            failed = c["transition"]
            if not failed:
                raise StateError("No interrupted transition to roll back")
            previous = failed["previous"]
            target = previous["profile"] if previous else None
            rollback_revision = store.revision(pair, previous["revision"] if previous else c["staged_revision"])
            incoming = strict_json(read_private(args.receipt_file)) if args.receipt_file else None
            emit({"status": "preview", "operation": "Coordinated rollback", "target": previous,
                  "outage": "Stop target on VPS1 then VPS2, exchange both barriers, restart saved profile and reverify"}, args)
            def rollback():
                coordinator = Coordinator(store, rt)
                if c["role"] == "vps1":
                    if not failed.get("recovery_of"):
                        coordinator.begin_recovery(pair)
                return coordinator.advance(pair, rollback_revision, target, incoming, args.transaction, args.step, operation="recover", refresh=args.refresh_receipt)
            result = commit(rollback)
            if result:
                if args.output and result.get("receipt"):
                    write_new(args.output, canonical(result.pop("receipt")).decode())
                emit(result, args)
                return 0 if result["status"] == "complete" else 3
            return 0
        emit({"status": "recovery-required", "pair_id": pair, "transition": view(store, pair, c)["transition"],
              "next": "Inspect system changes and receipts; automatic local snapshot rollback is disabled for coordinated transitions"}, args)
        return 4
    raise ValidationError("Unsupported v2 operation")


def doctor(args, store):
    from .diagnostics import collect
    from .reports import merge, compare, parse, MAX_REPORT_BYTES
    if args.merge:
        report = merge(*(parse(read_private(p, MAX_REPORT_BYTES)) for p in args.merge))
        report = Redactor(args.redaction, stored_secrets(store)).scrub(report)
        summary = {"level": args.redaction, "context": "private merged-report context; equality only within this export"}
        report["redaction_summary"] = summary
        for original in report["reports"]:
            original["redaction_summary"] = dict(summary)
    else:
        state = store.read()
        pair = args.pair
        if state["version"] == 2 and (pair or len(state["pairs"]) == 1):
            pair, _ = select_pair(state, pair)
        match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([smh]?)", args.watch or "0")
        if not match:
            raise ValidationError("Watch duration must be seconds, 5m, or 1h")
        duration = float(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600}[match[2]]
        if args.preview:
            emit({"status": "preview", "budgets": {"seconds": duration or (60 if args.deep else 15), "command_seconds": 3,
                  "command_bytes": 65536, "concurrency": 4, "sampling_seconds": args.interval}, "redaction": args.redaction}, args)
            return 0
        state = store.read()
        redactor = Redactor(args.redaction, stored_secrets(store))
        report = collect(store, pair, args.deep, duration, args.interval, args.redaction, redactor=redactor)
        if args.capture:
            from .diagnostics import capture_metadata, evidence
            metadata = capture_metadata(args.capture_interface, args.capture_peer, args.capture_port, args.capture_direction)
            import time
            from .diagnostics import utc
            now = time.monotonic()
            report["profile_evidence"].append(redactor.scrub(evidence("scoped-capture", metadata["result"], metadata,
                now - report["collection_window"]["monotonic"]["start"])))
            report["collection_window"]["end"] = utc()
            report["collection_window"]["monotonic"]["end"] = now
            from .diagnostics import cap_report
            report = cap_report(report)
        if args.compare:
            report = compare(parse(read_private(args.compare, MAX_REPORT_BYTES)), report)
    from .diagnostics import cap_report
    report = cap_report(report, envelope={"schema_version": 2, "action": args.group + " " + getattr(args, "action", ""),
                                         "status": report.get("overall_status", "unknown")})
    if args.export:
        write_new(args.export, json.dumps(report, indent=2))
    emit({"status": report.get("overall_status", "unknown"), "report": report}, args)
    return 0 if report.get("overall_status") in ("healthy", "off") else 1 if report.get("overall_status") == "failed" else 3
