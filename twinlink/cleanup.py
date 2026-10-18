"""Off-only, journalled deletion of resources with durable ownership proof."""
import copy
from pathlib import Path

from .contracts import canonical
from .baseline import MAX_BASELINE_ITEMS, serialize as serialize_baseline
from .ownership import Ownership
from .store import StateError, atomic_write, reject_symlink


def restore_packages(store, runtime):
    """Remove exact new packages only after a no-foreign-removals simulation."""
    import re
    baseline_path = store.directory / "baseline.json"
    reject_symlink(baseline_path)
    if not baseline_path.exists():
        return ["Historical installer/package baseline is unknown"]
    baseline = store.baseline()
    conflicts = []
    if baseline.get("historical_baseline") != "recorded":
        conflicts.append("Historical baseline is unknown; original package state cannot be guaranteed")
    delta = baseline.get("package_delta", {})
    if not delta:
        return conflicts
    result = runtime.host.run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\n"], check=False)
    if result["returncode"]:
        return conflicts + ["Package removal simulation is not available for this package manager; dependencies preserved"]
    installed = {r[0]: r[1] for r in (line.split("\t") for line in result["stdout"].splitlines()) if len(r) == 3 and r[2] == "installed"}
    candidates = []
    for name, version in delta.items():
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.:_-]*", name) or name.split(":")[0].startswith("python"):
            conflicts.append("Dependency retained for recovery or invalid package identity: " + name)
        elif name not in installed:
            continue
        elif installed[name] != version:
            conflicts.append("Dependency version changed externally: " + name)
        else:
            candidates.append(name)
    if not candidates:
        return conflicts
    command = ["apt-get", "remove", "--no-auto-remove", "-y", *sorted(candidates)]
    simulation = runtime.host.run(["apt-get", "--simulate", *command[1:]], check=False)
    removals = {line.split()[1] for line in simulation["stdout"].splitlines() if line.startswith("Remv ")}
    if simulation["returncode"] or removals != set(candidates) or any(line.startswith(("Inst ", "Purg ")) for line in simulation["stdout"].splitlines()):
        return conflicts + ["Package removal would affect foreign dependents; dependencies preserved"]
    baseline.setdefault("operations", []).append({"operation": "restore-packages", "status": "pending", "packages": candidates})
    atomic_write(baseline_path, serialize_baseline(baseline))
    runtime.host.run(command)
    current = runtime.host.run(["dpkg-query", "-W", "-f=${binary:Package}\t${db:Status-Status}\n"], check=False)
    if current["returncode"]:
        return conflicts + ["Cannot verify dependency removal; recovery records retained"]
    still_installed = {r[0] for r in (line.split("\t") for line in current["stdout"].splitlines()) if len(r) == 2 and r[1] == "installed"}
    for name in candidates:
        if name in still_installed:
            conflicts.append("Dependency removal not verified: " + name)
        else:
            baseline["package_delta"].pop(name, None)
    baseline["operations"][-1]["status"] = "conflict" if conflicts else "complete"
    atomic_write(baseline_path, serialize_baseline(baseline))
    return conflicts


def restore_system(store, runtime, dependencies=False):
    state = store.read()
    if any(c["active"] or c["transition"] or c.get("commit_pending") for c in state["pairs"].values()):
        raise StateError("Complete coordinated off before restoring system changes")
    ledger = Ownership(store)
    rows = ledger.read()["resources"]
    conflicts = []
    for resource, row in sorted(rows.items(), key=lambda item: item[1]["type"] == "file"):
        if row["status"] == "restored":
            continue
        # release() owns sysctl reconciliation, including reboot resets of a
        # pending shared acquisition. Do not reject it before that check.
        pending_sysctl = row["status"] == "pending" and row["type"] == "sysctl"
        if row["status"] == "pending" and not pending_sysctl:
            try:
                if row["type"] == "unit-enable":
                    observed = runtime.host.unit_status(resource[len("unit-enable:"):])["enabled"]
                elif row["type"] == "file":
                    observed = ledger.file_value(resource[len("file:"):])
                elif row["type"] == "binary":
                    observed = ledger.binary_value(resource[len("binary:"):])
                else:
                    raise StateError("Recover runtime off first: " + resource)
                row = ledger.reconcile(resource, observed, allow_before=True)
            except (StateError, OSError, RuntimeError) as exc:
                conflicts.append(str(exc))
                continue
        if row["status"] not in ("complete", "restoring") and not pending_sysctl:
            conflicts.append(resource + ": unresolved journal/conflict")
            continue
        try:
            if row["type"] == "sysctl":
                key = resource[len("sysctl:"):]
                current = runtime.host.run(["sysctl", "-n", key])["stdout"].strip()
                def restore(before):
                    runtime.host.run(["sysctl", "-w", key + "=" + before])
                    return runtime.host.run(["sysctl", "-n", key])["stdout"].strip()
                for owner in row["owners"]:
                    ledger.release(resource, owner, current, restore)
            elif row["type"] == "unit-enable":
                name = resource[len("unit-enable:"):]
                current = runtime.host.unit_status(name)["enabled"]
                def restore(before):
                    runtime.host.run(["systemctl", "enable" if before else "disable", name])
                    return runtime.host.unit_status(name)["enabled"]
                for owner in row["owners"]:
                    ledger.release(resource, owner, current, restore)
            elif row["type"] == "binary":
                path = Path(resource[len("binary:"):])
                def restore(before):
                    if before is not None:
                        raise StateError("Cannot remove a pre-existing executable: " + str(path))
                    path.unlink(missing_ok=True)
                    return ledger.binary_value(path)
                for owner in row["owners"]:
                    ledger.release(resource, owner, ledger.binary_value(path), restore)
            elif row["type"] == "file":
                path = Path(resource[len("file:"):])
                # Private configs normally remain, but durable restoration
                # intent from interrupted cleanup must also be resumable.
                if row["status"] == "restoring" or store.directory not in path.parents:
                    for owner in row["owners"]:
                        ledger.remove_file(path, owner)
            else:
                conflicts.append(resource + ": runtime resource remains; recover off first")
        except (StateError, OSError, RuntimeError) as exc:
            conflicts.append(str(exc))
    runtime.host.run(["systemctl", "daemon-reload"])
    if dependencies and not conflicts:
        conflicts.extend(restore_packages(store, runtime))
    if dependencies and not conflicts and not state["pairs"]:
        for resource, row in ledger.read()["resources"].items():
            if row["type"] == "file" and row["owners"] == ["installation"] and row["status"] in ("complete", "restoring"):
                ledger.remove_file(Path(resource[len("file:"):]), "installation")
    return {"status": "conflict" if conflicts else "complete", "conflicts": conflicts,
            "configuration": "Pair settings retained; regenerate prepared units before future activation"}


def remove_program(store, runtime):
    """Resume final removal from a private checkpoint, including missing files."""
    import base64
    import hashlib
    from .contracts import strict_json
    executable = Path(runtime.executable)
    launcher = executable.parent.parent / "bin" / "twinlink"
    manifest_path = executable.parent / "twinlink-install.json"
    journal = store.directory / "uninstall.json"
    records = {str(store.directory / name) for name in ("state.json", "ownership.json", "baseline.json", "mutation.lock")}
    programs = {str(launcher), str(executable), str(manifest_path)}
    ledger = Ownership(store)
    reject_symlink(journal)
    if journal.exists():
        checkpoint = store.private_read(journal, 32 * 1024 * 1024, max_items=MAX_BASELINE_ITEMS)
        if (checkpoint.get("version") != 1 or checkpoint.get("operation") != "remove-program"
                or checkpoint.get("executable") != str(executable)
                or set(checkpoint.get("records", {})) != records
                or set(checkpoint.get("program_files", {})) != programs
                or checkpoint.get("status") not in ("verified", "program-removed")):
            raise StateError("Uninstall checkpoint does not match this installation")
        manifest = checkpoint["manifest"]
    else:
        reject_symlink(manifest_path)
        if not manifest_path.is_file():
            raise StateError("Program installation manifest is missing; runtime retained for recovery")
        manifest = strict_json(manifest_path.read_bytes())
        state = store.read()
        if state.get("version") != 2 or state["pairs"]:
            raise StateError("Pair records remain or final v2 state is unavailable; refusing program removal")
        if any(r["status"] != "restored" for r in ledger.read()["resources"].values()):
            raise StateError("Owned resources remain; refusing program removal")
        baseline = store.baseline()
        checkpoint = {"version": 1, "operation": "remove-program", "executable": str(executable),
            "manifest": manifest, "baseline": baseline, "status": "verified",
            "records": {path: ledger.file_value(path) for path in records},
            "program_files": {path: ledger.file_value(path) for path in programs}}
    if manifest.get("owner") != "twinlink" or manifest.get("version") != 1 or set(manifest.get("files", {})) != {str(launcher), str(executable)}:
        raise StateError("Installation manifest does not authenticate this runtime and launcher")
    # Authenticate durable backups too, so a missing installation manifest is
    # recoverable without accepting arbitrary paths or replacement contents.
    for filename, value in checkpoint["program_files"].items():
        if value is not None:
            content = base64.b64decode(value["content"], validate=True)
            if filename in manifest["files"] and hashlib.sha256(content).hexdigest() != manifest["files"][filename]:
                raise StateError("Modified program file retained: " + filename)
            if filename == str(manifest_path) and strict_json(content) != manifest:
                raise StateError("Uninstall manifest checkpoint differs")
    for filename, value in {**checkpoint["records"], **checkpoint["program_files"]}.items():
        observed = ledger.file_value(filename)
        if observed is not None and observed != value:
            raise StateError("Modified file retained during uninstall: " + filename)
    for path in store.directory.rglob("*"):
        reject_symlink(path)
        if path.is_file() and str(path) not in records and path != journal:
            if path.parent == store.directory and path.name.startswith("baseline.json.backup-"):
                raise StateError("Legacy baseline backup retained: " + str(path) +
                    "; run twinlink system preserve-backups --apply --yes using the same --state-dir, then retry uninstall. Contents are preserved outside the state directory")
            raise StateError("Unresolved private artifact retained with runtime: " + str(path))
    if not journal.exists():
        content = canonical(checkpoint)
        strict_json(content, 32 * 1024 * 1024, max_items=MAX_BASELINE_ITEMS)
        atomic_write(journal, content)
    baseline = checkpoint["baseline"]
    try:
        # Keep all private records until every program removal has succeeded.
        # The checkpoint retains authenticated copies for process-death recovery.
        for path in (launcher, manifest_path, executable):
            path.unlink(missing_ok=True)
        checkpoint["status"] = "program-removed"
        atomic_write(journal, canonical(checkpoint))
        for filename in sorted(records):
            Path(filename).unlink(missing_ok=True)
        for directory in sorted((p for p in store.directory.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
            directory.rmdir()
        for directory in (launcher.parent, executable.parent, executable.parent.parent):
            original = baseline.get("directories", {}).get(str(directory), {})
            if original.get("existed") is False and directory.is_dir() and not any(directory.iterdir()):
                directory.rmdir()
        journal.unlink()
        if baseline.get("directories", {}).get(str(store.directory), {}).get("existed") is False:
            store.directory.rmdir()
    except BaseException:
        # Catchable interruptions and I/O failures restore the recovery command
        # before propagating the original error to the caller.
        # An uncatchable process death is resumed from the durable checkpoint.
        for filename, value in {**checkpoint["records"], **checkpoint["program_files"]}.items():
            try:
                if value is not None and ledger.file_value(filename) is None:
                    atomic_write(filename, base64.b64decode(value["content"], validate=True), value["mode"])
            except (OSError, StateError):
                pass  # Keep the checkpoint even if the filesystem is unavailable.
        try:
            atomic_write(journal, canonical(checkpoint))
        except OSError:
            pass
        raise
    return {"status": "complete", "program": "Owned launcher/runtime and private records removed", "peer": "Local completion only; peer cleanup remains separate"}


def delete_pair(store, runtime, pair):
    state = store.read()
    journal = store.directory / "journals" / ("purge-" + pair + ".json")
    reject_symlink(journal)
    pending = store.private_read(journal, 4 * 1024 * 1024) if journal.exists() else None
    control = state["pairs"].get(pair) or (pending or {}).get("state_before", {}).get("pairs", {}).get(pair)
    if not control:
        raise StateError("No pair or resumable deletion journal")
    if control["active"] or control["transition"] or control.get("commit_pending"):
        raise StateError("Complete coordinated off before deleting pair resources")
    ledger = Ownership(store)
    # A crash after a file/enablement mutation but before its completion record
    # is recoverable from the exact saved before/expected observation.
    for resource, row in ledger.read()["resources"].items():
        if pair in row["owners"] and row["status"] == "pending":
            if row["type"] == "file":
                ledger.reconcile(resource, ledger.file_value(resource[len("file:"):]), allow_before=True)
            elif row["type"] == "unit-enable":
                ledger.reconcile(resource, runtime.host.unit_status(resource[len("unit-enable:"):])["enabled"], allow_before=True)
    rows = {key: row for key, row in ledger.read()["resources"].items() if pair in row["owners"] or pending and key in pending["resources"]}
    if any(row["status"] not in ("complete", "restored", "restoring") for row in rows.values()):
        raise StateError("Unresolved ownership conflicts/pending operations retain recovery data")
    # Full validation precedes the first deletion, including foreign edits.
    for resource, row in rows.items():
        if row["status"] == "restored":
            if row["type"] == "file" and ledger.file_value(resource[len("file:"):]) != row["before"]:
                raise StateError("Foreign file appeared after restoration: " + resource)
            continue
        if row["type"] == "file":
            path = Path(resource[len("file:"):])
            if row["status"] == "restoring" and ledger.file_value(path) == row["before"]:
                continue
            ledger.check(resource, ledger.file_value(path), allow_restoring=True)
            if path.suffix in (".service", ".timer"):
                status = runtime.assert_unit_safe(path.name, allow_restoring=True)
                if status["active"] and path.name != "twinlink-v2-restore.service":
                    raise StateError("Unexpected active unit; recover off before deletion")
        elif row["type"] == "unit-enable":
            unit = resource[len("unit-enable:"):]
            ledger.check(resource, runtime.host.unit_status(unit)["enabled"], allow_restoring=True)
        else:
            raise StateError("Owned runtime resource remains after off: " + resource)
    root = store.directory / "revisions" / pair
    expected_paths = {Path(k[len("file:"):]) for k in rows if k.startswith("file:")}
    expected_dirs = {parent for path in expected_paths for parent in path.parents if parent == root or root in parent.parents}
    if root.exists():
        for path in root.rglob("*"):
            reject_symlink(path)
            if path.is_dir() and path not in expected_dirs or not path.is_dir() and path not in expected_paths:
                raise StateError("Untracked pair path retained during cleanup: " + str(path))
    if not pending:
        atomic_write(journal, canonical({"pair_id": pair, "operation": "delete", "resources": sorted(rows), "state_before": state}))
    for resource, row in rows.items():
        if row["type"] == "unit-enable" and pair in row["owners"]:
            unit = resource[len("unit-enable:"):]
            def restore(before):
                runtime.host.run(["systemctl", "enable" if before else "disable", unit])
                return runtime.host.unit_status(unit)["enabled"]
            ledger.release(resource, pair, runtime.host.unit_status(unit)["enabled"], restore)
    for resource, row in rows.items():
        if row["type"] == "file" and pair in row["owners"]:
            ledger.remove_file(Path(resource[len("file:"):]), pair)
    runtime.host.run(["systemctl", "daemon-reload"])
    # Remove empty generated directories only. An unknown file is a conflict,
    # not permission to recursively delete an operator's content.
    reject_symlink(root)
    if root.exists():
        paths = sorted(root.rglob("*"), key=lambda p: len(p.parts), reverse=True)
        for path in paths:
            reject_symlink(path)
            if path.is_dir():
                path.rmdir()
            else:
                raise StateError("Untracked pair file retained during cleanup: " + str(path))
        root.rmdir()
    new = copy.deepcopy(state)
    new["pairs"].pop(pair, None)
    store.write(new)
    # Delete ledger bodies containing this pair's secret configs once restored.
    data = ledger.read()
    for resource in rows:
        row = data["resources"].get(resource)
        if row and row["status"] == "restored" and not row["owners"]:
            del data["resources"][resource]
    ledger.save(data)
    journal.unlink()
    return {"status": "complete", "pair_id": pair, "peer": "Local cleanup complete; delete separately on the peer"}
