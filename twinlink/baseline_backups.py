"""Explicit preservation of legacy snapshots; never use them as restore authority."""
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

from .baseline import MAX_BASELINE_BYTES, parse
from .contracts import fields
from .store import StateError, reject_symlink

LEGACY_NAME = re.compile(r"baseline\.json\.backup-[0-9]{19}\Z")
ORIGINAL_FIELDS = ("version", "installation_id", "created_at", "historical_baseline",
                   "directories", "packages_before", "python")


def _read(path):
    reject_symlink(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid():
        raise StateError("Baseline backup must be a regular mode-0600 file owned by the current root user: " + str(path))
    if info.st_size > MAX_BASELINE_BYTES:
        raise StateError("Baseline backup exceeds the size limit: " + str(path))
    with path.open("rb") as stream:
        data = stream.read(MAX_BASELINE_BYTES + 1)
    if len(data) > MAX_BASELINE_BYTES:
        raise StateError("Baseline backup exceeds the size limit: " + str(path))
    return data


def _validate(data, baseline):
    snapshot = parse(data)
    fields(snapshot, (*ORIGINAL_FIELDS, "package_delta", "operations"))
    if type(snapshot["version"]) is not int or snapshot["version"] != 1:
        raise StateError("Unsupported baseline backup version")
    try:
        uuid.UUID(snapshot["installation_id"])
    except (TypeError, ValueError, AttributeError):
        raise StateError("Invalid installation identity in baseline backup") from None
    if any(snapshot[key] != baseline.get(key) for key in ORIGINAL_FIELDS):
        raise StateError("Baseline backup original facts differ from this installation")
    if (snapshot["historical_baseline"] not in ("recorded", "unknown")
            or type(snapshot["created_at"]) not in (int, float) or snapshot["created_at"] < 0
            or not isinstance(snapshot["directories"], dict) or not snapshot["directories"]):
        raise StateError("Malformed baseline backup original facts")
    for path, value in snapshot["directories"].items():
        fields(value, ("existed", "mode"))
        if not Path(path).is_absolute() or type(value["existed"]) is not bool or not (
                value["mode"] is None or type(value["mode"]) is int and 0 <= value["mode"] <= 0o777):
            raise StateError("Malformed baseline backup directory facts")
    fields(snapshot["python"], ("path", "pre_existing"))
    if not isinstance(snapshot["python"]["path"], str) or not Path(snapshot["python"]["path"]).is_absolute() or type(snapshot["python"]["pre_existing"]) is not bool:
        raise StateError("Malformed baseline backup Python facts")
    for name in ("packages_before", "package_delta"):
        inventory = snapshot[name]
        if inventory is None and name == "packages_before":
            continue
        if not isinstance(inventory, dict) or not all(isinstance(name, str) and isinstance(version, str) for name, version in inventory.items()):
            raise StateError("Malformed baseline backup package inventory")
    if not isinstance(snapshot["operations"], list) or any(
            not isinstance(op, dict) or op.get("operation") not in ("install", "restore-packages")
            or op.get("status") not in ("pending", "interrupted", "complete", "conflict") for op in snapshot["operations"]):
        raise StateError("Malformed baseline backup operation history")


def plan(store):
    """Read-only preview; only exact legacy leaf names are eligible."""
    reject_symlink(store.directory)
    if not store.directory.exists():
        return []
    directory = store.directory.resolve(strict=True)
    candidates = sorted(directory.glob("baseline.json.backup-*"))
    if len(candidates) > 64:
        raise StateError("At most 64 legacy baseline backups can be preserved at once")
    if not candidates:
        return []
    baseline = store.baseline()
    prefix = ".twinlink-baseline-" + hashlib.sha256(str(directory).encode()).hexdigest()[:16]
    rows = []
    for path in candidates:
        if not LEGACY_NAME.fullmatch(path.name):
            raise StateError("Unrecognized baseline backup filename retained: " + str(path))
        data = _read(path)
        _validate(data, baseline)
        target = directory.parent / (prefix + ".backup-" + path.name.split("backup-", 1)[1] + ".json")
        reject_symlink(target)
        if target.exists() and _read(target) != data:
            raise StateError("Modified/different baseline backup destination retained: " + str(target))
        rows.append({"source": str(path), "destination": str(target), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    return rows


def _sync(directory):
    descriptor = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def preserve(store):
    """Caller holds Store.lock(). Publish a durable copy before unlinking source.

    Retry accepts an identical already-published copy; it never overwrites it.
    No historical digest exists, so snapshots are preserved as data, not adopted.
    """
    rows = plan(store)
    for row in rows:
        source, target = Path(row["source"]), Path(row["destination"])
        data = _read(source)
        if hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise StateError("Baseline backup changed after validation; source retained")
        reject_symlink(target)
        if not target.exists():
            descriptor, temporary = tempfile.mkstemp(prefix=".twinlink-baseline-copy-", dir=target.parent)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(temporary, target)
                except FileExistsError:
                    pass  # Validate any raced publication before touching source.
            finally:
                Path(temporary).unlink(missing_ok=True)
        if _read(target) != data or _read(source) != data:
            raise StateError("Baseline backup changed during preservation; source retained")
        _sync(target.parent)
        source.unlink()
        _sync(source.parent)
    return {"status": "complete", "preserved_baseline_backups": rows,
            "policy": "Byte-for-byte private copies retained outside the state directory; never deleted by purge"}
