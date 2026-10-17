"""Durable before/after ledger with conditional, conflict-aware restoration."""
import base64
import copy
import hashlib
from pathlib import Path
import time

from .contracts import canonical, digest
from .store import atomic_write, reject_symlink, StateError

MAX_LEDGER_BYTES = 4 * 1024 * 1024
RECOVERY_RESERVE_BYTES = 512 * 1024
# Read older unbounded writers only far enough to compact their duplicate file
# snapshots. All new writes must fit the normal recovery reader's budget.
MAX_LEGACY_LEDGER_BYTES = 64 * 1024 * 1024
MAX_LEDGER_ITEMS = 16384


class Ownership:
    def __init__(self, store, read_only=False):
        self.store = store
        self.read_only = read_only
        self.path = store.directory / "ownership.json"

    def read(self):
        reject_symlink(self.path)
        ledger = self.store.private_read(self.path, MAX_LEGACY_LEDGER_BYTES, max_items=MAX_LEDGER_ITEMS) if self.path.exists() else {"version": 1, "resources": {}}
        for row in ledger["resources"].values():
            if row["type"] == "file":
                for field in ("after", "observed_before"):
                    row[field] = self.evidence("file", row[field])
        return ledger

    def save(self, ledger, *, new_resource=None):
        if self.read_only:
            raise StateError("Ownership reconciliation requires a locked lifecycle operation; profile check is read-only")
        content = canonical(ledger)
        limit = MAX_LEDGER_BYTES
        if new_resource is not None:
            path = Path(new_resource[len("file:"):]) if new_resource.startswith("file:") else None
            recovery_record = path is not None and path.parent == self.store.directory / "journals" and path.name.startswith(("receipt-", "recovery-", "withdrawal-"))
            if not recovery_record:
                limit -= RECOVERY_RESERVE_BYTES
        if len(content) > limit or len(ledger["resources"]) > MAX_LEDGER_ITEMS:
            raise StateError("Ownership ledger capacity exceeded; no resource mutation performed")
        atomic_write(self.path, content)

    @staticmethod
    def evidence(kind, value):
        # Restoration needs the original bytes only. Read-back needs a digest
        # and mode, including when retrying a legacy inline file observation.
        if kind == "file" and isinstance(value, dict) and "content" in value:
            return {"sha256": hashlib.sha256(base64.b64decode(value["content"], validate=True)).hexdigest(), "mode": value["mode"]}
        return value

    @staticmethod
    def boot_id():
        try:
            return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except OSError:
            return None

    def begin(self, resource, kind, owner, before, expected, restore):
        ledger = self.read()
        old = ledger["resources"].get(resource)
        if old and old["status"] == "pending":
            self.reconcile(resource, before, allow_before=True)
            ledger = self.read()
            old = ledger["resources"][resource]
        if old and old["status"] != "restored":
            rebooted = (kind in ("link", "nft", "sysctl") and self.boot_id() is not None
                        and old.get("boot_id") is not None and old["boot_id"] != self.boot_id()
                        and before == old["before"])
            if old["status"] != "complete" or (old["after"] != self.evidence(kind, before) and not rebooted):
                raise StateError("Owned resource changed or has incomplete journal: " + resource)
            original, owners = old["before"], set(old["owners"])
        else:
            original, owners = copy.deepcopy(before), set()
        owners.add(owner)
        ledger["resources"][resource] = {"resource": resource, "type": kind, "owners": sorted(owners),
            "before": original, "after": self.evidence(kind, expected), "restore": restore, "status": "pending",
            "observed_before": self.evidence(kind, before), "operation_time": time.time(), "ownership_proof": digest(expected)}
        ledger["resources"][resource]["boot_id"] = self.boot_id()
        self.save(ledger, new_resource=resource if old is None else None)

    def retire_absent(self, resource, owner):
        """An already-absent dedicated ephemeral resource needs no host change."""
        ledger = self.read()
        row = ledger["resources"].get(resource)
        if row and row["type"] in ("link", "nft") and row["before"] is None and row["owners"] == [owner] and row["status"] in ("complete", "restoring", "pending"):
            row["status"], row["owners"] = "restored", []
            self.save(ledger)

    def complete(self, resource, observed):
        ledger = self.read()
        row = ledger["resources"][resource]
        observed = self.evidence(row["type"], observed)
        if observed != row["after"]:
            row["status"] = "conflict"
            self.save(ledger)
            raise StateError("Resource failed read-back: " + resource)
        row["status"] = "complete"
        self.save(ledger)

    def reconcile(self, resource, observed, allow_before=False):
        """Resolve an interrupted mutation only from its durable observations.

        The intended result proves completion; the saved pre-mutation value
        permits retry/withdrawal. A third value is always a conflict. Runtime
        adapters must verify descriptor-based link/nft intents before binding.
        """
        ledger = self.read()
        row = ledger["resources"].get(resource)
        if not row or row["status"] != "pending":
            return row
        observed = self.evidence(row["type"], observed)
        if observed == row["after"]:
            row["status"] = "complete"
        elif observed == row["observed_before"]:
            if not allow_before:
                raise StateError("Mutation not applied; retry or withdraw " + resource)
            row["after"], row["status"] = copy.deepcopy(observed), "complete"
        else:
            row["status"] = "conflict"
            self.save(ledger)
            raise StateError("Pending resource differs from before/expected; preserving " + resource)
        self.save(ledger)
        return row

    def bind_expected(self, resource, observed, proof=None):
        """Adapter has proved the live object matches its persisted descriptor."""
        ledger = self.read()
        row = ledger["resources"][resource]
        if row["status"] != "pending":
            raise StateError("Cannot bind an operation without pending intent")
        row["after"] = self.evidence(row["type"], copy.deepcopy(observed))
        if proof is not None:
            row["ownership_proof"] = proof
        self.save(ledger)
        self.complete(resource, observed)

    def check(self, resource, observed, *, allow_restoring=False):
        """Cleanup may validate original/applied values of restoring records."""
        row = self.reconcile(resource, observed)
        if row and allow_restoring and row["status"] == "restoring":
            if observed == row["before"] or self.evidence(row["type"], observed) == row["after"]:
                return row
        if not row or row["status"] != "complete" or row["after"] != self.evidence(row["type"], observed):
            raise StateError("Ownership/read-back conflict; preserving " + resource)
        return row

    def release(self, resource, owner, observed, restore):
        ledger = self.read()
        row = ledger["resources"].get(resource)
        if not row or row["status"] == "restored":
            return
        if owner not in row["owners"]:
            raise StateError("Resource is owned by another pair: " + resource)
        boot = self.boot_id()
        if (row["type"] == "sysctl" and row["status"] in ("pending", "complete", "restoring")
                and boot is not None and row.get("boot_id") is not None and boot != row["boot_id"]
                and observed == row["before"]):
            # Volatile settings can reset at boot. The original value is
            # already present: release this owner without a host write or
            # discarding another pair's reference. Keep the mutation's boot ID.
            row["owners"] = [o for o in row["owners"] if o != owner]
            row["status"] = "complete" if row["owners"] else "restored"
            self.save(ledger)
            return
        self.reconcile(resource, observed, allow_before=True)
        ledger = self.read()
        row = ledger["resources"].get(resource)
        if not row or row["status"] == "restored":
            return
        if owner not in row["owners"]:
            raise StateError("Resource is owned by another pair: " + resource)
        if row["status"] == "restoring" and observed == row["before"]:
            row["status"], row["owners"] = "restored", []
            self.save(ledger)
            return
        if row["status"] not in ("complete", "restoring") or self.evidence(row["type"], observed) != row["after"]:
            row["status"] = "conflict"
            self.save(ledger)
            raise StateError("Third-party change or interrupted operation; preserving " + resource)
        others = [o for o in row["owners"] if o != owner]
        if others:
            row["owners"] = others
            self.save(ledger)
            return
        row["status"] = "restoring"
        self.save(ledger)
        restored = restore(row["before"])
        if restored != row["before"]:
            row["status"] = "conflict"
            self.save(ledger)
            raise StateError("Restoration failed: " + resource)
        row["status"], row["owners"] = "restored", []
        self.save(ledger)

    @staticmethod
    def file_value(path):
        path = Path(path)
        reject_symlink(path)
        if not path.exists():
            return None
        if not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
            raise StateError("Not a bounded regular owned file: " + str(path))
        return {"content": base64.b64encode(path.read_bytes()).decode(), "mode": path.stat().st_mode & 0o777}

    def write_file(self, path, content, owner, mode=0o600):
        path = Path(path)
        before = self.file_value(path)
        resource = "file:" + str(path)
        expected = {"content": base64.b64encode(content.encode()).decode(), "mode": mode}
        old = self.read()["resources"].get(resource)
        if before is not None and (not old or old["status"] == "restored"):
            raise StateError("Refusing to replace foreign file: " + str(path))
        if old and old["status"] == "complete" and old["after"] == self.evidence("file", before) == self.evidence("file", expected) and owner in old["owners"]:
            return
        self.begin(resource, "file", owner, before, expected, "restore-file")
        atomic_write(path, content, mode)
        self.complete(resource, self.file_value(path))

    def remove_file(self, path, owner):
        path = Path(path)
        def restore(before):
            if before is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, base64.b64decode(before["content"]), before["mode"])
            return self.file_value(path)
        self.release("file:" + str(path), owner, self.file_value(path), restore)

    def adopt(self, resource, kind, owners, observed, provenance):
        """Adopt an exactly regenerated v1 artifact, never a historical baseline.

        These application outputs are deleted at retirement. Package/sysctl
        baselines remain unknown; a marker alone is insufficient proof.
        """
        ledger = self.read()
        old = ledger["resources"].get(resource)
        if old and old["status"] != "restored":
            self.check(resource, observed)
            if set(old["owners"]) != set(owners):
                raise StateError("Legacy adoption owner conflict: " + resource)
            return
        ledger["resources"][resource] = {"resource": resource, "type": kind, "owners": sorted(owners),
            "before": None, "observed_before": self.evidence(kind, observed), "after": self.evidence(kind, observed), "status": "pending",
            "restore": "delete-proven-legacy-output", "operation_time": time.time(), "boot_id": self.boot_id(),
            "ownership_proof": digest(provenance), "provenance": provenance, "historical_baseline": "unknown"}
        self.save(ledger, new_resource=resource if old is None else None)
        self.complete(resource, observed)

    def summary(self):
        # Never expose baseline file bodies or credentials.
        return [{k: copy.deepcopy(row[k]) for k in ("resource", "type", "owners", "status", "operation_time", "ownership_proof")}
                for row in self.read()["resources"].values()]
