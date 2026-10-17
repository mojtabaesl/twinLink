"""Private, atomic state and a process-wide network mutation lock."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import platform
import stat
import tempfile
import time


class StateError(RuntimeError):
    pass


def reject_symlink(path):
    path = Path(path)
    for part in (path, *path.parents):
        if part.is_symlink():
            raise StateError("Refusing symlink: " + str(part))


def atomic_write(path, content, mode=0o600):
    path = Path(path)
    reject_symlink(path)
    missing = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)
    data = content.encode() if isinstance(content, str) else content
    fd, temp = tempfile.mkstemp(prefix=".twinlink-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


class Store:
    def __init__(self, directory="/var/lib/twinlink"):
        self.directory = Path(directory).absolute()
        self.path = self.directory / "state.json"
        self.journal = self.directory / "transaction.json"

    def read(self):
        from .models import empty_state, validate_state
        reject_symlink(self.path)
        if not self.path.exists():
            return empty_state()
        if self.path.stat().st_mode & 0o077:
            raise StateError("State contains secrets; chmod 600 " + str(self.path))
        try:
            from .contracts import strict_json
            with self.path.open("rb") as stream:
                state = strict_json(stream.read(4 * 1024 * 1024 + 1), 4 * 1024 * 1024)
            normalized = validate_state(state)
            for key in ("_nft_fingerprint", "_rules_digest"):
                if key in state:
                    if state[key] is not None and not isinstance(state[key], str):
                        raise ValueError("invalid verification metadata")
                    normalized[key] = state[key]
            return normalized
        except (ValueError, KeyError, TypeError) as exc:
            raise StateError("Invalid state; restore a known good backup: " + str(exc)) from exc

    def write(self, state):
        atomic_write(self.path, json.dumps(state, indent=2, sort_keys=True) + "\n")

    def private_read(self, path, limit=65536, *, max_items=1024):
        from .contracts import strict_json
        path = Path(path)
        reject_symlink(path)
        if not path.is_file() or path.stat().st_mode & 0o077:
            raise StateError("Private regular mode-0600 file required: " + str(path))
        with path.open("rb") as stream:
            return strict_json(stream.read(limit + 1), limit, max_items=max_items)

    def revision_path(self, pair_id, revision):
        from .models import _name, _integer
        return self.directory / "revisions" / _name(pair_id) / str(_integer(revision, "revision", 1, 2147483647))

    def revision(self, pair_id, revision):
        from .contracts import validate_revision
        from .pair_bundle import MAX_DECODED
        value = validate_revision(self.private_read(self.revision_path(pair_id, revision) / "pair.json", MAX_DECODED))
        if value["pair_id"] != pair_id or value["revision"] != revision:
            raise StateError("Revision identity does not match its storage path")
        return value

    def baseline(self):
        from .baseline import MAX_BASELINE_BYTES, MAX_BASELINE_ITEMS
        return self.private_read(self.directory / "baseline.json", MAX_BASELINE_BYTES, max_items=MAX_BASELINE_ITEMS)

    def credential_path(self, pair_id, revision):
        return self.revision_path(pair_id, revision) / "credentials.json"

    def credentials(self, pair_id, revision=None):
        from .models import _name
        if revision is None:
            state = self.read()
            if state["version"] == 2 and pair_id in state["pairs"]:
                revision = state["pairs"][pair_id]["staged_revision"]
        if revision is not None:
            path = self.credential_path(pair_id, revision)
            reject_symlink(path)
            if path.exists():
                return self.private_read(path)
        return self.private_read(self.directory / "secrets" / (_name(pair_id) + ".json"))

    def pending_stage(self, pair_id):
        from .models import _name
        path = self.directory / "journals" / ("stage-" + _name(pair_id) + ".json")
        reject_symlink(path)
        if not path.exists():
            return None
        pending = self.private_read(path, 4 * 1024 * 1024)
        current = self.read()
        if pending.get("state_before") != current and pending.get("state_after") != current:
            raise StateError("Staging journal no longer matches current state; recover explicitly")
        return pending

    def facts_path(self, pair_id, revision):
        return self.revision_path(pair_id, revision) / "local-facts.json"

    def preparation_path(self, pair_id, revision):
        return self.revision_path(pair_id, revision) / "prepared.json"

    def facts(self, pair_id, revision=None):
        from .models import _name
        state = self.read()
        if revision is None and state["version"] == 2 and pair_id in state["pairs"]:
            revision = state["pairs"][pair_id]["staged_revision"]
        if revision is not None:
            path = self.facts_path(pair_id, revision)
            reject_symlink(path)
            if path.exists():
                return self.private_read(path)
            # Legacy pair-wide facts are usable only with matching preparation
            # evidence. A newer preparation must never be borrowed for rollback.
            prepared = self.directory / "local" / (_name(pair_id) + "-prepared.json")
            reject_symlink(prepared)
            if not prepared.exists():
                return None
            from .contracts import digest
            if self.private_read(prepared).get("config_digest") != digest(self.revision(pair_id, revision)):
                return None
        path = self.directory / "local" / (_name(pair_id) + ".json")
        reject_symlink(path)
        return self.private_read(path) if path.exists() else None

    def stage(self, state, revision, role, credentials, facts=None, commit_state=True):
        """Caller holds lock. Files precede the sole authoritative state commit.

        Interrupted staging leaves immutable orphan artifacts, never active runtime.
        Retrying identical content safely completes their state pointer.
        """
        import copy
        from .contracts import (digest, empty_v2, validate_revision, validate_reservations,
                                validate_v2_state, canonical)
        from .models import ValidationError
        from .profiles import manifests
        from .ownership import Ownership
        revision = validate_revision(revision)
        if role not in ("vps1", "vps2"):
            raise ValidationError("Invalid local role")
        # Reject unreadable/untransferable revisions before any journal,
        # retirement or state mutation. The complete bundle includes overhead
        # and shared credentials beyond the canonical revision itself.
        from .contracts import strict_json
        from .pair_bundle import encode, MAX_DECODED
        strict_json(canonical(revision), MAX_DECODED)
        encode(revision, credentials)
        if state["version"] == 1:
            if state["tunnels"] or state["forwards"]:
                raise StateError("Use explicit config migrate for a v1 installation")
            baseline_path = self.directory / "baseline.json"
            reject_symlink(baseline_path)
            installation_id = self.baseline().get("installation_id") if baseline_path.exists() else None
            new = empty_v2(installation_id)
        else:
            new = copy.deepcopy(validate_v2_state(state))
        pair_id, number = revision["pair_id"], revision["revision"]
        control = new["pairs"].get(pair_id)
        initial_noise = False
        if control:
            if control["transition"] or control.get("commit_pending"):
                raise StateError("Finish or recover the pair transition before staging")
            if control["role"] != role:
                raise StateError("Import cannot change the local role")
            latest = self.revision(pair_id, control["staged_revision"])
            if number < latest["revision"] or (number == latest["revision"] and digest(latest) != digest(revision)):
                raise StateError("Older or same-revision/different-content import")
            if number > latest["revision"] and (number != latest["revision"] + 1 or revision["parent_digest"] != digest(latest)):
                raise StateError("Revision lineage fork or missing immediate parent")
            old_credentials = self.credentials(pair_id)
            if old_credentials != credentials:
                initial_noise = ("noise_private" not in old_credentials and set(credentials) == set(old_credentials) | {"noise_private"}
                    and all(credentials[k] == v for k, v in old_credentials.items()) and latest["public_keys"]["noise"] is None
                    and revision["public_keys"]["noise"] is not None and number == latest["revision"] + 1)
                if not initial_noise:
                    raise StateError("Credential replacement requires an authenticated rotation protocol")
            if control["active"] and number == control["active"]["revision"] and facts != self.facts(pair_id, number):
                raise StateError("Cannot regenerate active revision local facts; stage a new revision")
        others = []
        for key, value in new["pairs"].items():
            for n in {value["staged_revision"], *((value["active"]["revision"],) if value["active"] else ())}:
                others.append(self.revision(key, n))
        validate_reservations(revision, others)
        root = self.revision_path(pair_id, number)
        pair_path = root / "pair.json"
        reject_symlink(pair_path)
        if pair_path.exists() and canonical(self.private_read(pair_path)) != canonical(revision):
            raise StateError("Immutable revision already exists with different content")
        rendered = manifests(revision, role, credentials, facts, new["installation_id"])
        self.retire_revision_artifacts(new, pair_id, preserve={number})
        new["pairs"][pair_id] = {**(control or {"role": role, "author": "vps1", "active": None,
            "last_good": None, "transition": None, "peer_observations": [], "epoch": 0}), "staged_revision": number}
        # Preparation journal is durable before creating revision/secrets paths.
        journal = self.directory / "journals" / ("stage-" + pair_id + ".json")
        atomic_write(journal, canonical({"operation": "stage", "pair_id": pair_id,
            "revision": number, "digest": digest(revision), "state_before": state,
            "revision_config": revision, "credentials": credentials, "role": role, "facts": facts, "state_after": new}))
        ledger = Ownership(self)
        def owned(path, content):
            ledger.write_file(path, content.decode() if isinstance(content, bytes) else content, pair_id)
        owned(pair_path, canonical(revision))
        secret_path = self.credential_path(pair_id, number)
        reject_symlink(secret_path)
        if secret_path.exists() and self.private_read(secret_path) != credentials:
            raise StateError("Existing credentials differ; refusing overwrite")
        owned(secret_path, canonical(credentials))
        owned(self.facts_path(pair_id, number), canonical(facts))
        for profile, manifest in rendered.items():
            directory = root / role / profile
            for filename, content in manifest["files"].items():
                owned(directory / filename, content)
            owned(directory / "manifest.json", canonical({k: v for k, v in manifest.items() if k != "files"}))
        if commit_state:
            self.write(new)
            self.retire_revision_artifacts(new, pair_id)
        journal.unlink()
        return new

    def retire_revision_artifacts(self, state, pair_id, preserve=()):
        """Retain exportable history, but retire obsolete generated outputs.

        Only unreferenced revisions are eligible. Canonical settings, role
        credentials and local facts remain available for sequential export.
        Active, staged, last-good and interrupted transition revisions are kept.
        Every unlink uses the ledger's conditional restoration/read-back.
        """
        from .ownership import Ownership
        control = state["pairs"].get(pair_id)
        if not control or control["transition"] or control.get("commit_pending"):
            return
        retained = {control["staged_revision"], *preserve}
        for selection in (control["active"], control["last_good"]):
            if selection:
                retained.add(selection["revision"])
        root = self.revision_path(pair_id, 1).parent
        reject_symlink(root)
        if not root.exists():
            return
        ledger = Ownership(self)
        for revision in root.iterdir():
            reject_symlink(revision)
            if not revision.is_dir() or not revision.name.isdigit() or int(revision.name) in retained:
                continue
            rows = ledger.read()["resources"]
            retired = []
            for resource, row in rows.items():
                if row["type"] != "file":
                    continue
                path = Path(resource[len("file:"):])
                if revision not in path.parents or path.parent == revision and path.name in ("pair.json", "credentials.json", "local-facts.json"):
                    continue
                if row["owners"] not in ([pair_id], []) or row["before"] is not None:
                    raise StateError("Obsolete revision has foreign ownership: " + resource)
                if row["status"] == "restored":
                    if ledger.file_value(path) is not None:
                        raise StateError("Foreign file appeared after revision retirement: " + resource)
                else:
                    ledger.remove_file(path, pair_id)
                retired.append(resource)
            # A crash before this checkpoint leaves restored records to retry.
            data = ledger.read()
            for resource in retired:
                del data["resources"][resource]
            ledger.save(data)
            for path in sorted(revision.rglob("*"), key=lambda p: len(p.parts), reverse=True):
                reject_symlink(path)
                if path.is_dir() and not any(path.iterdir()):
                    path.rmdir()

    @contextlib.contextmanager
    def lock(self, timeout=20):
        reject_symlink(self.directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if stat.S_IMODE(self.directory.stat().st_mode) & 0o077:
            raise StateError("State directory must be private: chmod 700 " + str(self.directory))
        lock_path = self.directory / "mutation.lock"
        reject_symlink(lock_path)
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        deadline = time.monotonic() + timeout
        global_fd = None
        try:
            # All installations in a host network namespace share the same
            # firewall namespace. Serialize even different --state-dir callers.
            if platform.system() == "Linux" and os.geteuid() == 0:
                global_path = Path("/run/lock/twinlink.lock")
                reject_symlink(global_path)
                global_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                global_fd = os.open(str(global_path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                if os.fstat(global_fd).st_uid != 0:
                    raise StateError("Global mutation lock is not root-owned")
                while True:
                    try:
                        fcntl.flock(global_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise StateError("Another host network mutation holds the global lock; retry later")
                        time.sleep(0.1)
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise StateError("Another network mutation holds the lock; retry later")
                    time.sleep(0.1)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
            if global_fd is not None:
                fcntl.flock(global_fd, fcntl.LOCK_UN)
                os.close(global_fd)
