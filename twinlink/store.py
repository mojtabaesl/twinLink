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
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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
            state = json.loads(self.path.read_text())
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
