"""Small filesystem helpers for the local gate state (attestation, spend ledger).

* ``gate_state_dir`` anchors that state to a fixed per-user location, never the
  current directory: a cloned repository that ships its own ``.bughunt/`` must
  not be able to supply a forged attestation or budget.
* ``file_lock`` is an OS-level cross-process lock (released automatically if the
  holder crashes), so concurrent runs cannot both spend the last request.
* ``write_json_atomic`` writes to a unique temp file, fsyncs, then replaces.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
import time

LOCK_TIMEOUT_SECONDS = 10.0


def gate_state_dir() -> Path:
    """``BUGHUNT_HOME`` if set, otherwise ``~/.bughunt``; always absolute."""
    configured = os.environ.get("BUGHUNT_HOME")
    return (Path(configured) if configured else Path.home() / ".bughunt").expanduser().resolve()


@contextmanager
def file_lock(path, timeout=LOCK_TIMEOUT_SECONDS):
    """Exclusive cross-process lock on ``path`` + '.lock'; fails closed if it cannot be taken."""
    lock_path = Path(str(path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(lock_path, "a+b")
    locked = False
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise ValueError(f"State file is busy (lock not acquired within {timeout:g}s); "
                                     "nothing was changed. Try again.") from None
                time.sleep(0.02)
        yield
    finally:
        try:
            if locked:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def write_json_atomic(path, document) -> None:
    """Unique temp file -> flush -> fsync -> replace (retrying briefly if Windows holds the target)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(document, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        for attempt in range(6):
            try:
                os.replace(temporary, path)
                return
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(0.05)
    finally:
        try:
            os.unlink(temporary)
        except OSError:
            pass
