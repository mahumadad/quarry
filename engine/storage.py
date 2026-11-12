"""Crash-safe, concurrency-safe persistence primitives for engagement state."""
from __future__ import annotations

import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


class StateCorruptionError(RuntimeError):
    """Raised instead of silently replacing malformed engagement state."""


@contextmanager
def engagement_lock(audit_dir: str | Path) -> Iterator[None]:
    """Serialize writers belonging to one engagement across processes."""
    state_dir = Path(audit_dir) / ".pentest-state"
    state_dir.mkdir(parents=True, exist_ok=True)
    lock_path = state_dir / ".lock"
    with lock_path.open("a+") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def read_json(path: str | Path, default: Any = None) -> Any:
    source = Path(path)
    if not source.exists():
        return default
    try:
        return json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StateCorruptionError(f"Cannot read valid JSON state: {source}: {exc}") from exc


def atomic_write_bytes(path: str | Path, data: bytes, mode: int = 0o600) -> None:
    """Write + fsync + atomic rename; retain the previous valid version."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temp_path = Path(temporary)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if destination.exists():
            backup = destination.with_suffix(destination.suffix + ".bak")
            backup.write_bytes(destination.read_bytes())
            try:
                os.chmod(backup, mode)
            except OSError:
                pass
        os.replace(temp_path, destination)
        dir_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def atomic_write_json(path: str | Path, value: Any, mode: int = 0o600) -> None:
    payload = json.dumps(value, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    atomic_write_bytes(path, payload, mode=mode)


def append_jsonl(path: str | Path, value: Any) -> None:
    """Append one complete event and flush it to stable storage."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(value, ensure_ascii=False).encode("utf-8") + b"\n"
    fd = os.open(destination, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)
