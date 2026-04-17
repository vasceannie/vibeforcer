from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from time import time
from types import ModuleType
from typing import TextIO, cast

from vibeforcer.util.logger import warning

fcntl: ModuleType | None
try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows only
    fcntl = None
else:
    fcntl = _fcntl

msvcrt: ModuleType | None
try:
    import msvcrt as _msvcrt
except ImportError:  # pragma: no cover - POSIX only
    msvcrt = None
else:
    msvcrt = _msvcrt


class HookStateStore:
    """Persist small cross-hook state under the trace dir.

    Hooks run as separate subprocesses in production, so even the first
    stateful features need a disk-backed store. Keep it tiny and scoped.
    """

    _TTL_SECONDS = 3600

    def __init__(self, trace_dir: Path) -> None:
        self._path = trace_dir / "hook-state.json"
        self._lock_path = trace_dir / "hook-state.lock"
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def has_full_read(self, session_id: str, path: str) -> bool:
        key = self._full_read_key(session_id, path)
        state = self._load_state()
        return key in state.get("full_reads", {})

    def record_full_read(self, session_id: str, path: str) -> None:
        normalized_path = self._normalize_path(path)
        if not Path(normalized_path).exists():
            return
        key = self._full_read_key(session_id, normalized_path)
        with self._locked_state():
            state = self._load_state()
            state.setdefault("full_reads", {})[key] = int(time())
            self._save_state(state)

    @contextmanager
    def _locked_state(self) -> Iterator[None]:
        with self._lock_path.open("a+", encoding="utf-8") as handle:
            self._acquire_lock(handle)
            try:
                yield
            finally:
                self._release_lock(handle)

    def _acquire_lock(self, handle: TextIO) -> None:
        fileno = handle.fileno()
        if fcntl is not None:
            fcntl.flock(fileno, fcntl.LOCK_EX)
            return
        if msvcrt is not None:  # pragma: no cover - Windows only
            handle.seek(0)
            handle.write("\0")
            handle.flush()
            handle.seek(0)
            msvcrt.locking(fileno, msvcrt.LK_LOCK, 1)

    def _release_lock(self, handle: TextIO) -> None:
        fileno = handle.fileno()
        if fcntl is not None:
            fcntl.flock(fileno, fcntl.LOCK_UN)
            return
        if msvcrt is not None:  # pragma: no cover - Windows only
            handle.seek(0)
            msvcrt.locking(fileno, msvcrt.LK_UNLCK, 1)

    def _full_read_key(self, session_id: str, path: str) -> str:
        return json.dumps(
            {"session_id": session_id.strip(), "path": self._normalize_path(path.strip())},
            sort_keys=True,
        )

    def _normalize_path(self, path: str) -> str:
        try:
            return str(Path(path).resolve(strict=False))
        except OSError:
            return str(Path(path).absolute())

    def _load_state(self) -> dict[str, dict[str, int]]:
        cutoff = int(time()) - self._TTL_SECONDS
        state = self._read_state_file()
        full_reads = self._coerce_full_reads(state.get("full_reads"), cutoff)
        return {"full_reads": full_reads}

    def _read_state_file(self) -> dict[str, object]:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(raw, Mapping):
            return {}
        result: dict[str, object] = {}
        for key, value in cast(Mapping[object, object], raw).items():
            if isinstance(key, str):
                result[key] = value
        return result

    @staticmethod
    def _coerce_full_reads(raw_full_reads: object, cutoff: int) -> dict[str, int]:
        if not isinstance(raw_full_reads, Mapping):
            return {}
        full_reads: dict[str, int] = {}
        for key, timestamp in cast(Mapping[object, object], raw_full_reads).items():
            if isinstance(key, str) and isinstance(timestamp, int) and timestamp >= cutoff:
                full_reads[key] = timestamp
        return full_reads

    def _save_state(self, state: dict[str, dict[str, int]]) -> None:
        fd, tmp_name = tempfile.mkstemp(
            prefix="hook-state-", suffix=".json", dir=str(self._path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, sort_keys=True)
            os.replace(tmp_name, self._path)
        finally:
            try:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
            except OSError as exc:
                warning("hook state temp cleanup failed", path=tmp_name, error=str(exc))
