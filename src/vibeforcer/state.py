from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from time import time


@dataclass(frozen=True, slots=True)
class FullReadKey:
    session_id: str
    path: str


class HookStateStore:
    """Persist small cross-hook state under the trace dir.

    Hooks run as separate subprocesses in production, so even the first
    stateful features need a disk-backed store. Keep it tiny and scoped.
    """

    _TTL_SECONDS = 3600

    def __init__(self, trace_dir: Path) -> None:
        self._path = trace_dir / "hook-state.json"
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def has_full_read(self, session_id: str, path: str) -> bool:
        key = self._full_read_key(session_id, path)
        state = self._load_state()
        return key in state.get("full_reads", {})

    def record_full_read(self, session_id: str, path: str) -> None:
        key = self._full_read_key(session_id, path)
        state = self._load_state()
        state.setdefault("full_reads", {})[key] = int(time())
        self._save_state(state)

    def _full_read_key(self, session_id: str, path: str) -> str:
        return json.dumps(
            {"session_id": session_id.strip(), "path": self._normalize_path(path)},
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
        full_reads = {
            key: int(ts)
            for key, ts in state.get("full_reads", {}).items()
            if isinstance(ts, int) and ts >= cutoff
        }
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
        return dict(raw)

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
            except OSError:
                pass
