from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class TraceWriter:
    def __init__(self, trace_dir: Path) -> None:
        self.trace_dir = trace_dir
        if not self.trace_dir.exists():
            self.trace_dir.mkdir(parents=True, exist_ok=True)
            (self.trace_dir / "async").mkdir(exist_ok=True)

    def _append(self, filename: str, payload: dict[str, Any]) -> None:
        target = self.trace_dir / filename
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        try:
            with target.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        except OSError:
            return

    def event(self, payload: dict[str, Any]) -> None:
        self._append("events.jsonl", payload)

    def rule(self, payload: dict[str, Any]) -> None:
        self._append("rules.jsonl", payload)

    def result(self, payload: dict[str, Any]) -> None:
        self._append("results.jsonl", payload)

    def subprocess(self, payload: dict[str, Any], async_mode: bool = False) -> None:
        filename = "async/subprocess.jsonl" if async_mode else "subprocess.jsonl"
        self._append(filename, payload)
