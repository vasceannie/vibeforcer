from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def _make_record(payload: dict[str, object]) -> str:
    """Build a timestamped JSON line from a payload dict."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    return json.dumps(record, sort_keys=True, default=str)


class TraceWriter:
    def __init__(self, trace_dir: Path) -> None:
        self.trace_dir = trace_dir
        self.trace_dir.mkdir(parents=True, exist_ok=True)
        (self.trace_dir / "async").mkdir(exist_ok=True)

    def _append(self, filename: str, payload: dict[str, object]) -> None:
        target = self.trace_dir / filename
        line = _make_record(payload)
        try:
            with target.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            return

    def event(self, payload: dict[str, object]) -> None:
        """Append a hook event entry to the events log."""
        self._append("events.jsonl", payload)

    def rule(self, payload: dict[str, object]) -> None:
        """Append a rule evaluation entry to the rules log."""
        self._append("rules.jsonl", payload)

    def result(self, payload: dict[str, object]) -> None:
        """Append a final result entry to the results log."""
        self._append("results.jsonl", payload)

    def subprocess(self, payload: dict[str, object], async_mode: bool = False) -> None:
        filename = "async/subprocess.jsonl" if async_mode else "subprocess.jsonl"
        self._append(filename, payload)
