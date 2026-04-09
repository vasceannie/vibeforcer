"""Unit tests for TraceWriter and telemetry pipeline."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vibeforcer.trace import TraceWriter, _make_record


class TestMakeRecord:
    def test_adds_timestamp(self) -> None:
        result = json.loads(_make_record({"key": "val"}))
        assert "timestamp" in result, "record must include a timestamp"

    def test_preserves_payload_keys(self) -> None:
        result = json.loads(_make_record({"rule_id": "TEST-001", "severity": "HIGH"}))
        assert result["rule_id"] == "TEST-001", "payload keys must be preserved"
        assert result["severity"] == "HIGH", "payload values must be preserved"

    def test_sorts_keys(self) -> None:
        line = _make_record({"z_field": 1, "a_field": 2})
        keys = list(json.loads(line).keys())
        assert keys == sorted(keys), "keys must be sorted for grep-ability"


class TestTraceWriterInit:
    def test_creates_missing_dir(self, tmp_path: Path) -> None:
        trace_dir = tmp_path / "new" / "logs"
        TraceWriter(trace_dir)
        assert trace_dir.exists(), "trace_dir must be created"
        assert (trace_dir / "async").exists(), "async subdir must be created"

    def test_existing_dir_without_async_subdir(self, tmp_path: Path) -> None:
        trace_dir = tmp_path / "logs"
        trace_dir.mkdir()
        TraceWriter(trace_dir)
        assert (trace_dir / "async").exists(), "async subdir must be created even if parent exists"


class TestTraceWriterAppend:
    def test_event_creates_jsonl(self, tmp_path: Path) -> None:
        tw = TraceWriter(tmp_path)
        tw.event({"event_name": "PreToolUse", "tool_name": "Bash"})
        events_file = tmp_path / "events.jsonl"
        assert events_file.exists(), "events.jsonl must be created"
        record = json.loads(events_file.read_text().strip())
        assert record["event_name"] == "PreToolUse", "event_name must be in record"

    def test_rule_creates_jsonl(self, tmp_path: Path) -> None:
        tw = TraceWriter(tmp_path)
        tw.rule({"rule_id": "GIT-001", "decision": "deny"})
        rules_file = tmp_path / "rules.jsonl"
        assert rules_file.exists(), "rules.jsonl must be created"

    def test_result_creates_jsonl(self, tmp_path: Path) -> None:
        tw = TraceWriter(tmp_path)
        tw.result({"event_name": "PreToolUse", "findings": []})
        assert (tmp_path / "results.jsonl").exists(), "results.jsonl must be created"

    def test_subprocess_sync(self, tmp_path: Path) -> None:
        tw = TraceWriter(tmp_path)
        tw.subprocess({"command": "pytest", "returncode": 0})
        assert (tmp_path / "subprocess.jsonl").exists(), "subprocess.jsonl must be created"

    def test_subprocess_async(self, tmp_path: Path) -> None:
        tw = TraceWriter(tmp_path)
        tw.subprocess({"command": "ruff check ."}, async_mode=True)
        assert (tmp_path / "async" / "subprocess.jsonl").exists(), "async subprocess log must be created"

    def test_multiple_appends(self, tmp_path: Path) -> None:
        tw = TraceWriter(tmp_path)
        tw.event({"n": 1})
        tw.event({"n": 2})
        lines = (tmp_path / "events.jsonl").read_text().strip().splitlines()
        assert len(lines) == 2, "multiple appends must produce multiple lines"
