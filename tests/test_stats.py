"""Unit tests for stats.analyze() and related functions."""

from __future__ import annotations

from datetime import datetime, timezone

from vibeforcer._types import ObjectDict, object_dict, object_list
from vibeforcer.stats import analyze, _parse_timestamp


def _analyze(entries: list[ObjectDict]) -> ObjectDict:
    return object_dict(analyze(entries))


def _pair_counts(stats: ObjectDict, key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in object_list(stats.get(key)):
        if isinstance(item, tuple) and len(item) == 2:
            name, count = item
            if isinstance(name, str) and isinstance(count, int):
                counts[name] = count
    return counts


def _string_list(mapping: ObjectDict, key: str) -> list[str]:
    return [value for value in object_list(mapping.get(key)) if isinstance(value, str)]


class TestParseTimestamp:
    def test_none_cutoff_never_skips(self) -> None:
        assert not _parse_timestamp("2026-01-01T00:00:00+00:00", None), (
            "None cutoff must not skip"
        )

    def test_before_cutoff_skips(self) -> None:
        cutoff = datetime(2026, 3, 1, tzinfo=timezone.utc)
        assert _parse_timestamp("2026-02-01T00:00:00+00:00", cutoff), (
            "entry before cutoff must be skipped"
        )

    def test_after_cutoff_keeps(self) -> None:
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert not _parse_timestamp("2026-06-01T00:00:00+00:00", cutoff), (
            "entry after cutoff must be kept"
        )

    def test_invalid_timestamp_keeps(self) -> None:
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert not _parse_timestamp("not-a-date", cutoff), (
            "invalid timestamp must not be skipped"
        )


class TestAnalyze:
    def _entry(
        self,
        event: str = "PreToolUse",
        rule_id: str = "GIT-001",
        decision: str = "deny",
        session: str = "s1",
    ) -> ObjectDict:
        return {
            "timestamp": "2026-04-01T12:00:00+00:00",
            "event_name": event,
            "session_id": session,
            "tool_name": "Bash",
            "findings": [
                {
                    "rule_id": rule_id,
                    "decision": decision,
                    "severity": "HIGH",
                    "message": f"{rule_id} triggered",
                    "metadata": {"path": "src/main.py"},
                },
            ],
        }

    def test_counts_deny_decision(self) -> None:
        stats = _analyze([self._entry()])
        decisions = _pair_counts(stats, "by_decision")
        assert decisions.get("deny") == 1, "deny count must be 1"

    def test_context_only_not_counted_as_allow(self) -> None:
        entry = self._entry(decision="context")
        stats = _analyze([entry])
        decisions = _pair_counts(stats, "by_decision")
        assert decisions.get("context", 0) == 1, (
            "context-only findings must be counted as context"
        )
        assert decisions.get("allow", 0) == 0, (
            "context-only must not inflate allow count"
        )

    def test_no_findings_counted_as_allow(self) -> None:
        entry: ObjectDict = {
            "timestamp": "2026-04-01T12:00:00+00:00",
            "event_name": "PreToolUse",
            "session_id": "s1",
            "tool_name": "Read",
            "findings": [],
        }
        stats = _analyze([entry])
        decisions = _pair_counts(stats, "by_decision")
        assert decisions.get("allow") == 1, "empty findings must count as allow"

    def test_fixture_sessions_filtered(self) -> None:
        entry = self._entry(session="fixture-abc")
        stats = _analyze([entry])
        assert stats["fixture_filtered"] == 1, "fixture sessions must be filtered"

    def test_retry_patterns_detected(self) -> None:
        entries = [self._entry(session="s1")] * 3
        stats = _analyze(entries)
        retries = object_list(stats.get("retry_patterns"))
        assert len(retries) > 0, (
            "repeated denies in same session must produce retry patterns"
        )

    def test_daily_counts(self) -> None:
        stats = _analyze([self._entry()])
        daily = _pair_counts(stats, "daily_counts")
        assert "2026-04-01" in daily, "daily count must include the entry date"

    def test_rule_examples_capped_at_three(self) -> None:
        entries = [self._entry()] * 5
        stats = _analyze(entries)
        examples = object_dict(stats.get("rule_examples"))
        assert len(_string_list(examples, "GIT-001")) <= 3, (
            "rule examples must be capped at 3"
        )
