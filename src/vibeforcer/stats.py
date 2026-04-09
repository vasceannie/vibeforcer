"""Hook activity log analysis.

Reads results.jsonl and produces human-readable or JSON reports.
Replaces the standalone hook-stats.py script.
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _default_log_path() -> Path:
    """Find the results.jsonl log file."""
    from vibeforcer.config import config_dir

    xdg = config_dir() / "logs" / "results.jsonl"
    if xdg.exists():
        return xdg

    legacy = Path.home() / ".claude" / "hooks" / "enforcer" / ".claude" / "hook-layer" / "logs" / "results.jsonl"
    if legacy.exists():
        return legacy

    return xdg


def _parse_timestamp(ts_raw: str, cutoff: datetime | None) -> bool:
    """Return True if the entry should be skipped (before cutoff)."""
    if cutoff is None:
        return False
    try:
        return datetime.fromisoformat(ts_raw) < cutoff
    except (ValueError, TypeError):
        return False


def load_entries(path: Path, days: int | None) -> list[dict[str, object]]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days) if days is not None else None
    entries: list[dict[str, object]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                entry = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            ts = entry.get("timestamp", "")
            if isinstance(ts, str) and _parse_timestamp(ts, cutoff):
                continue
            entries.append(entry)
    return entries


@dataclass
class _Counters:
    """Mutable accumulators for the analysis pass."""

    by_event: Counter[str] = field(default_factory=Counter)
    by_decision: Counter[str] = field(default_factory=Counter)
    by_rule: Counter[str] = field(default_factory=Counter)
    by_severity: Counter[str] = field(default_factory=Counter)
    by_tool: Counter[str] = field(default_factory=Counter)
    by_session: Counter[str] = field(default_factory=Counter)
    denies_by_file: Counter[str] = field(default_factory=Counter)
    denies_by_rule: Counter[str] = field(default_factory=Counter)
    rule_examples: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    daily_counts: Counter[str] = field(default_factory=Counter)
    session_deny_seq: dict[str, list[tuple[str, str, str]]] = field(
        default_factory=lambda: defaultdict(list),
    )
    fixture_filtered: int = 0


@dataclass(slots=True)
class _EntryContext:
    """Per-entry fields extracted once and reused across findings."""

    session: str
    tool: str
    ts_str: str


def _record_deny_metadata(meta: object, counters: _Counters) -> None:
    """Track file paths from a deny finding's metadata dict."""
    if not isinstance(meta, dict):
        return
    path_val = meta.get("path")
    if isinstance(path_val, str):
        counters.denies_by_file[path_val] += 1
    for hit in meta.get("hits", []):
        if isinstance(hit, str):
            counters.denies_by_file[hit] += 1


def _process_finding(
    finding: dict[str, object],
    ectx: _EntryContext,
    counters: _Counters,
) -> bool:
    """Process a single finding dict. Returns True if it was a deny."""
    rule_id = str(finding.get("rule_id", "unknown"))
    decision = finding.get("decision")
    severity = str(finding.get("severity", "unknown"))

    counters.by_rule[rule_id] += 1
    if isinstance(decision, str):
        counters.by_decision[decision] += 1
    counters.by_severity[severity] += 1

    if decision != "deny":
        return False

    counters.denies_by_rule[rule_id] += 1
    counters.session_deny_seq[ectx.session].append((rule_id, ectx.tool, ectx.ts_str))
    _record_deny_metadata(finding.get("metadata", {}), counters)
    if len(counters.rule_examples[rule_id]) < 3:
        counters.rule_examples[rule_id].append(str(finding.get("message", "")))
    return True


def _classify_findings(findings: list[object], ectx: _EntryContext, counters: _Counters) -> None:
    """Process all findings and record an entry-level allow when nothing fired."""
    has_deny = False
    has_any_decision = False
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if _process_finding(finding, ectx, counters):
            has_deny = True
        if finding.get("decision") is not None:
            has_any_decision = True

    if not findings or (not has_deny and not has_any_decision):
        counters.by_decision["allow"] += 1


def _process_entry(entry: dict[str, object], counters: _Counters) -> None:
    """Process a single results.jsonl entry into the counters."""
    session = str(entry.get("session_id", "unknown"))
    if session.startswith("fixture-") or session.startswith("test-"):
        counters.fixture_filtered += 1
        return

    event = str(entry.get("event_name", "unknown"))
    counters.by_event[event] += 1
    tool = str(entry.get("tool_name", "")) or "(none)"
    counters.by_tool[tool] += 1
    counters.by_session[session] += 1

    ts_str = str(entry.get("timestamp", ""))
    if ts_str:
        counters.daily_counts[ts_str[:10]] += 1

    findings = entry.get("findings", [])
    ectx = _EntryContext(session=session, tool=tool, ts_str=ts_str)
    _classify_findings(findings if isinstance(findings, list) else [], ectx, counters)


def _compute_retry_patterns(counters: _Counters) -> Counter[str]:
    retry_counts: Counter[str] = Counter()
    for session, denies in counters.session_deny_seq.items():
        rc: Counter[str] = Counter(r for r, _, _ in denies)
        for rule_id, count in rc.items():
            if count >= 2:
                retry_counts[f"{rule_id} (session {session[:8]}...)"] = count
    return retry_counts


def analyze(entries: list[dict[str, object]]) -> dict[str, object]:
    counters = _Counters()
    for entry in entries:
        _process_entry(entry, counters)

    retry_counts = _compute_retry_patterns(counters)
    dates = sorted(counters.daily_counts.keys())
    date_range = f"{dates[0]} to {dates[-1]}" if dates else "unknown"

    return {
        "total_events": len(entries),
        "fixture_filtered": counters.fixture_filtered,
        "date_range": date_range,
        "by_event": counters.by_event.most_common(),
        "by_decision": counters.by_decision.most_common(),
        "by_severity": counters.by_severity.most_common(),
        "top_rules_denied": counters.denies_by_rule.most_common(20),
        "top_files_denied": counters.denies_by_file.most_common(15),
        "top_tools": counters.by_tool.most_common(10),
        "sessions": len(counters.by_session),
        "daily_counts": sorted(counters.daily_counts.items()),
        "retry_patterns": retry_counts.most_common(15),
        "rule_examples": dict(counters.rule_examples),
    }


_PairList = list[tuple[str, int]]


def _pairs(stats: dict[str, object], key: str) -> _PairList:
    """Safely extract a list of (str, int) pairs from the stats dict."""
    raw = stats.get(key, [])
    return list(raw) if isinstance(raw, list) else []


def print_report(stats: dict[str, object]) -> None:
    print("=" * 70)
    print("VIBEFORCER HOOK ACTIVITY REPORT")
    print("=" * 70)
    print(f"\nDate range: {stats['date_range']}")
    print(f"Total hook events: {stats['total_events']:,}")
    if stats.get("fixture_filtered"):
        print(f"Fixture/test sessions filtered: {stats['fixture_filtered']:,}")
    print(f"Unique sessions: {stats['sessions']}")

    raw_total = stats.get("total_events", 0)
    total = int(raw_total) if isinstance(raw_total, (int, float, str)) else 1
    print("\n--- Decisions ---")
    for decision, count in _pairs(stats, "by_decision"):
        pct = count / total * 100
        print(f"  {decision:12s} {count:6,}  ({pct:.1f}%)")

    print("\n--- Event Types ---")
    for event, count in _pairs(stats, "by_event"):
        print(f"  {event:25s} {count:6,}")

    _print_denied_rules(stats)
    _print_denied_files(stats)
    _print_retry_patterns(stats)
    _print_daily_volume(stats)
    _print_severity(stats)


def _print_denied_rules(stats: dict[str, object]) -> None:
    print("\n--- Top Denied Rules ---")
    examples = stats.get("rule_examples", {})
    for rule, count in _pairs(stats, "top_rules_denied"):
        print(f"  {rule:25s} {count:5,}")
        if isinstance(examples, dict):
            exs = examples.get(rule, [])
            if isinstance(exs, list) and exs:
                print(f"    \u2514\u2500 e.g. {str(exs[0])[:100]}")


def _print_denied_files(stats: dict[str, object]) -> None:
    print("\n--- Top Denied Files ---")
    for path, count in _pairs(stats, "top_files_denied"):
        short = str(path).replace(str(Path.home()), "~")
        print(f"  {count:4,}  {short}")


def _print_retry_patterns(stats: dict[str, object]) -> None:
    print("\n--- Retry Patterns (same rule denied 2+ in one session) ---")
    patterns = _pairs(stats, "retry_patterns")
    if patterns:
        for desc, count in patterns:
            print(f"  {count:3,}x  {desc}")
    else:
        print("  (none detected)")


def _print_daily_volume(stats: dict[str, object]) -> None:
    print("\n--- Daily Volume ---")
    for day, count in _pairs(stats, "daily_counts")[-14:]:
        bar = "\u2588" * min(count // 50, 60)
        print(f"  {day}  {count:5,}  {bar}")


def _print_severity(stats: dict[str, object]) -> None:
    print("\n--- Severity Breakdown ---")
    for sev, count in _pairs(stats, "by_severity"):
        print(f"  {sev:10s} {count:6,}")
    print()


def run_stats(
    log_path: str | None = None,
    days: int | None = None,
    as_json: bool = False,
) -> int:
    path = Path(log_path) if log_path else _default_log_path()
    if not path.exists():
        print(f"Log not found: {path}", file=sys.stderr)
        return 1

    label = f" (last {days} days)" if days else ""
    if not as_json:
        print(f"Loading {path}{label}...")

    entries = load_entries(path, days)
    stats = analyze(entries)

    if as_json:
        print(json.dumps(stats, indent=2, default=str))
    else:
        print_report(stats)

    return 0
