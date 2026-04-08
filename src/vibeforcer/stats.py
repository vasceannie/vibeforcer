"""Hook activity log analysis.

Reads results.jsonl and produces human-readable or JSON reports.
Replaces the standalone hook-stats.py script.
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _default_log_path() -> Path:
    """Find the results.jsonl log file."""
    from vibeforcer.config import config_dir

    # XDG location first
    xdg = config_dir() / "logs" / "results.jsonl"
    if xdg.exists():
        return xdg

    # Legacy location
    legacy = Path.home() / ".claude" / "hooks" / "enforcer" / ".claude" / "hook-layer" / "logs" / "results.jsonl"
    if legacy.exists():
        return legacy

    return xdg  # default even if not found


def load_entries(path: Path, days: int | None) -> list[dict]:
    cutoff = None
    if days is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if cutoff and "timestamp" in entry:
                try:
                    ts = datetime.fromisoformat(entry["timestamp"])
                    if ts < cutoff:
                        continue
                except (ValueError, TypeError):
                    pass
            entries.append(entry)
    return entries


def analyze(entries: list[dict]) -> dict:
    total = len(entries)
    by_event: Counter = Counter()
    by_decision: Counter = Counter()
    by_rule: Counter = Counter()
    by_severity: Counter = Counter()
    by_tool: Counter = Counter()
    by_session: Counter = Counter()
    denies_by_file: Counter = Counter()
    denies_by_rule: Counter = Counter()
    rule_examples: dict = defaultdict(list)
    daily_counts: Counter = Counter()
    session_deny_seq: dict = defaultdict(list)
    fixture_filtered = 0

    for entry in entries:
        session = entry.get("session_id", "unknown")
        if session.startswith("fixture-") or session.startswith("test-"):
            fixture_filtered += 1
            continue
        event = entry.get("event_name", "unknown")
        by_event[event] += 1
        tool = entry.get("tool_name", "") or "(none)"
        by_tool[tool] += 1
        by_session[session] += 1
        ts_str = entry.get("timestamp", "")
        if ts_str:
            try:
                daily_counts[ts_str[:10]] += 1
            except Exception:
                pass
        findings = entry.get("findings", [])
        has_deny = False
        for f in findings:
            rule_id = f.get("rule_id", "unknown")
            decision = f.get("decision")
            severity = f.get("severity", "unknown")
            message = f.get("message", "")
            by_rule[rule_id] += 1
            if decision:
                by_decision[decision] += 1
            by_severity[severity] += 1
            if decision == "deny":
                has_deny = True
                denies_by_rule[rule_id] += 1
                session_deny_seq[session].append((rule_id, tool, ts_str))
                meta = f.get("metadata", {})
                if "path" in meta:
                    denies_by_file[meta["path"]] += 1
                for hit in meta.get("hits", []):
                    denies_by_file[hit] += 1
                if len(rule_examples[rule_id]) < 3:
                    rule_examples[rule_id].append(message)
        if not findings:
            by_decision["allow"] += 1
        elif not has_deny:
            by_decision["allow"] += 1

    retry_counts: Counter = Counter()
    for session, denies in session_deny_seq.items():
        rc = Counter(r for r, _, _ in denies)
        for rule_id, count in rc.items():
            if count >= 2:
                retry_counts[f"{rule_id} (session {session[:8]}...)"] = count

    dates = sorted(daily_counts.keys())
    date_range = f"{dates[0]} to {dates[-1]}" if dates else "unknown"

    return {
        "total_events": total,
        "fixture_filtered": fixture_filtered,
        "date_range": date_range,
        "by_event": by_event.most_common(),
        "by_decision": by_decision.most_common(),
        "by_severity": by_severity.most_common(),
        "top_rules_denied": denies_by_rule.most_common(20),
        "top_files_denied": denies_by_file.most_common(15),
        "top_tools": by_tool.most_common(10),
        "sessions": len(by_session),
        "daily_counts": sorted(daily_counts.items()),
        "retry_patterns": retry_counts.most_common(15),
        "rule_examples": dict(rule_examples),
    }


def print_report(stats: dict) -> None:
    print("=" * 70)
    print("VIBEFORCER HOOK ACTIVITY REPORT")
    print("=" * 70)
    print(f"\nDate range: {stats['date_range']}")
    print(f"Total hook events: {stats['total_events']:,}")
    if stats.get("fixture_filtered"):
        print(f"Fixture/test sessions filtered: {stats['fixture_filtered']:,}")
    print(f"Unique sessions: {stats['sessions']}")

    print("\n--- Decisions ---")
    for d, c in stats["by_decision"]:
        pct = c / max(stats["total_events"], 1) * 100
        print(f"  {d:12s} {c:6,}  ({pct:.1f}%)")

    print("\n--- Event Types ---")
    for e, c in stats["by_event"]:
        print(f"  {e:25s} {c:6,}")

    print("\n--- Top Denied Rules ---")
    for r, c in stats["top_rules_denied"]:
        print(f"  {r:25s} {c:5,}")
        exs = stats["rule_examples"].get(r, [])
        if exs:
            print(f"    └─ e.g. {exs[0][:100]}")

    print("\n--- Top Denied Files ---")
    for p, c in stats["top_files_denied"]:
        short = p.replace(str(Path.home()), "~")
        print(f"  {c:4,}  {short}")

    print("\n--- Retry Patterns (same rule denied 2+ in one session) ---")
    if stats["retry_patterns"]:
        for desc, c in stats["retry_patterns"]:
            print(f"  {c:3,}x  {desc}")
    else:
        print("  (none detected)")

    print("\n--- Daily Volume ---")
    for day, c in stats["daily_counts"][-14:]:
        bar = "█" * min(c // 50, 60)
        print(f"  {day}  {c:5,}  {bar}")

    print("\n--- Severity Breakdown ---")
    for s, c in stats["by_severity"]:
        print(f"  {s:10s} {c:6,}")
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
