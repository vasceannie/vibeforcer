"""Baseline-based quality enforcement infrastructure.

"No new debt" quality gates.  Compares against a frozen baseline of
existing violations.  Any new violation fails immediately.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from typing_extensions import override

from vibeforcer.lint._config import get_config

SCHEMA_VERSION = 1


def _baseline_path() -> Path:
    """Return the baseline file path — from config or default."""
    cfg = get_config()
    if cfg.baseline_path:
        return cfg.baseline_path
    return cfg.project_root / "baselines.json"


@dataclass(frozen=True)
class Violation:
    """A single quality violation tied to a rule, file, and identifier."""

    rule: str
    relative_path: str
    identifier: str
    detail: str = ""

    @property
    def stable_id(self) -> str:
        parts = [self.rule, self.relative_path, self.identifier]
        if self.detail:
            parts.append(self.detail)
        return "|".join(parts)

    @override
    def __str__(self) -> str:
        base = f"{self.relative_path}:{self.identifier}"
        return f"{base} ({self.detail})" if self.detail else base


@dataclass
class BaselineResult:
    """Outcome of comparing current violations against the baseline."""

    new_violations: list[Violation]
    fixed_violations: list[str]
    current_count: int
    baseline_count: int

    @property
    def passed(self) -> bool:
        return len(self.new_violations) == 0


def load_baseline() -> dict[str, set[str]]:
    """Load the baseline file and return ``{rule: {stable_id, …}}``."""
    bp = _baseline_path()
    if not bp.exists():
        return {}
    data = cast(object, json.loads(bp.read_text(encoding="utf-8")))
    if not isinstance(data, dict):
        raise ValueError("Baseline data must be a JSON object")
    raw_data = cast(dict[object, object], data)
    if raw_data.get("schema_version", 0) != SCHEMA_VERSION:
        raise ValueError("Baseline schema version mismatch")
    rules = raw_data.get("rules", {})
    if not isinstance(rules, dict):
        raise ValueError("Baseline rules must be a JSON object")
    typed_rules = cast(dict[str, object], rules)
    result: dict[str, set[str]] = {}
    for rule, ids in typed_rules.items():
        if not isinstance(ids, list):
            continue
        typed_ids = cast(list[object], ids)
        result[str(rule)] = {str(item) for item in typed_ids}
    return result


def save_baseline(violations_by_rule: dict[str, list[Violation]]) -> None:
    """Persist a new baseline snapshot."""
    bp = _baseline_path()
    data = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rules": {
            rule: sorted(v.stable_id for v in violations)
            for rule, violations in violations_by_rule.items()
        },
    }
    _ = bp.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def assert_no_new_violations(
    rule: str,
    current_violations: list[Violation],
    *,
    max_new_allowed: int = 0,
) -> BaselineResult:
    """Fail if any violations are *new* relative to the baseline."""
    if os.environ.get("QUALITY_GENERATE_BASELINE") == "1":
        return BaselineResult(
            new_violations=[],
            fixed_violations=[],
            current_count=len(current_violations),
            baseline_count=0,
        )

    baseline = load_baseline()
    allowed_ids = baseline.get(rule, set())
    current_ids = {v.stable_id for v in current_violations}
    new_ids = current_ids - allowed_ids
    fixed_ids = allowed_ids - current_ids

    new_violations = sorted(
        [v for v in current_violations if v.stable_id in new_ids],
        key=lambda v: v.stable_id,
    )

    result = BaselineResult(
        new_violations=new_violations,
        fixed_violations=sorted(fixed_ids),
        current_count=len(current_violations),
        baseline_count=len(allowed_ids),
    )

    if len(new_violations) > max_new_allowed:
        parts = [
            f"[{rule}] {len(new_violations)} NEW violation(s) "
            + f"(baseline: {len(allowed_ids)}, current: {len(current_violations)}):",
        ]
        parts.extend(f"  + {v}" for v in new_violations[:20])
        if len(new_violations) > 20:
            parts.append(f"  ... and {len(new_violations) - 20} more")
        if fixed_ids:
            parts.append(f"\nFixed {len(fixed_ids)} (update baseline):")
            parts.extend(f"  - {fid}" for fid in list(fixed_ids)[:5])
        raise AssertionError("\n".join(parts))

    return result


def content_hash(content: str, length: int = 8) -> str:
    """Deterministic short hash of *content* for deduplication."""
    return hashlib.sha256(content.encode()).hexdigest()[:length]
