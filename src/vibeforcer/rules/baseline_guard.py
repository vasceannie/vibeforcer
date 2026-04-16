from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, cast

from typing_extensions import override

from vibeforcer._types import object_dict, object_list
from vibeforcer.models import RuleFinding, Severity
from vibeforcer.rules.base import Rule, is_rule_enabled
from vibeforcer.util.payloads import path_matches_glob

if TYPE_CHECKING:
    from vibeforcer.context import HookContext


def _extract_rules_dict(raw: object) -> dict[str, list[str]]:
    """Parse a rules mapping from JSON-loaded baseline data."""
    typed = object_dict(raw)
    if not typed:
        return {}
    result: dict[str, list[str]] = {}
    for rule_name, ids_val in typed.items():
        ids = object_list(ids_val)
        if ids:
            result[rule_name] = [str(v) for v in ids]
    return result


def _parse_json_dict(text: str) -> dict[str, object] | None:
    """Parse JSON text and return a dict, or None on failure."""
    try:
        raw: object = cast(object, json.loads(text))
    except (json.JSONDecodeError, TypeError):
        return None
    parsed = object_dict(raw)
    if not parsed:
        return None
    return parsed


def _find_increases(
    new_rules: dict[str, list[str]],
    old_rules: dict[str, list[str]],
) -> list[str]:
    """Return formatted strings for rules with increased violation counts."""
    increases: list[str] = []
    for rule_name, new_ids in new_rules.items():
        old_ids = old_rules.get(rule_name, [])
        old_count = len(old_ids)
        new_count = len(new_ids)
        if new_count > old_count:
            increases.append(
                f"  {rule_name}: {old_count} -> {new_count} (+{new_count - old_count})"
            )
    return increases


class BaselineGuardRule(Rule):
    """Block writes to baselines.json that increase violation counts.

    Decreases are allowed (fixing violations). Increases are denied
    (inflating the baseline to hide new debt).
    """

    rule_id: str = "BASELINE-001"
    title: str = "Baseline inflation guard"
    events: tuple[str, ...] = ("PreToolUse",)

    _BASELINE_GLOBS: tuple[str, ...] = ("baselines.json", "**/baselines.json")

    @override
    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []

        for target in ctx.content_targets:
            if not target.path:
                continue
            if not any(path_matches_glob(target.path, g) for g in self._BASELINE_GLOBS):
                continue

            return self._check_baseline_change(target.path, target.content, ctx)

        # Catch CLI commands that regenerate the baseline
        if ctx.bash_command:
            cmd = ctx.bash_command.strip()
            if any(
                token in cmd
                for token in (
                    "quality-gate baseline",
                    "vibeforcer lint baseline",
                    "vfc lint baseline",
                )
            ):
                return [
                    RuleFinding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.HIGH,
                        decision="deny",
                        message=(
                            "Running repo-wide baseline generation is blocked. "
                            "`quality-gate baseline`, `vibeforcer lint baseline`, and `vfc lint baseline` "
                            "all hide technical debt by normalizing existing violations. "
                            "Fix the violations instead of inflating the baseline."
                        ),
                    )
                ]

        return []

    def _resolve_existing_path(self, path_str: str, ctx: HookContext) -> Path | None:
        """Find the existing baselines.json on disk."""
        p = Path(path_str)
        if p.is_absolute() and p.exists():
            return p

        # Claude Code sets CLAUDE_PROJECT_DIR when running hooks
        project_dir = os.environ.get("CLAUDE_PROJECT_DIR", "")
        if project_dir:
            candidate = Path(project_dir) / path_str
            if candidate.exists():
                return candidate

        # Try relative to config root and cwd
        for base in (ctx.config.root, Path.cwd()):
            candidate = base / path_str
            if candidate.exists():
                return candidate

        return None

    def _check_baseline_change(
        self,
        path_str: str,
        new_content: str,
        ctx: HookContext,
    ) -> list[RuleFinding]:
        new_data = _parse_json_dict(new_content)
        if new_data is None:
            return []
        new_rules = _extract_rules_dict(new_data.get("rules", {}))

        existing = self._resolve_existing_path(path_str, ctx)
        if existing is None:
            return []
        old_data = _parse_json_dict(existing.read_text(encoding="utf-8"))
        if old_data is None:
            return []
        old_rules = _extract_rules_dict(old_data.get("rules", {}))

        increases = _find_increases(new_rules, old_rules)
        if not increases:
            return []
        detail = "\n".join(increases)
        msg = (
            "Baseline inflation blocked. The following rules have MORE "
            f"violations than before:\n{detail}\n\n"
            "Fix the violations instead of increasing the baseline. "
            "Only decreases (fixing debt) are allowed."
        )
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.HIGH,
                decision="deny",
                message=msg,
            )
        ]
