from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

from vibeforcer.models import RuleFinding, Severity
from vibeforcer.rules.base import Rule, is_rule_enabled
from vibeforcer.util.payloads import path_matches_glob

if TYPE_CHECKING:
    from vibeforcer.context import HookContext


class BaselineGuardRule(Rule):
    """Block writes to baselines.json that increase violation counts.

    Decreases are allowed (fixing violations). Increases are denied
    (inflating the baseline to hide new debt).
    """

    rule_id = "BASELINE-001"
    title = "Baseline inflation guard"
    events = ("PreToolUse",)

    _BASELINE_GLOBS = ("baselines.json", "**/baselines.json")

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
            if "quality-gate baseline" in cmd:
                return [
                    RuleFinding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.HIGH,
                        decision="deny",
                        message=(
                            "Running `quality-gate baseline` is blocked. "
                            "Baselines must only decrease (fix violations), never increase. "
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
        try:
            new_data = json.loads(new_content)
        except (json.JSONDecodeError, TypeError):
            return []

        # Guard: Edit tool may supply a partial JSON fragment (string/list/etc.)
        # rather than a full baselines.json dict — bail out gracefully.
        if not isinstance(new_data, dict):
            return []

        new_rules: dict[str, list] = new_data.get("rules", {})

        existing = self._resolve_existing_path(path_str, ctx)
        if existing is None:
            return []  # First baseline creation — allow

        try:
            old_data = json.loads(existing.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

        # Guard: on-disk file may be malformed or non-dict
        if not isinstance(old_data, dict):
            return []

        old_rules: dict[str, list] = old_data.get("rules", {})

        # Compare counts per rule
        increases: list[str] = []
        for rule_name, new_ids in new_rules.items():
            old_ids = old_rules.get(rule_name, [])
            old_count = len(old_ids)
            new_count = len(new_ids)
            if new_count > old_count:
                increases.append(
                    f"  {rule_name}: {old_count} -> {new_count} (+{new_count - old_count})"
                )

        if not increases:
            return []  # All decreases or unchanged

        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.HIGH,
                decision="deny",
                message=(
                    "Baseline inflation blocked. The following rules have MORE "
                    "violations than before:\n"
                    + "\n".join(increases)
                    + "\n\nFix the violations instead of increasing the baseline. "
                    "Only decreases (fixing debt) are allowed."
                ),
            )
        ]
