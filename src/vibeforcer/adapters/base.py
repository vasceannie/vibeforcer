"""Base adapter protocol for platform-specific input/output translation."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from vibeforcer.models import RuleFinding


class PlatformAdapter(ABC):
    name: str = ""

    @abstractmethod
    def normalize_payload(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Convert a raw platform payload into canonical form."""

    @abstractmethod
    def render_output(
        self,
        event_name: str,
        findings: list[RuleFinding],
        *,
        context: str | None = None,
        updated_input: dict[str, Any] | None = None,
        decision: str | None = None,
    ) -> dict[str, Any] | None:
        """Render findings into platform-native JSON for stdout."""

    @staticmethod
    def join_messages(findings: list[RuleFinding]) -> str:
        lines: list[str] = []
        for finding in findings:
            if finding.message:
                lines.append(
                    f"[{finding.rule_id} | {finding.severity.as_name()}] {finding.message}"
                )
        return "\n".join(lines)

    @staticmethod
    def decision_findings(
        findings: list[RuleFinding], decision: str | None
    ) -> list[RuleFinding]:
        return [f for f in findings if f.decision == decision]
