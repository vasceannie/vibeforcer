"""Base adapter protocol for platform-specific input/output translation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from vibeforcer.models import RuleFinding
from vibeforcer.rules.base import join_messages as _join_messages


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

    join_messages = staticmethod(_join_messages)

    @staticmethod
    def decision_findings(
        findings: list[RuleFinding], decision: str | None
    ) -> list[RuleFinding]:
        return [f for f in findings if f.decision == decision]
