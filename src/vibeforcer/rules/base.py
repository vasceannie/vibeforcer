from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Iterable

from vibeforcer.models import RuleFinding

if TYPE_CHECKING:
    from vibeforcer.context import HookContext


class Rule(ABC):
    rule_id: str = ""
    title: str = ""
    events: tuple[str, ...] = ()

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def supports(self, event_name: str) -> bool:
        return not self.events or event_name in self.events

    @abstractmethod
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        raise NotImplementedError


def is_rule_enabled(ctx: HookContext, rule_id: str, default: bool = True) -> bool:
    value = ctx.config.enabled_rules.get(rule_id)
    return default if value is None else bool(value)


def join_messages(findings: Iterable[RuleFinding]) -> str:
    lines = []
    for finding in findings:
        if finding.message:
            lines.append(
                f"[{finding.rule_id} | {finding.severity.as_name()}] {finding.message}"
            )
    return "\n".join(lines)
