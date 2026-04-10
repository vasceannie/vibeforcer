from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, final

from typing_extensions import override

from vibeforcer.models import RegexRuleConfig, RuleFinding, Severity
from vibeforcer.rules.base import Rule
from vibeforcer.util.payloads import any_path_matches

if TYPE_CHECKING:
    from vibeforcer.context import HookContext


@dataclass(slots=True)
class RegexHit:
    path: str | None
    snippet: str | None = None


@final
class RegexRule(Rule):
    config: RegexRuleConfig
    _patterns: list[re.Pattern[str]]

    def __init__(self, config: RegexRuleConfig, enabled: bool = True) -> None:
        super().__init__(enabled=enabled)
        self.config = config
        self.rule_id = config.rule_id
        self.title = config.title
        self.events = tuple(config.events)
        flags = 0
        if config.multiline:
            flags |= re.MULTILINE | re.DOTALL
        if not config.case_sensitive:
            flags |= re.IGNORECASE
        self._patterns = [re.compile(pattern, flags) for pattern in config.patterns]

    def _tool_matches(self, tool_name: str) -> bool:
        if not self.config.tool_matchers:
            return True
        return any(
            re.fullmatch(pattern, tool_name) for pattern in self.config.tool_matchers
        )

    def _path_allowed(self, path_value: str | None) -> bool:
        if not path_value:
            return True
        if self.config.path_globs and not any_path_matches(
            path_value, self.config.path_globs
        ):
            return False
        if self.config.exclude_path_globs and any_path_matches(
            path_value, self.config.exclude_path_globs
        ):
            return False
        return True

    def _render_message(self, hits: list[RegexHit]) -> str:
        if not self.config.message:
            return self.rule_id
        first_path = hits[0].path or ""
        all_paths = ", ".join(sorted({hit.path for hit in hits if hit.path}))
        return self.config.message.format(
            path=first_path, matched_paths=all_paths, rule_id=self.rule_id
        )

    def _collect_content_hits(self, ctx: HookContext) -> list[RegexHit]:
        hits: list[RegexHit] = []
        for content_target in ctx.content_targets:
            if not self._path_allowed(content_target.path):
                continue
            if any(p.search(content_target.content) for p in self._patterns):
                hits.append(RegexHit(path=content_target.path))
        return hits

    def _collect_command_hits(self, ctx: HookContext) -> list[RegexHit]:
        if ctx.bash_command and any(p.search(ctx.bash_command) for p in self._patterns):
            return [RegexHit(path=None)]
        return []

    def _collect_path_hits(self, ctx: HookContext) -> list[RegexHit]:
        hits: list[RegexHit] = []
        for path_value in ctx.candidate_paths:
            if not self._path_allowed(path_value):
                continue
            if any(p.search(path_value) for p in self._patterns):
                hits.append(RegexHit(path=path_value))
        return hits

    def _collect_prompt_hits(self, ctx: HookContext) -> list[RegexHit]:
        if ctx.user_prompt and any(p.search(ctx.user_prompt) for p in self._patterns):
            return [RegexHit(path=None)]
        return []

    def _build_finding(self, hits: list[RegexHit]) -> RuleFinding:
        is_context = self.config.action == "context"
        return RuleFinding(
            rule_id=self.rule_id,
            title=self.title,
            severity=Severity.from_value(self.config.severity),
            decision=None if is_context else self.config.action,
            message=None if is_context else self._render_message(hits),
            additional_context=self.config.additional_context,
            metadata={
                "target": self.config.target,
                "hits": [hit.path for hit in hits if hit.path],
            },
        )

    @override
    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not self.enabled or not self.supports(ctx.event_name):
            return []
        if not self._tool_matches(ctx.tool_name):
            return []

        collectors = {
            "content": self._collect_content_hits,
            "command": self._collect_command_hits,
            "path": self._collect_path_hits,
            "prompt": self._collect_prompt_hits,
        }
        collector = collectors.get(self.config.target)
        if collector is None:
            return []
        hits = collector(ctx)
        if not hits:
            return []
        return [self._build_finding(hits)]
