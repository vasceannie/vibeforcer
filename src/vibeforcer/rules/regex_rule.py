from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from vibeforcer.models import RegexRuleConfig, RuleFinding, Severity
from vibeforcer.rules.base import Rule
from vibeforcer.util.payloads import any_path_matches


@dataclass(slots=True)
class RegexHit:
    path: str | None
    snippet: str | None = None


class RegexRule(Rule):
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
        return any(re.fullmatch(pattern, tool_name) for pattern in self.config.tool_matchers)

    def _path_allowed(self, path_value: str | None) -> bool:
        if not path_value:
            return True
        if self.config.path_globs and not any_path_matches(path_value, self.config.path_globs):
            return False
        if self.config.exclude_path_globs and any_path_matches(path_value, self.config.exclude_path_globs):
            return False
        return True

    def _match_in_text(self, text: str) -> bool:
        return any(pattern.search(text) for pattern in self._patterns)

    def _render_message(self, hits: list[RegexHit]) -> str:
        if not self.config.message:
            return self.rule_id
        first_path = hits[0].path or ""
        all_paths = ", ".join(sorted({hit.path for hit in hits if hit.path}))
        return self.config.message.format(path=first_path, matched_paths=all_paths, rule_id=self.rule_id)

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not self.enabled or not self.supports(ctx.event_name):
            return []
        if not self._tool_matches(ctx.tool_name):
            return []

        hits: list[RegexHit] = []
        target = self.config.target

        if target == "content":
            for content_target in ctx.content_targets:
                if not self._path_allowed(content_target.path):
                    continue
                if self._match_in_text(content_target.content):
                    hits.append(RegexHit(path=content_target.path))
        elif target == "command":
            if ctx.bash_command and self._match_in_text(ctx.bash_command):
                hits.append(RegexHit(path=None))
        elif target == "path":
            for path_value in ctx.candidate_paths:
                if not self._path_allowed(path_value):
                    continue
                if self._match_in_text(path_value):
                    hits.append(RegexHit(path=path_value))
        elif target == "prompt":
            if ctx.user_prompt and self._match_in_text(ctx.user_prompt):
                hits.append(RegexHit(path=None))
        else:
            return []

        if not hits:
            return []

        finding = RuleFinding(
            rule_id=self.rule_id,
            title=self.title,
            severity=Severity.from_value(self.config.severity),
            decision=None if self.config.action == "context" else self.config.action,
            message=self._render_message(hits) if self.config.action != "context" else None,
            additional_context=self.config.additional_context,
            metadata={
                "target": self.config.target,
                "hits": [hit.path for hit in hits if hit.path],
            },
        )
        return [finding]
