"""Codex CLI adapter."""

from __future__ import annotations

from typing_extensions import override

from vibeforcer._types import (
    ObjectDict,
    ObjectMapping,
    is_object_dict,
    object_dict,
    string_value,
)
from vibeforcer.adapters.base import PlatformAdapter
from vibeforcer.models import RuleFinding, Severity

CODEX_EVENTS = {"SessionStart", "PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop"}


class CodexAdapter(PlatformAdapter):
    name: str = "codex"

    def _apply_block_decision(
        self,
        payload: dict[str, object],
        findings: list[RuleFinding],
        decision: str | None,
    ) -> None:
        if decision not in {"block", "deny", "ask"}:
            return
        payload["decision"] = "block"
        payload["reason"] = self.join_messages(
            self.decision_findings(findings, decision)
        )

    @override
    def normalize_payload(self, raw: ObjectMapping) -> ObjectDict:
        if is_object_dict(raw):
            return raw
        return object_dict(raw)

    @override
    def render_output(
        self,
        event_name: str,
        findings: list[RuleFinding],
        *,
        context: str | None = None,
        updated_input: ObjectDict | None = None,
        decision: str | None = None,
    ) -> ObjectDict | None:
        if not findings:
            return None
        if event_name not in CODEX_EVENTS:
            return None

        updated_input = updated_input or {}

        if event_name == "PreToolUse":
            specific: dict[str, object] = {"hookEventName": "PreToolUse"}
            pretool_response: dict[str, object] = {"hookSpecificOutput": specific}
            if decision in {"deny", "ask", "allow"}:
                specific["permissionDecision"] = decision
                specific["permissionDecisionReason"] = self.join_messages(
                    self.decision_findings(findings, decision)
                )
            elif decision == "block":
                specific["permissionDecision"] = "deny"
                specific["permissionDecisionReason"] = self.join_messages(
                    self.decision_findings(findings, decision)
                )
            if context:
                specific["additionalContext"] = context
            if updated_input:
                specific["updatedInput"] = updated_input
            return pretool_response if len(specific) > 1 else None

        if event_name == "PostToolUse":
            critical_blocks = [
                f
                for f in findings
                if f.decision == "block" and f.severity >= Severity.CRITICAL
            ]
            if critical_blocks:
                critical_response: ObjectDict = {
                    "continue": False,
                    "stopReason": self.join_messages(critical_blocks),
                }
                if context:
                    critical_response["hookSpecificOutput"] = {
                        "hookEventName": "PostToolUse",
                        "additionalContext": context,
                    }
                return critical_response

            payload: dict[str, object] = {}
            self._apply_block_decision(payload, findings, decision)
            if context:
                payload["hookSpecificOutput"] = {
                    "hookEventName": "PostToolUse",
                    "additionalContext": context,
                }
            return payload or None

        if event_name == "SessionStart":
            if context:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "SessionStart",
                        "additionalContext": context,
                    }
                }
            return None

        if event_name == "UserPromptSubmit":
            prompt_response: dict[str, object] = {}
            self._apply_block_decision(prompt_response, findings, decision)
            if context:
                prompt_response["hookSpecificOutput"] = {
                    "hookEventName": "UserPromptSubmit",
                    "additionalContext": context,
                }
            return prompt_response or None

        if event_name == "Stop":
            stop_response: dict[str, object] = {}
            self._apply_block_decision(stop_response, findings, decision)
            if context and not stop_response.get("decision"):
                stop_response["systemMessage"] = context
            elif context:
                existing = string_value(stop_response.get("reason"))
                stop_response["reason"] = (
                    (existing + "\n\n" + context).strip() if existing else context
                )
            return stop_response or None

        return None
