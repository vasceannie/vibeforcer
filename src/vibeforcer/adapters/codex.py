"""Codex CLI adapter."""
from __future__ import annotations

from typing import Any

from vibeforcer.adapters.base import PlatformAdapter
from vibeforcer.models import RuleFinding, Severity

CODEX_EVENTS = {"SessionStart", "PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop"}


class CodexAdapter(PlatformAdapter):
    name = "codex"

    def normalize_payload(self, raw: dict[str, Any]) -> dict[str, Any]:
        return raw

    def render_output(
        self,
        event_name: str,
        findings: list[RuleFinding],
        *,
        context: str | None = None,
        updated_input: dict[str, Any] | None = None,
        decision: str | None = None,
    ) -> dict[str, Any] | None:
        if not findings:
            return None
        if event_name not in CODEX_EVENTS:
            return None

        updated_input = updated_input or {}

        if event_name == "PreToolUse":
            payload: dict[str, Any] = {
                "hookSpecificOutput": {"hookEventName": "PreToolUse"}
            }
            specific = payload["hookSpecificOutput"]
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
            return payload if len(specific) > 1 else None

        if event_name == "PostToolUse":
            critical_blocks = [
                f for f in findings
                if f.decision == "block" and f.severity >= Severity.CRITICAL
            ]
            if critical_blocks:
                payload: dict[str, Any] = {
                    "continue": False,
                    "stopReason": self.join_messages(critical_blocks),
                }
                if context:
                    payload["hookSpecificOutput"] = {
                        "hookEventName": "PostToolUse",
                        "additionalContext": context,
                    }
                return payload

            payload = {}
            if decision in {"block", "deny", "ask"}:
                payload["decision"] = "block"
                payload["reason"] = self.join_messages(
                    self.decision_findings(findings, decision)
                )
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
            payload = {}
            if decision in {"block", "deny", "ask"}:
                payload["decision"] = "block"
                payload["reason"] = self.join_messages(
                    self.decision_findings(findings, decision)
                )
            if context:
                payload["hookSpecificOutput"] = {
                    "hookEventName": "UserPromptSubmit",
                    "additionalContext": context,
                }
            return payload or None

        if event_name == "Stop":
            payload = {}
            if decision in {"block", "deny", "ask"}:
                payload["decision"] = "block"
                payload["reason"] = self.join_messages(
                    self.decision_findings(findings, decision)
                )
            if context and not payload.get("decision"):
                payload["systemMessage"] = context
            elif context:
                existing = payload.get("reason", "")
                payload["reason"] = (
                    (existing + "\n\n" + context).strip() if existing else context
                )
            return payload or None

        return None
