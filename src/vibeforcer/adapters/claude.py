"""Claude Code adapter — the original/default platform."""

from __future__ import annotations

from typing_extensions import override

from vibeforcer._types import ObjectDict, ObjectMapping, object_dict, string_value
from vibeforcer.adapters.base import PlatformAdapter
from vibeforcer.models import RuleFinding


class ClaudeAdapter(PlatformAdapter):
    name: str = "claude"

    @override
    def normalize_payload(self, raw: ObjectMapping) -> ObjectDict:
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

        updated_input = updated_input or {}

        if event_name == "PreToolUse":
            payload: ObjectDict = {
                "hookSpecificOutput": {"hookEventName": "PreToolUse"}
            }
            specific = object_dict(payload["hookSpecificOutput"])
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
            if updated_input:
                specific["updatedInput"] = updated_input
            if context:
                specific["additionalContext"] = context
            return payload if len(specific) > 1 else None

        if event_name == "PermissionRequest":
            if decision not in {"deny", "allow"}:
                return None
            inner: ObjectDict = {"behavior": "allow" if decision == "allow" else "deny"}
            if updated_input and decision == "allow":
                inner["updatedInput"] = updated_input
            if decision == "deny":
                inner["message"] = self.join_messages(
                    self.decision_findings(findings, decision)
                )
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PermissionRequest",
                    "decision": inner,
                }
            }

        if event_name == "SessionStart":
            if context:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "SessionStart",
                        "additionalContext": context,
                    }
                }
            return None

        if event_name in {"UserPromptSubmit", "PostToolUse"}:
            payload: ObjectDict = {}
            if decision in {"block", "deny", "ask"}:
                payload["decision"] = "block"
                payload["reason"] = self.join_messages(
                    self.decision_findings(findings, decision)
                )
            if context:
                payload["hookSpecificOutput"] = {
                    "hookEventName": event_name,
                    "additionalContext": context,
                }
            return payload or None

        if event_name in {"Stop", "SubagentStop", "ConfigChange"}:
            payload = {}
            if decision in {"block", "deny", "ask"}:
                payload["decision"] = "block"
                payload["reason"] = self.join_messages(
                    self.decision_findings(findings, decision)
                )
            if context and not payload.get("decision"):
                payload["systemMessage"] = context
            elif context:
                existing = string_value(payload.get("reason"))
                payload["reason"] = (
                    (existing + "\n\n" + context).strip() if existing else context
                )
            return payload or None

        if event_name == "PostToolUseFailure":
            if context:
                return {"systemMessage": context}
            return None

        if event_name in {"TaskCompleted", "TeammateIdle"}:
            if decision in {"block", "deny"}:
                return {
                    "continue": False,
                    "stopReason": self.join_messages(
                        self.decision_findings(findings, decision)
                    ),
                }
            if context:
                return {"systemMessage": context}
            return None

        return None
