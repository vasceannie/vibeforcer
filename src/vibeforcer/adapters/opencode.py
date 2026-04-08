"""OpenCode adapter."""
from __future__ import annotations

from typing import Any

from vibeforcer.adapters.base import PlatformAdapter
from vibeforcer.models import RuleFinding

OPENCODE_EVENT_MAP: dict[str, str] = {
    "tool.execute.before": "PreToolUse",
    "tool.execute.after": "PostToolUse",
    "session.created": "SessionStart",
    "session.idle": "Stop",
    "permission.asked": "PermissionRequest",
}


class OpenCodeAdapter(PlatformAdapter):
    name = "opencode"

    def normalize_payload(self, raw: dict[str, Any]) -> dict[str, Any]:
        canonical = dict(raw)
        oc_event = raw.get("hook_event_name", "")
        canonical_event = OPENCODE_EVENT_MAP.get(oc_event, oc_event)
        canonical["hook_event_name"] = canonical_event

        tool_name = raw.get("tool_name", "")
        if tool_name and tool_name[0].islower():
            canonical["tool_name"] = tool_name.capitalize()

        if "tool_response" in canonical and "tool_result" not in canonical:
            canonical["tool_result"] = canonical["tool_response"]
        elif "tool_result" in canonical and "tool_response" not in canonical:
            canonical["tool_response"] = canonical["tool_result"]

        return canonical

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

        updated_input = updated_input or {}

        if event_name == "PreToolUse":
            if decision in {"deny", "block"}:
                result: dict[str, Any] = {
                    "action": "block",
                    "reason": self.join_messages(
                        self.decision_findings(findings, decision)
                    ),
                }
                if context:
                    result["context"] = context
                return result
            if decision == "ask":
                return {
                    "action": "block",
                    "reason": self.join_messages(
                        self.decision_findings(findings, decision)
                    ),
                }
            if decision == "allow" and updated_input:
                result = {"action": "allow"}
                result["updated_args"] = updated_input
                if context:
                    result["context"] = context
                return result
            if context:
                return {"action": "context", "context": context}
            return None

        if event_name == "PermissionRequest":
            if decision == "deny":
                return {
                    "action": "block",
                    "reason": self.join_messages(
                        self.decision_findings(findings, decision)
                    ),
                }
            if decision == "allow" and updated_input:
                return {"action": "allow", "updated_args": updated_input}
            return None

        if event_name == "PostToolUse":
            payload: dict[str, Any] = {}
            if decision in {"block", "deny"}:
                payload["action"] = "warn"
                payload["reason"] = self.join_messages(
                    self.decision_findings(findings, decision)
                )
            if context:
                payload["context"] = context
            return payload or None

        if event_name == "SessionStart":
            if context:
                return {"action": "context", "context": context}
            return None

        if event_name == "Stop":
            if decision in {"block", "deny"}:
                return {
                    "action": "continue",
                    "reason": self.join_messages(
                        self.decision_findings(findings, decision)
                    ),
                }
            if context:
                return {"action": "context", "context": context}
            return None

        return None
