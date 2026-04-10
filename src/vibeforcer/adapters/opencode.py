"""OpenCode adapter."""

from __future__ import annotations

from typing_extensions import override

from vibeforcer._types import ObjectDict, ObjectMapping, object_dict, string_value
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
    name: str = "opencode"

    @override
    def normalize_payload(self, raw: ObjectMapping) -> ObjectDict:
        canonical = object_dict(raw)
        oc_event = string_value(raw.get("hook_event_name")) or ""
        canonical_event = OPENCODE_EVENT_MAP.get(oc_event, oc_event)
        canonical["hook_event_name"] = canonical_event

        tool_name = string_value(raw.get("tool_name")) or ""
        if tool_name and tool_name[0].islower():
            canonical["tool_name"] = tool_name.capitalize()

        if "tool_response" in canonical and "tool_result" not in canonical:
            canonical["tool_result"] = canonical["tool_response"]
        elif "tool_result" in canonical and "tool_response" not in canonical:
            canonical["tool_response"] = canonical["tool_result"]

        return canonical

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
            if decision in {"deny", "block"}:
                blocked_result: ObjectDict = {
                    "action": "block",
                    "reason": self.join_messages(
                        self.decision_findings(findings, decision)
                    ),
                }
                if context:
                    blocked_result["context"] = context
                return blocked_result
            if decision == "ask":
                return {
                    "action": "block",
                    "reason": self.join_messages(
                        self.decision_findings(findings, decision)
                    ),
                }
            if decision == "allow" and updated_input:
                allowed_result: ObjectDict = {"action": "allow"}
                allowed_result["updated_args"] = updated_input
                if context:
                    allowed_result["context"] = context
                return allowed_result
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
            payload: ObjectDict = {}
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
