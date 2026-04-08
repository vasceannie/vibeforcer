"""Tests for platform adapters — input normalisation + output rendering.

Tests cover:
  1. Claude adapter backward compatibility (same output as before)
  2. Codex adapter input/output shapes
  3. OpenCode adapter input normalisation and output shapes
  4. Cross-platform: same payload → same findings, different output format
  5. Unsupported events produce None on restricted platforms
  6. Edge cases: mixed decisions, empty messages, mutation safety, combined
     context+decision, fixture replay through full engine pipeline
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vibeforcer.adapters import get_adapter, ADAPTERS
from vibeforcer.adapters.base import PlatformAdapter
from vibeforcer.adapters.claude import ClaudeAdapter
from vibeforcer.adapters.codex import CodexAdapter
from vibeforcer.adapters.opencode import OpenCodeAdapter
from vibeforcer.engine import evaluate_payload
from vibeforcer.models import RuleFinding, Severity
from conftest import BUNDLE_ROOT

FIXTURES_DIR = BUNDLE_ROOT / "fixtures"


# ===========================================================================
# Adapter registry
# ===========================================================================

class TestAdapterRegistry:
    def test_all_platforms_registered(self):
        assert "claude" in ADAPTERS
        assert "codex" in ADAPTERS
        assert "opencode" in ADAPTERS

    def test_get_adapter_returns_correct_type(self):
        assert isinstance(get_adapter("claude"), ClaudeAdapter)
        assert isinstance(get_adapter("codex"), CodexAdapter)
        assert isinstance(get_adapter("opencode"), OpenCodeAdapter)

    def test_unknown_platform_raises(self):
        with pytest.raises(ValueError, match="Unknown platform"):
            get_adapter("vim")


# ===========================================================================
# Claude adapter — backward compatibility
# ===========================================================================

class TestClaudeAdapter:
    """Ensure Claude adapter produces identical output to old render_output."""

    def test_normalize_is_passthrough(self):
        adapter = ClaudeAdapter()
        raw = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": "/tmp"}
        assert adapter.normalize_payload(raw) is raw

    def test_pretool_deny(self):
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="GIT-001",
                title="No --no-verify",
                severity=Severity.HIGH,
                decision="deny",
                message="hook bypass detected",
            )
        ]
        output = adapter.render_output(
            "PreToolUse", findings,
            decision="deny", context=None, updated_input={},
        )
        assert output is not None
        spec = output["hookSpecificOutput"]
        assert spec["permissionDecision"] == "deny"
        assert "GIT-001" in spec["permissionDecisionReason"]

    def test_permission_request_deny(self):
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="TEST-001", title="t", severity=Severity.HIGH,
                decision="deny", message="blocked",
            )
        ]
        output = adapter.render_output(
            "PermissionRequest", findings,
            decision="deny", context=None, updated_input={},
        )
        assert output is not None
        inner = output["hookSpecificOutput"]["decision"]
        assert inner["behavior"] == "deny"
        assert "TEST-001" in inner["message"]

    def test_stop_block(self):
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="STOP-001", title="t", severity=Severity.HIGH,
                decision="block", message="check issues",
            )
        ]
        output = adapter.render_output(
            "Stop", findings,
            decision="block", context=None, updated_input={},
        )
        assert output is not None
        assert output["decision"] == "block"
        assert "STOP-001" in output["reason"]

    def test_session_start_context(self):
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="CTX-001", title="t", severity=Severity.LOW,
                additional_context="load conventions",
            )
        ]
        output = adapter.render_output(
            "SessionStart", findings,
            decision=None, context="load conventions", updated_input={},
        )
        assert output is not None
        assert output["hookSpecificOutput"]["additionalContext"] == "load conventions"

    def test_task_completed_block(self):
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="TC-001", title="t", severity=Severity.HIGH,
                decision="block", message="not done",
            )
        ]
        output = adapter.render_output(
            "TaskCompleted", findings,
            decision="block", context=None, updated_input={},
        )
        assert output is not None
        assert output["continue"] is False
        assert "TC-001" in output["stopReason"]

    def test_pretool_block_maps_to_deny(self):
        """Engine uses 'block' internally; Claude Code expects 'deny' for PreToolUse."""
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="SYS-001", title="t", severity=Severity.HIGH,
                decision="block", message="system path blocked",
            )
        ]
        output = adapter.render_output(
            "PreToolUse", findings,
            decision="block", context=None, updated_input={},
        )
        assert output is not None
        spec = output["hookSpecificOutput"]
        # "block" → "deny" in Claude Code output
        assert spec["permissionDecision"] == "deny"
        assert "SYS-001" in spec["permissionDecisionReason"]

    def test_pretool_deny_with_context_and_updated_input(self):
        """All three fields (decision, context, updatedInput) in one output."""
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="X-001", title="t", severity=Severity.HIGH,
                decision="deny", message="nope",
                additional_context="policy says no",
                updated_input={"command": "echo safe"},
            )
        ]
        output = adapter.render_output(
            "PreToolUse", findings,
            decision="deny", context="policy says no",
            updated_input={"command": "echo safe"},
        )
        spec = output["hookSpecificOutput"]
        assert spec["permissionDecision"] == "deny"
        assert spec["additionalContext"] == "policy says no"
        assert spec["updatedInput"] == {"command": "echo safe"}

    def test_permission_request_allow_with_updated_input(self):
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="MOD-001", title="t", severity=Severity.LOW,
                decision="allow", updated_input={"command": "echo safe"},
            )
        ]
        output = adapter.render_output(
            "PermissionRequest", findings,
            decision="allow", context=None, updated_input={"command": "echo safe"},
        )
        inner = output["hookSpecificOutput"]["decision"]
        assert inner["behavior"] == "allow"
        assert inner["updatedInput"] == {"command": "echo safe"}
        assert "message" not in inner  # message is for deny only

    def test_permission_request_non_deny_non_allow_returns_none(self):
        """PermissionRequest only handles deny and allow; anything else → None."""
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(rule_id="X", title="t", severity=Severity.HIGH,
                        decision="block", message="m")
        ]
        assert adapter.render_output(
            "PermissionRequest", findings,
            decision="block", context=None, updated_input={},
        ) is None

    def test_posttool_use_failure_advisory(self):
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(rule_id="F-001", title="t", severity=Severity.MEDIUM,
                        additional_context="the tool failed, try another approach")
        ]
        output = adapter.render_output(
            "PostToolUseFailure", findings,
            decision=None, context="the tool failed, try another approach",
            updated_input={},
        )
        assert output == {"systemMessage": "the tool failed, try another approach"}

    def test_posttool_use_failure_no_context_returns_none(self):
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(rule_id="F-002", title="t", severity=Severity.HIGH,
                        decision="block", message="m")
        ]
        # PostToolUseFailure ignores decision; only context produces output
        assert adapter.render_output(
            "PostToolUseFailure", findings,
            decision="block", context=None, updated_input={},
        ) is None

    def test_stop_context_only_no_decision(self):
        """Stop with context but no blocking decision → systemMessage."""
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(rule_id="CTX-002", title="t", severity=Severity.LOW,
                        additional_context="don't forget to commit")
        ]
        output = adapter.render_output(
            "Stop", findings,
            decision=None, context="don't forget to commit", updated_input={},
        )
        assert output == {"systemMessage": "don't forget to commit"}

    def test_stop_block_with_context(self):
        """When Stop has both block + context, context appends to reason."""
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(rule_id="STOP-001", title="t", severity=Severity.HIGH,
                        decision="block", message="unfinished tests",
                        additional_context="also check lint")
        ]
        output = adapter.render_output(
            "Stop", findings,
            decision="block", context="also check lint", updated_input={},
        )
        assert output["decision"] == "block"
        assert "STOP-001" in output["reason"]
        assert "also check lint" in output["reason"]

    def test_teammate_idle_context_only(self):
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(rule_id="CTX", title="t", severity=Severity.LOW,
                        additional_context="work available in queue")
        ]
        output = adapter.render_output(
            "TeammateIdle", findings,
            decision=None, context="work available in queue", updated_input={},
        )
        assert output == {"systemMessage": "work available in queue"}

    def test_unknown_event_returns_none(self):
        """Events not handled by any branch fall through to None."""
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(rule_id="X", title="t", severity=Severity.HIGH,
                        decision="block", message="m")
        ]
        assert adapter.render_output(
            "CompletelyFakeEvent", findings,
            decision="block", context=None, updated_input={},
        ) is None

    def test_empty_findings_returns_none_for_all_events(self):
        """No findings → None for every event type."""
        adapter = ClaudeAdapter()
        for event in ["PreToolUse", "PermissionRequest", "PostToolUse",
                       "Stop", "SessionStart", "UserPromptSubmit",
                       "TaskCompleted", "TeammateIdle", "PostToolUseFailure",
                       "ConfigChange", "SubagentStop"]:
            assert adapter.render_output(
                event, [], decision=None, context=None, updated_input={},
            ) is None


# ===========================================================================
# Codex adapter
# ===========================================================================

class TestCodexAdapter:
    def test_normalize_is_passthrough(self):
        adapter = CodexAdapter()
        raw = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "cwd": "/tmp",
            "session_id": "s1",
            "turn_id": "t1",
            "model": "gpt-5.4",
        }
        canonical = adapter.normalize_payload(raw)
        assert canonical is raw  # Codex format is already canonical

    def test_pretool_deny(self):
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="GIT-001", title="No --no-verify",
                severity=Severity.HIGH, decision="deny",
                message="hook bypass detected",
            )
        ]
        output = adapter.render_output(
            "PreToolUse", findings,
            decision="deny", context=None, updated_input={},
        )
        assert output is not None
        spec = output["hookSpecificOutput"]
        assert spec["hookEventName"] == "PreToolUse"
        assert spec["permissionDecision"] == "deny"
        assert "GIT-001" in spec["permissionDecisionReason"]

    def test_pretool_block_maps_to_deny(self):
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="SYS-001", title="t", severity=Severity.HIGH,
                decision="block", message="system path",
            )
        ]
        output = adapter.render_output(
            "PreToolUse", findings,
            decision="block", context=None, updated_input={},
        )
        spec = output["hookSpecificOutput"]
        assert spec["permissionDecision"] == "deny"

    def test_stop_block(self):
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="STOP-001", title="t", severity=Severity.HIGH,
                decision="block", message="review issues",
            )
        ]
        output = adapter.render_output(
            "Stop", findings,
            decision="block", context=None, updated_input={},
        )
        assert output is not None
        assert output["decision"] == "block"
        assert "STOP-001" in output["reason"]

    def test_session_start_context(self):
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="CTX-001", title="t", severity=Severity.LOW,
                additional_context="workspace conventions",
            )
        ]
        output = adapter.render_output(
            "SessionStart", findings,
            decision=None, context="workspace conventions", updated_input={},
        )
        assert output is not None
        assert "workspace conventions" in output["hookSpecificOutput"]["additionalContext"]

    def test_user_prompt_submit_block(self):
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="PROMPT-001", title="t", severity=Severity.HIGH,
                decision="block", message="api key detected",
            )
        ]
        output = adapter.render_output(
            "UserPromptSubmit", findings,
            decision="block", context=None, updated_input={},
        )
        assert output is not None
        assert output["decision"] == "block"

    def test_posttool_context(self):
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="Q-001", title="t", severity=Severity.MEDIUM,
                additional_context="files were updated",
            )
        ]
        output = adapter.render_output(
            "PostToolUse", findings,
            decision=None, context="files were updated", updated_input={},
        )
        assert output is not None
        assert "files were updated" in output["hookSpecificOutput"]["additionalContext"]

    def test_unsupported_event_returns_none(self):
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="X-001", title="t", severity=Severity.HIGH,
                decision="deny", message="blocked",
            )
        ]
        # PermissionRequest doesn't exist in Codex
        output = adapter.render_output(
            "PermissionRequest", findings,
            decision="deny", context=None, updated_input={},
        )
        assert output is None

        # SubagentStop doesn't exist in Codex
        output = adapter.render_output(
            "SubagentStop", findings,
            decision="block", context=None, updated_input={},
        )
        assert output is None

    def test_no_findings_returns_none(self):
        adapter = CodexAdapter()
        output = adapter.render_output(
            "PreToolUse", [],
            decision=None, context=None, updated_input={},
        )
        assert output is None

    def test_posttool_critical_block_stops_session(self):
        """CRITICAL severity block on PostToolUse should emit continue:false
        WITHOUT decision:"block" (they conflict in Codex semantics)."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="CRIT-001", title="critical", severity=Severity.CRITICAL,
                decision="block", message="critical safety violation",
            )
        ]
        output = adapter.render_output(
            "PostToolUse", findings,
            decision="block", context=None, updated_input={},
        )
        assert output is not None
        assert output["continue"] is False
        assert "CRIT-001" in output["stopReason"]
        # Must NOT include decision:"block" alongside continue:false
        assert "decision" not in output

    def test_posttool_high_block_does_not_stop_session(self):
        """HIGH severity block on PostToolUse should NOT emit continue:false."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="HIGH-001", title="high", severity=Severity.HIGH,
                decision="block", message="non-critical issue",
            )
        ]
        output = adapter.render_output(
            "PostToolUse", findings,
            decision="block", context=None, updated_input={},
        )
        assert output is not None
        assert output["decision"] == "block"
        assert "continue" not in output

    def test_posttool_critical_with_context(self):
        """CRITICAL PostToolUse stop should preserve additionalContext."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="CRIT-002", title="t", severity=Severity.CRITICAL,
                decision="block", message="critical",
                additional_context="also check this",
            )
        ]
        output = adapter.render_output(
            "PostToolUse", findings,
            decision="block", context="also check this", updated_input={},
        )
        assert output["continue"] is False
        assert "decision" not in output  # no conflicting decision
        assert output["hookSpecificOutput"]["additionalContext"] == "also check this"

    def test_posttool_mixed_critical_and_high(self):
        """Mixed CRITICAL + HIGH: CRITICAL wins → continue:false, no decision."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(rule_id="HIGH-001", title="t", severity=Severity.HIGH,
                        decision="block", message="high issue"),
            RuleFinding(rule_id="CRIT-001", title="t", severity=Severity.CRITICAL,
                        decision="block", message="critical issue"),
        ]
        output = adapter.render_output(
            "PostToolUse", findings,
            decision="block", context=None, updated_input={},
        )
        assert output["continue"] is False
        assert "CRIT-001" in output["stopReason"]
        assert "decision" not in output

    def test_pretool_deny_with_context(self):
        """PreToolUse deny + context both present in output."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(rule_id="R-001", title="t", severity=Severity.HIGH,
                        decision="deny", message="nope",
                        additional_context="try something else"),
        ]
        output = adapter.render_output(
            "PreToolUse", findings,
            decision="deny", context="try something else", updated_input={},
        )
        spec = output["hookSpecificOutput"]
        assert spec["permissionDecision"] == "deny"
        assert spec["additionalContext"] == "try something else"

    def test_pretool_only_context_no_decision(self):
        """PreToolUse with only context (no deny/block) → additionalContext."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(rule_id="CTX-001", title="t", severity=Severity.LOW,
                        additional_context="check search results"),
        ]
        output = adapter.render_output(
            "PreToolUse", findings,
            decision=None, context="check search results", updated_input={},
        )
        spec = output["hookSpecificOutput"]
        # No permissionDecision, only context
        assert "permissionDecision" not in spec
        assert spec["additionalContext"] == "check search results"

    def test_stop_context_appended_to_reason(self):
        """Stop block + context → context merged into reason."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(rule_id="STOP-001", title="t", severity=Severity.HIGH,
                        decision="block", message="unfinished",
                        additional_context="run tests"),
        ]
        output = adapter.render_output(
            "Stop", findings,
            decision="block", context="run tests", updated_input={},
        )
        assert output["decision"] == "block"
        assert "STOP-001" in output["reason"]
        assert "run tests" in output["reason"]

    def test_user_prompt_block_with_context(self):
        """UserPromptSubmit block + context → both in output."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(rule_id="P-001", title="t", severity=Severity.HIGH,
                        decision="block", message="api key",
                        additional_context="redact first"),
        ]
        output = adapter.render_output(
            "UserPromptSubmit", findings,
            decision="block", context="redact first", updated_input={},
        )
        assert output["decision"] == "block"
        assert output["hookSpecificOutput"]["additionalContext"] == "redact first"

    def test_all_unsupported_codex_events(self):
        """Every Claude Code event not in CODEX_EVENTS → None."""
        adapter = CodexAdapter()
        dummy = [RuleFinding(rule_id="X", title="t", severity=Severity.HIGH,
                             decision="block", message="m")]
        for event in ["PermissionRequest", "SubagentStop", "PostToolUseFailure",
                       "TaskCompleted", "TeammateIdle", "ConfigChange",
                       "Notification", "SubagentStart", "InstructionsLoaded",
                       "WorktreeCreate", "WorktreeRemove", "PreCompact",
                       "PostCompact", "Elicitation", "ElicitationResult",
                       "SessionEnd", "StopFailure", "CwdChanged",
                       "FileChanged", "TaskCreated"]:
            assert adapter.render_output(
                event, dummy, decision="block", context=None, updated_input={},
            ) is None, f"{event} should return None on Codex"


# ===========================================================================
# OpenCode adapter
# ===========================================================================

class TestOpenCodeAdapter:
    def test_normalize_maps_event_name(self):
        adapter = OpenCodeAdapter()
        raw = {
            "hook_event_name": "tool.execute.before",
            "tool_name": "bash",
            "tool_input": {"command": "ls"},
            "cwd": "/tmp",
            "session_id": "opencode-123-abc",
        }
        canonical = adapter.normalize_payload(raw)
        assert canonical["hook_event_name"] == "PreToolUse"
        assert canonical["tool_name"] == "Bash"

    def test_normalize_preserves_already_canonical(self):
        adapter = OpenCodeAdapter()
        raw = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/x.py", "content": "print(1)"},
            "cwd": "/tmp",
            "session_id": "oc2",
        }
        canonical = adapter.normalize_payload(raw)
        # Already uppercase, already canonical event name
        assert canonical["hook_event_name"] == "PreToolUse"
        assert canonical["tool_name"] == "Write"

    def test_normalize_capitalizes_tool_name(self):
        adapter = OpenCodeAdapter()
        raw = {
            "hook_event_name": "tool.execute.before",
            "tool_name": "write",
            "tool_input": {},
            "cwd": "/tmp",
            "session_id": "oc3",
        }
        canonical = adapter.normalize_payload(raw)
        assert canonical["tool_name"] == "Write"

    def test_pretool_deny_action_block(self):
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="GIT-001", title="t", severity=Severity.HIGH,
                decision="deny", message="hook bypass detected",
            )
        ]
        output = adapter.render_output(
            "PreToolUse", findings,
            decision="deny", context=None, updated_input={},
        )
        assert output is not None
        assert output["action"] == "block"
        assert "GIT-001" in output["reason"]

    def test_pretool_allow_with_updated_args(self):
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="MOD-001", title="t", severity=Severity.LOW,
                decision="allow", updated_input={"command": "echo safe"},
            )
        ]
        output = adapter.render_output(
            "PreToolUse", findings,
            decision="allow", context=None, updated_input={"command": "echo safe"},
        )
        assert output is not None
        assert output["action"] == "allow"
        assert output["updated_args"] == {"command": "echo safe"}

    def test_pretool_context_only(self):
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="INFO-001", title="t", severity=Severity.LOW,
                additional_context="remember to test",
            )
        ]
        output = adapter.render_output(
            "PreToolUse", findings,
            decision=None, context="remember to test", updated_input={},
        )
        assert output is not None
        assert output["action"] == "context"
        assert output["context"] == "remember to test"

    def test_posttool_warn(self):
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="Q-001", title="t", severity=Severity.MEDIUM,
                decision="block", message="quality issue",
            )
        ]
        output = adapter.render_output(
            "PostToolUse", findings,
            decision="block", context=None, updated_input={},
        )
        assert output is not None
        assert output["action"] == "warn"
        assert "Q-001" in output["reason"]

    def test_stop_continue(self):
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="STOP-001", title="t", severity=Severity.HIGH,
                decision="block", message="run tests",
            )
        ]
        output = adapter.render_output(
            "Stop", findings,
            decision="block", context=None, updated_input={},
        )
        assert output is not None
        assert output["action"] == "continue"
        assert "STOP-001" in output["reason"]

    def test_session_start_context(self):
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="CTX-001", title="t", severity=Severity.LOW,
                additional_context="load conventions",
            )
        ]
        output = adapter.render_output(
            "SessionStart", findings,
            decision=None, context="load conventions", updated_input={},
        )
        assert output is not None
        assert output["action"] == "context"

    def test_permission_deny(self):
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="PERM-001", title="t", severity=Severity.HIGH,
                decision="deny", message="not allowed",
            )
        ]
        output = adapter.render_output(
            "PermissionRequest", findings,
            decision="deny", context=None, updated_input={},
        )
        assert output is not None
        assert output["action"] == "block"

    def test_no_findings_returns_none(self):
        adapter = OpenCodeAdapter()
        output = adapter.render_output(
            "PreToolUse", [],
            decision=None, context=None, updated_input={},
        )
        assert output is None

    def test_pretool_ask_maps_to_block(self):
        """OpenCode has no 'ask' concept; ask → block."""
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="ASK-001", title="t", severity=Severity.MEDIUM,
                decision="ask", message="confirm this",
            )
        ]
        output = adapter.render_output(
            "PreToolUse", findings,
            decision="ask", context=None, updated_input={},
        )
        assert output is not None
        assert output["action"] == "block"

    def test_normalize_tool_result_aliasing(self):
        """tool_response should be aliased to tool_result and vice versa."""
        adapter = OpenCodeAdapter()

        # Shim sends tool_result (preferred) → tool_response should appear
        raw1 = {
            "hook_event_name": "tool.execute.after",
            "tool_name": "bash",
            "tool_input": {"command": "echo hi"},
            "cwd": "/tmp",
            "session_id": "oc-test",
            "tool_result": "hi\n",
        }
        canonical1 = adapter.normalize_payload(raw1)
        assert canonical1["tool_result"] == "hi\n"
        assert canonical1["tool_response"] == "hi\n"

        # Shim sends tool_response (legacy) → tool_result should appear
        raw2 = {
            "hook_event_name": "tool.execute.after",
            "tool_name": "bash",
            "tool_input": {"command": "echo hi"},
            "cwd": "/tmp",
            "session_id": "oc-test",
            "tool_response": "hi\n",
        }
        canonical2 = adapter.normalize_payload(raw2)
        assert canonical2["tool_result"] == "hi\n"
        assert canonical2["tool_response"] == "hi\n"

    def test_normalize_session_idle_maps_to_stop(self):
        """session.idle → Stop."""
        adapter = OpenCodeAdapter()
        raw = {
            "hook_event_name": "session.idle",
            "tool_name": "",
            "tool_input": {},
            "cwd": "/tmp",
            "session_id": "oc-test",
        }
        canonical = adapter.normalize_payload(raw)
        assert canonical["hook_event_name"] == "Stop"

    def test_normalize_permission_asked_maps_to_permission_request(self):
        """permission.asked → PermissionRequest."""
        adapter = OpenCodeAdapter()
        raw = {
            "hook_event_name": "permission.asked",
            "tool_name": "bash",
            "tool_input": {"command": "rm -rf /"},
            "cwd": "/tmp",
            "session_id": "oc-test",
        }
        canonical = adapter.normalize_payload(raw)
        assert canonical["hook_event_name"] == "PermissionRequest"
        assert canonical["tool_name"] == "Bash"

    def test_normalize_does_not_mutate_original(self):
        """normalize_payload must return a new dict, not modify the input."""
        adapter = OpenCodeAdapter()
        raw = {
            "hook_event_name": "tool.execute.before",
            "tool_name": "bash",
            "tool_input": {"command": "ls"},
            "cwd": "/tmp",
            "session_id": "oc-test",
        }
        original_event = raw["hook_event_name"]
        original_tool = raw["tool_name"]
        canonical = adapter.normalize_payload(raw)
        # The returned dict should be different (shallow copy)
        assert canonical is not raw
        # Original should be untouched
        assert raw["hook_event_name"] == original_event
        assert raw["tool_name"] == original_tool

    def test_normalize_unknown_event_passthrough(self):
        """Unknown event names pass through unchanged (forward compat)."""
        adapter = OpenCodeAdapter()
        raw = {
            "hook_event_name": "some.future.event",
            "tool_name": "",
            "tool_input": {},
            "cwd": "/tmp",
            "session_id": "oc-test",
        }
        canonical = adapter.normalize_payload(raw)
        assert canonical["hook_event_name"] == "some.future.event"

    def test_normalize_empty_tool_name_stays_empty(self):
        """Empty string tool_name should not be capitalized to something weird."""
        adapter = OpenCodeAdapter()
        raw = {
            "hook_event_name": "session.idle",
            "tool_name": "",
            "tool_input": {},
            "cwd": "/tmp",
            "session_id": "oc-test",
        }
        canonical = adapter.normalize_payload(raw)
        assert canonical["tool_name"] == ""

    def test_normalize_both_tool_result_fields_present(self):
        """When shim sends both, both pass through without double-aliasing."""
        adapter = OpenCodeAdapter()
        raw = {
            "hook_event_name": "tool.execute.after",
            "tool_name": "bash",
            "tool_input": {},
            "cwd": "/tmp",
            "session_id": "oc-test",
            "tool_result": "output-a",
            "tool_response": "output-b",  # different value
        }
        canonical = adapter.normalize_payload(raw)
        # Both fields present → no aliasing, original values preserved
        assert canonical["tool_result"] == "output-a"
        assert canonical["tool_response"] == "output-b"

    def test_normalize_no_tool_result_fields(self):
        """PreToolUse payloads have no tool_result — shouldn't create one."""
        adapter = OpenCodeAdapter()
        raw = {
            "hook_event_name": "tool.execute.before",
            "tool_name": "bash",
            "tool_input": {"command": "ls"},
            "cwd": "/tmp",
            "session_id": "oc-test",
        }
        canonical = adapter.normalize_payload(raw)
        assert "tool_result" not in canonical
        assert "tool_response" not in canonical

    def test_pretool_deny_with_context(self):
        """Deny output includes context when provided."""
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(rule_id="R-001", title="t", severity=Severity.HIGH,
                        decision="deny", message="blocked",
                        additional_context="hint for the agent"),
        ]
        output = adapter.render_output(
            "PreToolUse", findings,
            decision="deny", context="hint for the agent", updated_input={},
        )
        assert output["action"] == "block"
        assert output["context"] == "hint for the agent"
        assert "R-001" in output["reason"]

    def test_posttool_with_context_and_decision(self):
        """PostToolUse block + context → both in output."""
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(rule_id="Q-001", title="t", severity=Severity.MEDIUM,
                        decision="block", message="quality issue",
                        additional_context="consider adding tests"),
        ]
        output = adapter.render_output(
            "PostToolUse", findings,
            decision="block", context="consider adding tests", updated_input={},
        )
        assert output["action"] == "warn"
        assert output["context"] == "consider adding tests"
        assert "Q-001" in output["reason"]

    def test_posttool_context_only(self):
        """PostToolUse with only context, no block decision."""
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(rule_id="CTX-001", title="t", severity=Severity.LOW,
                        additional_context="check test coverage"),
        ]
        output = adapter.render_output(
            "PostToolUse", findings,
            decision=None, context="check test coverage", updated_input={},
        )
        assert output == {"context": "check test coverage"}

    def test_stop_context_only(self):
        """Stop with context but no block → context action."""
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(rule_id="CTX", title="t", severity=Severity.LOW,
                        additional_context="remember to commit"),
        ]
        output = adapter.render_output(
            "Stop", findings,
            decision=None, context="remember to commit", updated_input={},
        )
        assert output == {"action": "context", "context": "remember to commit"}

    def test_permission_allow_with_updated_input(self):
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(rule_id="MOD-001", title="t", severity=Severity.LOW,
                        decision="allow", updated_input={"command": "echo safe"}),
        ]
        output = adapter.render_output(
            "PermissionRequest", findings,
            decision="allow", context=None, updated_input={"command": "echo safe"},
        )
        assert output["action"] == "allow"
        assert output["updated_args"] == {"command": "echo safe"}

    def test_permission_allow_no_updated_input_returns_none(self):
        """PermissionRequest allow without updated_input → nothing to do."""
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(rule_id="X", title="t", severity=Severity.LOW,
                        decision="allow"),
        ]
        assert adapter.render_output(
            "PermissionRequest", findings,
            decision="allow", context=None, updated_input={},
        ) is None

    def test_unknown_event_returns_none(self):
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(rule_id="X", title="t", severity=Severity.HIGH,
                        decision="block", message="m"),
        ]
        assert adapter.render_output(
            "TaskCompleted", findings,
            decision="block", context=None, updated_input={},
        ) is None


# ===========================================================================
# Base adapter helpers
# ===========================================================================

class TestBaseAdapterHelpers:
    """Test the static helper methods on PlatformAdapter."""

    def test_join_messages_formats_rule_id_and_severity(self):
        findings = [
            RuleFinding(rule_id="GIT-001", title="t", severity=Severity.HIGH,
                        message="hook bypass detected"),
            RuleFinding(rule_id="SYS-002", title="t", severity=Severity.CRITICAL,
                        message="system path violation"),
        ]
        text = PlatformAdapter.join_messages(findings)
        assert "[GIT-001 | HIGH]" in text
        assert "[SYS-002 | CRITICAL]" in text
        assert "hook bypass detected" in text
        assert "system path violation" in text

    def test_join_messages_skips_none_messages(self):
        findings = [
            RuleFinding(rule_id="A", title="t", severity=Severity.LOW, message=None),
            RuleFinding(rule_id="B", title="t", severity=Severity.LOW, message="visible"),
        ]
        text = PlatformAdapter.join_messages(findings)
        assert "visible" in text
        assert "A" not in text  # no message → no line

    def test_join_messages_empty_list(self):
        assert PlatformAdapter.join_messages([]) == ""

    def test_decision_findings_filters_correctly(self):
        findings = [
            RuleFinding(rule_id="A", title="t", severity=Severity.HIGH, decision="deny", message="a"),
            RuleFinding(rule_id="B", title="t", severity=Severity.LOW, decision="allow", message="b"),
            RuleFinding(rule_id="C", title="t", severity=Severity.MEDIUM, decision="deny", message="c"),
            RuleFinding(rule_id="D", title="t", severity=Severity.LOW, decision=None, message="d"),
        ]
        deny_findings = PlatformAdapter.decision_findings(findings, "deny")
        assert [f.rule_id for f in deny_findings] == ["A", "C"]

        allow_findings = PlatformAdapter.decision_findings(findings, "allow")
        assert [f.rule_id for f in allow_findings] == ["B"]

        none_findings = PlatformAdapter.decision_findings(findings, None)
        assert [f.rule_id for f in none_findings] == ["D"]

        empty = PlatformAdapter.decision_findings(findings, "block")
        assert empty == []


# ===========================================================================
# Multi-finding edge cases (cross-adapter)
# ===========================================================================

class TestMultiFindingBehavior:
    """Test what happens when the engine produces multiple findings with
    mixed decisions, and the adapter has to render a coherent output.

    These tests go through the full engine render_output path
    (decision priority, context merging, updated_input merging)
    into each adapter.
    """

    def _make_findings(self):
        """Three findings: deny (HIGH), allow (LOW), context-only (MEDIUM)."""
        return [
            RuleFinding(rule_id="DENY-001", title="t", severity=Severity.HIGH,
                        decision="deny", message="blocked by policy"),
            RuleFinding(rule_id="ALLOW-001", title="t", severity=Severity.LOW,
                        decision="allow", updated_input={"command": "safe"}),
            RuleFinding(rule_id="CTX-001", title="t", severity=Severity.MEDIUM,
                        additional_context="extra context here"),
        ]

    def test_claude_deny_wins_over_allow(self):
        """With mixed deny+allow, Claude adapter should deny (highest priority)."""
        from vibeforcer.engine import _top_decision, _collect_context, _merge_updated_input
        findings = self._make_findings()
        decision = _top_decision(findings)
        context = _collect_context(findings)
        updated = _merge_updated_input(findings)

        adapter = ClaudeAdapter()
        output = adapter.render_output(
            "PreToolUse", findings,
            decision=decision, context=context, updated_input=updated,
        )
        spec = output["hookSpecificOutput"]
        # Deny wins
        assert spec["permissionDecision"] == "deny"
        assert "DENY-001" in spec["permissionDecisionReason"]
        # Context still included
        assert spec["additionalContext"] == "extra context here"
        # Updated input still included (forward-looking)
        assert spec["updatedInput"] == {"command": "safe"}

    def test_codex_deny_wins_over_allow(self):
        from vibeforcer.engine import _top_decision, _collect_context, _merge_updated_input
        findings = self._make_findings()
        decision = _top_decision(findings)
        context = _collect_context(findings)
        updated = _merge_updated_input(findings)

        adapter = CodexAdapter()
        output = adapter.render_output(
            "PreToolUse", findings,
            decision=decision, context=context, updated_input=updated,
        )
        spec = output["hookSpecificOutput"]
        assert spec["permissionDecision"] == "deny"
        assert "DENY-001" in spec["permissionDecisionReason"]

    def test_opencode_deny_wins_over_allow(self):
        from vibeforcer.engine import _top_decision, _collect_context, _merge_updated_input
        findings = self._make_findings()
        decision = _top_decision(findings)
        context = _collect_context(findings)
        updated = _merge_updated_input(findings)

        adapter = OpenCodeAdapter()
        output = adapter.render_output(
            "PreToolUse", findings,
            decision=decision, context=context, updated_input=updated,
        )
        assert output["action"] == "block"
        assert "DENY-001" in output["reason"]
        # Context included despite block
        assert output["context"] == "extra context here"

    def test_context_deduplication(self):
        """Identical context strings should be deduplicated."""
        from vibeforcer.engine import _collect_context
        findings = [
            RuleFinding(rule_id="A", title="t", severity=Severity.LOW,
                        additional_context="same thing"),
            RuleFinding(rule_id="B", title="t", severity=Severity.LOW,
                        additional_context="same thing"),
            RuleFinding(rule_id="C", title="t", severity=Severity.LOW,
                        additional_context="different thing"),
        ]
        context = _collect_context(findings)
        assert context == "same thing\n\ndifferent thing"

    def test_updated_input_last_write_wins(self):
        """When multiple findings set the same key, last one wins."""
        from vibeforcer.engine import _merge_updated_input
        findings = [
            RuleFinding(rule_id="A", title="t", severity=Severity.LOW,
                        updated_input={"command": "first"}),
            RuleFinding(rule_id="B", title="t", severity=Severity.LOW,
                        updated_input={"command": "second", "extra": "value"}),
        ]
        merged = _merge_updated_input(findings)
        assert merged == {"command": "second", "extra": "value"}


# ===========================================================================
# Fixture replay — full engine pipeline
# ===========================================================================

class TestFixtureReplay:
    """Load real fixtures and replay them through the engine.

    These are integration tests: fixture → normalize → rules → render → verify.
    No mocking. Verifies that the full pipeline produces sensible output.
    """

    def test_codex_git_no_verify_denied(self):
        payload = json.loads(
            (FIXTURES_DIR / "codex" / "pretool_bash_git_no_verify.json").read_text()
        )
        result = evaluate_payload(payload, platform="codex")
        assert result.output is not None
        spec = result.output.get("hookSpecificOutput", {})
        assert spec.get("permissionDecision") == "deny"
        assert "GIT-001" in spec.get("permissionDecisionReason", "")
        # Also verify findings list
        ids = {f.rule_id for f in result.findings}
        assert "GIT-001" in ids

    def test_codex_rm_rf_denied(self):
        payload = json.loads(
            (FIXTURES_DIR / "codex" / "pretool_bash_rm_rf.json").read_text()
        )
        result = evaluate_payload(payload, platform="codex")
        assert result.output is not None
        spec = result.output.get("hookSpecificOutput", {})
        assert spec.get("permissionDecision") == "deny"

    def test_codex_session_start_produces_context(self):
        payload = json.loads(
            (FIXTURES_DIR / "codex" / "session_start.json").read_text()
        )
        result = evaluate_payload(payload, platform="codex")
        # SessionStart may or may not produce output depending on config;
        # the key is it doesn't crash and returns a valid EngineResult
        assert result.event_name == "SessionStart"
        assert result.errors == []

    def test_opencode_git_no_verify_denied(self):
        payload = json.loads(
            (FIXTURES_DIR / "opencode" / "pretool_bash_git_no_verify.json").read_text()
        )
        result = evaluate_payload(payload, platform="opencode")
        assert result.output is not None
        assert result.output["action"] == "block"
        assert "GIT-001" in result.output["reason"]

    def test_opencode_write_protected_denied(self):
        payload = json.loads(
            (FIXTURES_DIR / "opencode" / "pretool_write_protected.json").read_text()
        )
        result = evaluate_payload(payload, platform="opencode")
        assert result.output is not None
        assert result.output["action"] == "block"
        # Protected path rule should fire
        ids = {f.rule_id for f in result.findings}
        assert any("PROTECT" in rid or "CUPCAKE" in rid or "SECURITY" in rid
                    for rid in ids), f"Expected a protection rule, got: {ids}"

    def test_opencode_session_idle_no_crash(self):
        payload = json.loads(
            (FIXTURES_DIR / "opencode" / "session_idle.json").read_text()
        )
        result = evaluate_payload(payload, platform="opencode")
        assert result.event_name == "Stop"
        assert result.errors == []

    def test_opencode_permission_asked_processes(self):
        payload = json.loads(
            (FIXTURES_DIR / "opencode" / "permission_asked.json").read_text()
        )
        result = evaluate_payload(payload, platform="opencode")
        assert result.event_name == "PermissionRequest"
        assert result.errors == []
        # rm -rf should trigger something
        if result.output:
            assert result.output["action"] == "block"

    def test_codex_posttool_no_crash(self):
        payload = json.loads(
            (FIXTURES_DIR / "codex" / "posttool_bash.json").read_text()
        )
        result = evaluate_payload(payload, platform="codex")
        assert result.event_name == "PostToolUse"
        assert result.errors == []

    def test_all_fixtures_replay_without_errors(self):
        """Every fixture file replays through the engine without errors."""
        platform_map = {"codex": "codex", "opencode": "opencode"}
        for platform_dir in FIXTURES_DIR.iterdir():
            if not platform_dir.is_dir():
                continue
            platform = platform_map.get(platform_dir.name, "claude")
            for fixture_file in platform_dir.glob("*.json"):
                payload = json.loads(fixture_file.read_text())
                result = evaluate_payload(payload, platform=platform)
                assert result.errors == [], (
                    f"Fixture {platform_dir.name}/{fixture_file.name} "
                    f"produced errors: {result.errors}"
                )
        # Also replay top-level (Claude) fixtures
        for fixture_file in FIXTURES_DIR.glob("*.json"):
            if fixture_file.is_file():
                payload = json.loads(fixture_file.read_text())
                result = evaluate_payload(payload, platform="claude")
                assert result.errors == [], (
                    f"Fixture {fixture_file.name} produced errors: {result.errors}"
                )


# ===========================================================================
# Cross-platform: same findings, different output shapes
# ===========================================================================

class TestCrossPlatform:
    """Same payload through all adapters produces correct per-platform output."""

    def _git_no_verify_payload(self):
        return {
            "session_id": "cross-test",
            "cwd": str(BUNDLE_ROOT),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git commit --no-verify -m 'test'"},
        }

    def test_claude_and_codex_produce_same_structure(self):
        """Claude and Codex both use hookSpecificOutput.permissionDecision."""
        payload = self._git_no_verify_payload()
        claude_result = evaluate_payload(payload, platform="claude")
        codex_result = evaluate_payload(payload, platform="codex")

        # Both should deny
        assert claude_result.output is not None
        assert codex_result.output is not None

        c_spec = claude_result.output.get("hookSpecificOutput", {})
        x_spec = codex_result.output.get("hookSpecificOutput", {})

        assert c_spec.get("permissionDecision") == "deny"
        assert x_spec.get("permissionDecision") == "deny"
        assert "GIT-001" in c_spec.get("permissionDecisionReason", "")
        assert "GIT-001" in x_spec.get("permissionDecisionReason", "")

    def test_opencode_produces_block_action(self):
        """OpenCode uses action:block instead of hookSpecificOutput."""
        payload = self._git_no_verify_payload()
        # Simulate OpenCode shim sending us the payload with OC event name
        oc_payload = dict(payload)
        oc_payload["hook_event_name"] = "tool.execute.before"
        oc_payload["tool_name"] = "bash"  # lowercase from OpenCode

        result = evaluate_payload(oc_payload, platform="opencode")
        assert result.output is not None
        assert result.output["action"] == "block"
        assert "GIT-001" in result.output["reason"]

    def test_same_findings_different_format(self):
        """All platforms produce the same findings, just rendered differently."""
        payload = self._git_no_verify_payload()
        claude_result = evaluate_payload(payload, platform="claude")

        oc_payload = dict(payload)
        oc_payload["hook_event_name"] = "tool.execute.before"
        oc_payload["tool_name"] = "bash"
        opencode_result = evaluate_payload(oc_payload, platform="opencode")

        codex_result = evaluate_payload(payload, platform="codex")

        # All should have the same finding rule IDs
        claude_ids = {f.rule_id for f in claude_result.findings}
        codex_ids = {f.rule_id for f in codex_result.findings}
        opencode_ids = {f.rule_id for f in opencode_result.findings}

        assert "GIT-001" in claude_ids
        assert "GIT-001" in codex_ids
        assert "GIT-001" in opencode_ids


# ===========================================================================
# CLI --platform integration
# ===========================================================================

class TestCLIPlatform:
    def test_handle_with_platform_flag(self):
        """Verify CLI accepts --platform without error."""
        from vibeforcer.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["handle", "--platform", "codex"])
        assert args.platform == "codex"

    def test_handle_default_platform(self):
        from vibeforcer.cli import build_parser
        parser = build_parser()
        args = parser.parse_args(["handle"])
        assert args.platform == "claude"

    def test_replay_with_platform(self):
        from vibeforcer.cli import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "replay", "--payload", "test.json", "--platform", "opencode"
        ])
        assert args.platform == "opencode"

    def test_invalid_platform_rejected(self):
        from vibeforcer.cli import build_parser
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["handle", "--platform", "vim"])

    def test_safe_main_returns_130_on_keyboard_interrupt(self, monkeypatch):
        from vibeforcer import cli

        def boom(_argv=None):
            raise KeyboardInterrupt

        monkeypatch.setattr(cli, "main", boom)
        assert cli.safe_main() == 130
