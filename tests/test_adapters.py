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

from collections.abc import Callable
import json
from pathlib import Path
import vibeforcer.engine as engine_module
from typing import cast

import pytest

from tests import support as test_support

from vibeforcer._types import ObjectDict, object_dict, string_value
from vibeforcer.adapters import get_adapter, ADAPTERS
from vibeforcer.adapters.base import PlatformAdapter
from vibeforcer.adapters.claude import ClaudeAdapter
from vibeforcer.adapters.codex import CodexAdapter
from vibeforcer.adapters.opencode import OpenCodeAdapter
from vibeforcer.engine import evaluate_payload
from vibeforcer.models import RuleFinding, Severity

FIXTURES_DIR = test_support.BUNDLE_ROOT / "fixtures"
_RESOURCES_DIR = test_support.BUNDLE_ROOT / "src" / "vibeforcer" / "resources"


def _config_with_enabled_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *rule_ids: str
) -> None:
    raw = json.loads((_RESOURCES_DIR / "defaults.json").read_text(encoding="utf-8"))
    enabled = dict(raw.get("enabled_rules", {}))
    for rule_id in rule_ids:
        enabled[rule_id] = True
    raw["enabled_rules"] = enabled
    config_path = tmp_path / "adapter-spec-config.json"
    config_path.write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setenv("VIBEFORCER_CONFIG", str(config_path))


def require_rendered(output: ObjectDict | None) -> ObjectDict:
    assert output is not None, "Expected rendered adapter output, got None"
    return output


def require_spec(output: ObjectDict | None) -> ObjectDict:
    rendered = require_rendered(output)
    spec = object_dict(rendered.get("hookSpecificOutput"))
    assert spec, f"Expected hookSpecificOutput, got: {rendered}"
    return spec


def require_nested(mapping: ObjectDict, key: str) -> ObjectDict:
    nested = object_dict(mapping.get(key))
    assert nested, f"Expected nested mapping at {key!r}, got: {mapping}"
    return nested


def rendered_string(mapping: ObjectDict, key: str, default: str = "") -> str:
    value = string_value(mapping.get(key))
    return value if value is not None else default


# ===========================================================================
# Adapter registry
# ===========================================================================


class TestAdapterRegistry:
    def test_all_platforms_registered(self) -> None:
        assert "claude" in ADAPTERS, "claude adapter must be registered"
        assert "codex" in ADAPTERS, "codex adapter must be registered"
        assert "opencode" in ADAPTERS, "opencode adapter must be registered"

    def test_get_adapter_returns_correct_type(self) -> None:
        assert isinstance(get_adapter("claude"), ClaudeAdapter), (
            "claude must return ClaudeAdapter"
        )
        assert isinstance(get_adapter("codex"), CodexAdapter), (
            "codex must return CodexAdapter"
        )
        assert isinstance(get_adapter("opencode"), OpenCodeAdapter), (
            "opencode must return OpenCodeAdapter"
        )

    def test_unknown_platform_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown platform"):
            _ = get_adapter("vim")


# ===========================================================================
# Claude adapter — backward compatibility
# ===========================================================================


class TestClaudeAdapterBasic:
    """Claude adapter — core event rendering (normalize, pretool, permission, stop)."""

    def test_normalize_is_passthrough(self) -> None:
        adapter = ClaudeAdapter()
        raw = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": "/tmp"}
        assert adapter.normalize_payload(raw) is raw

    def test_pretool_deny(self) -> None:
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
            "PreToolUse",
            findings,
            decision="deny",
            context=None,
            updated_input={},
        )
        spec = require_spec(output)
        assert spec["permissionDecision"] == "deny", (
            "PreToolUse deny must set permissionDecision=deny"
        )
        assert "GIT-001" in test_support.required_string(
            spec, "permissionDecisionReason"
        )

    def test_permission_request_deny(self) -> None:
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="TEST-001",
                title="t",
                severity=Severity.HIGH,
                decision="deny",
                message="blocked",
            )
        ]
        output = adapter.render_output(
            "PermissionRequest",
            findings,
            decision="deny",
            context=None,
            updated_input={},
        )
        inner = require_nested(require_spec(output), "decision")
        assert inner["behavior"] == "deny", (
            "PermissionRequest deny must set behavior=deny"
        )
        assert "TEST-001" in test_support.required_string(inner, "message")

    def test_stop_block(self) -> None:
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="STOP-001",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="check issues",
            )
        ]
        output = adapter.render_output(
            "Stop",
            findings,
            decision="block",
            context=None,
            updated_input={},
        )
        rendered = require_rendered(output)
        assert rendered["decision"] == "block", "Stop block must set decision=block"
        assert "STOP-001" in test_support.required_string(rendered, "reason")

    def test_session_start_context(self) -> None:
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="CTX-001",
                title="t",
                severity=Severity.LOW,
                additional_context="load conventions",
            )
        ]
        output = adapter.render_output(
            "SessionStart",
            findings,
            decision=None,
            context="load conventions",
            updated_input={},
        )
        assert (
            test_support.required_string(require_spec(output), "additionalContext")
            == "load conventions"
        )

    def test_task_completed_block(self) -> None:
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="TC-001",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="not done",
            )
        ]
        output = adapter.render_output(
            "TaskCompleted",
            findings,
            decision="block",
            context=None,
            updated_input={},
        )
        rendered = require_rendered(output)
        assert rendered["continue"] is False, (
            "TaskCompleted block must set continue=False"
        )
        assert "TC-001" in test_support.required_string(rendered, "stopReason")

    def test_pretool_block_maps_to_deny(self) -> None:
        """Engine uses 'block' internally; Claude Code expects 'deny' for PreToolUse."""
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="SYS-001",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="system path blocked",
            )
        ]
        output = adapter.render_output(
            "PreToolUse",
            findings,
            decision="block",
            context=None,
            updated_input={},
        )
        spec = require_spec(output)
        # "block" → "deny" in Claude Code output
        assert spec["permissionDecision"] == "deny", (
            "block must map to deny for PreToolUse"
        )
        assert "SYS-001" in test_support.required_string(
            spec, "permissionDecisionReason"
        )

    def test_pretool_deny_with_context_and_updated_input(self) -> None:
        """All three fields (decision, context, updatedInput) in one output."""
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="X-001",
                title="t",
                severity=Severity.HIGH,
                decision="deny",
                message="nope",
                additional_context="policy says no",
                updated_input={"command": "echo safe"},
            )
        ]
        output = adapter.render_output(
            "PreToolUse",
            findings,
            decision="deny",
            context="policy says no",
            updated_input={"command": "echo safe"},
        )
        spec = require_spec(output)
        assert spec["permissionDecision"] == "deny", "decision must be deny"
        assert spec["additionalContext"] == "policy says no", "context must be included"
        assert spec["updatedInput"] == {"command": "echo safe"}, (
            "updatedInput must be included"
        )

    def test_permission_request_allow_with_updated_input(self) -> None:
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="MOD-001",
                title="t",
                severity=Severity.LOW,
                decision="allow",
                updated_input={"command": "echo safe"},
            )
        ]
        output = adapter.render_output(
            "PermissionRequest",
            findings,
            decision="allow",
            context=None,
            updated_input={"command": "echo safe"},
        )
        inner = require_nested(require_spec(output), "decision")
        assert inner["behavior"] == "allow", (
            "PermissionRequest allow must set behavior=allow"
        )
        assert inner["updatedInput"] == {"command": "echo safe"}, (
            "updatedInput must be forwarded"
        )
        assert "message" not in inner  # message is for deny only


class TestClaudeAdapterEdgeCases:
    """Claude adapter — edge cases: failures, context-only, unknown events."""

    def test_permission_request_non_deny_non_allow_returns_none(self) -> None:
        """PermissionRequest only handles deny and allow; anything else → None."""
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="X",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="m",
            )
        ]
        assert (
            adapter.render_output(
                "PermissionRequest",
                findings,
                decision="block",
                context=None,
                updated_input={},
            )
            is None
        )

    def test_posttool_use_failure_advisory(self) -> None:
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="F-001",
                title="t",
                severity=Severity.MEDIUM,
                additional_context="the tool failed, try another approach",
            )
        ]
        output = adapter.render_output(
            "PostToolUseFailure",
            findings,
            decision=None,
            context="the tool failed, try another approach",
            updated_input={},
        )
        assert output == {"systemMessage": "the tool failed, try another approach"}

    def test_posttool_use_failure_no_context_returns_none(self) -> None:
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="F-002",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="m",
            )
        ]
        # PostToolUseFailure ignores decision; only context produces output
        assert (
            adapter.render_output(
                "PostToolUseFailure",
                findings,
                decision="block",
                context=None,
                updated_input={},
            )
            is None
        )

    def test_stop_context_only_no_decision(self) -> None:
        """Stop with context but no blocking decision → systemMessage."""
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="CTX-002",
                title="t",
                severity=Severity.LOW,
                additional_context="don't forget to commit",
            )
        ]
        output = adapter.render_output(
            "Stop",
            findings,
            decision=None,
            context="don't forget to commit",
            updated_input={},
        )
        assert output == {"systemMessage": "don't forget to commit"}

    def test_stop_block_with_context(self) -> None:
        """When Stop has both block + context, context appends to reason."""
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="STOP-001",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="unfinished tests",
                additional_context="also check lint",
            )
        ]
        output = adapter.render_output(
            "Stop",
            findings,
            decision="block",
            context="also check lint",
            updated_input={},
        )
        rendered = require_rendered(output)
        assert rendered["decision"] == "block", "Stop block must set decision=block"
        reason = test_support.required_string(rendered, "reason")
        assert "STOP-001" in reason, "rule id must appear in reason"
        assert "also check lint" in reason, "context must be appended to reason"

    def test_teammate_idle_context_only(self) -> None:
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="CTX",
                title="t",
                severity=Severity.LOW,
                additional_context="work available in queue",
            )
        ]
        output = adapter.render_output(
            "TeammateIdle",
            findings,
            decision=None,
            context="work available in queue",
            updated_input={},
        )
        assert output == {"systemMessage": "work available in queue"}

    def test_unknown_event_returns_none(self) -> None:
        """Events not handled by any branch fall through to None."""
        adapter = ClaudeAdapter()
        findings = [
            RuleFinding(
                rule_id="X",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="m",
            )
        ]
        assert (
            adapter.render_output(
                "CompletelyFakeEvent",
                findings,
                decision="block",
                context=None,
                updated_input={},
            )
            is None
        )

    @pytest.mark.parametrize(
        "event",
        [
            "PreToolUse",
            "PermissionRequest",
            "PostToolUse",
            "Stop",
            "SessionStart",
            "UserPromptSubmit",
            "TaskCompleted",
            "TeammateIdle",
            "PostToolUseFailure",
            "ConfigChange",
            "SubagentStop",
        ],
    )
    def test_empty_findings_returns_none_for_all_events(self, event: str) -> None:
        """No findings → None for every event type."""
        adapter = ClaudeAdapter()
        assert (
            adapter.render_output(
                event,
                [],
                decision=None,
                context=None,
                updated_input={},
            )
            is None
        ), f"Empty findings must return None for event {event!r}"


# ===========================================================================
# Codex adapter
# ===========================================================================


class TestCodexAdapterBasic:
    """Codex adapter — normalize, core pretool/stop/session/posttool events."""

    def test_normalize_is_passthrough(self) -> None:
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

    def test_pretool_deny(self) -> None:
        adapter = CodexAdapter()
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
            "PreToolUse",
            findings,
            decision="deny",
            context=None,
            updated_input={},
        )
        spec = require_spec(output)
        assert spec["hookEventName"] == "PreToolUse", "Codex must echo hookEventName"
        assert spec["permissionDecision"] == "deny", (
            "deny must set permissionDecision=deny"
        )
        assert "GIT-001" in test_support.required_string(
            spec, "permissionDecisionReason"
        )

    def test_pretool_block_maps_to_deny(self) -> None:
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="SYS-001",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="system path",
            )
        ]
        output = adapter.render_output(
            "PreToolUse",
            findings,
            decision="block",
            context=None,
            updated_input={},
        )
        spec = require_spec(output)
        assert spec["permissionDecision"] == "deny", (
            "block must map to deny for Codex PreToolUse"
        )

    def test_stop_block(self) -> None:
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="STOP-001",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="review issues",
            )
        ]
        output = adapter.render_output(
            "Stop",
            findings,
            decision="block",
            context=None,
            updated_input={},
        )
        rendered = require_rendered(output)
        assert rendered["decision"] == "block", "Stop block must set decision=block"
        assert "STOP-001" in test_support.required_string(rendered, "reason")

    def test_session_start_context(self) -> None:
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="CTX-001",
                title="t",
                severity=Severity.LOW,
                additional_context="workspace conventions",
            )
        ]
        output = adapter.render_output(
            "SessionStart",
            findings,
            decision=None,
            context="workspace conventions",
            updated_input={},
        )
        assert "workspace conventions" in test_support.required_string(
            require_spec(output), "additionalContext"
        )

    def test_user_prompt_submit_block(self) -> None:
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="PROMPT-001",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="api key detected",
            )
        ]
        output = adapter.render_output(
            "UserPromptSubmit",
            findings,
            decision="block",
            context=None,
            updated_input={},
        )
        assert output is not None, "UserPromptSubmit block must produce output"
        assert output["decision"] == "block", (
            "UserPromptSubmit block must set decision=block"
        )

    def test_posttool_context(self) -> None:
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="Q-001",
                title="t",
                severity=Severity.MEDIUM,
                additional_context="files were updated",
            )
        ]
        output = adapter.render_output(
            "PostToolUse",
            findings,
            decision=None,
            context="files were updated",
            updated_input={},
        )
        assert "files were updated" in test_support.required_string(
            require_spec(output), "additionalContext"
        )

    def test_unsupported_event_returns_none(self) -> None:
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="X-001",
                title="t",
                severity=Severity.HIGH,
                decision="deny",
                message="blocked",
            )
        ]
        # PermissionRequest doesn't exist in Codex
        output = adapter.render_output(
            "PermissionRequest",
            findings,
            decision="deny",
            context=None,
            updated_input={},
        )
        assert output is None, "PermissionRequest must return None on Codex"

        # SubagentStop doesn't exist in Codex
        output = adapter.render_output(
            "SubagentStop",
            findings,
            decision="block",
            context=None,
            updated_input={},
        )
        assert output is None, "SubagentStop must return None on Codex"

    def test_no_findings_returns_none(self) -> None:
        adapter = CodexAdapter()
        output = adapter.render_output(
            "PreToolUse",
            [],
            decision=None,
            context=None,
            updated_input={},
        )
        assert output is None


class TestCodexAdapterEdgeCases:
    """Codex adapter — PostToolUse severity semantics, context merging, unsupported events."""

    def test_posttool_critical_block_stops_session(self) -> None:
        """CRITICAL severity block on PostToolUse should emit continue:false
        WITHOUT decision:"block" (they conflict in Codex semantics)."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="CRIT-001",
                title="critical",
                severity=Severity.CRITICAL,
                decision="block",
                message="critical safety violation",
            )
        ]
        output = adapter.render_output(
            "PostToolUse",
            findings,
            decision="block",
            context=None,
            updated_input={},
        )
        rendered = require_rendered(output)
        assert rendered["continue"] is False, "CRITICAL must set continue=False"
        assert "CRIT-001" in test_support.required_string(rendered, "stopReason")
        assert "decision" not in rendered, (
            "continue:false and decision must not coexist"
        )

    def test_posttool_high_block_does_not_stop_session(self) -> None:
        """HIGH severity block on PostToolUse should NOT emit continue:false."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="HIGH-001",
                title="high",
                severity=Severity.HIGH,
                decision="block",
                message="non-critical issue",
            )
        ]
        output = adapter.render_output(
            "PostToolUse",
            findings,
            decision="block",
            context=None,
            updated_input={},
        )
        assert output is not None, "HIGH block must produce output"
        assert output["decision"] == "block", "HIGH block must set decision=block"
        assert "continue" not in output, "HIGH must not set continue:false"

    def test_posttool_critical_with_context(self) -> None:
        """CRITICAL PostToolUse stop should preserve additionalContext."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="CRIT-002",
                title="t",
                severity=Severity.CRITICAL,
                decision="block",
                message="critical",
                additional_context="also check this",
            )
        ]
        output = adapter.render_output(
            "PostToolUse",
            findings,
            decision="block",
            context="also check this",
            updated_input={},
        )
        rendered = require_rendered(output)
        assert rendered["continue"] is False, "CRITICAL must set continue=False"
        assert "decision" not in rendered, (
            "decision must not coexist with continue:false"
        )
        assert (
            test_support.required_string(require_spec(output), "additionalContext")
            == "also check this"
        )

    def test_posttool_mixed_critical_and_high(self) -> None:
        """Mixed CRITICAL + HIGH: CRITICAL wins → continue:false, no decision."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="HIGH-001",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="high issue",
            ),
            RuleFinding(
                rule_id="CRIT-001",
                title="t",
                severity=Severity.CRITICAL,
                decision="block",
                message="critical issue",
            ),
        ]
        output = adapter.render_output(
            "PostToolUse",
            findings,
            decision="block",
            context=None,
            updated_input={},
        )
        rendered = require_rendered(output)
        assert rendered["continue"] is False, "CRITICAL wins: continue must be False"
        assert "CRIT-001" in test_support.required_string(rendered, "stopReason")
        assert "decision" not in rendered, "CRITICAL must suppress decision key"

    def test_pretool_deny_with_context(self) -> None:
        """PreToolUse deny + context both present in output."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="R-001",
                title="t",
                severity=Severity.HIGH,
                decision="deny",
                message="nope",
                additional_context="try something else",
            ),
        ]
        output = adapter.render_output(
            "PreToolUse",
            findings,
            decision="deny",
            context="try something else",
            updated_input={},
        )
        spec = require_spec(output)
        assert spec["permissionDecision"] == "deny", (
            "deny must set permissionDecision=deny"
        )
        assert spec["additionalContext"] == "try something else", (
            "context must be included"
        )

    def test_pretool_only_context_no_decision(self) -> None:
        """PreToolUse with only context (no deny/block) → additionalContext."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="CTX-001",
                title="t",
                severity=Severity.LOW,
                additional_context="check search results",
            ),
        ]
        output = adapter.render_output(
            "PreToolUse",
            findings,
            decision=None,
            context="check search results",
            updated_input={},
        )
        spec = require_spec(output)
        # No permissionDecision, only context
        assert "permissionDecision" not in spec, (
            "context-only must not set permissionDecision"
        )
        assert spec["additionalContext"] == "check search results", (
            "context must appear"
        )

    def test_stop_context_appended_to_reason(self) -> None:
        """Stop block + context → context merged into reason."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="STOP-001",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="unfinished",
                additional_context="run tests",
            ),
        ]
        output = adapter.render_output(
            "Stop",
            findings,
            decision="block",
            context="run tests",
            updated_input={},
        )
        rendered = require_rendered(output)
        assert rendered["decision"] == "block", "Stop block must set decision=block"
        reason = test_support.required_string(rendered, "reason")
        assert "STOP-001" in reason, "rule id must appear in reason"
        assert "run tests" in reason, "context must be appended to reason"

    def test_user_prompt_block_with_context(self) -> None:
        """UserPromptSubmit block + context → both in output."""
        adapter = CodexAdapter()
        findings = [
            RuleFinding(
                rule_id="P-001",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="api key",
                additional_context="redact first",
            ),
        ]
        output = adapter.render_output(
            "UserPromptSubmit",
            findings,
            decision="block",
            context="redact first",
            updated_input={},
        )
        rendered = require_rendered(output)
        assert rendered["decision"] == "block", (
            "UserPromptSubmit must set decision=block"
        )
        assert (
            test_support.required_string(require_spec(output), "additionalContext")
            == "redact first"
        )

    @pytest.mark.parametrize(
        "event",
        [
            "PermissionRequest",
            "SubagentStop",
            "PostToolUseFailure",
            "TaskCompleted",
            "TeammateIdle",
            "ConfigChange",
            "Notification",
            "SubagentStart",
            "InstructionsLoaded",
            "WorktreeCreate",
            "WorktreeRemove",
            "PreCompact",
            "PostCompact",
            "Elicitation",
            "ElicitationResult",
            "SessionEnd",
            "StopFailure",
            "CwdChanged",
            "FileChanged",
            "TaskCreated",
        ],
    )
    def test_all_unsupported_codex_events(self, event: str) -> None:
        """Every Claude Code event not in CODEX_EVENTS → None."""
        adapter = CodexAdapter()
        dummy = [
            RuleFinding(
                rule_id="X",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="m",
            )
        ]
        assert (
            adapter.render_output(
                event,
                dummy,
                decision="block",
                context=None,
                updated_input={},
            )
            is None
        ), f"{event} should return None on Codex"


# ===========================================================================
# OpenCode adapter
# ===========================================================================


class TestOpenCodeAdapterNormalize:
    """Event name and tool name normalization."""

    def test_normalize_maps_event_name(self) -> None:
        adapter = OpenCodeAdapter()
        raw = {
            "hook_event_name": "tool.execute.before",
            "tool_name": "bash",
            "tool_input": {"command": "ls"},
            "cwd": "/tmp",
            "session_id": "opencode-123-abc",
        }
        canonical = adapter.normalize_payload(raw)
        assert canonical["hook_event_name"] == "PreToolUse", "event name not mapped"
        assert canonical["tool_name"] == "Bash", "tool name not capitalized"

    def test_normalize_preserves_already_canonical(self) -> None:
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
        assert canonical["hook_event_name"] == "PreToolUse", "canonical event changed"
        assert canonical["tool_name"] == "Write", "canonical tool name changed"

    def test_normalize_capitalizes_tool_name(self) -> None:
        adapter = OpenCodeAdapter()
        raw: ObjectDict = {
            "hook_event_name": "tool.execute.before",
            "tool_name": "write",
            "tool_input": {},
            "cwd": "/tmp",
            "session_id": "oc3",
        }
        canonical = adapter.normalize_payload(raw)
        assert canonical["tool_name"] == "Write", "lowercase tool name not capitalized"

    def test_normalize_session_idle_maps_to_stop(self) -> None:
        """session.idle → Stop."""
        adapter = OpenCodeAdapter()
        raw: ObjectDict = {
            "hook_event_name": "session.idle",
            "tool_name": "",
            "tool_input": {},
            "cwd": "/tmp",
            "session_id": "oc-test",
        }
        canonical = adapter.normalize_payload(raw)
        assert canonical["hook_event_name"] == "Stop", "session.idle not mapped to Stop"

    def test_normalize_permission_asked_maps_to_permission_request(self) -> None:
        """permission.asked → PermissionRequest."""
        adapter = OpenCodeAdapter()
        raw: ObjectDict = {
            "hook_event_name": "permission.asked",
            "tool_name": "bash",
            "tool_input": {"command": "rm -rf /"},
            "cwd": "/tmp",
            "session_id": "oc-test",
        }
        canonical = adapter.normalize_payload(raw)
        assert canonical["hook_event_name"] == "PermissionRequest", (
            "permission.asked not mapped to PermissionRequest"
        )
        assert canonical["tool_name"] == "Bash", "tool name not capitalized"

    def test_normalize_does_not_mutate_original(self) -> None:
        """normalize_payload must return a new dict, not modify the input."""
        adapter = OpenCodeAdapter()
        raw: ObjectDict = {
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
        assert canonical is not raw, "normalize_payload returned same dict object"
        # Original should be untouched
        assert raw["hook_event_name"] == original_event, "original event name mutated"
        assert raw["tool_name"] == original_tool, "original tool name mutated"

    def test_normalize_unknown_event_passthrough(self) -> None:
        """Unknown event names pass through unchanged (forward compat)."""
        adapter = OpenCodeAdapter()
        raw: ObjectDict = {
            "hook_event_name": "some.future.event",
            "tool_name": "",
            "tool_input": {},
            "cwd": "/tmp",
            "session_id": "oc-test",
        }
        canonical = adapter.normalize_payload(raw)
        assert canonical["hook_event_name"] == "some.future.event", (
            "unknown event name should pass through unchanged"
        )

    def test_normalize_empty_tool_name_stays_empty(self) -> None:
        """Empty string tool_name should not be capitalized to something weird."""
        adapter = OpenCodeAdapter()
        raw: ObjectDict = {
            "hook_event_name": "session.idle",
            "tool_name": "",
            "tool_input": {},
            "cwd": "/tmp",
            "session_id": "oc-test",
        }
        canonical = adapter.normalize_payload(raw)
        assert canonical["tool_name"] == "", "empty tool name should remain empty"


class TestOpenCodeAdapterNormalizeToolResult:
    """tool_result / tool_response aliasing behavior."""

    def test_normalize_tool_result_aliasing(self) -> None:
        """tool_response should be aliased to tool_result and vice versa."""
        adapter = OpenCodeAdapter()

        # Shim sends tool_result (preferred) → tool_response should appear
        raw1: ObjectDict = {
            "hook_event_name": "tool.execute.after",
            "tool_name": "bash",
            "tool_input": {"command": "echo hi"},
            "cwd": "/tmp",
            "session_id": "oc-test",
            "tool_result": "hi\n",
        }
        canonical1 = adapter.normalize_payload(raw1)
        assert canonical1["tool_result"] == "hi\n", "tool_result missing after alias"
        assert canonical1["tool_response"] == "hi\n", "tool_response alias not set"

        # Shim sends tool_response (legacy) → tool_result should appear
        raw2: ObjectDict = {
            "hook_event_name": "tool.execute.after",
            "tool_name": "bash",
            "tool_input": {"command": "echo hi"},
            "cwd": "/tmp",
            "session_id": "oc-test",
            "tool_response": "hi\n",
        }
        canonical2 = adapter.normalize_payload(raw2)
        assert canonical2["tool_result"] == "hi\n", (
            "tool_result not aliased from tool_response"
        )
        assert canonical2["tool_response"] == "hi\n", (
            "tool_response missing after alias"
        )

    def test_normalize_both_tool_result_fields_present(self) -> None:
        """When shim sends both, both pass through without double-aliasing."""
        adapter = OpenCodeAdapter()
        raw: ObjectDict = {
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
        assert canonical["tool_result"] == "output-a", (
            "tool_result overwritten when both present"
        )
        assert canonical["tool_response"] == "output-b", (
            "tool_response overwritten when both present"
        )

    def test_normalize_no_tool_result_fields(self) -> None:
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
        assert "tool_result" not in canonical, (
            "tool_result should not be created for PreToolUse"
        )
        assert "tool_response" not in canonical, (
            "tool_response should not be created for PreToolUse"
        )


class TestOpenCodeAdapterRenderPreTool:
    """render_output for PreToolUse and PermissionRequest events."""

    def test_pretool_deny_action_block(self) -> None:
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="GIT-001",
                title="t",
                severity=Severity.HIGH,
                decision="deny",
                message="hook bypass detected",
            )
        ]
        output = adapter.render_output(
            "PreToolUse",
            findings,
            decision="deny",
            context=None,
            updated_input={},
        )
        assert output is not None, "deny finding should produce output"
        assert output["action"] == "block", "deny should map to block action"
        assert "GIT-001" in test_support.required_string(output, "reason"), (
            "rule id should appear in reason"
        )

    def test_pretool_allow_with_updated_args(self) -> None:
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="MOD-001",
                title="t",
                severity=Severity.LOW,
                decision="allow",
                updated_input={"command": "echo safe"},
            )
        ]
        output = adapter.render_output(
            "PreToolUse",
            findings,
            decision="allow",
            context=None,
            updated_input={"command": "echo safe"},
        )
        assert output is not None, "allow with updated_input should produce output"
        assert output["action"] == "allow", "action should be allow"
        assert output["updated_args"] == {"command": "echo safe"}, (
            "updated_args not set"
        )

    def test_pretool_context_only(self) -> None:
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="INFO-001",
                title="t",
                severity=Severity.LOW,
                additional_context="remember to test",
            )
        ]
        output = adapter.render_output(
            "PreToolUse",
            findings,
            decision=None,
            context="remember to test",
            updated_input={},
        )
        assert output is not None, "context-only finding should produce output"
        assert output["action"] == "context", "action should be context"
        assert output["context"] == "remember to test", "context value not set"

    def test_pretool_deny_with_context(self) -> None:
        """Deny output includes context when provided."""
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="R-001",
                title="t",
                severity=Severity.HIGH,
                decision="deny",
                message="blocked",
                additional_context="hint for the agent",
            ),
        ]
        output = adapter.render_output(
            "PreToolUse",
            findings,
            decision="deny",
            context="hint for the agent",
            updated_input={},
        )
        rendered = require_rendered(output)
        assert rendered["action"] == "block", "deny should produce block action"
        assert rendered["context"] == "hint for the agent", (
            "context not included in deny output"
        )
        assert "R-001" in test_support.required_string(rendered, "reason"), (
            "rule id should appear in reason"
        )

    def test_pretool_ask_maps_to_block(self) -> None:
        """OpenCode has no 'ask' concept; ask → block."""
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="ASK-001",
                title="t",
                severity=Severity.MEDIUM,
                decision="ask",
                message="confirm this",
            )
        ]
        output = adapter.render_output(
            "PreToolUse",
            findings,
            decision="ask",
            context=None,
            updated_input={},
        )
        assert output is not None, "ask finding should produce output"
        assert output["action"] == "block", "ask should map to block for OpenCode"

    def test_no_findings_returns_none(self) -> None:
        adapter = OpenCodeAdapter()
        output = adapter.render_output(
            "PreToolUse",
            [],
            decision=None,
            context=None,
            updated_input={},
        )
        assert output is None, "empty findings should return None"

    def test_permission_deny(self) -> None:
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="PERM-001",
                title="t",
                severity=Severity.HIGH,
                decision="deny",
                message="not allowed",
            )
        ]
        output = adapter.render_output(
            "PermissionRequest",
            findings,
            decision="deny",
            context=None,
            updated_input={},
        )
        assert output is not None, "deny on PermissionRequest should produce output"
        assert output["action"] == "block", "deny should map to block action"

    def test_permission_allow_with_updated_input(self) -> None:
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="MOD-001",
                title="t",
                severity=Severity.LOW,
                decision="allow",
                updated_input={"command": "echo safe"},
            ),
        ]
        output = adapter.render_output(
            "PermissionRequest",
            findings,
            decision="allow",
            context=None,
            updated_input={"command": "echo safe"},
        )
        rendered = require_rendered(output)
        assert rendered["action"] == "allow", "action should be allow"
        assert rendered["updated_args"] == {"command": "echo safe"}, (
            "updated_args not set"
        )

    def test_permission_allow_no_updated_input_returns_none(self) -> None:
        """PermissionRequest allow without updated_input → nothing to do."""
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="X", title="t", severity=Severity.LOW, decision="allow"
            ),
        ]
        assert (
            adapter.render_output(
                "PermissionRequest",
                findings,
                decision="allow",
                context=None,
                updated_input={},
            )
            is None
        ), "allow without updated_input should return None"


class TestOpenCodeAdapterRenderPostTool:
    """render_output for PostToolUse, Stop, SessionStart, and unknown events."""

    def test_posttool_warn(self) -> None:
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="Q-001",
                title="t",
                severity=Severity.MEDIUM,
                decision="block",
                message="quality issue",
            )
        ]
        output = adapter.render_output(
            "PostToolUse",
            findings,
            decision="block",
            context=None,
            updated_input={},
        )
        assert output is not None, "PostToolUse block should produce output"
        assert output["action"] == "warn", "PostToolUse block should map to warn"
        assert "Q-001" in test_support.required_string(output, "reason"), (
            "rule id should appear in reason"
        )

    def test_posttool_with_context_and_decision(self) -> None:
        """PostToolUse block + context → both in output."""
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="Q-001",
                title="t",
                severity=Severity.MEDIUM,
                decision="block",
                message="quality issue",
                additional_context="consider adding tests",
            ),
        ]
        output = adapter.render_output(
            "PostToolUse",
            findings,
            decision="block",
            context="consider adding tests",
            updated_input={},
        )
        rendered = require_rendered(output)
        assert rendered["action"] == "warn", "PostToolUse block should map to warn"
        assert rendered["context"] == "consider adding tests", "context not included"
        assert "Q-001" in test_support.required_string(rendered, "reason"), (
            "rule id should appear in reason"
        )

    def test_posttool_context_only(self) -> None:
        """PostToolUse with only context, no block decision."""
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="CTX-001",
                title="t",
                severity=Severity.LOW,
                additional_context="check test coverage",
            ),
        ]
        output = adapter.render_output(
            "PostToolUse",
            findings,
            decision=None,
            context="check test coverage",
            updated_input={},
        )
        assert output == {"context": "check test coverage"}, (
            "context-only PostToolUse should return context dict"
        )

    def test_stop_continue(self) -> None:
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="STOP-001",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="run tests",
            )
        ]
        output = adapter.render_output(
            "Stop",
            findings,
            decision="block",
            context=None,
            updated_input={},
        )
        assert output is not None, "Stop with block should produce output"
        assert output["action"] == "continue", "Stop block should map to continue"
        assert "STOP-001" in test_support.required_string(output, "reason"), (
            "rule id should appear in reason"
        )

    def test_stop_context_only(self) -> None:
        """Stop with context but no block → context action."""
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="CTX",
                title="t",
                severity=Severity.LOW,
                additional_context="remember to commit",
            ),
        ]
        output = adapter.render_output(
            "Stop",
            findings,
            decision=None,
            context="remember to commit",
            updated_input={},
        )
        assert output == {"action": "context", "context": "remember to commit"}, (
            "Stop context-only should return context action dict"
        )

    def test_session_start_context(self) -> None:
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="CTX-001",
                title="t",
                severity=Severity.LOW,
                additional_context="load conventions",
            )
        ]
        output = adapter.render_output(
            "SessionStart",
            findings,
            decision=None,
            context="load conventions",
            updated_input={},
        )
        assert output is not None, "SessionStart with context should produce output"
        assert output["action"] == "context", "SessionStart should use context action"

    def test_unknown_event_returns_none(self) -> None:
        adapter = OpenCodeAdapter()
        findings = [
            RuleFinding(
                rule_id="X",
                title="t",
                severity=Severity.HIGH,
                decision="block",
                message="m",
            ),
        ]
        assert (
            adapter.render_output(
                "TaskCompleted",
                findings,
                decision="block",
                context=None,
                updated_input={},
            )
            is None
        ), "unknown event should return None"


# ===========================================================================
# Base adapter helpers
# ===========================================================================


class TestBaseAdapterHelpers:
    """Test the static helper methods on PlatformAdapter."""

    def test_join_messages_formats_rule_id_and_severity(self) -> None:
        findings = [
            RuleFinding(
                rule_id="GIT-001",
                title="t",
                severity=Severity.HIGH,
                message="hook bypass detected",
            ),
            RuleFinding(
                rule_id="SYS-002",
                title="t",
                severity=Severity.CRITICAL,
                message="system path violation",
            ),
        ]
        text = PlatformAdapter.join_messages(findings)
        assert "[GIT-001 | HIGH]" in text, "GIT-001 header not in output"
        assert "[SYS-002 | CRITICAL]" in text, "SYS-002 header not in output"
        assert "hook bypass detected" in text, "GIT-001 message not in output"
        assert "system path violation" in text, "SYS-002 message not in output"

    def test_join_messages_skips_none_messages(self) -> None:
        findings = [
            RuleFinding(rule_id="A", title="t", severity=Severity.LOW, message=None),
            RuleFinding(
                rule_id="B", title="t", severity=Severity.LOW, message="visible"
            ),
        ]
        text = PlatformAdapter.join_messages(findings)
        assert "visible" in text, "message 'visible' should appear in output"
        assert "A" not in text, "rule A has no message so should be omitted"

    def test_join_messages_empty_list(self) -> None:
        assert PlatformAdapter.join_messages([]) == ""

    def test_decision_findings_filters_correctly(self) -> None:
        findings = [
            RuleFinding(
                rule_id="A",
                title="t",
                severity=Severity.HIGH,
                decision="deny",
                message="a",
            ),
            RuleFinding(
                rule_id="B",
                title="t",
                severity=Severity.LOW,
                decision="allow",
                message="b",
            ),
            RuleFinding(
                rule_id="C",
                title="t",
                severity=Severity.MEDIUM,
                decision="deny",
                message="c",
            ),
            RuleFinding(
                rule_id="D",
                title="t",
                severity=Severity.LOW,
                decision=None,
                message="d",
            ),
        ]
        deny_findings = PlatformAdapter.decision_findings(findings, "deny")
        assert [f.rule_id for f in deny_findings] == ["A", "C"], "deny filter wrong"

        allow_findings = PlatformAdapter.decision_findings(findings, "allow")
        assert [f.rule_id for f in allow_findings] == ["B"], "allow filter wrong"

        none_findings = PlatformAdapter.decision_findings(findings, None)
        assert [f.rule_id for f in none_findings] == ["D"], "None filter wrong"

        empty = PlatformAdapter.decision_findings(findings, "block")
        assert empty == [], "block filter should return empty list"


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

    def _make_findings(self) -> list[RuleFinding]:
        """Three findings: deny (HIGH), allow (LOW), context-only (MEDIUM)."""
        return [
            RuleFinding(
                rule_id="DENY-001",
                title="t",
                severity=Severity.HIGH,
                decision="deny",
                message="blocked by policy",
            ),
            RuleFinding(
                rule_id="ALLOW-001",
                title="t",
                severity=Severity.LOW,
                decision="allow",
                updated_input={"command": "safe"},
            ),
            RuleFinding(
                rule_id="CTX-001",
                title="t",
                severity=Severity.MEDIUM,
                additional_context="extra context here",
            ),
        ]

    @staticmethod
    def _render_inputs(
        findings: list[RuleFinding],
    ) -> tuple[str | None, str | None, ObjectDict]:
        decision = cast(
            Callable[[list[RuleFinding]], str | None],
            getattr(engine_module, "_top_decision"),
        )(findings)
        context = cast(
            Callable[[list[RuleFinding]], str | None],
            getattr(engine_module, "_collect_context"),
        )(findings)
        updated = cast(
            Callable[[list[RuleFinding]], ObjectDict],
            getattr(engine_module, "_merge_updated_input"),
        )(findings)
        return decision, context, updated

    def test_claude_deny_wins_over_allow(self) -> None:
        """With mixed deny+allow, Claude adapter should deny (highest priority)."""
        findings = self._make_findings()
        decision, context, updated = self._render_inputs(findings)

        adapter = ClaudeAdapter()
        output = adapter.render_output(
            "PreToolUse",
            findings,
            decision=decision,
            context=context,
            updated_input=updated,
        )
        spec = require_spec(output)
        # Deny wins
        assert spec["permissionDecision"] == "deny", "deny should win over allow"
        assert "DENY-001" in test_support.required_string(
            spec, "permissionDecisionReason"
        ), "DENY-001 should appear in reason"
        # Context still included
        assert spec["additionalContext"] == "extra context here", (
            "context should be included"
        )
        # Updated input still included (forward-looking)
        assert spec["updatedInput"] == {"command": "safe"}, (
            "updated input should be included"
        )

    def test_codex_deny_wins_over_allow(self) -> None:
        findings = self._make_findings()
        decision, context, updated = self._render_inputs(findings)

        adapter = CodexAdapter()
        output = adapter.render_output(
            "PreToolUse",
            findings,
            decision=decision,
            context=context,
            updated_input=updated,
        )
        spec = require_spec(output)
        assert spec["permissionDecision"] == "deny", "Codex deny should win over allow"
        assert "DENY-001" in test_support.required_string(
            spec, "permissionDecisionReason"
        ), "DENY-001 should appear in reason"

    def test_opencode_deny_wins_over_allow(self) -> None:
        findings = self._make_findings()
        decision, context, updated = self._render_inputs(findings)

        adapter = OpenCodeAdapter()
        output = adapter.render_output(
            "PreToolUse",
            findings,
            decision=decision,
            context=context,
            updated_input=updated,
        )
        rendered = require_rendered(output)
        assert rendered["action"] == "block", (
            "OpenCode deny should produce block action"
        )
        assert "DENY-001" in test_support.required_string(rendered, "reason"), (
            "DENY-001 should appear in reason"
        )
        # Context included despite block
        assert rendered["context"] == "extra context here", (
            "context should be included with block"
        )

    def test_context_deduplication(self) -> None:
        """Identical context strings should be deduplicated."""
        findings = [
            RuleFinding(
                rule_id="A",
                title="t",
                severity=Severity.LOW,
                additional_context="same thing",
            ),
            RuleFinding(
                rule_id="B",
                title="t",
                severity=Severity.LOW,
                additional_context="same thing",
            ),
            RuleFinding(
                rule_id="C",
                title="t",
                severity=Severity.LOW,
                additional_context="different thing",
            ),
        ]
        context = cast(
            Callable[[list[RuleFinding]], str | None],
            getattr(engine_module, "_collect_context"),
        )(findings)
        assert context == "same thing\n\ndifferent thing"

    def test_updated_input_last_write_wins(self) -> None:
        """When multiple findings set the same key, last one wins."""
        findings = [
            RuleFinding(
                rule_id="A",
                title="t",
                severity=Severity.LOW,
                updated_input={"command": "first"},
            ),
            RuleFinding(
                rule_id="B",
                title="t",
                severity=Severity.LOW,
                updated_input={"command": "second", "extra": "value"},
            ),
        ]
        merged = cast(
            Callable[[list[RuleFinding]], ObjectDict],
            getattr(engine_module, "_merge_updated_input"),
        )(findings)
        assert merged == {"command": "second", "extra": "value"}


# ===========================================================================
# Fixture replay — full engine pipeline
# ===========================================================================


class TestFixtureReplay:
    """Load real fixtures and replay them through the engine.

    These are integration tests: fixture → normalize → rules → render → verify.
    No mocking. Verifies that the full pipeline produces sensible output.
    """

    def test_codex_git_no_verify_denied(self) -> None:
        payload = object_dict(
            cast(
                object,
                json.loads(
                    (
                        FIXTURES_DIR / "codex" / "pretool_bash_git_no_verify.json"
                    ).read_text()
                ),
            )
        )
        result = evaluate_payload(payload, platform="codex")
        assert result.output is not None
        spec = require_spec(test_support.require_output(result))
        assert test_support.output_string(spec, "permissionDecision") == "deny"
        assert "GIT-001" in test_support.output_string(spec, "permissionDecisionReason")
        # Also verify findings list
        ids = {f.rule_id for f in result.findings}
        assert "GIT-001" in ids

    def test_codex_rm_rf_denied(self) -> None:
        payload = object_dict(
            cast(
                object,
                json.loads(
                    (FIXTURES_DIR / "codex" / "pretool_bash_rm_rf.json").read_text()
                ),
            )
        )
        result = evaluate_payload(payload, platform="codex")
        assert result.output is not None
        spec = require_spec(test_support.require_output(result))
        assert test_support.output_string(spec, "permissionDecision") == "deny"

    def test_codex_session_start_produces_context(self) -> None:
        payload = object_dict(
            cast(
                object,
                json.loads((FIXTURES_DIR / "codex" / "session_start.json").read_text()),
            )
        )
        result = evaluate_payload(payload, platform="codex")
        # SessionStart may or may not produce output depending on config;
        # the key is it doesn't crash and returns a valid EngineResult
        assert result.event_name == "SessionStart"
        assert result.errors == []

    def test_opencode_git_no_verify_denied(self) -> None:
        payload = object_dict(
            cast(
                object,
                json.loads(
                    (
                        FIXTURES_DIR / "opencode" / "pretool_bash_git_no_verify.json"
                    ).read_text()
                ),
            )
        )
        result = evaluate_payload(payload, platform="opencode")
        assert result.output is not None
        rendered = test_support.require_output(result)
        assert rendered["action"] == "block"
        assert "GIT-001" in test_support.required_string(rendered, "reason")

    def test_opencode_write_protected_denied(self) -> None:
        payload = object_dict(
            cast(
                object,
                json.loads(
                    (
                        FIXTURES_DIR / "opencode" / "pretool_write_protected.json"
                    ).read_text()
                ),
            )
        )
        result = evaluate_payload(payload, platform="opencode")
        assert result.output is not None
        assert result.output["action"] == "block"
        # Protected path rule should fire
        ids = {f.rule_id for f in result.findings}
        assert any(
            "PROTECT" in rid or "CUPCAKE" in rid or "SECURITY" in rid for rid in ids
        ), f"Expected a protection rule, got: {ids}"

    def test_opencode_session_idle_no_crash(self) -> None:
        payload = object_dict(
            cast(
                object,
                json.loads(
                    (FIXTURES_DIR / "opencode" / "session_idle.json").read_text()
                ),
            )
        )
        result = evaluate_payload(payload, platform="opencode")
        assert result.event_name == "Stop"
        assert result.errors == []

    def test_opencode_permission_asked_processes(self) -> None:
        payload = object_dict(
            cast(
                object,
                json.loads(
                    (FIXTURES_DIR / "opencode" / "permission_asked.json").read_text()
                ),
            )
        )
        result = evaluate_payload(payload, platform="opencode")
        assert result.event_name == "PermissionRequest"
        assert result.errors == []
        assert result.output is not None, (
            "permission_asked fixture should produce output"
        )
        assert test_support.require_output(result)["action"] == "block"

    def test_codex_posttool_no_crash(self) -> None:
        payload = object_dict(
            cast(
                object,
                json.loads((FIXTURES_DIR / "codex" / "posttool_bash.json").read_text()),
            )
        )
        result = evaluate_payload(payload, platform="codex")
        assert result.event_name == "PostToolUse"
        assert result.errors == []

    @pytest.mark.parametrize(
        "fixture_rel,platform",
        [
            # codex sub-fixtures
            ("codex/posttool_bash.json", "codex"),
            ("codex/pretool_bash_git_no_verify.json", "codex"),
            ("codex/pretool_bash_rm_rf.json", "codex"),
            ("codex/session_start.json", "codex"),
            ("codex/stop_basic.json", "codex"),
            ("codex/user_prompt_submit.json", "codex"),
            # opencode sub-fixtures
            ("opencode/permission_asked.json", "opencode"),
            ("opencode/pretool_bash_git_no_verify.json", "opencode"),
            ("opencode/pretool_edit_python_todo.json", "opencode"),
            ("opencode/pretool_write_protected.json", "opencode"),
            ("opencode/session_idle.json", "opencode"),
            # top-level claude fixtures
            ("configchange_disable_hooks.json", "claude"),
            ("configchange_safe.json", "claude"),
            ("pretool_assertion_roulette.json", "claude"),
            ("pretool_baseline_inflate.json", "claude"),
            ("pretool_datetime_fallback.json", "claude"),
            ("pretool_default_swallow.json", "claude"),
            ("pretool_design_tokens.json", "claude"),
            ("pretool_fe_linter.json", "claude"),
            ("pretool_fixture_outside_conftest.json", "claude"),
            ("pretool_git_no_verify.json", "claude"),
            ("pretool_git_stash.json", "claude"),
            ("pretool_linter_config.json", "claude"),
            ("pretool_python_any.json", "claude"),
            ("pretool_python_source_bash.json", "claude"),
            ("pretool_python_todo.json", "claude"),
            ("pretool_quality_test_path.json", "claude"),
            ("pretool_read_partial.json", "claude"),
            ("pretool_rust_unwrap.json", "claude"),
            ("pretool_shell_bypass.json", "claude"),
            ("pretool_silent_except.json", "claude"),
            ("pretool_silent_none.json", "claude"),
            ("pretool_test_loop_assert.json", "claude"),
            ("pretool_test_sleep.json", "claude"),
            ("pretool_ts_ignore.json", "claude"),
            ("pretool_ts_todo.json", "claude"),
            ("sessionstart_startup.json", "claude"),
            ("stop_preexisting.json", "claude"),
        ],
    )
    def test_all_fixtures_replay_without_errors(
        self, fixture_rel: str, platform: str
    ) -> None:
        """Every fixture file replays through the engine without errors."""
        payload = object_dict(
            cast(object, json.loads((FIXTURES_DIR / fixture_rel).read_text()))
        )
        result = evaluate_payload(payload, platform=platform)
        assert result.errors == [], (
            f"Fixture {fixture_rel} produced errors: {result.errors}"
        )


# ===========================================================================
# Cross-platform: same findings, different output shapes
# ===========================================================================


class TestCrossPlatform:
    """Same payload through all adapters produces correct per-platform output."""

    def _git_no_verify_payload(self) -> dict[str, object]:
        return {
            "session_id": "cross-test",
            "cwd": str(test_support.BUNDLE_ROOT),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git commit --no-verify -m 'test'"},
        }

    def test_claude_and_codex_produce_same_structure(self) -> None:
        """Claude and Codex both use hookSpecificOutput.permissionDecision."""
        payload = self._git_no_verify_payload()
        claude_result = evaluate_payload(payload, platform="claude")
        codex_result = evaluate_payload(payload, platform="codex")

        assert claude_result.output is not None, "Claude should produce output"
        assert codex_result.output is not None, "Codex should produce output"

        c_spec = require_spec(test_support.require_output(claude_result))
        x_spec = require_spec(test_support.require_output(codex_result))

        assert test_support.output_string(c_spec, "permissionDecision") == "deny", (
            "Claude should deny"
        )
        assert test_support.output_string(x_spec, "permissionDecision") == "deny", (
            "Codex should deny"
        )
        assert "GIT-001" in test_support.output_string(
            c_spec, "permissionDecisionReason"
        ), "GIT-001 should appear in Claude reason"
        assert "GIT-001" in test_support.output_string(
            x_spec, "permissionDecisionReason"
        ), "GIT-001 should appear in Codex reason"

    def test_opencode_produces_block_action(self) -> None:
        """OpenCode uses action:block instead of hookSpecificOutput."""
        payload = self._git_no_verify_payload()
        # Simulate OpenCode shim sending us the payload with OC event name
        oc_payload = dict(payload)
        oc_payload["hook_event_name"] = "tool.execute.before"
        oc_payload["tool_name"] = "bash"  # lowercase from OpenCode

        result = evaluate_payload(oc_payload, platform="opencode")
        assert result.output is not None, "OpenCode should produce output"
        rendered = test_support.require_output(result)
        assert rendered["action"] == "block", "OpenCode should produce block action"
        assert "GIT-001" in test_support.required_string(rendered, "reason"), (
            "GIT-001 should appear in reason"
        )

    def test_same_findings_different_format(self) -> None:
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

        assert "GIT-001" in claude_ids, "Claude should find GIT-001"
        assert "GIT-001" in codex_ids, "Codex should find GIT-001"
        assert "GIT-001" in opencode_ids, "OpenCode should find GIT-001"

    def test_full_read_unlock_survives_relative_follow_up_for_claude_and_codex(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Adapter/platform selection must not break stateful read-path normalization."""
        _config_with_enabled_rules(tmp_path, monkeypatch, "BUILTIN-ENFORCE-FULL-READ")
        target = tmp_path / "module.py"
        target.write_text("print('hi')\nprint('bye')\n", encoding="utf-8")

        initial_payload = {
            "session_id": "adapter-cross-read",
            "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(target)},
        }
        follow_up_payload = {
            "session_id": "adapter-cross-read",
            "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "module.py", "offset": 1, "limit": 1},
        }

        for platform in ("claude", "codex"):
            first = evaluate_payload(dict(initial_payload), platform=platform)
            second = evaluate_payload(dict(follow_up_payload), platform=platform)
            denied_rules = {finding.rule_id for finding in second.findings}

            assert not first.findings, f"{platform} full read should stay clean"
            assert "BUILTIN-ENFORCE-FULL-READ" not in denied_rules, (
                f"{platform} should preserve the full-read unlock across path forms"
            )


# ===========================================================================
# CLI --platform integration
# ===========================================================================


class TestCLIPlatform:
    def test_handle_with_platform_flag(self) -> None:
        """Verify CLI accepts --platform without error."""
        from vibeforcer.cli import build_parser

        parsed = object_dict(
            vars(build_parser().parse_args(["handle", "--platform", "codex"]))
        )
        assert string_value(parsed.get("platform")) == "codex"

    def test_handle_default_platform(self) -> None:
        from vibeforcer.cli import build_parser

        parsed = object_dict(vars(build_parser().parse_args(["handle"])))
        assert string_value(parsed.get("platform")) == "claude"

    def test_replay_with_platform(self) -> None:
        from vibeforcer.cli import build_parser

        parsed = object_dict(
            vars(
                build_parser().parse_args(
                    ["replay", "--payload", "test.json", "--platform", "opencode"]
                )
            )
        )
        assert string_value(parsed.get("platform")) == "opencode"

    def test_invalid_platform_rejected(self) -> None:
        from vibeforcer.cli import build_parser

        with pytest.raises(SystemExit):
            _ = build_parser().parse_args(["handle", "--platform", "vim"])

    def test_safe_main_returns_130_on_keyboard_interrupt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from vibeforcer import cli

        def boom(_argv: object | None = None) -> int:
            raise KeyboardInterrupt

        monkeypatch.setattr(cli, "main", boom)
        assert cli.safe_main() == 130
