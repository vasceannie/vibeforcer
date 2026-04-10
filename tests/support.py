"""Shared test helpers that are not pytest fixtures."""

from __future__ import annotations

from pathlib import Path

from vibeforcer._types import ObjectDict, object_dict, string_value
from vibeforcer.models import EngineResult

BUNDLE_ROOT = Path(__file__).resolve().parents[1]


def require_output(result: EngineResult) -> ObjectDict:
    assert result.output is not None, "Expected structured output, got None"
    return result.output


def hook_output(result: EngineResult) -> ObjectDict:
    return object_dict(require_output(result).get("hookSpecificOutput"))


def nested_output(mapping: ObjectDict, key: str) -> ObjectDict:
    return object_dict(mapping.get(key))


def output_string(mapping: ObjectDict, key: str, default: str = "") -> str:
    value = string_value(mapping.get(key))
    return value if value is not None else default


def required_string(mapping: ObjectDict, key: str) -> str:
    value = string_value(mapping.get(key))
    assert value is not None, (
        f"Expected string at key '{key}', got: {mapping.get(key)!r}"
    )
    return value


def assert_denied_by(
    result: EngineResult, rule_id: str, msg_fragment: str = ""
) -> None:
    spec = hook_output(result)
    decision = output_string(spec, "permissionDecision") or None
    if decision is None:
        inner = nested_output(spec, "decision")
        decision = output_string(inner, "behavior") or None
        reason = output_string(inner, "message")
    else:
        reason = output_string(spec, "permissionDecisionReason")
    assert decision == "deny", f"Expected deny, got {decision}. Output: {result.output}"
    assert rule_id in reason, f"Expected {rule_id} in reason, got: {reason}"
    if msg_fragment:
        assert msg_fragment.lower() in reason.lower(), (
            f"Expected '{msg_fragment}' in reason"
        )


def assert_blocked(result: EngineResult, rule_id: str = "") -> None:
    output = require_output(result)
    assert output_string(output, "decision") == "block", (
        f"Expected block, got: {result.output}"
    )
    if rule_id:
        reason = output_string(output, "reason")
        assert rule_id in reason, f"Expected {rule_id} in reason, got: {reason}"


def assert_not_denied(result: EngineResult) -> None:
    if result.output is None:
        return
    spec = hook_output(result)
    decision = output_string(spec, "permissionDecision") or None
    assert decision != "deny", (
        f"Expected no deny but got: {output_string(spec, 'permissionDecisionReason')}"
    )


def finding_ids(result: EngineResult) -> set[str]:
    return {f.rule_id for f in result.findings}
