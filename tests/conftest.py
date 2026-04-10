"""Shared fixtures for vibeforcer tests."""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from vibeforcer._types import ObjectDict, object_dict, string_value
from vibeforcer.engine import evaluate_payload as _evaluate_payload
from vibeforcer.models import EngineResult

BUNDLE_ROOT = Path(__file__).resolve().parents[1]

# vibeforcer config lives under src/vibeforcer/resources/
_RESOURCES = BUNDLE_ROOT / "src" / "vibeforcer" / "resources"


# ---------------------------------------------------------------------------
# Core fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _vibeforcer_env(tmp_path):
    """Set up vibeforcer env vars for every test.

    Points VIBEFORCER_ROOT to a tmp dir with config + logs.
    Points VIBEFORCER_CONFIG to the bundled defaults.json.
    """
    old_root = os.environ.get("VIBEFORCER_ROOT")
    old_config = os.environ.get("VIBEFORCER_CONFIG")
    old_legacy = os.environ.get("CLAUDE_HOOK_LAYER_ROOT")

    # Create a temp vibeforcer root with prompt context
    test_root = tmp_path / "vibeforcer_root"
    test_root.mkdir()
    (test_root / "logs").mkdir()
    (test_root / "logs" / "async").mkdir()

    # Copy prompt context
    if (_RESOURCES / "prompt_context").exists():
        shutil.copytree(_RESOURCES / "prompt_context", test_root / "prompt_context")

    os.environ["VIBEFORCER_ROOT"] = str(test_root)
    os.environ["VIBEFORCER_CONFIG"] = str(_RESOURCES / "defaults.json")
    # Clear legacy env to avoid fallback
    os.environ.pop("CLAUDE_HOOK_LAYER_ROOT", None)
    os.environ.pop("HOOK_LAYER_ROOT", None)

    yield

    # Restore
    if old_root is None:
        os.environ.pop("VIBEFORCER_ROOT", None)
    else:
        os.environ["VIBEFORCER_ROOT"] = old_root
    if old_config is None:
        os.environ.pop("VIBEFORCER_CONFIG", None)
    else:
        os.environ["VIBEFORCER_CONFIG"] = old_config
    if old_legacy is not None:
        os.environ["CLAUDE_HOOK_LAYER_ROOT"] = old_legacy


@pytest.fixture
def bundle_root() -> Path:
    return BUNDLE_ROOT


@pytest.fixture
def load_fixture():
    """Return a callable that loads a fixture JSON by name."""

    def _load(name: str) -> dict[str, object]:
        fixture_path = BUNDLE_ROOT / "fixtures" / name
        raw = fixture_path.read_text(encoding="utf-8")
        return json.loads(raw)

    return _load


@pytest.fixture
def evaluate():
    """Return the evaluate_payload callable."""
    return _evaluate_payload


@pytest.fixture
def tmp_project(tmp_path):
    """Create a temp directory with vibeforcer config."""
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "logs").mkdir()
    (project_dir / "logs" / "async").mkdir()

    # Copy prompt context
    if (_RESOURCES / "prompt_context").exists():
        shutil.copytree(_RESOURCES / "prompt_context", project_dir / "prompt_context")

    old_root = os.environ.get("VIBEFORCER_ROOT")
    old_config = os.environ.get("VIBEFORCER_CONFIG")
    os.environ["VIBEFORCER_ROOT"] = str(project_dir)
    os.environ["VIBEFORCER_CONFIG"] = str(_RESOURCES / "defaults.json")

    yield project_dir

    if old_root is None:
        os.environ.pop("VIBEFORCER_ROOT", None)
    else:
        os.environ["VIBEFORCER_ROOT"] = old_root
    if old_config is None:
        os.environ.pop("VIBEFORCER_CONFIG", None)
    else:
        os.environ["VIBEFORCER_CONFIG"] = old_config


@pytest.fixture
def langgraph_project(tmp_path):
    """Create a temp project with a pyproject.toml declaring langgraph."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["langgraph>=0.2"]\n',
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "async").mkdir()

    old_root = os.environ.get("VIBEFORCER_ROOT")
    os.environ["VIBEFORCER_ROOT"] = str(tmp_path)
    yield tmp_path
    if old_root is None:
        os.environ.pop("VIBEFORCER_ROOT", None)
    else:
        os.environ["VIBEFORCER_ROOT"] = old_root


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


@pytest.fixture
def pretool_write():
    """Build a PreToolUse Write payload."""

    def _build(
        file_path: str, content: str, cwd: str | None = None
    ) -> dict[str, object]:
        return {
            "session_id": "t",
            "cwd": cwd or str(BUNDLE_ROOT),
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": file_path, "content": content},
        }

    return _build


@pytest.fixture
def pretool_bash():
    """Build a PreToolUse Bash payload."""

    def _build(command: str, cwd: str | None = None) -> dict[str, object]:
        return {
            "session_id": "t",
            "cwd": cwd or str(BUNDLE_ROOT),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }

    return _build


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------


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
    """Assert output is deny and the specific rule_id appears in the reason."""
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
    """Assert top-level decision='block' (Stop/ConfigChange)."""
    output = require_output(result)
    assert output_string(output, "decision") == "block", (
        f"Expected block, got: {result.output}"
    )
    if rule_id:
        reason = output_string(output, "reason")
        assert rule_id in reason, f"Expected {rule_id} in reason, got: {reason}"


def assert_not_denied(result: EngineResult) -> None:
    """Assert the result either has no output or does not deny."""
    if result.output is None:
        return
    spec = hook_output(result)
    decision = output_string(spec, "permissionDecision") or None
    assert decision != "deny", (
        f"Expected no deny but got: {output_string(spec, 'permissionDecisionReason')}"
    )


def finding_ids(result: EngineResult) -> set[str]:
    """Get the set of rule IDs from findings."""
    return {f.rule_id for f in result.findings}
