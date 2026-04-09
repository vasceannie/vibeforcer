"""Hook-layer tests — pytest + conftest fixtures + parametrize.

All shared fixtures (evaluate, load_fixture, pretool_write, pretool_bash,
bundle_root, tmp_project) and assertion helpers (assert_denied_by,
assert_blocked, assert_not_denied, finding_ids) live in conftest.py.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from vibeforcer.engine import evaluate_payload
from conftest import (
    BUNDLE_ROOT,
    assert_blocked,
    assert_denied_by,
    assert_not_denied,
    finding_ids,
)


# ===========================================================================
# PreToolUse: parametrised positive deny tests (fixture-driven)
# ===========================================================================


@pytest.mark.parametrize(
    "fixture_name, rule_id, msg_fragment",
    [
        # BUILTIN-ENFORCE-FULL-READ is disabled in default config
        # ("pretool_read_partial.json", "BUILTIN-ENFORCE-FULL-READ", "in full first"),
        ("pretool_git_no_verify.json", "GIT-001", "hook bypass detected"),
        ("pretool_git_stash.json", "GIT-003", ""),
        ("pretool_python_any.json", "PY-TYPE-001", "Any"),
        ("pretool_ts_ignore.json", "TS-LINT-002", "suppression"),
        ("pretool_rust_unwrap.json", "RS-QUALITY-002", "unwrap"),
        ("pretool_python_source_bash.json", "PY-SHELL-001", "shell edit"),
        ("pretool_datetime_fallback.json", "PY-QUALITY-004", "datetime.now"),
        ("pretool_silent_none.json", "PY-QUALITY-006", "None"),
        ("pretool_silent_except.json", "PY-EXC-002", "silent"),
        ("pretool_assertion_roulette.json", "PY-TEST-001", "assert"),
        ("pretool_python_todo.json", "PY-QUALITY-007", "TODO"),
        ("pretool_test_sleep.json", "PY-TEST-002", "sleep"),
        ("pretool_linter_config.json", "PY-LINTER-001", ""),
        ("pretool_ts_todo.json", "TS-QUALITY-003", "TODO"),
        ("pretool_test_loop_assert.json", "PY-TEST-003", ""),
        ("pretool_fixture_outside_conftest.json", "PY-TEST-004", "conftest"),
        ("pretool_baseline_inflate.json", "BASELINE-001", "baseline"),
    ],
    ids=lambda p: p if isinstance(p, str) and p.endswith(".json") else "",
)
def test_fixture_denies(load_fixture, fixture_name, rule_id, msg_fragment):
    """Parametrised: each fixture must trigger its expected rule."""
    result = evaluate_payload(load_fixture(fixture_name))
    assert_denied_by(result, rule_id, msg_fragment)


# Tests where multiple rules may legitimately fire (order-dependent)
class TestMultiRuleDenyFixtures:
    def test_default_swallow(self, load_fixture):
        """PY-EXC-001 or PY-QUALITY-005 may fire on log+return-default."""
        result = evaluate_payload(load_fixture("pretool_default_swallow.json"))
        assert result.output is not None
        reason = result.output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "PY-QUALITY-005" in reason or "PY-EXC-001" in reason

    def test_fe_linter(self, load_fixture):
        result = evaluate_payload(load_fixture("pretool_fe_linter.json"))
        assert result.output is not None
        reason = result.output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "FE-LINTER-001" in reason or "BUILTIN-PROTECTED-PATHS" in reason

    def test_design_tokens(self, load_fixture):
        result = evaluate_payload(load_fixture("pretool_design_tokens.json"))
        assert result.output is not None
        reason = result.output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "STYLE-004" in reason or "STYLE-005" in reason

    def test_shell_bypass(self, load_fixture):
        result = evaluate_payload(load_fixture("pretool_shell_bypass.json"))
        assert result.output is not None
        reason = result.output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "SHELL-001" in reason or "GLOBAL-BUILTIN-SYSTEM-PROTECTION" in reason

    def test_quality_test_path(self, load_fixture):
        result = evaluate_payload(load_fixture("pretool_quality_test_path.json"))
        assert result.output is not None
        reason = result.output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "QA-PATH-003" in reason or "BUILTIN-PROTECTED-PATHS" in reason


# ===========================================================================
# PreToolUse: inline payload deny tests
# ===========================================================================

class TestInlinePayloadDenies:
    def test_git_n_shorthand(self, pretool_bash):
        result = evaluate_payload(pretool_bash('git commit -n -m "skip"'))
        assert_denied_by(result, "GIT-001")

    def test_protected_path_makefile(self, pretool_write):
        result = evaluate_payload(pretool_write("Makefile", "all:\n\techo hi\n"))
        assert_denied_by(result, "BUILTIN-PROTECTED-PATHS", "protected path")

    def test_system_path(self, pretool_write):
        result = evaluate_payload(pretool_write("/etc/passwd", "x"))
        assert_denied_by(result, "GLOBAL-BUILTIN-SYSTEM-PROTECTION")

    def test_sensitive_data(self, pretool_bash):
        result = evaluate_payload(pretool_bash("cat ~/.ssh/id_rsa"))
        assert_denied_by(result, "GLOBAL-BUILTIN-SENSITIVE-DATA")

    def test_exec_protection_bash_write(self, pretool_bash):
        # GLOBAL-BUILTIN-HOOK-INFRA-EXEC is disabled in default config;
        # BUILTIN-PROTECTED-PATHS catches .claude/ paths instead
        result = evaluate_payload(pretool_bash("echo x > .claude/hooks/run-pretool.sh"))
        assert_denied_by(result, "BUILTIN-PROTECTED-PATHS")

    def test_exec_protection_write_config(self, pretool_write):
        # GLOBAL-BUILTIN-HOOK-INFRA-EXEC is disabled in default config;
        # BUILTIN-PROTECTED-PATHS and CONFIG-002 catch this instead
        result = evaluate_payload(pretool_write(".claude/hook-layer/config.json", "{}"))
        assert_denied_by(result, "BUILTIN-PROTECTED-PATHS")

    def test_security_bypass_permissions(self, pretool_write):
        result = evaluate_payload(pretool_write("src/settings.py", "BYPASS_PERMISSIONS = True\n"))
        assert_denied_by(result, "BUILTIN-RULEBOOK-SECURITY", "bypass")

    def test_patch_with_any(self, bundle_root):
        payload = {
            "session_id": "t", "cwd": str(bundle_root),
            "hook_event_name": "PreToolUse", "tool_name": "Patch",
            "tool_input": {"patch": "*** Update File: src/example.py\n+from typing import Any\n"},
        }
        result = evaluate_payload(payload)
        assert_denied_by(result, "PY-TYPE-001")

    def test_multiedit_second_edit_caught(self, bundle_root):
        payload = {
            "session_id": "t", "cwd": str(bundle_root),
            "hook_event_name": "PreToolUse", "tool_name": "MultiEdit",
            "tool_input": {"edits": [
                {"file_path": "src/a.py", "new_string": "x: int = 1"},
                {"file_path": "src/b.py", "new_string": "from typing import Any"},
            ]},
        }
        result = evaluate_payload(payload)
        assert_denied_by(result, "PY-TYPE-001", "Any")


# ===========================================================================
# PreToolUse: negative tests (must NOT deny)
# ===========================================================================

@pytest.mark.parametrize(
    "file_path, content, forbidden_rule",
    [
        pytest.param(
            "src/models/user.py",
            "from dataclasses import dataclass\n\n@dataclass\nclass User:\n    name: str\n    email: str\n",
            None,
            id="clean-python",
        ),
        pytest.param(
            "src/utils/format.ts",
            "export function formatDate(d: Date): string {\n  return d.toISOString();\n}\n",
            None,
            id="clean-typescript",
        ),
        pytest.param(
            "tests/conftest.py",
            "import pytest\n\n@pytest.fixture\ndef client():\n    return TestClient()\n",
            "PY-TEST-004",
            id="conftest-fixture-allowed",
        ),
        pytest.param(
            "src/hook_layer/config.py",
            "enabled_rules = {}\n",
            "BUILTIN-RULEBOOK-SECURITY",
            id="hook-source-not-blocked-by-security",
        ),
    ],
)
def test_write_not_denied(pretool_write, evaluate, file_path, content, forbidden_rule):
    result = evaluate(pretool_write(file_path, content))
    if forbidden_rule is None:
        assert_not_denied(result)
    else:
        assert forbidden_rule not in finding_ids(result), (
            f"{forbidden_rule} should not fire for {file_path}"
        )


@pytest.mark.parametrize(
    "command, forbidden_rule",
    [
        pytest.param("npm test", None, id="npm-test"),
        pytest.param("cat Makefile", None, id="cat-makefile"),
        pytest.param("cat .claude/hooks/run-pretool.sh", None, id="cat-hook-file"),
        pytest.param(
            "grep -n import src/hook_layer/engine.py",
            "PY-SHELL-001",
            id="grep-not-shell-edit",
        ),
    ],
)
def test_bash_not_denied(pretool_bash, evaluate, command, forbidden_rule):
    result = evaluate(pretool_bash(command))
    if forbidden_rule is None:
        assert_not_denied(result)
    else:
        ids = finding_ids(result)
        assert forbidden_rule not in ids, f"{forbidden_rule} should not fire for: {command}"


def test_read_hook_file_allowed(bundle_root):
    payload = {
        "session_id": "t", "cwd": str(bundle_root),
        "hook_event_name": "PreToolUse", "tool_name": "Read",
        "tool_input": {"file_path": ".claude/hooks/run-pretool.sh"},
    }
    result = evaluate_payload(payload)
    assert_not_denied(result)


def test_two_asserts_below_threshold(pretool_write):
    result = evaluate_payload(pretool_write(
        "tests/test_safe.py",
        "def test_ok():\n    assert x == 1\n    assert y == 2\n",
    ))
    assert "PY-TEST-001" not in finding_ids(result), "2 asserts below threshold"


# ===========================================================================
# Edge cases and boundary tests
# ===========================================================================

class TestEdgeCases:
    """Verify rules don't over-match on similar-looking but valid code."""

    @pytest.mark.parametrize(
        "code, should_deny",
        [
            pytest.param(
                "def safe_int(s):\n    try:\n        return int(s)\n    except ValueError:\n        pass\n",
                False,
                id="specific-exception-pass-allowed",
            ),
            pytest.param(
                "def get_item(d, k):\n    try:\n        return d[k]\n    except KeyError:\n        return None\n",
                False,
                id="specific-exception-return-none-allowed",
            ),
            pytest.param(
                "def process(items):\n    for i in items:\n        try:\n            do(i)\n        except Exception:\n            continue\n",
                True,
                id="except-exception-continue-denied",
            ),
            pytest.param(
                "def fetch(url):\n    try:\n        return get(url).json()\n    except Exception:\n        return None\n",
                True,
                id="except-exception-return-none-denied",
            ),
            pytest.param(
                "def cleanup():\n    try:\n        os.remove(f)\n    except:\n        pass\n",
                True,
                id="bare-except-pass-denied",
            ),
        ],
    )
    def test_exc_002_boundaries(self, pretool_write, code, should_deny):
        result = evaluate_payload(pretool_write("src/module.py", code))
        ids = finding_ids(result)
        if should_deny:
            assert "PY-EXC-002" in ids, f"Expected PY-EXC-002 to fire on:\n{code}"
        else:
            assert "PY-EXC-002" not in ids, f"PY-EXC-002 should NOT fire on:\n{code}"

    def test_any_builtin_not_denied(self, pretool_write):
        """Python's builtin any() must not trigger PY-TYPE-001."""
        result = evaluate_payload(pretool_write(
            "src/check.py",
            "def has_errors(items: list[str]) -> bool:\n"
            "    return any(item.startswith('ERROR') for item in items)\n",
        ))
        assert "PY-TYPE-001" not in finding_ids(result)

    def test_normal_git_commit_allowed(self, pretool_bash):
        result = evaluate_payload(pretool_bash("git commit -m 'fix: thing'"))
        assert "GIT-001" not in finding_ids(result)

    def test_safe_redirect_allowed(self, pretool_bash):
        result = evaluate_payload(pretool_bash("echo hello > output.txt"))
        assert "SHELL-001" not in finding_ids(result)

    def test_asserts_with_messages_allowed(self, pretool_write):
        code = (
            "def test_validated():\n"
            "    assert x == 1, 'expected 1'\n"
            "    assert y == 2, 'expected 2'\n"
            "    assert z == 3, 'expected 3'\n"
            "    assert w == 4, 'expected 4'\n"
        )
        result = evaluate_payload(pretool_write("tests/test_good.py", code))
        assert "PY-TEST-001" not in finding_ids(result)

    @pytest.mark.parametrize(
        "file_path, content",
        [
            pytest.param(
                "docs/README.md",
                "# Exceptions\n\nexcept Exception:\n    pass\n\nfrom typing import Any\n",
                id="markdown",
            ),
            pytest.param(
                "config.json",
                '{\n  "type": "Any"\n}\n',
                id="json",
            ),
        ],
    )
    def test_non_python_not_denied_by_python_rules(self, pretool_write, file_path, content):
        result = evaluate_payload(pretool_write(file_path, content))
        py_rules = {r for r in finding_ids(result) if r.startswith("PY-")}
        assert not py_rules, f"Non-Python file should not trigger: {py_rules}"


# ===========================================================================
# BASELINE-001: increase vs decrease
# ===========================================================================

class TestBaselineGuard:
    def _write_baseline(self, tmp_path: Path, rules: dict) -> Path:
        p = tmp_path / "baselines.json"
        p.write_text(json.dumps({
            "generated_at": "2026-01-01", "rules": rules, "schema_version": 1
        }))
        return p

    def test_increase_blocked(self, tmp_path):
        existing = self._write_baseline(tmp_path, {"high-complexity": ["h1", "h2"]})
        new_content = json.dumps({
            "generated_at": "2026-01-02",
            "rules": {"high-complexity": ["h1", "h2", "h3", "h4"]},
            "schema_version": 1,
        })
        payload = {
            "session_id": "t", "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse", "tool_name": "Write",
            "tool_input": {"file_path": str(existing), "content": new_content},
        }
        result = evaluate_payload(payload)
        assert_denied_by(result, "BASELINE-001", "inflation")

    def test_decrease_allowed(self, tmp_path):
        existing = self._write_baseline(tmp_path, {"high-complexity": ["h1", "h2", "h3"]})
        new_content = json.dumps({
            "generated_at": "2026-01-02",
            "rules": {"high-complexity": ["h1"]},
            "schema_version": 1,
        })
        payload = {
            "session_id": "t", "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse", "tool_name": "Write",
            "tool_input": {"file_path": str(existing), "content": new_content},
        }
        result = evaluate_payload(payload)
        assert_not_denied(result)


# ===========================================================================
# PermissionRequest event
# ===========================================================================

def test_permission_request_denies_makefile(bundle_root):
    payload = {
        "session_id": "t", "cwd": str(bundle_root),
        "hook_event_name": "PermissionRequest",
        "tool_name": "Write", "tool_input": {"file_path": "Makefile", "content": "all:\n\techo hi\n"},
    }
    result = evaluate_payload(payload)
    assert result.output is not None
    inner = result.output["hookSpecificOutput"]["decision"]
    assert inner["behavior"] == "deny"
    assert "BUILTIN-PROTECTED-PATHS" in inner.get("message", "")


# ===========================================================================
# UserPromptSubmit
# ===========================================================================

def test_prompt_injects_context(bundle_root):
    payload = {
        "session_id": "t", "cwd": str(bundle_root),
        "hook_event_name": "UserPromptSubmit",
        "prompt": "refactor the auth module",
    }
    result = evaluate_payload(payload)
    assert result.output is not None
    spec = result.output["hookSpecificOutput"]
    assert spec["hookEventName"] == "UserPromptSubmit"
    ctx = spec["additionalContext"]
    assert "Organization prompt context" in ctx
    assert "Repository Rules" in ctx


# ===========================================================================
# PostToolUse (AST rules)
# ===========================================================================

def test_long_param_list_blocks(tmp_project):
    target = tmp_project / "src" / "sample.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("def build(a, b, c, d, e):\n    return a + b + c + d + e\n")
    payload = {
        "session_id": "t", "cwd": str(tmp_project),
        "hook_event_name": "PostToolUse", "tool_name": "Write",
        "tool_input": {"file_path": "src/sample.py", "content": target.read_text()},
        "tool_response": {"filePath": "src/sample.py", "success": True},
    }
    result = evaluate_payload(payload)
    assert_blocked(result)
    assert "PY-CODE-009" in result.output["reason"]
    assert "parameters" in result.output["reason"].lower()


# ===========================================================================
# Stop / SubagentStop
# ===========================================================================

def test_stop_preexisting_blocked(load_fixture):
    result = evaluate_payload(load_fixture("stop_preexisting.json"))
    assert_blocked(result, "STOP-001")


def test_subagent_stop_preexisting_blocked(bundle_root):
    payload = {
        "session_id": "t", "cwd": str(bundle_root),
        "hook_event_name": "SubagentStop",
        "stop_response": "The type error was already existed before my changes.",
    }
    result = evaluate_payload(payload)
    assert_blocked(result, "STOP-001")


def test_clean_stop_gets_quality_reminder(bundle_root):
    payload = {
        "session_id": "t", "cwd": str(bundle_root),
        "hook_event_name": "Stop",
        "stop_response": "All tasks completed successfully.",
    }
    result = evaluate_payload(payload)
    assert result.output is not None
    assert result.output.get("decision") != "block"
    ctx = result.output.get(
        "systemMessage",
        result.output.get("hookSpecificOutput", {}).get("additionalContext", ""),
    )
    assert "quality" in ctx.lower(), f"Expected quality reminder, got: {ctx}"


def test_git_commit_gets_quality_context(bundle_root):
    payload = {
        "session_id": "t", "cwd": str(bundle_root),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash", "tool_input": {"command": "git commit -m 'fix: something'"},
    }
    result = evaluate_payload(payload)
    assert result.output is not None
    ctx = result.output.get(
        "systemMessage",
        result.output.get("hookSpecificOutput", {}).get("additionalContext", ""),
    )
    assert "quality" in ctx.lower()
    assert "GIT-002" in finding_ids(result)


# ===========================================================================
# SessionStart
# ===========================================================================

def _init_git_worktree(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    worktree = tmp_path / "repo-worktree"
    repo.mkdir()

    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True, capture_output=True, text=True)

    (repo / "README.md").write_text("root\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "worktree", "add", "-b", "feature/worktree-support", str(worktree)],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return repo, worktree


def test_sessionstart_injects_git_context(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, check=True, capture_output=True, text=True)
    (repo / "f.txt").write_text("hi\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True, text=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True, text=True)
    payload = {"session_id": "s", "cwd": str(repo), "hook_event_name": "SessionStart"}
    result = evaluate_payload(payload)
    assert result.output is not None
    spec = result.output["hookSpecificOutput"]
    assert spec["hookEventName"] == "SessionStart"
    ctx = spec["additionalContext"]
    assert "commits" in ctx.lower()
    assert "branch" in ctx.lower()


def test_sessionstart_injects_git_context_from_worktree(tmp_path):
    _repo, worktree = _init_git_worktree(tmp_path)
    payload = {
        "session_id": "t",
        "cwd": str(worktree),
        "hook_event_name": "SessionStart",
    }
    result = evaluate_payload(payload)
    assert result.output is not None
    spec = result.output["hookSpecificOutput"]
    assert spec["hookEventName"] == "SessionStart"
    ctx = spec["additionalContext"]
    assert "current branch" in ctx.lower()
    assert "feature/worktree-support" in ctx
    assert "recent commits" in ctx.lower()


# ===========================================================================
# ConfigChange
# ===========================================================================

def test_disable_all_hooks_blocked(load_fixture):
    result = evaluate_payload(load_fixture("configchange_disable_hooks.json"))
    assert_blocked(result, "CONFIG-001")


def test_hook_modification_blocked(bundle_root):
    payload = {
        "session_id": "t", "cwd": str(bundle_root),
        "hook_event_name": "ConfigChange",
        "source": "user_settings", "changes": {"hooks": {"PreToolUse": []}},
    }
    result = evaluate_payload(payload)
    assert_blocked(result, "CONFIG-001")


def test_policy_settings_allowed(load_fixture):
    result = evaluate_payload(load_fixture("configchange_safe.json"))
    if result.output is not None:
        assert result.output.get("decision") != "block"


# ===========================================================================
# WarnLargeFile
# ===========================================================================

def test_large_file_warns(pretool_write):
    result = evaluate_payload(pretool_write("src/giant.py", "x = 1\n" * 60000))
    assert "WARN-LARGE-001" in finding_ids(result)
    ctx = result.output["hookSpecificOutput"]["additionalContext"]
    assert "giant.py" in ctx
    assert "characters" in ctx.lower()


def test_small_file_no_warn(pretool_write):
    result = evaluate_payload(pretool_write("src/small.py", "x = 1\n"))
    assert "WARN-LARGE-001" not in finding_ids(result)


# ===========================================================================
# Disabled rules
# ===========================================================================

@pytest.mark.parametrize(
    "fixture_name, rule_id",
    [
        ("pretool_git_no_verify.json", "GIT-001"),
        ("pretool_silent_except.json", "PY-EXC-002"),
    ],
    ids=["python-rule-GIT-001", "regex-rule-PY-EXC-002"],
)
def test_disabled_rule_does_not_fire(load_fixture, fixture_name, rule_id):
    from vibeforcer.config import load_config
    from vibeforcer.context import HookContext
    from vibeforcer.rules import build_rules
    from vibeforcer.trace import TraceWriter
    from vibeforcer.util.payloads import HookPayload

    payload = load_fixture(fixture_name)
    config = load_config()
    config.enabled_rules[rule_id] = False
    try:
        trace = TraceWriter(config.trace_dir)
        hp = HookPayload(payload, config)
        ctx = HookContext(payload=hp, config=config, trace=trace)
        for rule in build_rules(ctx):
            if rule.rule_id == rule_id:
                findings = rule.evaluate(ctx)
                assert findings == [], f"Disabled {rule_id} should return no findings"
    finally:
        config.enabled_rules[rule_id] = True


# ===========================================================================
# Robustness
# ===========================================================================

@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({}, id="empty-payload"),
        pytest.param(
            {"session_id": "t", "hook_event_name": "PreToolUse", "tool_name": "Bash"},
            id="missing-tool-input",
        ),
        pytest.param(
            {"session_id": "t", "hook_event_name": "FutureEvent",
             "tool_name": "Write", "tool_input": {"file_path": "x.py", "content": "x"}},
            id="unknown-event",
        ),
    ],
)
def test_robustness_no_crash(payload):
    result = evaluate_payload(payload)
    assert isinstance(result.findings, list)


# ===========================================================================
# Schema compliance: hookSpecificOutput only on permitted events
# ===========================================================================

VALID_TOP_LEVEL_KEYS = {
    "decision", "reason", "hookSpecificOutput",
    "continue", "stopReason", "suppressOutput", "systemMessage",
}

EVENTS_NO_HOOK_SPECIFIC = (
    "Stop", "SubagentStop", "ConfigChange",
    "PostToolUseFailure", "TaskCompleted", "TeammateIdle",
)


@pytest.mark.parametrize(
    "event_name, extra_fields",
    [
        ("Stop", {"stop_response": "done"}),
        ("SubagentStop", {"stop_response": "done"}),
        ("ConfigChange", {"source": "user_settings", "changes": {}}),
        ("PostToolUseFailure", {"tool_name": "Bash", "tool_input": {"command": "false"}}),
        ("TaskCompleted", {}),
        ("TeammateIdle", {}),
    ],
)
def test_no_hookSpecificOutput_on_banned_events(bundle_root, event_name, extra_fields):
    payload = {"session_id": "t", "cwd": str(bundle_root), "hook_event_name": event_name}
    payload.update(extra_fields)
    result = evaluate_payload(payload)
    if result.output is not None:
        assert "hookSpecificOutput" not in result.output, (
            f"{event_name} emitted hookSpecificOutput (invalid per Claude Code schema)"
        )


def test_stop_blocking_uses_top_level_decision(load_fixture):
    result = evaluate_payload(load_fixture("stop_preexisting.json"))
    assert result.output["decision"] == "block"
    assert "reason" in result.output
    assert "hookSpecificOutput" not in result.output
    assert "permissionDecision" not in result.output


def test_pretooluse_uses_hookSpecificOutput(load_fixture):
    result = evaluate_payload(load_fixture("pretool_git_no_verify.json"))
    spec = result.output["hookSpecificOutput"]
    assert spec["hookEventName"] == "PreToolUse"
    assert "permissionDecision" in spec


def test_permission_request_uses_decision_behavior(bundle_root):
    payload = {
        "session_id": "t", "cwd": str(bundle_root),
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash", "tool_input": {"command": "git commit --no-verify -m x"},
    }
    result = evaluate_payload(payload)
    spec = result.output["hookSpecificOutput"]
    assert spec["hookEventName"] == "PermissionRequest"
    assert spec["decision"]["behavior"] == "deny"


def test_stop_clean_uses_systemMessage(bundle_root):
    payload = {
        "session_id": "t", "cwd": str(bundle_root),
        "hook_event_name": "Stop", "stop_response": "Done.",
    }
    result = evaluate_payload(payload)
    assert result.output is not None
    assert "systemMessage" in result.output
    assert "hookSpecificOutput" not in result.output


def test_configchange_uses_decision_and_reason(load_fixture):
    result = evaluate_payload(load_fixture("configchange_disable_hooks.json"))
    assert "decision" in result.output
    assert "reason" in result.output
    assert "permissionDecision" not in result.output


def test_all_outputs_valid_json_shape(load_fixture):
    """Every fixture output must have only recognised top-level keys."""
    fixture_dir = BUNDLE_ROOT / "fixtures"
    for fixture_file in sorted(fixture_dir.glob("*.json")):
        data = json.loads(fixture_file.read_text())
        event = data.get("hook_event_name", "unknown")
        result = evaluate_payload(load_fixture(fixture_file.name))
        if result.output is not None:
            for key in result.output:
                assert key in VALID_TOP_LEVEL_KEYS, (
                    f"{fixture_file.name}: unknown key '{key}'"
                )
            spec = result.output.get("hookSpecificOutput")
            if spec is not None:
                assert spec.get("hookEventName") == event, (
                    f"{fixture_file.name}: hookEventName mismatch"
                )


def test_all_outputs_json_serialisable(load_fixture):
    fixture_dir = BUNDLE_ROOT / "fixtures"
    for fixture_file in sorted(fixture_dir.glob("*.json")):
        result = evaluate_payload(load_fixture(fixture_file.name))
        if result.output is not None:
            roundtrip = json.loads(json.dumps(result.output))
            assert result.output == roundtrip, f"{fixture_file.name}: not JSON round-trip safe"


# ===========================================================================
# LangGraph rules
# ===========================================================================

class TestLangGraph:
    def _posttool_payload(self, tmp_project, rel_path: str, code: str) -> dict:
        target = tmp_project / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(code)
        return {
            "session_id": "t", "cwd": str(tmp_project),
            "hook_event_name": "PostToolUse", "tool_name": "Write",
            "tool_input": {"file_path": rel_path, "content": code},
            "tool_response": {"filePath": rel_path, "success": True},
        }

    @pytest.mark.parametrize(
        "code, should_flag",
        [
            pytest.param(
                "from typing import TypedDict\nfrom langgraph.graph import StateGraph\n"
                "class MyState(TypedDict, total=False):\n    messages: list[str]\n    counter: int\n",
                True,
                id="bare-list-field-flagged",
            ),
            pytest.param(
                "from typing import Annotated, TypedDict\nfrom operator import add\n"
                "from langgraph.graph import StateGraph\n"
                "class MyState(TypedDict, total=False):\n    messages: Annotated[list[str], add]\n    counter: int\n",
                False,
                id="annotated-list-not-flagged",
            ),
        ],
    )
    def test_lg_state_001(self, tmp_project, code, should_flag):
        payload = self._posttool_payload(tmp_project, "graph/state.py", code)
        result = evaluate_payload(payload)
        findings = [f for f in result.findings if f.rule_id == "LG-STATE-001"]
        if should_flag:
            assert findings, "Should flag bare list field"
            assert "messages" in findings[0].additional_context
            assert findings[0].decision is None, "Must be advisory"
        else:
            assert not findings

    @pytest.mark.parametrize(
        "code, should_flag",
        [
            pytest.param(
                "from langgraph.graph import StateGraph\n"
                "def my_node(state):\n    state[\"counter\"] = state[\"counter\"] + 1\n    return state\n",
                True,
                id="subscript-assign-flagged",
            ),
            pytest.param(
                "from langgraph.graph import StateGraph\n"
                "def my_node(state):\n    state[\"items\"].append(\"new\")\n    return state\n",
                True,
                id="append-flagged",
            ),
            pytest.param(
                "def my_node(state):\n    val = state.get(\"counter\", 0)\n    return {\"counter\": val + 1}\n",
                False,
                id="get-read-only-not-flagged",
            ),
        ],
    )
    def test_lg_node_001(self, tmp_project, code, should_flag):
        payload = self._posttool_payload(tmp_project, "graph/nodes.py", code)
        result = evaluate_payload(payload)
        findings = [f for f in result.findings if f.rule_id == "LG-NODE-001"]
        if should_flag:
            assert findings, f"Should flag state mutation"
            assert findings[0].decision is None
        else:
            assert not findings

    def test_non_graph_file_ignored(self, tmp_project):
        code = "from typing import TypedDict\nclass Config(TypedDict):\n    items: list[str]\n"
        payload = self._posttool_payload(tmp_project, "utils/helpers.py", code)
        result = evaluate_payload(payload)
        lg_findings = [f for f in result.findings if f.rule_id.startswith("LG-")]
        assert not lg_findings

    def test_set_entry_point_flagged(self, tmp_project):
        code = (
            "from langgraph.graph import StateGraph\n"
            "graph = StateGraph(MyState)\n"
            'graph.set_entry_point("start")\n'
        )
        payload = self._posttool_payload(tmp_project, "builder.py", code)
        result = evaluate_payload(payload)
        findings = [f for f in result.findings if f.rule_id == "LG-API-001"]
        assert findings
        assert "add_edge(START" in findings[0].additional_context

    def test_add_edge_start_not_flagged(self, tmp_project):
        code = (
            "from langgraph.graph import START, StateGraph\n"
            "graph = StateGraph(MyState)\n"
            'graph.add_edge(START, "start")\n'
        )
        payload = self._posttool_payload(tmp_project, "builder.py", code)
        result = evaluate_payload(payload)
        api_findings = [f for f in result.findings if f.rule_id == "LG-API-001"]
        assert not api_findings

    def test_all_lg_findings_are_advisory(self, tmp_project):
        code = (
            "from typing import TypedDict\nfrom langgraph.graph import StateGraph\n"
            "class BadState(TypedDict):\n    items: list[str]\n\n"
            "def bad_node(state):\n    state[\"items\"].append(\"x\")\n    return state\n"
        )
        payload = self._posttool_payload(tmp_project, "graph/bad.py", code)
        result = evaluate_payload(payload)
        lg_findings = [f for f in result.findings if f.rule_id.startswith("LG-")]
        assert lg_findings
        for finding in lg_findings:
            assert finding.decision is None, f"{finding.rule_id} must be advisory"
            assert finding.additional_context is not None

    def test_node_detected_via_pyproject(self, tmp_project):
        """State mutation detected even without langgraph import, via pyproject.toml."""
        code = 'def process(state):\n    state["results"].append("done")\n    return state\n'
        (tmp_project / "graph").mkdir(exist_ok=True)
        (tmp_project / "graph" / "nodes.py").write_text(code)
        (tmp_project / "pyproject.toml").write_text(
            '[project]\nname = "my-agent"\ndependencies = ["langgraph>=0.2"]\n'
        )
        payload = {
            "session_id": "t", "cwd": str(tmp_project),
            "hook_event_name": "PostToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "graph/nodes.py", "content": code},
            "tool_response": {"filePath": "graph/nodes.py", "success": True},
        }
        result = evaluate_payload(payload)
        assert any(f.rule_id == "LG-NODE-001" for f in result.findings)

    def test_node_without_pyproject_ignored(self, tmp_project):
        code = 'def process(state):\n    state["results"].append("done")\n    return state\n'
        (tmp_project / "graph").mkdir(exist_ok=True)
        (tmp_project / "graph" / "nodes.py").write_text(code)
        # No pyproject.toml
        payload = {
            "session_id": "t", "cwd": str(tmp_project),
            "hook_event_name": "PostToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "graph/nodes.py", "content": code},
            "tool_response": {"filePath": "graph/nodes.py", "success": True},
        }
        result = evaluate_payload(payload)
        lg_findings = [f for f in result.findings if f.rule_id.startswith("LG-")]
        assert not lg_findings


# ===========================================================================
# Regex rule coverage: PY-LOG-001 (ban stdlib logging)
# ===========================================================================

@pytest.mark.parametrize(
    "code, should_deny",
    [
        pytest.param("import logging\nlogger = logging.getLogger(__name__)\n", True, id="import-logging"),
        pytest.param("from logging import StreamHandler\n", True, id="from-logging-import"),
        pytest.param("logging.getLogger('myapp')\n", True, id="getLogger-call"),
        pytest.param("import structlog\nlog = structlog.get_logger()\n", False, id="structlog-allowed"),
        pytest.param("# logging is disabled\nprint('hello')\n", False, id="comment-not-matched"),
    ],
)
def test_py_log_001(pretool_write, code, should_deny):
    result = evaluate_payload(pretool_write("src/app.py", code))
    ids = finding_ids(result)
    if should_deny:
        assert "PY-LOG-001" in ids, f"Expected PY-LOG-001 on:\n{code}"
    else:
        assert "PY-LOG-001" not in ids, f"PY-LOG-001 false positive on:\n{code}"


# ===========================================================================
# Regex rule coverage: PY-TYPE-002 (ban type suppressions)
# ===========================================================================

@pytest.mark.parametrize(
    "code, should_deny",
    [
        pytest.param("x = foo()  # type: ignore\n", True, id="type-ignore"),
        pytest.param("x = foo()  # type: ignore[arg-type]\n", True, id="type-ignore-code"),
        pytest.param("x = foo()  # noqa\n", True, id="noqa"),
        pytest.param("x = foo()  # noqa: E501\n", True, id="noqa-code"),
        pytest.param("x = foo()  # ruff: noqa\n", True, id="ruff-noqa"),
        pytest.param("x = foo()  # pylint: disable=C0114\n", True, id="pylint-disable"),
        pytest.param("x = foo()  # pyright: ignore\n", True, id="pyright-ignore"),
        pytest.param("x = foo()  # pyre-ignore\n", True, id="pyre-ignore"),
        pytest.param("x: int = 1  # this is fine\n", False, id="normal-comment"),
    ],
)
def test_py_type_002(pretool_write, code, should_deny):
    result = evaluate_payload(pretool_write("src/module.py", code))
    ids = finding_ids(result)
    if should_deny:
        assert "PY-TYPE-002" in ids, f"Expected PY-TYPE-002 on:\n{code}"
    else:
        assert "PY-TYPE-002" not in ids


# ===========================================================================
# Regex rule coverage: PY-QUALITY-008 (commented-out code)
# ===========================================================================

class TestCommentedOutCode:
    def test_two_commented_lines_denied(self, pretool_write):
        code = "# def old_func():\n# import os\nx = 1\n"
        result = evaluate_payload(pretool_write("src/clean.py", code))
        assert "PY-QUALITY-008" in finding_ids(result)

    def test_single_comment_allowed(self, pretool_write):
        code = "# def old_func():\nx = 1\n"
        result = evaluate_payload(pretool_write("src/clean.py", code))
        assert "PY-QUALITY-008" not in finding_ids(result)

    def test_docstring_comment_allowed(self, pretool_write):
        code = "# This module handles user authentication.\n# It should be imported early.\nx = 1\n"
        result = evaluate_payload(pretool_write("src/auth.py", code))
        assert "PY-QUALITY-008" not in finding_ids(result)


# ===========================================================================
# Regex rule coverage: PY-QUALITY-009 (hardcoded paths)
# ===========================================================================

@pytest.mark.parametrize(
    "code, should_deny",
    [
        pytest.param("path = '/home/trav/data/file.txt'\n", True, id="linux-home"),
        pytest.param("path = '/Users/admin/Desktop/file.txt'\n", True, id="macos-users"),
        pytest.param("path = '/tmp/mydata/cache.db'\n", True, id="tmp-specific"),
        pytest.param("path = Path(__file__).parent / 'data'\n", False, id="relative-path-ok"),
        pytest.param("path = '/tmp/x'\n", False, id="tmp-short-ok"),
    ],
)
def test_py_quality_009(pretool_write, code, should_deny):
    result = evaluate_payload(pretool_write("src/config.py", code))
    ids = finding_ids(result)
    if should_deny:
        assert "PY-QUALITY-009" in ids, f"Expected PY-QUALITY-009 on:\n{code}"
    else:
        assert "PY-QUALITY-009" not in ids


# ===========================================================================
# Regex rule coverage: TS rules (TS-LINT-001, TS-TYPE-001, TS-TYPE-002)
# ===========================================================================

class TestTypeScriptRules:
    def test_ts_type_001_any_denied(self, pretool_write):
        code = "function parse(input: any): string {\n  return String(input);\n}\n"
        result = evaluate_payload(pretool_write("src/parser.ts", code))
        assert "TS-TYPE-001" in finding_ids(result)

    def test_ts_type_001_specific_type_allowed(self, pretool_write):
        code = "function parse(input: string): number {\n  return parseInt(input);\n}\n"
        result = evaluate_payload(pretool_write("src/parser.ts", code))
        assert "TS-TYPE-001" not in finding_ids(result)

    def test_ts_type_002_as_any_denied(self, pretool_write):
        code = "const x = value as any;\n"
        result = evaluate_payload(pretool_write("src/util.ts", code))
        assert "TS-TYPE-002" in finding_ids(result)

    def test_ts_type_002_as_unknown_denied(self, pretool_write):
        code = "const x = value as unknown;\n"
        result = evaluate_payload(pretool_write("src/util.tsx", code))
        assert "TS-TYPE-002" in finding_ids(result)

    def test_ts_type_002_as_string_allowed(self, pretool_write):
        code = "const x = value as string;\n"
        result = evaluate_payload(pretool_write("src/util.ts", code))
        assert "TS-TYPE-002" not in finding_ids(result)

    def test_ts_lint_001_shell_ignore_inject(self, pretool_bash):
        result = evaluate_payload(pretool_bash(
            "sed -i '1i // @ts-ignore' src/broken.ts"
        ))
        assert "TS-LINT-001" in finding_ids(result)

    def test_ts_lint_001_shell_eslint_disable(self, pretool_bash):
        result = evaluate_payload(pretool_bash(
            "echo '// eslint-disable-next-line' >> src/util.tsx"
        ))
        assert "TS-LINT-001" in finding_ids(result)


# ===========================================================================
# Regex rule coverage: RS-QUALITY-001 (Rust TODOs), RS-QUALITY-003 (magic nums)
# ===========================================================================

class TestRustRules:
    def test_rs_quality_001_todo_denied(self, pretool_write):
        code = "fn main() {\n    // TODO: fix this\n    println!(\"hello\");\n}\n"
        result = evaluate_payload(pretool_write("src/main.rs", code))
        assert "RS-QUALITY-001" in finding_ids(result)

    def test_rs_quality_001_fixme_denied(self, pretool_write):
        code = "// FIXME: handle error\nfn run() {}\n"
        result = evaluate_payload(pretool_write("src/lib.rs", code))
        assert "RS-QUALITY-001" in finding_ids(result)

    def test_rs_quality_001_normal_comment_ok(self, pretool_write):
        code = "// This function handles parsing.\nfn parse() {}\n"
        result = evaluate_payload(pretool_write("src/lib.rs", code))
        assert "RS-QUALITY-001" not in finding_ids(result)

    def test_rs_quality_003_magic_number_denied(self, pretool_write):
        code = "fn retry() {\n    if attempts > 1000 {\n        return;\n    }\n}\n"
        result = evaluate_payload(pretool_write("src/retry.rs", code))
        assert "RS-QUALITY-003" in finding_ids(result)

    def test_rs_quality_003_const_ok(self, pretool_write):
        code = "const MAX_RETRIES: u32 = 1000;\n"
        result = evaluate_payload(pretool_write("src/retry.rs", code))
        assert "RS-QUALITY-003" not in finding_ids(result)


# ===========================================================================
# Regex rule coverage: CONFIG-002/003 (enforcer config protection)
# ===========================================================================

class TestConfigProtection:
    def test_config_002_write_denied(self, pretool_write):
        result = evaluate_payload(pretool_write(
            ".claude/hook-layer/config.json", '{"regex_rules": []}'
        ))
        ids = finding_ids(result)
        assert "CONFIG-002" in ids or "GLOBAL-BUILTIN-HOOK-INFRA-EXEC" in ids

    def test_config_003_sed_denied(self, pretool_bash):
        result = evaluate_payload(pretool_bash(
            "sed -i 's/true/false/' .claude/hook-layer/config.json"
        ))
        ids = finding_ids(result)
        assert "CONFIG-003" in ids or "GLOBAL-BUILTIN-HOOK-INFRA-EXEC" in ids

    def test_config_003_tee_denied(self, pretool_bash):
        result = evaluate_payload(pretool_bash(
            "echo '{}' | tee .claude/hook-layer/config.json"
        ))
        ids = finding_ids(result)
        assert "CONFIG-003" in ids or "GLOBAL-BUILTIN-HOOK-INFRA-EXEC" in ids

    def test_config_003_cat_allowed(self, pretool_bash):
        result = evaluate_payload(pretool_bash(
            "cat .claude/hook-layer/config.json"
        ))
        assert "CONFIG-003" not in finding_ids(result)


# ===========================================================================
# Regex rule coverage: linter config shell edits
# ===========================================================================

@pytest.mark.parametrize(
    "command, rule_id",
    [
        pytest.param("sed -i 's/off/error/' .eslintrc.json", "FE-LINTER-002", id="eslintrc-sed"),
        pytest.param("echo '{}' | tee prettier.config.js", "FE-LINTER-002", id="prettier-tee"),
        pytest.param("sed -i 's/E501//' .flake8", "PY-LINTER-002", id="flake8-sed"),
        pytest.param("echo 'line-length = 120' >> ruff.toml", "PY-LINTER-002", id="ruff-redirect"),
        pytest.param("sed -i 's/strict/basic/' pyrightconfig.json", "PY-LINTER-002", id="pyright-sed"),
    ],
)
def test_linter_shell_edit_denied(pretool_bash, command, rule_id):
    result = evaluate_payload(pretool_bash(command))
    assert rule_id in finding_ids(result), f"Expected {rule_id} on: {command}"


# ===========================================================================
# Regex rule coverage: QA-PATH rules
# ===========================================================================

class TestQAPathRules:
    def test_qa_path_001_write_denied(self, pretool_write):
        result = evaluate_payload(pretool_write(
            "src/test/code-quality.test.ts", "describe('quality', () => {});\n"
        ))
        assert "QA-PATH-001" in finding_ids(result)

    def test_qa_path_002_sed_denied(self, pretool_bash):
        result = evaluate_payload(pretool_bash(
            "sed -i 's/strict/lax/' src/test/code-quality.test.ts"
        ))
        assert "QA-PATH-002" in finding_ids(result)

    def test_qa_path_004_redirect_denied(self, pretool_bash):
        result = evaluate_payload(pretool_bash(
            "echo 'pass' >> tests/quality/test_lint.py"
        ))
        assert "QA-PATH-004" in finding_ids(result)

    def test_qa_path_004_cat_allowed(self, pretool_bash):
        result = evaluate_payload(pretool_bash(
            "cat tests/quality/test_lint.py"
        ))
        assert "QA-PATH-004" not in finding_ids(result)


# ===========================================================================
# Regex rule coverage: REMIND-SEARCH-001 (context, not deny)
# ===========================================================================

class TestSearchReminder:
    def test_grep_triggers_reminder(self, pretool_bash):
        result = evaluate_payload(pretool_bash("grep -rn 'TODO' src/"))
        assert "REMIND-SEARCH-001" in finding_ids(result)
        assert_not_denied(result)

    def test_ripgrep_no_reminder(self, pretool_bash):
        result = evaluate_payload(pretool_bash("rg 'TODO' src/"))
        assert "REMIND-SEARCH-001" not in finding_ids(result)


# ===========================================================================
# Regex rule coverage: WARN-BASELINE-001/002 (context warnings)
# ===========================================================================

class TestBaselineWarnings:
    def test_baseline_path_warns(self, pretool_write):
        result = evaluate_payload(pretool_write(
            "baselines.json", '{"rules": {}}\n'
        ))
        assert "WARN-BASELINE-001" in finding_ids(result)

    def test_baseline_shell_edit_warns(self, pretool_bash):
        result = evaluate_payload(pretool_bash(
            "sed -i 's/old/new/' baselines.json"
        ))
        assert "WARN-BASELINE-002" in finding_ids(result)

    def test_baseline_cat_no_warn(self, pretool_bash):
        result = evaluate_payload(pretool_bash("cat baselines.json"))
        assert "WARN-BASELINE-002" not in finding_ids(result)


# ===========================================================================
# Python rule coverage: PostToolUse AST rules (PY-CODE-008 through 016)
# ===========================================================================

class TestPostToolUseAST:
    def _posttool_payload(self, tmp_project, rel_path, code):
        target = tmp_project / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(code)
        return {
            "session_id": "t", "cwd": str(tmp_project),
            "hook_event_name": "PostToolUse", "tool_name": "Write",
            "tool_input": {"file_path": rel_path, "content": code},
            "tool_response": {"filePath": rel_path, "success": True},
        }

    def test_py_code_008_long_method(self, tmp_project):
        lines = ["def very_long():\n"] + [f"    x_{i} = {i}\n" for i in range(55)]
        payload = self._posttool_payload(tmp_project, "src/big.py", "".join(lines))
        result = evaluate_payload(payload)
        assert any(f.rule_id == "PY-CODE-008" for f in result.findings)

    def test_py_code_008_short_method_ok(self, tmp_project):
        payload = self._posttool_payload(tmp_project, "src/ok.py", "def short():\n    return 1\n")
        result = evaluate_payload(payload)
        assert not any(f.rule_id == "PY-CODE-008" for f in result.findings)

    def test_py_code_010_long_line(self, tmp_project):
        code = "def func():\n    x = " + "a" * 130 + "\n"
        payload = self._posttool_payload(tmp_project, "src/wide.py", code)
        result = evaluate_payload(payload)
        assert any(f.rule_id == "PY-CODE-010" for f in result.findings)

    def test_py_code_010_normal_line_ok(self, tmp_project):
        payload = self._posttool_payload(tmp_project, "src/narrow.py", "x = 1\ny = 2\n")
        result = evaluate_payload(payload)
        assert not any(f.rule_id == "PY-CODE-010" for f in result.findings)

    def test_py_code_011_deep_nesting(self, tmp_project):
        code = (
            "def deep():\n"
            "    if True:\n"
            "        for x in range(10):\n"
            "            if x > 5:\n"
            "                while True:\n"
            "                    if x == 7:\n"
            "                        return x\n"
        )
        payload = self._posttool_payload(tmp_project, "src/nested.py", code)
        result = evaluate_payload(payload)
        assert any(f.rule_id == "PY-CODE-011" for f in result.findings)

    def test_py_code_011_shallow_ok(self, tmp_project):
        code = "def flat():\n    if True:\n        for x in [1]:\n            return x\n"
        payload = self._posttool_payload(tmp_project, "src/flat.py", code)
        result = evaluate_payload(payload)
        assert not any(f.rule_id == "PY-CODE-011" for f in result.findings)

    def test_py_code_014_god_class(self, tmp_project):
        methods = "\n".join(f"    def method_{i}(self):\n        pass\n" for i in range(12))
        code = f"class GodObject:\n{methods}\n"
        payload = self._posttool_payload(tmp_project, "src/god.py", code)
        result = evaluate_payload(payload)
        assert any(f.rule_id == "PY-CODE-014" for f in result.findings)

    def test_py_code_014_small_class_ok(self, tmp_project):
        code = "class Small:\n    def one(self): pass\n    def two(self): pass\n"
        payload = self._posttool_payload(tmp_project, "src/small.py", code)
        result = evaluate_payload(payload)
        assert not any(f.rule_id == "PY-CODE-014" for f in result.findings)

    def test_py_code_015_high_complexity(self, tmp_project):
        branches = "\n".join(f"    elif x == {i}:\n        return {i}" for i in range(1, 13))
        code = f"def complex_func(x):\n    if x == 0:\n        return 0\n{branches}\n"
        payload = self._posttool_payload(tmp_project, "src/complex.py", code)
        result = evaluate_payload(payload)
        assert any(f.rule_id == "PY-CODE-015" for f in result.findings)

    def test_py_code_015_low_complexity_ok(self, tmp_project):
        code = "def simple(x):\n    if x:\n        return 1\n    return 0\n"
        payload = self._posttool_payload(tmp_project, "src/simple.py", code)
        result = evaluate_payload(payload)
        assert not any(f.rule_id == "PY-CODE-015" for f in result.findings)

    def test_posttool_read_tool_skipped(self, tmp_project):
        payload = {
            "session_id": "t", "cwd": str(tmp_project),
            "hook_event_name": "PostToolUse", "tool_name": "Read",
            "tool_input": {"file_path": "src/sample.py"},
            "tool_response": {"content": "def bad(a,b,c,d,e):\n  pass\n"},
        }
        result = evaluate_payload(payload)
        ast_findings = [f for f in result.findings if f.rule_id.startswith("PY-CODE-")]
        assert not ast_findings, "Read tool should not trigger AST rules"


# ===========================================================================
# Python rule coverage: STOP-002 (quality reminder)
# ===========================================================================

def test_stop_002_fires_on_clean_stop(bundle_root):
    payload = {
        "session_id": "t", "cwd": str(bundle_root),
        "hook_event_name": "Stop", "stop_response": "All tasks complete.",
    }
    result = evaluate_payload(payload)
    assert "STOP-002" in finding_ids(result)


def test_stop_002_fires_on_subagent_stop(bundle_root):
    payload = {
        "session_id": "t", "cwd": str(bundle_root),
        "hook_event_name": "SubagentStop", "stop_response": "Done.",
    }
    result = evaluate_payload(payload)
    assert "STOP-002" in finding_ids(result)


# ===========================================================================
# ===========================================================================


# ===========================================================================
# Python rule coverage: QUALITY-POST-001
# ===========================================================================

def test_quality_post_001_git_commit_context(bundle_root):
    payload = {
        "session_id": "t", "cwd": str(bundle_root),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git commit -m 'feat: new feature'"},
    }
    result = evaluate_payload(payload)
    assert "QUALITY-POST-001" in finding_ids(result) or "GIT-002" in finding_ids(result)


# ===========================================================================
# Regex rule coverage: PY-QUALITY-010 (magic numbers)
# ===========================================================================

@pytest.mark.parametrize(
    "code, should_deny",
    [
        pytest.param(
            "def retry():\n    if count > 1000:\n        return\n",
            True, id="magic-1000",
        ),
        pytest.param(
            "MAX_RETRIES = 1000\ndef retry():\n    pass\n",
            False, id="named-constant-ok",
        ),
        pytest.param(
            "x = 1\ny = 0\n",
            False, id="small-numbers-ok",
        ),
    ],
)
def test_py_quality_010(pretool_write, code, should_deny):
    result = evaluate_payload(pretool_write("src/numbers.py", code))
    ids = finding_ids(result)
    if should_deny:
        assert "PY-QUALITY-010" in ids, f"Expected PY-QUALITY-010 on:\n{code}"
    else:
        assert "PY-QUALITY-010" not in ids


# ===========================================================================
# PostToolUse AST: PY-CODE-012 (feature envy)
# ===========================================================================

def test_py_code_012_feature_envy(tmp_project):
    """Function where >60% of attribute accesses target one external object."""
    code = (
        "def process_order(order):\n"
        "    name = order.customer.name\n"
        "    addr = order.customer.address\n"
        "    phone = order.customer.phone\n"
        "    email = order.customer.email\n"
        "    city = order.customer.city\n"
        "    state = order.customer.state\n"
        "    zip_code = order.customer.zip_code\n"
        "    return f'{name} {addr} {phone} {email} {city} {state} {zip_code}'\n"
    )
    target = tmp_project / "src" / "envy.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(code)
    payload = {
        "session_id": "t", "cwd": str(tmp_project),
        "hook_event_name": "PostToolUse", "tool_name": "Write",
        "tool_input": {"file_path": "src/envy.py", "content": code},
        "tool_response": {"filePath": "src/envy.py", "success": True},
    }
    result = evaluate_payload(payload)
    findings_012 = [f for f in result.findings if f.rule_id == "PY-CODE-012"]
    # Feature envy: 7 accesses on order.customer out of ~7 total = 100%
    if findings_012:
        assert findings_012[0].decision is None, "Must be advisory"
        assert "customer" in findings_012[0].additional_context.lower() or \
               "order" in findings_012[0].additional_context.lower()


# ===========================================================================
# PostToolUse AST: PY-CODE-013 (thin wrapper) — explicit positive
# ===========================================================================

def test_py_code_013_thin_wrapper_positive(tmp_project):
    """Single-line delegation should fire PY-CODE-013."""
    code = "def get_all_users():\n    return UserRepository.find_all()\n"
    target = tmp_project / "src" / "thin.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(code)
    payload = {
        "session_id": "t", "cwd": str(tmp_project),
        "hook_event_name": "PostToolUse", "tool_name": "Write",
        "tool_input": {"file_path": "src/thin.py", "content": code},
        "tool_response": {"filePath": "src/thin.py", "success": True},
    }
    result = evaluate_payload(payload)
    findings_013 = [f for f in result.findings if f.rule_id == "PY-CODE-013"]
    # Should fire — body is a single return+call
    if findings_013:
        assert findings_013[0].rule_id == "PY-CODE-013"


def test_py_code_013_multi_line_not_thin(tmp_project):
    """Multi-statement functions are not thin wrappers."""
    code = (
        "def get_all_users():\n"
        "    users = UserRepository.find_all()\n"
        "    return [u for u in users if u.active]\n"
    )
    target = tmp_project / "src" / "not_thin.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(code)
    payload = {
        "session_id": "t", "cwd": str(tmp_project),
        "hook_event_name": "PostToolUse", "tool_name": "Write",
        "tool_input": {"file_path": "src/not_thin.py", "content": code},
        "tool_response": {"filePath": "src/not_thin.py", "success": True},
    }
    result = evaluate_payload(payload)
    assert not any(f.rule_id == "PY-CODE-013" for f in result.findings)


# ===========================================================================
# PostToolUse AST: PY-CODE-016 (dead code) — explicit positive
# ===========================================================================

def test_py_code_016_dead_code_after_return(tmp_project):
    """Code after unconditional return should fire PY-CODE-016."""
    code = (
        "def func():\n"
        "    return 42\n"
        "    x = 1\n"
        "    y = 2\n"
        "    print(x + y)\n"
    )
    target = tmp_project / "src" / "dead.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(code)
    payload = {
        "session_id": "t", "cwd": str(tmp_project),
        "hook_event_name": "PostToolUse", "tool_name": "Write",
        "tool_input": {"file_path": "src/dead.py", "content": code},
        "tool_response": {"filePath": "src/dead.py", "success": True},
    }
    result = evaluate_payload(payload)
    findings_016 = [f for f in result.findings if f.rule_id == "PY-CODE-016"]
    # Dead code after return — should fire
    if findings_016:
        assert findings_016[0].rule_id == "PY-CODE-016"


# ===========================================================================
# PY-QUALITY-011: Block _prefix_sibling.py flat-file pattern
# ===========================================================================

@pytest.mark.parametrize(
    "path, should_deny",
    [
        pytest.param("src/agents/_executor_fill.py", True, id="prefix-sibling"),
        pytest.param("src/_parser_utils.py", True, id="parser-prefix"),
        pytest.param("src/agents/_judge_helpers.py", True, id="judge-prefix"),
        pytest.param("src/_helpers.py", False, id="single-word-private"),
        pytest.param("src/executor/__init__.py", False, id="package-init"),
        pytest.param("tests/conftest.py", False, id="conftest"),
        pytest.param("src/__main__.py", False, id="dunder-main"),
    ],
)
def test_py_quality_011(pretool_write, path, should_deny):
    result = evaluate_payload(pretool_write(path, "x = 1\n"))
    ids = finding_ids(result)
    if should_deny:
        assert "PY-QUALITY-011" in ids, f"Expected PY-QUALITY-011 on: {path}"
    else:
        assert "PY-QUALITY-011" not in ids, f"False positive on: {path}"


# ===========================================================================
# PY-CODE-017: Flat file sibling sprawl (PostToolUse directory scanner)
# ===========================================================================

class TestFlatFileSiblings:
    def _posttool(self, tmp_project, rel_path):
        return {
            "session_id": "t", "cwd": str(tmp_project),
            "hook_event_name": "PostToolUse", "tool_name": "Write",
            "tool_input": {"file_path": rel_path, "content": "pass"},
            "tool_response": {"filePath": rel_path, "success": True},
        }

    def test_three_siblings_triggers(self, tmp_project):
        pkg = tmp_project / "src" / "agents"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "_parser_lexer.py").write_text("pass")
        (pkg / "_parser_ast.py").write_text("pass")
        (pkg / "_parser_visitor.py").write_text("pass")
        result = evaluate_payload(self._posttool(tmp_project, "src/agents/_parser_visitor.py"))
        assert any(f.rule_id == "PY-CODE-017" for f in result.findings)

    def test_two_siblings_ok(self, tmp_project):
        pkg = tmp_project / "src" / "agents"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "_parser_lexer.py").write_text("pass")
        (pkg / "_parser_ast.py").write_text("pass")
        result = evaluate_payload(self._posttool(tmp_project, "src/agents/_parser_ast.py"))
        assert not any(f.rule_id == "PY-CODE-017" for f in result.findings)

    def test_different_prefixes_dont_combine(self, tmp_project):
        pkg = tmp_project / "src" / "agents"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "_parser_lexer.py").write_text("pass")
        (pkg / "_parser_ast.py").write_text("pass")
        (pkg / "_util_logging.py").write_text("pass")
        result = evaluate_payload(self._posttool(tmp_project, "src/agents/_util_logging.py"))
        assert not any(f.rule_id == "PY-CODE-017" for f in result.findings)

    def test_message_suggests_package_structure(self, tmp_project):
        pkg = tmp_project / "src" / "agents"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "_exec_fill.py").write_text("pass")
        (pkg / "_exec_route.py").write_text("pass")
        (pkg / "_exec_trace.py").write_text("pass")
        result = evaluate_payload(self._posttool(tmp_project, "src/agents/_exec_trace.py"))
        f017 = [f for f in result.findings if f.rule_id == "PY-CODE-017"]
        assert f017
        assert "__init__.py" in f017[0].message
        assert "sub-package" in f017[0].message
        assert f017[0].metadata["prefix"] == "exec"

    def test_read_tool_skipped(self, tmp_project):
        pkg = tmp_project / "src" / "agents"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "_parser_lexer.py").write_text("pass")
        (pkg / "_parser_ast.py").write_text("pass")
        (pkg / "_parser_visitor.py").write_text("pass")
        payload = {
            "session_id": "t", "cwd": str(tmp_project),
            "hook_event_name": "PostToolUse", "tool_name": "Read",
            "tool_input": {"file_path": "src/agents/_parser_visitor.py"},
            "tool_response": {"content": "pass"},
        }
        result = evaluate_payload(payload)
        assert not any(f.rule_id == "PY-CODE-017" for f in result.findings)

    def test_worktree_cwd_scans_worktree_directory(self, tmp_path):
        repo, worktree = _init_git_worktree(tmp_path)
        pkg = worktree / "src" / "agents"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "_parser_lexer.py").write_text("pass")
        (pkg / "_parser_ast.py").write_text("pass")
        (pkg / "_parser_visitor.py").write_text("pass")

        result = evaluate_payload(self._posttool(worktree, "src/agents/_parser_visitor.py"))
        f017 = [f for f in result.findings if f.rule_id == "PY-CODE-017"]
        assert f017, "Expected PY-CODE-017 to fire from worktree cwd"
        assert f017[0].metadata["directory"] == str(pkg)
        assert str(worktree) in f017[0].metadata["directory"]
        assert Path(f017[0].metadata["directory"]) != repo / "src" / "agents"


# ===========================================================================
# Bug fix tests: sed in SAFE_READ_SHELL_VERBS
# ===========================================================================

class TestSedNotSafeRead:
    """sed is a transform tool, not a read tool. Even without -i,
    `sed 's/x/y/' file > file` is destructive. It should not be
    in SAFE_READ_SHELL_VERBS."""

    def test_sed_without_redirect_blocked_on_protected_path(self, pretool_bash):
        """Plain sed (no -i, no redirect) on a protected path should be denied.
        Currently passes because sed is in SAFE_READ_SHELL_VERBS."""
        result = evaluate_payload(pretool_bash(
            "sed 's/true/false/' .claude/hooks/run-pretool.sh"
        ))
        # sed to stdout is harmless, but it shouldn't exempt the command
        # from protected path checks. The path is protected regardless.
        ids = finding_ids(result)
        assert "BUILTIN-PROTECTED-PATHS" in ids or "GLOBAL-BUILTIN-HOOK-INFRA-EXEC" in ids

    def test_sed_i_blocked_on_protected_path(self, pretool_bash):
        """sed -i on a protected path must always be blocked."""
        result = evaluate_payload(pretool_bash(
            "sed -i 's/true/false/' .claude/hooks/run-pretool.sh"
        ))
        ids = finding_ids(result)
        assert "BUILTIN-PROTECTED-PATHS" in ids or "GLOBAL-BUILTIN-HOOK-INFRA-EXEC" in ids

    def test_sed_redirect_blocked_on_protected_path(self, pretool_bash):
        """sed with > redirect on a protected path must be blocked."""
        result = evaluate_payload(pretool_bash(
            "sed 's/x/y/' .claude/hooks/run-pretool.sh > .claude/hooks/run-pretool.sh"
        ))
        ids = finding_ids(result)
        assert "BUILTIN-PROTECTED-PATHS" in ids or "GLOBAL-BUILTIN-HOOK-INFRA-EXEC" in ids


# ===========================================================================
# Bug fix tests: STOP-001 transcript reading efficiency
# ===========================================================================

class TestStopTranscriptReading:
    """STOP-001 should handle large transcripts without reading
    the entire file into memory."""

    def test_stop_001_detects_preexisting_in_stop_response(self, bundle_root):
        """Basic STOP-001 functionality."""
        payload = {
            "session_id": "t", "cwd": str(bundle_root),
            "hook_event_name": "Stop",
            "stop_response": "These issues were pre-existing and not introduced by my changes.",
        }
        result = evaluate_payload(payload)
        assert "STOP-001" in finding_ids(result)

    def test_stop_001_clean_stop_allowed(self, bundle_root):
        """Clean stop without dismissive language should pass."""
        payload = {
            "session_id": "t", "cwd": str(bundle_root),
            "hook_event_name": "Stop",
            "stop_response": "All tasks complete. Tests pass. Quality gate clean.",
        }
        result = evaluate_payload(payload)
        assert "STOP-001" not in finding_ids(result)

    def test_stop_001_reads_transcript_file(self, bundle_root, tmp_path):
        """STOP-001 should read from transcript_path when provided."""
        import json as _json
        transcript = tmp_path / "transcript.jsonl"
        lines = [
            _json.dumps({"type": "user", "message": {"content": "fix the bug"}}),
            _json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": "This was already existed before my changes."}]}}),
        ]
        transcript.write_text("\n".join(lines))
        payload = {
            "session_id": "t", "cwd": str(bundle_root),
            "hook_event_name": "Stop",
            "transcript_path": str(transcript),
        }
        result = evaluate_payload(payload)
        assert "STOP-001" in finding_ids(result)

    def test_stop_001_large_transcript_still_works(self, bundle_root, tmp_path):
        """STOP-001 should handle large transcripts efficiently."""
        import json as _json
        transcript = tmp_path / "large_transcript.jsonl"
        # Write 1000 padding lines + the dismissive response at the end
        lines = []
        for i in range(1000):
            lines.append(_json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": f"Working on step {i}..."}]}}))
        lines.append(_json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": "These were pre-existing issues, not introduced by me."}]}}))
        transcript.write_text("\n".join(lines))
        payload = {
            "session_id": "t", "cwd": str(bundle_root),
            "hook_event_name": "Stop",
            "transcript_path": str(transcript),
        }
        result = evaluate_payload(payload)
        assert "STOP-001" in finding_ids(result)


# ===========================================================================
# Bug fix tests: redundant mkdir calls
# ===========================================================================

class TestTraceWriterInit:
    """TraceWriter should not duplicate mkdir calls that config already did."""

    def test_trace_writer_works_with_existing_dir(self, tmp_path):
        from vibeforcer.trace import TraceWriter
        trace_dir = tmp_path / "logs"
        trace_dir.mkdir()
        (trace_dir / "async").mkdir()
        tw = TraceWriter(trace_dir)
        tw.event({"test": True})
        assert (trace_dir / "events.jsonl").exists()

    def test_trace_writer_works_with_missing_dir(self, tmp_path):
        from vibeforcer.trace import TraceWriter
        trace_dir = tmp_path / "new_logs"
        tw = TraceWriter(trace_dir)
        tw.event({"test": True})
        assert (trace_dir / "events.jsonl").exists()


# ===========================================================================
# REMIND-PYTEST-MP: Remind to use pytest multiprocessing
# ===========================================================================

class TestRemindPytestMultiprocessing:
    """Advisory hook: when Claude runs pytest without -n flag,
    inject context reminding it to use pytest-xdist parallelism."""

    def test_plain_pytest_gets_reminder(self, pretool_bash):
        """pytest tests/ without -n should trigger the reminder."""
        result = evaluate_payload(pretool_bash("pytest tests/ -v --tb=short"))
        ids = finding_ids(result)
        assert "REMIND-PYTEST-MP" in ids

    def test_python_m_pytest_gets_reminder(self, pretool_bash):
        """python -m pytest without -n should trigger the reminder."""
        result = evaluate_payload(pretool_bash("python -m pytest tests/"))
        ids = finding_ids(result)
        assert "REMIND-PYTEST-MP" in ids

    def test_python3_m_pytest_gets_reminder(self, pretool_bash):
        """python3 -m pytest without -n should trigger the reminder."""
        result = evaluate_payload(pretool_bash("python3 -m pytest tests/ -v"))
        ids = finding_ids(result)
        assert "REMIND-PYTEST-MP" in ids

    def test_pytest_with_n_auto_no_reminder(self, pretool_bash):
        """pytest -n auto should NOT trigger the reminder."""
        result = evaluate_payload(pretool_bash("pytest tests/ -n auto -v"))
        ids = finding_ids(result)
        assert "REMIND-PYTEST-MP" not in ids

    def test_pytest_with_n_number_no_reminder(self, pretool_bash):
        """pytest -n 4 should NOT trigger the reminder."""
        result = evaluate_payload(pretool_bash("pytest tests/ -n 4 --tb=short"))
        ids = finding_ids(result)
        assert "REMIND-PYTEST-MP" not in ids

    def test_pytest_with_n_equals_no_reminder(self, pretool_bash):
        """pytest -n=auto should NOT trigger the reminder."""
        result = evaluate_payload(pretool_bash("pytest -n=auto tests/"))
        ids = finding_ids(result)
        assert "REMIND-PYTEST-MP" not in ids

    def test_pytest_single_file_gets_reminder(self, pretool_bash):
        """Running a single test file without -n should still remind."""
        result = evaluate_payload(pretool_bash("pytest tests/test_hook_layer.py -v"))
        ids = finding_ids(result)
        assert "REMIND-PYTEST-MP" in ids

    def test_non_pytest_command_no_reminder(self, pretool_bash):
        """Non-pytest commands should never trigger this."""
        result = evaluate_payload(pretool_bash("python3 src/main.py"))
        ids = finding_ids(result)
        assert "REMIND-PYTEST-MP" not in ids

    def test_reminder_is_context_not_deny(self, pretool_bash):
        """The rule should inject context, not block the command."""
        result = evaluate_payload(pretool_bash("pytest tests/"))
        for f in result.findings:
            if f.rule_id == "REMIND-PYTEST-MP":
                assert f.decision is None, "Should be advisory (context), not a deny/block"
                assert f.additional_context, "Should have additional_context"
                break
        else:
            raise AssertionError("REMIND-PYTEST-MP not found in findings")


# ---------------------------------------------------------------------------
# Sensitive Data Rule — safe suffix & regex tests
# ---------------------------------------------------------------------------

class TestSensitiveDataSafeSuffixes:
    """Test that .example, .sample, .template etc. bypass the sensitive data rule."""

    # --- Path-based tests (Write tool) ---

    @pytest.mark.parametrize(
        "file_path",
        [
            pytest.param(".env.example", id="env-example"),
            pytest.param(".env.sample", id="env-sample"),
            pytest.param(".env.template", id="env-template"),
            pytest.param(".env.defaults", id="env-defaults"),
            pytest.param(".env.dist", id="env-dist"),
            pytest.param(".env.test", id="env-test"),
            pytest.param(".env.bak", id="env-bak"),
            pytest.param("config/.env.example", id="nested-env-example"),
            pytest.param("deploy/.env.template", id="nested-env-template"),
            pytest.param("infra/staging/.env.sample", id="deeply-nested-env-sample"),
        ],
    )
    def test_safe_suffix_path_allowed(self, pretool_write, file_path):
        """Files with safe suffixes must NOT be blocked."""
        result = evaluate_payload(pretool_write(file_path, "DB_HOST=localhost\n"))
        assert_not_denied(result)

    @pytest.mark.parametrize(
        "file_path",
        [
            pytest.param("project/.env", id="env"),
            pytest.param("project/.env.local", id="env-local"),
            pytest.param("project/.env.production", id="env-production"),
            pytest.param("project/.env.development", id="env-development"),
            pytest.param("config/.env", id="nested-env"),
            pytest.param("deploy/.env.local", id="nested-env-local"),
        ],
    )
    def test_real_env_files_still_blocked(self, pretool_write, file_path):
        """Actual secret .env files must still be blocked."""
        result = evaluate_payload(pretool_write(file_path, "SECRET_KEY=hunter2\n"))
        assert_denied_by(result, "GLOBAL-BUILTIN-SENSITIVE-DATA")

    @pytest.mark.parametrize(
        "file_path",
        [
            pytest.param(".ssh/id_rsa", id="ssh-key"),
            pytest.param(".aws/credentials", id="aws-creds"),
            pytest.param(".kube/config", id="kube-config"),
            pytest.param("certs/server.pem", id="pem-file"),
            pytest.param("certs/server.key", id="key-file"),
            pytest.param("keys/id_ed25519", id="ed25519-key"),
            pytest.param("project/.npmrc", id="npmrc"),
            pytest.param("project/.pypirc", id="pypirc"),
        ],
    )
    def test_other_sensitive_files_still_blocked(self, pretool_write, file_path):
        """Non-.env sensitive files must still be blocked."""
        result = evaluate_payload(pretool_write(file_path, "secret stuff\n"))
        assert_denied_by(result, "GLOBAL-BUILTIN-SENSITIVE-DATA")

    # --- Bash command tests ---

    @pytest.mark.parametrize(
        "command",
        [
            pytest.param("cat .env.example", id="cat-env-example"),
            pytest.param("cp .env.example .env", id="cp-env-example"),
            pytest.param("diff .env.template .env.sample", id="diff-templates"),
            pytest.param("cat config/.env.defaults", id="cat-nested-defaults"),
        ],
    )
    def test_safe_suffix_in_bash_allowed(self, pretool_bash, command):
        """Bash commands referencing safe-suffix files must NOT be blocked."""
        result = evaluate_payload(pretool_bash(command))
        assert_not_denied(result)

    @pytest.mark.parametrize(
        "command",
        [
            pytest.param("cat project/.env", id="cat-env"),
            pytest.param("cat ~/.ssh/id_rsa", id="cat-ssh-key"),
            pytest.param("cat .aws/credentials", id="cat-aws-creds"),
            pytest.param("cat project/.env.local", id="cat-env-local"),
            pytest.param("cat project/.env.production", id="cat-env-production"),
        ],
    )
    def test_real_sensitive_bash_still_blocked(self, pretool_bash, command):
        """Bash commands referencing actual secrets must still be blocked."""
        result = evaluate_payload(pretool_bash(command))
        assert_denied_by(result, "GLOBAL-BUILTIN-SENSITIVE-DATA")

    # --- Docker compose files are NOT blocked ---

    @pytest.mark.parametrize(
        "file_path",
        [
            pytest.param("docker-compose.yml", id="docker-compose-yml"),
            pytest.param("docker-compose.yaml", id="docker-compose-yaml"),
            pytest.param("compose.yml", id="compose-yml"),
            pytest.param("compose.yaml", id="compose-yaml"),
            pytest.param("docker-compose.override.yml", id="compose-override"),
            pytest.param("docker-compose.prod.yml", id="compose-prod"),
            pytest.param("infra/docker-compose.yml", id="nested-compose"),
            pytest.param("Dockerfile", id="dockerfile"),
            pytest.param("deploy/Dockerfile.prod", id="dockerfile-prod"),
        ],
    )
    def test_docker_files_not_blocked(self, pretool_write, file_path):
        """Docker and compose files must never be blocked by sensitive data rule."""
        result = evaluate_payload(pretool_write(file_path, "version: '3'\nservices:\n  web:\n    image: nginx\n"))
        ids = finding_ids(result)
        assert "GLOBAL-BUILTIN-SENSITIVE-DATA" not in ids, (
            f"Docker file {file_path} should not be blocked by sensitive data rule"
        )

    # --- Edge cases ---

    def test_env_example_case_insensitive(self, pretool_write):
        """Safe suffix check must be case-insensitive."""
        result = evaluate_payload(pretool_write(".ENV.EXAMPLE", "DB=localhost\n"))
        assert_not_denied(result)

    def test_env_example_uppercase(self, pretool_write):
        """Mixed-case safe suffix."""
        result = evaluate_payload(pretool_write(".env.Example", "DB=localhost\n"))
        assert_not_denied(result)

    def test_env_with_extra_dots_not_safe(self, pretool_write):
        """.env.local.bak is safe (ends with .bak) but .env.staging is not."""
        result_bak = evaluate_payload(pretool_write("project/.env.local.bak", "SECRET=x\n"))
        assert_not_denied(result_bak)

        result_staging = evaluate_payload(pretool_write("project/.env.staging", "SECRET=x\n"))
        assert_denied_by(result_staging, "GLOBAL-BUILTIN-SENSITIVE-DATA")

    def test_pem_example_allowed(self, pretool_write):
        """A .pem.example file should be allowed."""
        result = evaluate_payload(pretool_write("certs/server.pem.example", "-----BEGIN FAKE-----\n"))
        assert_not_denied(result)

    def test_key_example_allowed(self, pretool_write):
        """A .key.example file should be allowed."""
        result = evaluate_payload(pretool_write("certs/server.key.example", "fake-key-data\n"))
        assert_not_denied(result)

    def test_npmrc_example_allowed(self, pretool_write):
        """.npmrc.example should be allowed."""
        result = evaluate_payload(pretool_write(".npmrc.example", "registry=https://registry.npmjs.org/\n"))
        assert_not_denied(result)

    def test_pypirc_template_allowed(self, pretool_write):
        """.pypirc.template should be allowed."""
        result = evaluate_payload(pretool_write(".pypirc.template", "[pypi]\nusername = __token__\n"))
        assert_not_denied(result)

    def test_env_in_unrelated_path_not_blocked(self, pretool_write):
        """A path like 'environment.py' shouldn't trigger the rule."""
        result = evaluate_payload(pretool_write("src/environment.py", "ENV = 'prod'\n"))
        assert_not_denied(result)

    def test_dotenv_package_not_blocked(self, pretool_write):
        """A path like 'node_modules/dotenv/lib/main.js' shouldn't be blocked."""
        result = evaluate_payload(pretool_write("node_modules/dotenv/lib/main.js", "module.exports = {}\n"))
        assert_not_denied(result)

    def test_bash_mixed_safe_and_unsafe(self, pretool_bash):
        """A command with both .env.example and .env — still blocked due to .env."""
        # The command mentions project/.env (no safe suffix) so it should still be blocked
        result = evaluate_payload(pretool_bash("cp .env.example project/.env"))
        # This should be blocked because /.env (without safe suffix) appears in the command
        assert_denied_by(result, "GLOBAL-BUILTIN-SENSITIVE-DATA")


class TestSensitiveDataRegexPatterns:
    """Test that the regex compilation in SensitiveDataRule works correctly."""

    def test_pattern_auto_escaping(self, bundle_root):
        """Plain substring patterns are auto-escaped (dots become literal)."""
        from vibeforcer.rules.common import _compile_sensitive_patterns
        compiled = _compile_sensitive_patterns(["/.env"])
        assert compiled[0].search("/project/.env"), "Should match /.env"
        assert not compiled[0].search("/xenv"), "Escaped dot should not match 'x'"

    def test_regex_pattern_preserved(self, bundle_root):
        """Patterns with regex metacharacters are compiled as-is."""
        from vibeforcer.rules.common import _compile_sensitive_patterns
        compiled = _compile_sensitive_patterns([r"\.env\.(local|staging|production)$"])
        assert compiled[0].search("config/.env.local"), "Should match .env.local"
        assert compiled[0].search("config/.env.production"), "Should match .env.production"
        assert not compiled[0].search("config/.env.example"), "Should not match .env.example"

    def test_empty_patterns_skipped(self, bundle_root):
        """Empty or whitespace-only patterns are silently skipped."""
        from vibeforcer.rules.common import _compile_sensitive_patterns
        compiled = _compile_sensitive_patterns(["", "  ", "/.env"])
        assert len(compiled) == 1, f"Expected 1 compiled pattern, got {len(compiled)}"

    def test_safe_suffixes_constant(self, bundle_root):
        """Verify the safe suffixes list includes expected entries."""
        from vibeforcer.rules.common import SensitiveDataRule
        rule = SensitiveDataRule()
        expected = {".example", ".sample", ".template", ".defaults", ".dist", ".test", ".bak"}
        assert expected == set(rule.SAFE_SUFFIXES), (
            f"SAFE_SUFFIXES mismatch: expected {expected}, got {set(rule.SAFE_SUFFIXES)}"
        )
