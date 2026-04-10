"""Tests for regex rule target types beyond 'content'.

Covers: command, path, and prompt targets to verify RegexRule routing.
"""

from __future__ import annotations

from vibeforcer.engine import evaluate_payload
from tests.support import BUNDLE_ROOT, finding_ids


class TestCommandTarget:
    """Regex rules with target=command match against bash_command."""

    @staticmethod
    def _bash_payload(command: str) -> dict[str, object]:
        return {
            "session_id": "t",
            "cwd": str(BUNDLE_ROOT),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }

    def test_shell_set_plus_e_denied(self) -> None:
        result = evaluate_payload(self._bash_payload("set +e && make build"))
        assert "SHELL-001" in finding_ids(result), "set +e must trigger SHELL-001"

    def test_py_shell_edit_denied(self) -> None:
        result = evaluate_payload(self._bash_payload("sed -i 's/foo/bar/' src/main.py"))
        assert "PY-SHELL-001" in finding_ids(result), (
            "sed -i on .py must trigger PY-SHELL-001"
        )

    def test_git_commit_gets_context(self) -> None:
        result = evaluate_payload(self._bash_payload("git commit -m 'fix: thing'"))
        assert "GIT-002" in finding_ids(result), (
            "git commit must trigger GIT-002 context"
        )

    def test_safe_command_no_shell_rule(self) -> None:
        result = evaluate_payload(self._bash_payload("npm test"))
        assert "SHELL-001" not in finding_ids(result), (
            "npm test must not trigger SHELL-001"
        )


class TestPathTarget:
    """Regex rules with target=path match against candidate_paths."""

    @staticmethod
    def _write_payload(file_path: str) -> dict[str, object]:
        return {
            "session_id": "t",
            "cwd": str(BUNDLE_ROOT),
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": file_path, "content": "x = 1\n"},
        }

    def test_linter_config_path_denied(self) -> None:
        result = evaluate_payload(self._write_payload(".pylintrc"))
        assert "PY-LINTER-001" in finding_ids(result), (
            ".pylintrc must trigger PY-LINTER-001"
        )

    def test_quality_test_path_denied(self) -> None:
        result = evaluate_payload(self._write_payload("tests/quality/test_new.py"))
        ids = finding_ids(result)
        matched = "QA-PATH-003" in ids or "BUILTIN-PROTECTED-PATHS" in ids
        assert matched, "tests/quality/ path must be flagged"

    def test_fe_linter_config_denied(self) -> None:
        result = evaluate_payload(self._write_payload(".eslintrc.json"))
        ids = finding_ids(result)
        matched = "FE-LINTER-001" in ids or "BUILTIN-PROTECTED-PATHS" in ids
        assert matched, ".eslintrc.json must be flagged"

    def test_normal_path_not_flagged(self) -> None:
        result = evaluate_payload(self._write_payload("src/utils/helpers.py"))
        path_rules = {"PY-LINTER-001", "FE-LINTER-001", "QA-PATH-001", "QA-PATH-003"}
        assert not (finding_ids(result) & path_rules), (
            "normal path must not trigger path rules"
        )


class TestBaselineWarnPath:
    """WARN-BASELINE-001 fires on baselines.json path access."""

    def test_baselines_json_flagged(self) -> None:
        payload = {
            "session_id": "t",
            "cwd": str(BUNDLE_ROOT),
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {
                "file_path": "baselines.json",
                "content": '{"rules": {}}',
            },
        }
        result = evaluate_payload(payload)
        ids = finding_ids(result)
        matched = "WARN-BASELINE-001" in ids or "BASELINE-001" in ids
        assert matched, "baselines.json must trigger baseline warning"
