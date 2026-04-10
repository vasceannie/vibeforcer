"""Tests for ERRORS-BASH-001, ERRORS-FAIL-001, and CONFIG-001 rules."""

from __future__ import annotations

from vibeforcer.engine import evaluate_payload
from tests.support import BUNDLE_ROOT, finding_ids


class TestBashOutputError:
    """ERRORS-BASH-001: detect errors in exit-0 bash output."""

    @staticmethod
    def _post_bash(
        command: str,
        stdout: str,
        stderr: str = "",
    ) -> dict[str, object]:
        return {
            "session_id": "t",
            "cwd": str(BUNDLE_ROOT),
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {
                "stdout": stdout,
                "stderr": stderr,
                "exitCode": 0,
            },
        }

    def test_traceback_detected(self) -> None:
        payload = self._post_bash(
            "python run.py",
            "Traceback (most recent call last):\n  File 'run.py'\nValueError: bad\nValueError: also bad",
        )
        result = evaluate_payload(payload)
        assert "ERRORS-BASH-001" in finding_ids(result), (
            "traceback in output must trigger error rule"
        )

    def test_test_failure_detected(self) -> None:
        payload = self._post_bash(
            "pytest tests/",
            "FAILED tests/test_auth.py::test_login - AssertionError\n1 failed, 5 passed",
        )
        result = evaluate_payload(payload)
        assert "ERRORS-BASH-001" in finding_ids(result), (
            "test failures must trigger error rule"
        )

    def test_read_only_command_skipped(self) -> None:
        payload = self._post_bash(
            "grep -n error src/main.py",
            "src/main.py:10: raise ValueError('error')",
        )
        result = evaluate_payload(payload)
        assert "ERRORS-BASH-001" not in finding_ids(result), (
            "read-only commands must not trigger"
        )

    def test_clean_output_no_trigger(self) -> None:
        payload = self._post_bash("npm build", "Build completed successfully.")
        result = evaluate_payload(payload)
        assert "ERRORS-BASH-001" not in finding_ids(result), (
            "clean output must not trigger"
        )


class TestBashFailureReinforcement:
    """ERRORS-FAIL-001: reinforce that non-zero exits must be resolved."""

    @staticmethod
    def _failure_bash(command: str) -> dict[str, object]:
        return {
            "session_id": "t",
            "cwd": str(BUNDLE_ROOT),
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": "", "stderr": "error", "exitCode": 1},
        }

    def test_build_failure_triggers(self) -> None:
        result = evaluate_payload(self._failure_bash("make build"))
        assert "ERRORS-FAIL-001" in finding_ids(result), (
            "non-zero exit on build must trigger"
        )

    def test_grep_failure_skipped(self) -> None:
        result = evaluate_payload(self._failure_bash("grep pattern file.txt"))
        assert "ERRORS-FAIL-001" not in finding_ids(result), "grep exit-1 is benign"

    def test_diff_failure_skipped(self) -> None:
        result = evaluate_payload(self._failure_bash("diff a.txt b.txt"))
        assert "ERRORS-FAIL-001" not in finding_ids(result), "diff exit-1 is benign"

    def test_cat_failure_skipped(self) -> None:
        result = evaluate_payload(self._failure_bash("cat nonexistent.txt"))
        assert "ERRORS-FAIL-001" not in finding_ids(result), (
            "read-only failures are skipped"
        )


class TestConfigChangeGuard:
    """CONFIG-001: block config changes that weaken security."""

    @staticmethod
    def _config_change(
        source: str,
        changes: dict[str, object],
    ) -> dict[str, object]:
        return {
            "session_id": "t",
            "cwd": str(BUNDLE_ROOT),
            "hook_event_name": "ConfigChange",
            "source": source,
            "changes": changes,
        }

    def test_disable_all_hooks_blocked(self) -> None:
        payload = self._config_change("project_settings", {"disableAllHooks": True})
        result = evaluate_payload(payload)
        assert result.output is not None, "disableAllHooks must produce output"
        assert result.output.get("decision") == "block", (
            "disableAllHooks must be blocked"
        )

    def test_hook_modification_blocked(self) -> None:
        payload = self._config_change("local_settings", {"hooks": {"pre_tool_use": []}})
        result = evaluate_payload(payload)
        assert result.output is not None, "hook modification must produce output"
        assert result.output.get("decision") == "block", (
            "hook modification must be blocked"
        )

    def test_non_security_change_allowed(self) -> None:
        payload = self._config_change("project_settings", {"theme": "dark"})
        result = evaluate_payload(payload)
        if result.output is not None:
            assert result.output.get("decision") != "block", (
                "non-security changes must not be blocked"
            )

    def test_unknown_source_allowed(self) -> None:
        payload = self._config_change("policy_settings", {"disableAllHooks": True})
        result = evaluate_payload(payload)
        if result.output is not None:
            assert result.output.get("decision") != "block", (
                "policy source must not be guarded"
            )
