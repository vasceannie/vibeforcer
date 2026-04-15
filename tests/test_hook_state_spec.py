from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from time import time

import pytest

from vibeforcer.adapters import get_adapter
from vibeforcer.engine import evaluate_payload
from vibeforcer.models import RuleFinding, Severity
from vibeforcer.state import HookStateStore
from tests.support import BUNDLE_ROOT, assert_denied_by, assert_not_denied, finding_ids

_RESOURCES = BUNDLE_ROOT / "src" / "vibeforcer" / "resources"


def _config_with_enabled_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *rule_ids: str
) -> None:
    raw = json.loads((_RESOURCES / "defaults.json").read_text(encoding="utf-8"))
    enabled = dict(raw.get("enabled_rules", {}))
    for rule_id in rule_ids:
        enabled[rule_id] = True
    raw["enabled_rules"] = enabled
    config_path = tmp_path / "spec-config.json"
    config_path.write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setenv("VIBEFORCER_CONFIG", str(config_path))


def _read_payload(
    file_path: str,
    *,
    cwd: str,
    session_id: str = "spec-session",
    offset: int | None = None,
    limit: int | None = None,
) -> dict[str, object]:
    tool_input: dict[str, object] = {"file_path": file_path}
    if offset is not None:
        tool_input["offset"] = offset
    if limit is not None:
        tool_input["limit"] = limit
    return {
        "session_id": session_id,
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": tool_input,
    }


def _bash_payload(
    command: str,
    *,
    cwd: str,
    session_id: str = "spec-session",
) -> dict[str, object]:
    return {
        "session_id": session_id,
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }


def _grep_payload(
    query: str,
    *,
    cwd: str,
    session_id: str = "spec-session",
) -> dict[str, object]:
    return {
        "session_id": session_id,
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Grep",
        "tool_input": {"query": query, "path": "src"},
    }


def _posttool_payload(
    *,
    cwd: Path,
    rel_path: str,
    code: str,
    session_id: str = "spec-session",
) -> dict[str, object]:
    target = cwd / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(code, encoding="utf-8")
    return {
        "session_id": session_id,
        "cwd": str(cwd),
        "hook_event_name": "PostToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": rel_path, "content": code},
        "tool_response": {"filePath": rel_path, "success": True},
    }


def _python_subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    src_path = str(BUNDLE_ROOT / "src")
    current_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        src_path if not current_pythonpath else src_path + os.pathsep + current_pythonpath
    )
    return env


def _run_payload_in_subprocess(
    payload: dict[str, object],
    *,
    platform: str = "claude",
) -> dict[str, object]:
    """Run one hook evaluation in a fresh Python process.

    Vibeforcer hooks are invoked as subprocesses in production, so this helper keeps
    the spec honest about persistence requirements.
    """

    script = """
import json
import sys
from vibeforcer.engine import evaluate_payload

payload = json.loads(sys.argv[1])
platform = sys.argv[2]
result = evaluate_payload(payload, platform=platform)
print(json.dumps({
    "finding_ids": [f.rule_id for f in result.findings],
    "findings": [
        {
            "rule_id": f.rule_id,
            "decision": f.decision,
            "severity": f.severity.name,
            "message": f.message,
            "metadata": f.metadata,
        }
        for f in result.findings
    ],
    "output": result.output,
}, default=str))
""".strip()
    completed = subprocess.run(
        [sys.executable, "-c", script, json.dumps(payload), platform],
        capture_output=True,
        text=True,
        check=True,
        env=_python_subprocess_env(),
    )
    return json.loads(completed.stdout)


def _start_full_read_record_subprocess(
    trace_dir: Path, session_id: str, file_path: Path
) -> subprocess.Popen[str]:
    script = """
import sys
from pathlib import Path
from vibeforcer.state import HookStateStore

store = HookStateStore(Path(sys.argv[1]))
store.record_full_read(sys.argv[2], sys.argv[3])
""".strip()
    return subprocess.Popen(
        [sys.executable, "-c", script, str(trace_dir), session_id, str(file_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_python_subprocess_env(),
    )


def _finding(result_rule_id: str, findings: list[RuleFinding]) -> RuleFinding | None:
    return next((item for item in findings if item.rule_id == result_rule_id), None)


class TestFullReadCurrentGuards:
    def test_partial_python_read_is_denied_when_rule_enabled(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _config_with_enabled_rules(tmp_path, monkeypatch, "BUILTIN-ENFORCE-FULL-READ")
        target = tmp_path / "sample.py"
        target.write_text("print('hi')\n", encoding="utf-8")

        result = evaluate_payload(
            _read_payload(str(target), cwd=str(tmp_path), offset=1, limit=1)
        )

        assert_denied_by(result, "BUILTIN-ENFORCE-FULL-READ", "full first")

    def test_partial_json_read_is_allowed_when_rule_enabled(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _config_with_enabled_rules(tmp_path, monkeypatch, "BUILTIN-ENFORCE-FULL-READ")
        target = tmp_path / "data.json"
        target.write_text('{"ok": true}\n', encoding="utf-8")

        result = evaluate_payload(
            _read_payload(str(target), cwd=str(tmp_path), offset=1, limit=1)
        )

        assert_not_denied(result)

    def test_large_python_read_is_exempt_when_rule_enabled(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _config_with_enabled_rules(tmp_path, monkeypatch, "BUILTIN-ENFORCE-FULL-READ")
        target = tmp_path / "large.py"
        target.write_text("x = 1\n" * 10000, encoding="utf-8")

        result = evaluate_payload(
            _read_payload(str(target), cwd=str(tmp_path), offset=1, limit=20)
        )

        assert_not_denied(result)

    def test_other_session_still_denied_without_stateful_unlock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _config_with_enabled_rules(tmp_path, monkeypatch, "BUILTIN-ENFORCE-FULL-READ")
        target = tmp_path / "module.py"
        target.write_text("a = 1\nb = 2\n", encoding="utf-8")

        _ = evaluate_payload(
            _read_payload(str(target), cwd=str(tmp_path), session_id="session-a")
        )
        result = evaluate_payload(
            _read_payload(
                str(target),
                cwd=str(tmp_path),
                session_id="session-b",
                offset=1,
                limit=1,
            )
        )

        assert_denied_by(result, "BUILTIN-ENFORCE-FULL-READ")

    def test_other_file_still_denied_without_stateful_unlock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _config_with_enabled_rules(tmp_path, monkeypatch, "BUILTIN-ENFORCE-FULL-READ")
        file_a = tmp_path / "a.py"
        file_b = tmp_path / "b.py"
        file_a.write_text("a = 1\n", encoding="utf-8")
        file_b.write_text("b = 2\n", encoding="utf-8")

        _ = evaluate_payload(
            _read_payload(str(file_a), cwd=str(tmp_path), session_id="session-a")
        )
        result = evaluate_payload(
            _read_payload(
                str(file_b),
                cwd=str(tmp_path),
                session_id="session-a",
                offset=1,
                limit=1,
            )
        )

        assert_denied_by(result, "BUILTIN-ENFORCE-FULL-READ")


class TestFullReadStatefulSpec:
    def test_partial_jsonl_read_is_allowed_when_rule_enabled(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _config_with_enabled_rules(tmp_path, monkeypatch, "BUILTIN-ENFORCE-FULL-READ")
        target = tmp_path / "events.jsonl"
        target.write_text('{"event": 1}\n{"event": 2}\n', encoding="utf-8")

        result = evaluate_payload(
            _read_payload(str(target), cwd=str(tmp_path), offset=2, limit=1)
        )

        assert_not_denied(result)

    def test_full_read_unlocks_follow_up_partial_read_in_same_session(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _config_with_enabled_rules(tmp_path, monkeypatch, "BUILTIN-ENFORCE-FULL-READ")
        target = tmp_path / "module.py"
        target.write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
        session_id = "same-session"

        first = evaluate_payload(
            _read_payload(str(target), cwd=str(tmp_path), session_id=session_id)
        )
        second = evaluate_payload(
            _read_payload(
                str(target),
                cwd=str(tmp_path),
                session_id=session_id,
                offset=2,
                limit=1,
            )
        )

        assert first.output is None or "deny" not in json.dumps(first.output)
        assert_not_denied(second)

    def test_absolute_and_relative_paths_share_unlock_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _config_with_enabled_rules(tmp_path, monkeypatch, "BUILTIN-ENFORCE-FULL-READ")
        target = tmp_path / "pkg" / "module.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("a = 1\nb = 2\n", encoding="utf-8")
        session_id = "same-session"

        _ = evaluate_payload(
            _read_payload(str(target), cwd=str(tmp_path), session_id=session_id)
        )
        result = evaluate_payload(
            _read_payload(
                "pkg/module.py",
                cwd=str(tmp_path),
                session_id=session_id,
                offset=1,
                limit=1,
            )
        )

        assert_not_denied(result)

    def test_same_session_unlock_must_survive_subprocess_boundary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _config_with_enabled_rules(tmp_path, monkeypatch, "BUILTIN-ENFORCE-FULL-READ")
        target = tmp_path / "module.py"
        target.write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
        session_id = "same-session"

        first = _run_payload_in_subprocess(
            _read_payload(str(target), cwd=str(tmp_path), session_id=session_id)
        )
        second = _run_payload_in_subprocess(
            _read_payload(
                str(target),
                cwd=str(tmp_path),
                session_id=session_id,
                offset=2,
                limit=1,
            )
        )

        assert "BUILTIN-ENFORCE-FULL-READ" not in first["finding_ids"]
        assert "BUILTIN-ENFORCE-FULL-READ" not in second["finding_ids"]

    def test_symlinked_paths_share_unlock_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _config_with_enabled_rules(tmp_path, monkeypatch, "BUILTIN-ENFORCE-FULL-READ")
        target = tmp_path / "module.py"
        link_path = tmp_path / "alias.py"
        target.write_text("a = 1\nb = 2\n", encoding="utf-8")
        link_path.symlink_to(target)
        session_id = "same-session"

        _ = evaluate_payload(
            _read_payload(str(target), cwd=str(tmp_path), session_id=session_id)
        )
        result = evaluate_payload(
            _read_payload(
                str(link_path),
                cwd=str(tmp_path),
                session_id=session_id,
                offset=1,
                limit=1,
            )
        )

        assert_not_denied(result)

    def test_missing_files_do_not_create_unlock_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _config_with_enabled_rules(tmp_path, monkeypatch, "BUILTIN-ENFORCE-FULL-READ")
        missing = tmp_path / "missing.py"
        session_id = "same-session"

        _ = evaluate_payload(
            _read_payload(str(missing), cwd=str(tmp_path), session_id=session_id)
        )
        result = evaluate_payload(
            _read_payload(
                str(missing),
                cwd=str(tmp_path),
                session_id=session_id,
                offset=1,
                limit=1,
            )
        )

        assert_denied_by(result, "BUILTIN-ENFORCE-FULL-READ")


class TestHookStateStore:
    def test_ttl_expiry_filters_stale_full_reads(self, tmp_path: Path) -> None:
        store = HookStateStore(tmp_path)
        key = store._full_read_key("session-a", str(tmp_path / "module.py"))
        store._save_state({"full_reads": {key: int(time()) - store._TTL_SECONDS - 5}})

        assert not store.has_full_read("session-a", str(tmp_path / "module.py"))

    def test_parallel_subprocess_writes_complete_without_losing_entries(
        self, tmp_path: Path
    ) -> None:
        store = HookStateStore(tmp_path)
        targets = []
        processes = []
        for idx in range(8):
            target = tmp_path / f"module_{idx}.py"
            target.write_text(f"value = {idx}\n", encoding="utf-8")
            targets.append(target)
            processes.append(
                _start_full_read_record_subprocess(tmp_path, f"session-{idx}", target)
            )

        for process in processes:
            try:
                _, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                raise AssertionError("hook-state write subprocess timed out") from exc
            assert process.returncode == 0, stderr

        state = store._load_state()
        assert len(state["full_reads"]) == len(targets)
        for idx, target in enumerate(targets):
            assert store.has_full_read(f"session-{idx}", str(target))


class TestSearchReminderCurrentGuards:
    def test_bash_grep_still_triggers_reminder(self, tmp_path: Path) -> None:
        result = evaluate_payload(
            _bash_payload("grep -rn 'TODO' src/", cwd=str(tmp_path))
        )
        assert "REMIND-SEARCH-001" in finding_ids(result)

    def test_ripgrep_does_not_trigger_reminder(self, tmp_path: Path) -> None:
        result = evaluate_payload(_bash_payload("rg 'TODO' src/", cwd=str(tmp_path)))
        assert "REMIND-SEARCH-001" not in finding_ids(result)

    def test_embedded_grep_token_does_not_trigger_reminder(self, tmp_path: Path) -> None:
        result = evaluate_payload(
            _bash_payload("egrep 'TODO' src/", cwd=str(tmp_path))
        )
        assert "REMIND-SEARCH-001" not in finding_ids(result)

    def test_new_session_still_gets_search_reminder(self, tmp_path: Path) -> None:
        _ = evaluate_payload(
            _bash_payload("grep -rn 'TODO' src/", cwd=str(tmp_path), session_id="s1")
        )
        result = evaluate_payload(
            _bash_payload("grep -rn 'TODO' src/", cwd=str(tmp_path), session_id="s2")
        )

        assert "REMIND-SEARCH-001" in finding_ids(result)


@pytest.mark.xfail(
    strict=True,
    reason="search reminder dedupe and native-tool suppression are not implemented yet",
)
class TestSearchReminderStatefulSpec:
    def test_native_grep_tool_does_not_self_remind(self, tmp_path: Path) -> None:
        result = evaluate_payload(_grep_payload("TODO", cwd=str(tmp_path)))
        assert "REMIND-SEARCH-001" not in finding_ids(result)

    def test_second_shell_grep_same_session_is_deduped(self, tmp_path: Path) -> None:
        first = evaluate_payload(
            _bash_payload("grep -rn 'TODO' src/", cwd=str(tmp_path), session_id="s1")
        )
        second = evaluate_payload(
            _bash_payload("grep -rn 'FIXME' src/", cwd=str(tmp_path), session_id="s1")
        )

        assert "REMIND-SEARCH-001" in finding_ids(first)
        assert "REMIND-SEARCH-001" not in finding_ids(second)

    def test_same_session_dedupe_must_survive_subprocess_boundary(
        self, tmp_path: Path
    ) -> None:
        first = _run_payload_in_subprocess(
            _bash_payload("grep -rn 'TODO' src/", cwd=str(tmp_path), session_id="s1")
        )
        second = _run_payload_in_subprocess(
            _bash_payload("grep -rn 'FIXME' src/", cwd=str(tmp_path), session_id="s1")
        )

        assert "REMIND-SEARCH-001" in first["finding_ids"]
        assert "REMIND-SEARCH-001" not in second["finding_ids"]


class TestCrossPlatformSessionIdentityCurrentGuards:
    def test_codex_adapter_preserves_session_id(self) -> None:
        payload = {
            "session_id": "codex-session",
            "cwd": str(BUNDLE_ROOT),
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/example.py"},
        }
        normalized = get_adapter("codex").normalize_payload(payload)
        assert normalized["session_id"] == "codex-session"
        assert normalized["hook_event_name"] == "PreToolUse"

    def test_opencode_session_idle_maps_to_stop_and_preserves_session_id(self) -> None:
        payload = {
            "session_id": "oc-session",
            "cwd": str(BUNDLE_ROOT),
            "hook_event_name": "session.idle",
            "tool_name": "bash",
            "tool_input": {"command": "echo hi"},
        }
        normalized = get_adapter("opencode").normalize_payload(payload)
        assert normalized["session_id"] == "oc-session"
        assert normalized["hook_event_name"] == "Stop"
        assert normalized["tool_name"] == "Bash"


class TestSecurityRuleCurrentGuards:
    def test_real_source_bypass_still_denied(self, tmp_path: Path) -> None:
        payload = {
            "session_id": "spec-session",
            "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {
                "file_path": "src/settings.py",
                "content": "BYPASS_PERMISSIONS = True\n",
            },
        }
        result = evaluate_payload(payload)
        assert_denied_by(result, "BUILTIN-RULEBOOK-SECURITY", "bypass")

    def test_fixture_like_paths_remain_allowed(self, tmp_path: Path) -> None:
        payload = {
            "session_id": "spec-session",
            "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {
                "file_path": "tests/fixtures/security_fixture.json",
                "content": '{"allowManagedHooksOnly": true}\n',
            },
        }
        result = evaluate_payload(payload)
        assert_not_denied(result)


@pytest.mark.xfail(
    strict=True,
    reason="path-based docs/examples carveouts are not implemented yet",
)
class TestSecurityRuleBoundarySpec:
    def test_markdown_docs_can_describe_bypass_settings(self, tmp_path: Path) -> None:
        payload = {
            "session_id": "spec-session",
            "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {
                "file_path": "docs/security.md",
                "content": "Use `bypass_permissions` only in emergency rollback guidance.\n",
            },
        }
        result = evaluate_payload(payload)
        assert_not_denied(result)

    def test_json_examples_can_show_guardrail_settings(self, tmp_path: Path) -> None:
        payload = {
            "session_id": "spec-session",
            "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {
                "file_path": "docs/examples/hooks.json",
                "content": '{"allowManagedHooksOnly": true}\n',
            },
        }
        result = evaluate_payload(payload)
        assert_not_denied(result)


@pytest.mark.xfail(
    strict=True,
    reason="repeat-aware debt escalation is not implemented yet",
)
class TestRepeatedDebtEscalationSpec:
    def test_second_thin_wrapper_hit_tracks_repeat_count(self, tmp_path: Path) -> None:
        code = "def get_all_users():\n    return UserRepository.find_all()\n"
        first = evaluate_payload(
            _posttool_payload(
                cwd=tmp_path,
                rel_path="src/thin.py",
                code=code,
                session_id="repeat-session",
            )
        )
        second = evaluate_payload(
            _posttool_payload(
                cwd=tmp_path,
                rel_path="src/thin.py",
                code=code,
                session_id="repeat-session",
            )
        )

        first_finding = _finding("PY-CODE-013", first.findings)
        second_finding = _finding("PY-CODE-013", second.findings)
        assert first_finding is not None
        assert second_finding is not None
        assert first_finding.metadata.get("repeat_count") == 1
        assert second_finding.metadata.get("repeat_count") == 2

    def test_third_thin_wrapper_hit_escalates(self, tmp_path: Path) -> None:
        code = "def get_all_users():\n    return UserRepository.find_all()\n"
        _ = evaluate_payload(
            _posttool_payload(
                cwd=tmp_path,
                rel_path="src/thin.py",
                code=code,
                session_id="repeat-session",
            )
        )
        _ = evaluate_payload(
            _posttool_payload(
                cwd=tmp_path,
                rel_path="src/thin.py",
                code=code,
                session_id="repeat-session",
            )
        )
        third = evaluate_payload(
            _posttool_payload(
                cwd=tmp_path,
                rel_path="src/thin.py",
                code=code,
                session_id="repeat-session",
            )
        )

        finding = _finding("PY-CODE-013", third.findings)
        assert finding is not None
        assert finding.metadata.get("repeat_count") == 3
        assert finding.severity >= Severity.HIGH or finding.decision in {"deny", "block"}

    def test_repeat_tracking_is_scoped_per_path(self, tmp_path: Path) -> None:
        code = "def get_all_users():\n    return UserRepository.find_all()\n"
        _ = evaluate_payload(
            _posttool_payload(
                cwd=tmp_path,
                rel_path="src/one.py",
                code=code,
                session_id="repeat-session",
            )
        )
        second_path = evaluate_payload(
            _posttool_payload(
                cwd=tmp_path,
                rel_path="src/two.py",
                code=code,
                session_id="repeat-session",
            )
        )

        finding = _finding("PY-CODE-013", second_path.findings)
        assert finding is not None
        assert finding.metadata.get("repeat_count") == 1

    def test_new_session_resets_repeat_counter(self, tmp_path: Path) -> None:
        code = "def get_all_users():\n    return UserRepository.find_all()\n"
        _ = evaluate_payload(
            _posttool_payload(
                cwd=tmp_path,
                rel_path="src/thin.py",
                code=code,
                session_id="session-a",
            )
        )
        result = evaluate_payload(
            _posttool_payload(
                cwd=tmp_path,
                rel_path="src/thin.py",
                code=code,
                session_id="session-b",
            )
        )

        finding = _finding("PY-CODE-013", result.findings)
        assert finding is not None
        assert finding.metadata.get("repeat_count") == 1

    def test_repeat_count_must_survive_subprocess_boundary(self, tmp_path: Path) -> None:
        code = "def get_all_users():\n    return UserRepository.find_all()\n"
        first = _run_payload_in_subprocess(
            _posttool_payload(
                cwd=tmp_path,
                rel_path="src/thin.py",
                code=code,
                session_id="repeat-session",
            )
        )
        second = _run_payload_in_subprocess(
            _posttool_payload(
                cwd=tmp_path,
                rel_path="src/thin.py",
                code=code,
                session_id="repeat-session",
            )
        )

        first_finding = next(
            item for item in first["findings"] if item["rule_id"] == "PY-CODE-013"
        )
        second_finding = next(
            item for item in second["findings"] if item["rule_id"] == "PY-CODE-013"
        )
        assert first_finding["metadata"].get("repeat_count") == 1
        assert second_finding["metadata"].get("repeat_count") == 2
