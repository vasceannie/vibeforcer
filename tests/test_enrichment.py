"""Tests for the context enrichment pipeline.

Tests use tmp_project to create real filesystem layouts with conftest.py,
sibling test files, and requirements files so enrichment can discover them.
"""

from __future__ import annotations

from pathlib import Path

from tests import support as test_support
from tests.support import LoadFixture

from vibeforcer._types import ObjectDict
from vibeforcer.engine import evaluate_payload
from vibeforcer.enrichment import (
    discover_fixtures,
    find_parametrize_examples,
    enrich_findings,
)
from vibeforcer.enrichment import quality_enrichers
from vibeforcer.models import RuleFinding, Severity


# ===========================================================================
# Helpers
# ===========================================================================


def _mkdir(directory: Path, *, parents: bool = False, exist_ok: bool = False) -> None:
    _ = directory.mkdir(parents=parents, exist_ok=exist_ok)


def _write_text(path: Path, content: str) -> None:
    _ = path.write_text(content, encoding="utf-8")


def _make_conftest(
    directory: Path, fixtures: list[str], with_params: list[str] | None = None
) -> Path:
    """Create a conftest.py with the given fixture names."""
    with_params = with_params or []
    lines = ["import pytest\n"]
    for name in fixtures:
        if name in with_params:
            lines.append(
                f"@pytest.fixture(params=[1, 2, 3])\ndef {name}(request):\n    return request.param\n\n"
            )
        else:
            lines.append(f"@pytest.fixture\ndef {name}():\n    return 'value'\n\n")
    conftest = directory / "conftest.py"
    _write_text(conftest, "\n".join(lines))
    return conftest


def _make_sibling_test(
    directory: Path, name: str, has_parametrize: bool = False
) -> Path:
    """Create a sibling test file, optionally with @pytest.mark.parametrize."""
    if has_parametrize:
        content = (
            "import pytest\n\n"
            '@pytest.mark.parametrize("x,expected", [(1, True), (2, False)])\n'
            "def test_example(x, expected):\n"
            "    assert process(x) == expected\n"
        )
    else:
        content = "def test_simple():\n    assert True\n"
    path = directory / name
    _write_text(path, content)
    return path


def _pretool_write_payload(file_path: str, content: str, cwd: str) -> ObjectDict:
    return {
        "session_id": "test-enrichment",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": file_path, "content": content},
    }


# ===========================================================================
# Unit tests: _discover_fixtures
# ===========================================================================


class TestDiscoverFixtures:
    def test_finds_fixtures_in_same_dir(self, tmp_path: Path) -> None:
        tests_dir = tmp_path / "tests"
        _mkdir(tests_dir)
        _make_conftest(tests_dir, ["db_session", "client", "auth_token"])
        test_file = tests_dir / "test_api.py"
        _write_text(test_file, "# test file")

        fixtures = discover_fixtures(test_file, tmp_path)
        names = {f["name"] for f in fixtures}
        assert names == {"db_session", "client", "auth_token"}

    def test_finds_fixtures_in_parent_dir(self, tmp_path: Path) -> None:
        tests_dir = tmp_path / "tests"
        sub_dir = tests_dir / "api"
        _mkdir(sub_dir, parents=True)
        _make_conftest(tests_dir, ["root_fixture"])
        _make_conftest(sub_dir, ["api_fixture"])
        test_file = sub_dir / "test_endpoints.py"
        _write_text(test_file, "# test")

        fixtures = discover_fixtures(test_file, tmp_path)
        names = {f["name"] for f in fixtures}
        assert "api_fixture" in names
        assert "root_fixture" in names

    def test_identifies_parametrized_fixtures(self, tmp_path: Path) -> None:
        tests_dir = tmp_path / "tests"
        _mkdir(tests_dir)
        _make_conftest(
            tests_dir, ["normal", "data_driven"], with_params=["data_driven"]
        )
        test_file = tests_dir / "test_x.py"
        _write_text(test_file, "# test")

        fixtures = discover_fixtures(test_file, tmp_path)
        by_name = {f["name"]: f for f in fixtures}
        assert by_name["normal"]["has_params"] is False
        assert by_name["data_driven"]["has_params"] is True

    def test_no_conftest_returns_empty(self, tmp_path: Path) -> None:
        tests_dir = tmp_path / "tests"
        _mkdir(tests_dir)
        test_file = tests_dir / "test_x.py"
        _write_text(test_file, "# test")

        fixtures = discover_fixtures(test_file, tmp_path)
        assert fixtures == []

    def test_caps_at_10(self, tmp_path: Path) -> None:
        tests_dir = tmp_path / "tests"
        _mkdir(tests_dir)
        _make_conftest(tests_dir, [f"fix_{i}" for i in range(15)])
        test_file = tests_dir / "test_x.py"
        _write_text(test_file, "# test")

        fixtures = discover_fixtures(test_file, tmp_path)
        assert len(fixtures) <= 10

    def test_handles_syntax_error_in_conftest(self, tmp_path: Path) -> None:
        tests_dir = tmp_path / "tests"
        _mkdir(tests_dir)
        conftest = tests_dir / "conftest.py"
        _write_text(conftest, "def broken(:\n    pass\n")
        test_file = tests_dir / "test_x.py"
        _write_text(test_file, "# test")

        # Should not raise, just return empty
        fixtures = discover_fixtures(test_file, tmp_path)
        assert fixtures == []


# ===========================================================================
# Unit tests: _find_parametrize_examples
# ===========================================================================


class TestFindParametrizeExamples:
    def test_finds_sibling_parametrize(self, tmp_path: Path) -> None:
        tests_dir = tmp_path / "tests"
        _mkdir(tests_dir)
        _make_sibling_test(tests_dir, "test_math.py", has_parametrize=True)
        test_file = tests_dir / "test_target.py"
        _write_text(test_file, "# target")

        examples = find_parametrize_examples(test_file, tmp_path)
        assert len(examples) >= 1
        assert "parametrize" in examples[0]["snippet"]
        assert examples[0]["file"] == "test_math.py"

    def test_skips_self(self, tmp_path: Path) -> None:
        tests_dir = tmp_path / "tests"
        _mkdir(tests_dir)
        test_file = tests_dir / "test_target.py"
        _write_text(
            test_file,
            '@pytest.mark.parametrize("x", [1])\ndef test_self(x):\n    pass\n',
        )

        examples = find_parametrize_examples(test_file, tmp_path)
        assert len(examples) == 0

    def test_caps_at_max(self, tmp_path: Path) -> None:
        tests_dir = tmp_path / "tests"
        _mkdir(tests_dir)
        for i in range(5):
            _make_sibling_test(tests_dir, f"test_sibling_{i}.py", has_parametrize=True)
        test_file = tests_dir / "test_target.py"
        _write_text(test_file, "# target")

        examples = find_parametrize_examples(test_file, tmp_path, max_examples=2)
        assert len(examples) <= 2

    def test_no_siblings_returns_empty(self, tmp_path: Path) -> None:
        tests_dir = tmp_path / "tests"
        _mkdir(tests_dir)
        test_file = tests_dir / "test_target.py"
        _write_text(test_file, "# alone")

        examples = find_parametrize_examples(test_file, tmp_path)
        assert examples == []


# ===========================================================================
# Integration: PY-TEST-003 enrichment through engine
# ===========================================================================


class TestPYTEST003Enrichment:
    """Test that PY-TEST-003 denials include enriched context when
    the filesystem has conftest.py and sibling tests."""

    LOOP_CODE = (
        "def test_all_items_valid():\n"
        "    items = get_items()\n"
        "    for item in items:\n"
        "        assert item.is_valid()\n"
    )

    def test_enriched_with_fixtures(self, tmp_project: Path) -> None:
        """When conftest.py has fixtures, denial message includes them."""
        tests_dir = tmp_project / "tests"
        _mkdir(tests_dir, exist_ok=True)
        _make_conftest(tests_dir, ["db_session", "client"])

        payload = _pretool_write_payload(
            "tests/test_items.py",
            self.LOOP_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-TEST-003")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "`db_session`" in reason or "`client`" in reason, (
            f"Expected fixture names in reason, got: {reason}"
        )

    def test_enriched_with_parametrize_examples(self, tmp_project: Path) -> None:
        """When siblings have parametrize, denial message includes examples."""
        tests_dir = tmp_project / "tests"
        _mkdir(tests_dir, exist_ok=True)
        _make_conftest(tests_dir, ["fixture_a"])
        _make_sibling_test(tests_dir, "test_math.py", has_parametrize=True)

        payload = _pretool_write_payload(
            "tests/test_items.py",
            self.LOOP_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-TEST-003")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "test_math.py" in reason, f"Expected sibling ref in reason: {reason}"

    def test_enriched_additional_context(self, tmp_project: Path) -> None:
        """Claude Code additional_context includes extended fixture list."""
        tests_dir = tmp_project / "tests"
        _mkdir(tests_dir, exist_ok=True)
        _make_conftest(tests_dir, ["db", "client", "auth"])

        payload = _pretool_write_payload(
            "tests/test_items.py",
            self.LOOP_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-TEST-003")

        context = test_support.output_string(
            test_support.hook_output(result), "additionalContext"
        )
        assert "AVAILABLE FIXTURES" in context or "COMPLIANT ALTERNATIVES" in context, (
            f"Expected enrichment in additionalContext: {context}"
        )

    def test_still_denies_without_fixtures(self, tmp_project: Path) -> None:
        """PY-TEST-003 still fires even with no conftest.py (just no enrichment)."""
        tests_dir = tmp_project / "tests"
        _mkdir(tests_dir, exist_ok=True)
        # No conftest.py

        payload = _pretool_write_payload(
            "tests/test_items.py",
            self.LOOP_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-TEST-003")

    def test_cross_platform_codex(self, tmp_project: Path) -> None:
        """Codex adapter: enrichment lands in permissionDecisionReason."""
        tests_dir = tmp_project / "tests"
        _mkdir(tests_dir, exist_ok=True)
        _make_conftest(tests_dir, ["db_session"])

        payload = _pretool_write_payload(
            "tests/test_items.py",
            self.LOOP_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload, platform="codex")
        assert result.output is not None
        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "PY-TEST-003" in reason
        assert "`db_session`" in reason, (
            f"Codex reason should include fixture names: {reason}"
        )

    def test_cross_platform_opencode(self, tmp_project: Path) -> None:
        """OpenCode adapter: enrichment lands in reason field."""
        tests_dir = tmp_project / "tests"
        _mkdir(tests_dir, exist_ok=True)
        _make_conftest(tests_dir, ["db_session"])

        payload = _pretool_write_payload(
            "tests/test_items.py",
            self.LOOP_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload, platform="opencode")
        assert result.output is not None
        reason = test_support.required_string(
            test_support.require_output(result), "reason"
        )
        assert "PY-TEST-003" in reason
        assert "`db_session`" in reason, (
            f"OpenCode reason should include fixture names: {reason}"
        )


# ===========================================================================
# Integration: PY-TEST-001 enrichment
# ===========================================================================


class TestPYTEST001Enrichment:
    ROULETTE_CODE = (
        "def test_create_user():\n"
        "    user = create_user('alice', 'alice@example.com')\n"
        "    assert user is not None\n"
        "    assert user.name == 'alice'\n"
        "    assert user.email == 'alice@example.com'\n"
        "    assert user.active\n"
    )

    def test_enriched_with_fixtures(self, tmp_project: Path) -> None:
        tests_dir = tmp_project / "tests"
        _mkdir(tests_dir, exist_ok=True)
        _make_conftest(tests_dir, ["user_factory"])

        payload = _pretool_write_payload(
            "tests/test_user.py",
            self.ROULETTE_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-TEST-001")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "`user_factory`" in reason, f"Expected fixture in reason: {reason}"

    def test_includes_split_tip(self, tmp_project: Path) -> None:
        tests_dir = tmp_project / "tests"
        _mkdir(tests_dir, exist_ok=True)

        payload = _pretool_write_payload(
            "tests/test_user.py",
            self.ROULETTE_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-TEST-001")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "splitting" in reason.lower() or "split" in reason.lower(), (
            f"Expected split tip in reason: {reason}"
        )


# ===========================================================================
# Integration: PY-TEST-004 enrichment
# ===========================================================================


class TestPYTEST004Enrichment:
    FIXTURE_CODE = (
        "import pytest\n\n"
        "@pytest.fixture\n"
        "def local_db():\n"
        "    return create_session()\n\n"
        "def test_query(local_db):\n"
        "    assert local_db.query(User).count() > 0\n"
    )

    def test_shows_existing_conftest_fixtures(self, tmp_project: Path) -> None:
        tests_dir = tmp_project / "tests"
        _mkdir(tests_dir, exist_ok=True)
        _make_conftest(tests_dir, ["shared_db", "client"])

        payload = _pretool_write_payload(
            "tests/test_db.py",
            self.FIXTURE_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-TEST-004")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "`shared_db`" in reason or "`client`" in reason, (
            f"Expected existing fixtures in reason: {reason}"
        )

    def test_suggests_creating_conftest(self, tmp_project: Path) -> None:
        tests_dir = tmp_project / "tests"
        _mkdir(tests_dir, exist_ok=True)
        # No conftest.py at all

        payload = _pretool_write_payload(
            "tests/test_db.py",
            self.FIXTURE_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-TEST-004")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "create" in reason.lower() or "no conftest" in reason.lower(), (
            f"Expected create suggestion in reason: {reason}"
        )


# ===========================================================================
# Integration: PY-TEST-002 enrichment
# ===========================================================================


class TestPYTEST002Enrichment:
    SLEEP_CODE = (
        "import time\n\n"
        "def test_api_call():\n"
        "    start_server()\n"
        "    time.sleep(5)\n"
        '    response = client.get("/api/v1/health")\n'
        "    assert response.status_code == 200\n"
    )

    def test_enriched_with_fixtures(self, tmp_project: Path) -> None:
        tests_dir = tmp_project / "tests"
        _mkdir(tests_dir, exist_ok=True)
        _make_conftest(tests_dir, ["server"])

        payload = _pretool_write_payload(
            "tests/test_api.py",
            self.SLEEP_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-TEST-002")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "`server`" in reason, f"Expected fixture in reason: {reason}"

    def test_detects_freezegun_in_requirements(self, tmp_project: Path) -> None:
        tests_dir = tmp_project / "tests"
        _mkdir(tests_dir, exist_ok=True)
        req = tmp_project / "requirements.txt"
        _write_text(req, "freezegun==1.2.3\nrequests\n")

        payload = _pretool_write_payload(
            "tests/test_api.py",
            self.SLEEP_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-TEST-002")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "freezegun" in reason.lower(), (
            f"Expected freezegun mention in reason: {reason}"
        )


# ===========================================================================
# Integration: PY-TYPE-001 enrichment
# ===========================================================================


class TestPYTYPE001Enrichment:
    ANY_DICT_CODE = (
        "from typing import Any\n\n"
        "def process(data: dict[str, Any]) -> dict[str, Any]:\n"
        "    return {k: v for k, v in data.items()}\n"
    )

    ANY_CALLBACK_CODE = (
        "from typing import Any, Callable\n\n"
        "def register_handler(callback: Callable[..., Any]) -> None:\n"
        "    handlers.append(callback)\n"
    )

    def test_suggests_typeddict_for_dicts(self, tmp_project: Path) -> None:
        payload = _pretool_write_payload(
            "src/models.py",
            self.ANY_DICT_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-TYPE-001")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "TypedDict" in reason, f"Expected TypedDict suggestion: {reason}"

    def test_suggests_callable_for_callbacks(self, tmp_project: Path) -> None:
        payload = _pretool_write_payload(
            "src/handlers.py",
            self.ANY_CALLBACK_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-TYPE-001")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "Callable" in reason, f"Expected Callable suggestion: {reason}"


# ===========================================================================
# Safety: enrichment errors don't break the pipeline
# ===========================================================================


class TestEnrichmentSafety:
    def test_enrichment_error_swallowed(self, tmp_project: Path) -> None:
        """Even if enrichment throws, the deny still comes through."""
        payload = _pretool_write_payload(
            "tests/test_items.py",
            "def test_all():\n    for x in [1,2]:\n        assert x > 0\n",
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        # Should still deny regardless of enrichment
        test_support.assert_denied_by(result, "PY-TEST-003")

    def test_original_message_preserved(self) -> None:
        """Enrichment should append, not replace the original message."""
        finding = RuleFinding(
            rule_id="PY-TEST-003",
            title="test",
            severity=Severity.HIGH,
            decision="deny",
            message="Original denial message",
            metadata={"hits": []},
        )
        # With no hits, enrichment should be a no-op
        from vibeforcer.context import build_context

        ctx = build_context(
            {
                "session_id": "t",
                "cwd": "/tmp",
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
                "tool_input": {},
            }
        )
        enrich_findings([finding], ctx)
        assert finding.message is not None
        assert finding.message.startswith("Original denial message")


# ===========================================================================
# Existing fixture-based tests still pass (regression)
# ===========================================================================


class TestRegressionFixtures:
    """Verify the original fixture tests still produce correct denials.

    These run against the bundle fixtures (not tmp_project) where there's
    no conftest.py to discover — enrichment should add nothing harmful.
    """

    def test_loop_assert_fixture(self, load_fixture: LoadFixture) -> None:
        result = evaluate_payload(load_fixture("pretool_test_loop_assert.json"))
        test_support.assert_denied_by(result, "PY-TEST-003")

    def test_assertion_roulette_fixture(self, load_fixture: LoadFixture) -> None:
        result = evaluate_payload(load_fixture("pretool_assertion_roulette.json"))
        test_support.assert_denied_by(result, "PY-TEST-001")

    def test_test_sleep_fixture(self, load_fixture: LoadFixture) -> None:
        result = evaluate_payload(load_fixture("pretool_test_sleep.json"))
        test_support.assert_denied_by(result, "PY-TEST-002")

    def test_fixture_outside_conftest_fixture(self, load_fixture: LoadFixture) -> None:
        result = evaluate_payload(load_fixture("pretool_fixture_outside_conftest.json"))
        test_support.assert_denied_by(result, "PY-TEST-004")


# ===========================================================================
# Integration: PY-CODE-008 enrichment (long methods)
# ===========================================================================


class TestPYCODE008Enrichment:
    """PY-CODE-008: long method denial includes function structure."""

    def test_shows_extraction_points(self, tmp_project: Path) -> None:
        """Denial should list if-blocks, loops, try-blocks as extraction points."""
        # Write a file with a long function so PostToolUse can read it
        src_dir = tmp_project / "src"
        _mkdir(src_dir, exist_ok=True)
        long_func = "def process_data(items):\n"
        long_func += "    if not items:\n        return []\n"
        long_func += "    for item in items:\n        pass\n"
        long_func += "    try:\n        result = compute()\n    except ValueError:\n        pass\n"
        # Pad to exceed 50 lines
        for i in range(45):
            long_func += f"    x_{i} = {i}\n"
        _write_text(src_dir / "processor.py", long_func)

        payload = _pretool_write_payload(
            "src/processor.py",
            long_func,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-CODE-008")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "extraction" in reason.lower() or "structure" in reason.lower(), (
            f"Expected extraction hints in reason: {reason}"
        )

    def test_shows_split_strategy(self, tmp_project: Path) -> None:
        """Denial should include the split strategy suggestion."""
        src_dir = tmp_project / "src"
        _mkdir(src_dir, exist_ok=True)
        long_func = "def big_func():\n"
        for i in range(55):
            long_func += f"    line_{i} = {i}\n"
        _write_text(src_dir / "big.py", long_func)

        payload = _pretool_write_payload("src/big.py", long_func, str(tmp_project))
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-CODE-008")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "split" in reason.lower() or "helper" in reason.lower(), (
            f"Expected split advice: {reason}"
        )


# ===========================================================================
# Integration: PY-CODE-009 enrichment (long params)
# ===========================================================================


class TestPYCODE009Enrichment:
    def test_lists_parameters(self, tmp_project: Path) -> None:
        """Denial should list the actual parameter names."""
        src_dir = tmp_project / "src"
        _mkdir(src_dir, exist_ok=True)
        code = (
            "def configure(host, port, user, password, database, timeout, retries):\n"
            "    pass\n"
        )
        _write_text(src_dir / "db.py", code)

        payload = _pretool_write_payload("src/db.py", code, str(tmp_project))
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-CODE-009")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "`host`" in reason or "`port`" in reason, (
            f"Expected parameter names in reason: {reason}"
        )

    def test_finds_existing_dataclass(self, tmp_project: Path) -> None:
        """When file has dataclasses, enrichment mentions them."""
        src_dir = tmp_project / "src"
        _mkdir(src_dir, exist_ok=True)
        code = (
            "from dataclasses import dataclass\n\n"
            "@dataclass\n"
            "class DbConfig:\n"
            "    host: str\n"
            "    port: int\n\n"
            "def configure(host, port, user, password, database, timeout, retries):\n"
            "    pass\n"
        )
        _write_text(src_dir / "db.py", code)

        payload = _pretool_write_payload("src/db.py", code, str(tmp_project))
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-CODE-009")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "DbConfig" in reason, f"Expected existing dataclass ref: {reason}"


# ===========================================================================
# Integration: PY-CODE-015 enrichment (cyclomatic complexity)
# ===========================================================================


class TestPYCODE015Enrichment:
    def test_shows_complexity_breakdown(self, tmp_project: Path) -> None:
        """Denial should break down the sources of complexity."""
        src_dir = tmp_project / "src"
        _mkdir(src_dir, exist_ok=True)
        # Build a function with complexity > 10
        # Each if/elif adds 1, each loop adds 1, each `and`/`or` adds 1
        code = "def complex_func(x, y, z):\n"
        code += "    if x > 0 and y > 0:\n        a = 1\n"
        code += "    elif x < 0 or y < 0:\n        a = 2\n"
        code += "    elif x == 0:\n        a = 3\n"
        code += "    elif y == 0:\n        a = 4\n"
        code += "    else:\n        a = 5\n"
        code += "    for i in range(x):\n"
        code += "        if i > 0:\n            pass\n"
        code += "        elif i < 0:\n            pass\n"
        code += "    for j in range(y):\n"
        code += "        if j > 0 and j < 10:\n            pass\n"
        code += "    try:\n        compute()\n"
        code += "    except ValueError:\n        pass\n"
        code += "    except TypeError:\n        pass\n"
        _write_text(src_dir / "logic.py", code)

        payload = _pretool_write_payload("src/logic.py", code, str(tmp_project))
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-CODE-015")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "branch" in reason.lower() or "if" in reason.lower(), (
            f"Expected complexity breakdown: {reason}"
        )


# ===========================================================================
# Integration: PY-CODE-012 enrichment (feature envy)
# ===========================================================================


class TestPYCODE012Enrichment:
    def test_shows_envied_object_context(self, tmp_project: Path) -> None:
        """Denial should include advice about the envied object."""
        src_dir = tmp_project / "src"
        _mkdir(src_dir, exist_ok=True)
        # Feature envy rule excludes parameters — use a module-level object
        # and access it enough times (>= min_accesses, default 6) with
        # >60% of total accesses targeting one object
        code = (
            "import config\n\n"
            "def process():\n"
            "    a = config.host\n"
            "    b = config.port\n"
            "    c = config.user\n"
            "    d = config.password\n"
            "    e = config.database\n"
            "    f = config.timeout\n"
            "    g = config.retries\n"
            "    return a, b, c, d, e, f, g\n"
        )
        _write_text(src_dir / "envy.py", code)

        payload = _pretool_write_payload("src/envy.py", code, str(tmp_project))
        result = evaluate_payload(payload)

        # Feature envy is decision="context", not deny — check findings directly
        envy_findings = [f for f in result.findings if f.rule_id == "PY-CODE-012"]
        assert len(envy_findings) >= 1, (
            f"Expected PY-CODE-012 finding, got: {[f.rule_id for f in result.findings]}"
        )
        msg = envy_findings[0].message
        assert msg is not None
        assert "moving" in msg.lower() or "restructur" in msg.lower(), (
            f"Expected refactoring advice: {msg}"
        )


# ===========================================================================
# Integration: PY-CODE-013 enrichment (thin wrappers)
# ===========================================================================


class TestPYCODE013Enrichment:
    def test_shows_call_count(self, tmp_project: Path) -> None:
        """Denial should mention usage count when wrapper is called in same file."""
        src_dir = tmp_project / "src"
        _mkdir(src_dir, exist_ok=True)
        code = (
            "def get_value(key):\n"
            "    return lookup(key)\n\n"
            "def main():\n"
            "    a = get_value('x')\n"
            "    b = get_value('y')\n"
            "    return a, b\n"
        )
        _write_text(src_dir / "wrappers.py", code)

        payload = _pretool_write_payload("src/wrappers.py", code, str(tmp_project))
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-CODE-013")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "called" in reason.lower() or "time" in reason.lower(), (
            f"Expected usage info: {reason}"
        )


# ===========================================================================
# Integration: PY-EXC-002 enrichment (silent exceptions)
# ===========================================================================


class TestPYEXC002Enrichment:
    SILENT_EXCEPT_CODE = (
        "def load_config(path):\n"
        "    try:\n"
        "        data = read_file(path)\n"
        "        return parse_json(data)\n"
        "    except Exception:\n"
        "        return None\n"
    )

    def test_lists_called_functions(self, tmp_project: Path) -> None:
        """Denial should list functions called in the try block."""
        payload = _pretool_write_payload(
            "src/config.py",
            self.SILENT_EXCEPT_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-EXC-002")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "`read_file`" in reason or "`parse_json`" in reason, (
            f"Expected called function names: {reason}"
        )

    def test_includes_common_exceptions(self, tmp_project: Path) -> None:
        """Denial should include common specific exception suggestions."""
        payload = _pretool_write_payload(
            "src/config.py",
            self.SILENT_EXCEPT_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-EXC-002")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "FileNotFoundError" in reason or "ValueError" in reason, (
            f"Expected specific exception suggestions: {reason}"
        )


# ===========================================================================
# Integration: PY-LOG-001 enrichment (stdlib logger)
# ===========================================================================


class TestPYLOG001Enrichment:
    LOG_CODE = "import logging\n\nlogger = logging.getLogger(__name__)\n"

    def test_detects_structlog_in_deps(self, tmp_project: Path) -> None:
        """When project uses structlog, denial mentions it."""
        req = tmp_project / "requirements.txt"
        _write_text(req, "structlog==23.1.0\nrequests\n")

        payload = _pretool_write_payload(
            "src/app.py",
            self.LOG_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-LOG-001")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "structlog" in reason.lower(), f"Expected structlog mention: {reason}"

    def test_finds_project_logger(self, tmp_project: Path) -> None:
        """When project has a logger module, denial points to it."""
        src_dir = tmp_project / "src"
        _mkdir(src_dir, exist_ok=True)
        _write_text(
            src_dir / "logger.py",
            "import structlog\n\ndef get_logger(name):\n    return structlog.get_logger(name)\n",
        )

        payload = _pretool_write_payload(
            "src/app.py",
            self.LOG_CODE,
            str(tmp_project),
        )
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-LOG-001")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "logger.py" in reason, f"Expected logger.py reference: {reason}"


# ===========================================================================
# Integration: PY-TYPE-002 enrichment (type suppressions)
# ===========================================================================


class TestPYTYPE002Enrichment:
    def test_identifies_specific_suppression(self, tmp_project: Path) -> None:
        """Denial should identify the specific type: ignore code."""
        code = "def process(x):\n    return x.value  # type: ignore[union-attr]\n"
        payload = _pretool_write_payload("src/proc.py", code, str(tmp_project))
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-TYPE-002")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "union-attr" in reason, f"Expected error code in reason: {reason}"

    def test_gives_fix_advice_for_arg_type(self, tmp_project: Path) -> None:
        """Denial should give specific fix advice for arg-type errors."""
        code = "def send(msg):\n    channel.post(msg)  # type: ignore[arg-type]\n"
        payload = _pretool_write_payload("src/sender.py", code, str(tmp_project))
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-TYPE-002")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "arg-type" in reason, f"Expected arg-type advice: {reason}"


# ===========================================================================
# Integration: PY-QUALITY-010 enrichment (magic numbers)
# ===========================================================================


class TestPYQUALITY010Enrichment:
    def test_finds_constants_module(self, tmp_project: Path) -> None:
        """When project has constants.py, denial points to it."""
        src_dir = tmp_project / "src"
        _mkdir(src_dir, exist_ok=True)
        _write_text(src_dir / "constants.py", "MAX_RETRIES = 3\nTIMEOUT = 30\n")

        # Magic numbers regex requires 3+ digits (starting with 2-9) or 4+ digits
        code = "def retry():\n    timeout = 300\n    if timeout > 500:\n        pass\n"
        payload = _pretool_write_payload("src/retry.py", code, str(tmp_project))
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-QUALITY-010")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "constants.py" in reason, f"Expected constants.py reference: {reason}"

    def test_suggests_creating_constants(self, tmp_project: Path) -> None:
        """When no constants module exists, suggest creating one."""
        code = "def retry():\n    timeout = 3600\n    pass\n"
        payload = _pretool_write_payload("src/retry.py", code, str(tmp_project))
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-QUALITY-010")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "constants" in reason.lower(), f"Expected constants suggestion: {reason}"


# ===========================================================================
# Integration: PY-QUALITY-009 enrichment (hardcoded paths)
# ===========================================================================


class TestPYQUALITY009Enrichment:
    def test_finds_path_config(self, tmp_project: Path) -> None:
        """When project has path config, denial points to it."""
        src_dir = tmp_project / "src"
        _mkdir(src_dir, exist_ok=True)
        _write_text(
            src_dir / "config.py",
            "from pathlib import Path\nBASE_DIR = Path(__file__).parent.parent\n",
        )

        code = 'DATA = "/home/user/data/file.csv"\n'
        payload = _pretool_write_payload("src/loader.py", code, str(tmp_project))
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-QUALITY-009")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "config.py" in reason, f"Expected config.py reference: {reason}"

    def test_suggests_pathlib_pattern(self, tmp_project: Path) -> None:
        """When no path config exists, suggest pathlib pattern."""
        code = 'DATA = "/home/user/data/file.csv"\n'
        payload = _pretool_write_payload("src/loader.py", code, str(tmp_project))
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-QUALITY-009")

        reason = test_support.required_string(
            test_support.hook_output(result), "permissionDecisionReason"
        )
        assert "pathlib" in reason.lower() or "Path(" in reason, (
            f"Expected pathlib suggestion: {reason}"
        )


class TestEnrichmentConstantIndexScope:
    def test_unrelated_quality_rule_does_not_build_constant_index(
        self, tmp_project: Path, monkeypatch
    ) -> None:
        calls: list[Path] = []

        def _track_build(root: Path, **_: object) -> object:
            calls.append(root)
            return object()

        monkeypatch.setattr(
            quality_enrichers,
            "build_project_constant_index",
            _track_build,
        )

        code = 'DATA = "/home/user/data/file.csv"\n'
        payload = _pretool_write_payload("src/loader.py", code, str(tmp_project))
        result = evaluate_payload(payload)
        test_support.assert_denied_by(result, "PY-QUALITY-009")
        assert calls == []
