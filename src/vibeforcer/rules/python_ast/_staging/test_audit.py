"""Audit tests for staging hook rules.

These tests validate false-positive resistance, false-negative coverage,
and stability of the new hook rules before they're wired into production.

Run: python -m pytest _staging/test_audit.py -v
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from typing import cast

from vibeforcer.context import HookContext
from vibeforcer.models import RuleFinding
from vibeforcer.rules.base import Rule

# We import the rules directly — they're self-contained
from .duplicate_rules import (
    PythonRepeatedBlocksRule,
    PythonDuplicateCallSequenceRule,
    PythonSemanticCloneRule,
    PythonRepeatedMagicNumberRule,
)
from .test_smell_rules import (
    PythonEagerTestRule,
    PythonAssertionRouletteRule,
    PythonFixtureOutsideConftestRule,
    PythonConditionalAssertionRule,
)


# ---------------------------------------------------------------------------
# Minimal stub context for unit-testing rules in isolation
# ---------------------------------------------------------------------------

@dataclass
class _FakeConfig:
    python_ast_enabled: bool = True
    python_ast_max_parse_chars: int = 500_000
    enabled_rules: dict[str, bool] = field(default_factory=dict)


@dataclass
class _FakeContentTarget:
    path: str
    content: str


@dataclass
class _FakeContext:
    event_name: str = "PreToolUse"
    tool_name: str = "Edit"
    config: _FakeConfig = field(default_factory=_FakeConfig)
    candidate_paths: list[str] = field(default_factory=list)
    content_targets: list[_FakeContentTarget] = field(default_factory=list)
    cwd: str = "/tmp"


def _evaluate_rule(rule: Rule, ctx: _FakeContext) -> list[RuleFinding]:
    return rule.evaluate(cast(HookContext, ctx))


# ---------------------------------------------------------------------------
# PY-DUP-001: Repeated code blocks
# ---------------------------------------------------------------------------

class TestRepeatedBlocks:
    """Audit PY-DUP-001 for false positives and false negatives."""

    def _eval(self, source: str, path: str = "src/example.py") -> list[RuleFinding]:
        rule = PythonRepeatedBlocksRule()
        ctx = _FakeContext(
            content_targets=[_FakeContentTarget(path, source)],
        )
        return _evaluate_rule(rule, ctx)

    def test_no_false_positive_single_block(self):
        """A function with no repeated blocks should be clean."""
        source = textwrap.dedent("""\
            def foo():
                x = 1
                y = 2
                z = 3
                return x + y + z
        """)
        findings = self._eval(source)
        assert len(findings) == 0, "Single block should not trigger"

    def test_detects_copy_paste(self):
        """Two identical blocks should be flagged."""
        block_lines = ["    x = fetch_data()", "    y = transform(x)", "    z = validate(y)"]
        block = "\n".join(block_lines)
        source = f"def foo():\n{block}\n\ndef bar():\n{block}"
        findings = self._eval(source)
        assert len(findings) >= 1, "Should detect repeated block"

    def test_no_false_positive_import_blocks(self):
        """Import-only blocks should not be flagged."""
        source = textwrap.dedent("""\
            import os
            import sys
            import json
        """)
        findings = self._eval(source)
        assert len(findings) == 0, "Import blocks should not trigger"

    def test_no_false_positive_different_logic(self):
        """Blocks with different logic should not be flagged."""
        source = textwrap.dedent("""\
            def foo():
                x = 1
                y = 2
                z = 3

            def bar():
                a = "hello"
                b = "world"
                c = "!"
        """)
        findings = self._eval(source)
        assert len(findings) == 0, "Different blocks should not trigger"


# ---------------------------------------------------------------------------
# PY-DUP-002: Duplicate call sequences
# ---------------------------------------------------------------------------

class TestDuplicateCallSequences:
    """Audit PY-DUP-002."""

    def _eval(self, source: str, path: str = "src/example.py") -> list[RuleFinding]:
        rule = PythonDuplicateCallSequenceRule()
        ctx = _FakeContext(
            content_targets=[_FakeContentTarget(path, source)],
        )
        return _evaluate_rule(rule, ctx)

    def test_no_false_positive_short_sequence(self):
        """Functions with <3 shared calls should not trigger."""
        source = textwrap.dedent("""\
            def foo():
                read()
                parse()

            def bar():
                read()
                parse()
        """)
        findings = self._eval(source)
        assert len(findings) == 0, "Short sequences should not trigger"

    def test_detects_duplicate_sequence(self):
        """Two functions with identical call sequences should trigger."""
        source = textwrap.dedent("""\
            def foo():
                read()
                parse()
                validate()
                save()

            def bar():
                read()
                parse()
                validate()
                save()
        """)
        findings = self._eval(source)
        assert len(findings) >= 1, "Should detect duplicate call sequence"

    def test_no_false_positive_different_order(self):
        """Different order of calls should not trigger."""
        source = textwrap.dedent("""\
            def foo():
                read()
                parse()
                validate()

            def bar():
                validate()
                parse()
                read()
        """)
        findings = self._eval(source)
        assert len(findings) == 0, "Different order should not trigger"


# ---------------------------------------------------------------------------
# PY-DUP-003: Semantic clones
# ---------------------------------------------------------------------------

class TestSemanticClones:
    """Audit PY-DUP-003."""

    def _eval(self, source: str, path: str = "src/example.py") -> list[RuleFinding]:
        rule = PythonSemanticCloneRule()
        ctx = _FakeContext(
            content_targets=[_FakeContentTarget(path, source)],
        )
        return _evaluate_rule(rule, ctx)

    def test_detects_parametric_clone(self):
        """Functions that differ only in variable names should be flagged."""
        source = textwrap.dedent("""\
            def process_user():
                data = fetch()
                result = transform(data)
                store(result)
                return result

            def process_order():
                items = fetch()
                output = transform(items)
                store(output)
                return output
        """)
        findings = self._eval(source)
        assert len(findings) >= 1, "Should detect parametric clone"

    def test_no_false_positive_different_structure(self):
        """Functions with genuinely different logic should be clean."""
        source = textwrap.dedent("""\
            def process_user():
                data = fetch()
                return data

            def process_order():
                for item in items:
                    handle(item)
                return True
        """)
        findings = self._eval(source)
        assert len(findings) == 0, "Different logic should not trigger"

    def test_no_false_positive_dunder(self):
        """Dunder methods should not be flagged."""
        source = textwrap.dedent("""\
            def __init__(self):
                self.x = 1
                self.y = 2
                self.z = 3

            def __repr__(self):
                self.x = 1
                self.y = 2
                self.z = 3
        """)
        findings = self._eval(source)
        assert len(findings) == 0, "Dunder methods should not trigger"


# ---------------------------------------------------------------------------
# PY-DUP-004: Repeated magic numbers
# ---------------------------------------------------------------------------

class TestRepeatedMagicNumbers:
    """Audit PY-DUP-004."""

    def _eval(self, source: str, path: str = "src/example.py") -> list[RuleFinding]:
        rule = PythonRepeatedMagicNumberRule()
        ctx = _FakeContext(
            content_targets=[_FakeContentTarget(path, source)],
        )
        return _evaluate_rule(rule, ctx)

    def test_no_false_positive_common_values(self):
        """0, 1, -1, 2 should never trigger."""
        source = textwrap.dedent("""\
            x = 0
            y = 1
            z = -1
            w = 2
            a = 0
            b = 1
            c = 2
        """)
        findings = self._eval(source)
        assert len(findings) == 0, "Common values should not trigger"

    def test_detects_repeated_magic_number(self):
        """A number appearing >3 times should trigger."""
        source = textwrap.dedent("""\
            x = 42
            y = 42
            z = 42
            w = 42
        """)
        findings = self._eval(source)
        assert len(findings) >= 1, "Should detect repeated magic number"

    def test_no_false_positive_below_threshold(self):
        """A number appearing exactly 3 times should not trigger."""
        source = "x = 42\ny = 42\nz = 42"
        findings = self._eval(source)
        assert len(findings) == 0, "At threshold should not trigger"

    def test_no_false_positive_in_docstring(self):
        """Numbers inside docstrings should not count."""
        source = '"""The answer is 42, or maybe 42, definitely 42."""'
        findings = self._eval(source)
        assert len(findings) == 0, "Docstring numbers should not trigger"


# ---------------------------------------------------------------------------
# PY-TEST-001: Eager tests
# ---------------------------------------------------------------------------

class TestEagerTests:
    """Audit PY-TEST-001."""

    def _eval(self, source: str, path: str = "tests/test_example.py") -> list[RuleFinding]:
        rule = PythonEagerTestRule()
        ctx = _FakeContext(
            content_targets=[_FakeContentTarget(path, source)],
        )
        return _evaluate_rule(rule, ctx)

    def test_detects_eager_test(self):
        """A test with >5 SUT calls should trigger."""
        source = textwrap.dedent("""\
            def test_everything():
                result1 = calculate(1)
                result2 = calculate(2)
                result3 = calculate(3)
                result4 = calculate(4)
                result5 = calculate(5)
                result6 = calculate(6)
        """)
        findings = self._eval(source)
        assert len(findings) >= 1, "Should detect eager test"

    def test_no_false_positive_reasonable_test(self):
        """A test with <=5 SUT calls should be clean."""
        source = textwrap.dedent("""\
            def test_foo():
                result = calculate(1)
                assert result == 42
        """)
        findings = self._eval(source)
        assert len(findings) == 0, "Reasonable test should not trigger"

    def test_no_false_positive_non_test_file(self):
        """Non-test files should be skipped entirely."""
        source = textwrap.dedent("""\
            def test_everything():
                calculate(1)
                calculate(2)
                calculate(3)
                calculate(4)
                calculate(5)
                calculate(6)
        """)
        findings = self._eval(source, path="src/production.py")
        assert len(findings) == 0, "Non-test file should not trigger"

    def test_no_false_positive_setup_calls(self):
        """mock/patch/fixture calls should not count as SUT calls."""
        source = textwrap.dedent("""\
            def test_with_mocks():
                mock = mock.Mock()
                patch("something")
                fixture("data")
                result = sut.run()
                sut.verify()
        """)
        findings = self._eval(source)
        assert len(findings) == 0, "Setup calls should not count"


# ---------------------------------------------------------------------------
# PY-TEST-002: Assertion roulette
# ---------------------------------------------------------------------------

class TestAssertionRoulette:
    """Audit PY-TEST-002."""

    def _eval(self, source: str, path: str = "tests/test_example.py") -> list[RuleFinding]:
        rule = PythonAssertionRouletteRule()
        ctx = _FakeContext(
            content_targets=[_FakeContentTarget(path, source)],
        )
        return _evaluate_rule(rule, ctx)

    def test_detects_roulette(self):
        """4+ consecutive bare asserts should trigger."""
        source = textwrap.dedent("""\
            def test_stuff():
                assert a == 1
                assert b == 2
                assert c == 3
                assert d == 4
        """)
        findings = self._eval(source)
        assert len(findings) >= 1, "Should detect assertion roulette"

    def test_no_false_positive_asserts_with_messages(self):
        """Asserts with messages should not count toward roulette."""
        source = textwrap.dedent("""\
            def test_stuff():
                assert a == 1, "a should be 1"
                assert b == 2, "b should be 2"
                assert c == 3, "c should be 3"
                assert d == 4, "d should be 4"
        """)
        findings = self._eval(source)
        assert len(findings) == 0, "Asserts with messages should not trigger"

    def test_no_false_positive_reasonable_count(self):
        """3 or fewer bare asserts should be fine."""
        source = textwrap.dedent("""\
            def test_stuff():
                assert a == 1
                assert b == 2
                assert c == 3
        """)
        findings = self._eval(source)
        assert len(findings) == 0, "3 bare asserts should not trigger"


# ---------------------------------------------------------------------------
# PY-TEST-003: Fixtures outside conftest
# ---------------------------------------------------------------------------

class TestFixtureOutsideConftest:
    """Audit PY-TEST-003."""

    def _eval(self, source: str, path: str = "tests/test_example.py") -> list[RuleFinding]:
        rule = PythonFixtureOutsideConftestRule()
        ctx = _FakeContext(
            content_targets=[_FakeContentTarget(path, source)],
        )
        return _evaluate_rule(rule, ctx)

    def test_detects_fixture_in_test_file(self):
        """@pytest.fixture in a test file should trigger."""
        source = textwrap.dedent("""\
            import pytest

            @pytest.fixture
            def sample_data():
                return [1, 2, 3]
        """)
        findings = self._eval(source)
        assert len(findings) >= 1, "Should detect fixture outside conftest"

    def test_no_false_positive_conftest(self):
        """conftest.py should be allowed to have fixtures."""
        source = textwrap.dedent("""\
            import pytest

            @pytest.fixture
            def sample_data():
                return [1, 2, 3]
        """)
        findings = self._eval(source, path="tests/conftest.py")
        assert len(findings) == 0, "conftest.py should not trigger"

    def test_no_false_positive_regular_function(self):
        """Regular functions (no @pytest.fixture) should be clean."""
        source = textwrap.dedent("""\
            def helper():
                return [1, 2, 3]
        """)
        findings = self._eval(source)
        assert len(findings) == 0, "Regular function should not trigger"

    def test_no_false_positive_direct_import_fixture(self):
        """@fixture (direct import) should also be detected."""
        source = textwrap.dedent("""\
            from pytest import fixture

            @fixture
            def sample_data():
                return [1, 2, 3]
        """)
        findings = self._eval(source)
        assert len(findings) >= 1, "Direct import @fixture should also trigger"


# ---------------------------------------------------------------------------
# PY-TEST-004: Conditional assertions
# ---------------------------------------------------------------------------

class TestConditionalAssertions:
    """Audit PY-TEST-004."""

    def _eval(self, source: str, path: str = "tests/test_example.py") -> list[RuleFinding]:
        rule = PythonConditionalAssertionRule()
        ctx = _FakeContext(
            content_targets=[_FakeContentTarget(path, source)],
        )
        return _evaluate_rule(rule, ctx)

    def test_detects_assertion_in_if(self):
        """Assertions inside if blocks should trigger."""
        source = textwrap.dedent("""\
            def test_conditional():
                if condition:
                    assert result == expected
        """)
        findings = self._eval(source)
        assert len(findings) >= 1, "Should detect assertion in if"

    def test_detects_assertion_in_for(self):
        """Assertions inside for loops should trigger."""
        source = textwrap.dedent("""\
            def test_loop():
                for item in items:
                    assert item.valid
        """)
        findings = self._eval(source)
        assert len(findings) >= 1, "Should detect assertion in for"

    def test_no_false_positive_top_level_assert(self):
        """Top-level assertions should be fine."""
        source = textwrap.dedent("""\
            def test_simple():
                result = calculate()
                assert result == 42
        """)
        findings = self._eval(source)
        assert len(findings) == 0, "Top-level assert should not trigger"

    def test_no_false_positive_non_test(self):
        """Non-test files should be skipped."""
        source = textwrap.dedent("""\
            def process():
                if error:
                    assert False, "should not happen"
        """)
        findings = self._eval(source, path="src/production.py")
        assert len(findings) == 0, "Non-test file should not trigger"


# ---------------------------------------------------------------------------
# Stability: ensure rules don't crash on edge-case inputs
# ---------------------------------------------------------------------------

class TestStability:
    """Ensure rules handle edge cases without crashing."""

    def _eval_all_rules(self, source: str, path: str = "src/example.py") -> None:
        rules = [
            PythonRepeatedBlocksRule(),
            PythonDuplicateCallSequenceRule(),
            PythonSemanticCloneRule(),
            PythonRepeatedMagicNumberRule(),
            PythonEagerTestRule(),
            PythonAssertionRouletteRule(),
            PythonFixtureOutsideConftestRule(),
            PythonConditionalAssertionRule(),
        ]
        for rule in rules:
            ctx = _FakeContext(
                content_targets=[_FakeContentTarget(path, source)],
            )
            findings = _evaluate_rule(rule, ctx)
            assert isinstance(findings, list), f"{rule.rule_id} returned non-list"

    def test_empty_file(self):
        self._eval_all_rules("")

    def test_syntax_error(self):
        self._eval_all_rules("def foo(:\n    pass")

    def test_binary_garbage(self):
        self._eval_all_rules("\x00\x01\x02\xff")

    def test_very_long_line(self):
        """Deeply nested expression can crash ast.parse — rules must survive."""
        source = "x = " + "1 + " * 10000 + "1"
        # This triggers RecursionError in ast.parse, which parse_module
        # should catch. If any rule crashes, the test fails.
        self._eval_all_rules(source)

    def test_deeply_nested(self):
        source = "def f():\n"
        for i in range(20):
            source += "    " * (i + 1) + "if True:\n"
        self._eval_all_rules(source)

    def test_unicode(self):
        self._eval_all_rules('# 文件\nx = "日本語"\n')

    def test_massive_file(self):
        """Rule should handle files beyond max_parse_chars gracefully."""
        source = "x = 1\n" * 100000  # well over default 500k chars
        self._eval_all_rules(source)
