"""PY-TEST-001 through PY-TEST-004: Test-smell hook rules.

Port the lint-only test smell detectors into reactive hooks so that
eager tests, assertion roulette, fixtures outside conftest, and
conditional assertions are caught at write time.

Staging: not yet registered in the rule registry.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from typing import TYPE_CHECKING, final
from typing_extensions import TypeGuard, override

from vibeforcer.models import RuleFinding, Severity
from vibeforcer.rules.base import Rule, is_rule_enabled

from .._helpers import (
    decision_for_context,
    evaluate_common,
    parse_module,
)

if TYPE_CHECKING:
    from vibeforcer.context import HookContext

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_ASSERT_PATTERNS = frozenset({
    "assert", "assertEqual", "assertRaises", "assertIn",
    "assertTrue", "assertFalse", "assertIsNone", "assertIsNotNone",
    "assertAlmostEqual", "assertGreater", "assertLess",
    "assertRegex", "assertNotEqual", "assertIs",
    "assert_called", "assert_called_once", "assert_called_with",
    "assert_called_once_with", "assert_not_called",
    "assert_any_call", "assert_has_calls",
})

_IGNORED_SUT_CALLS = frozenset({
    "mock", "patch", "fixture", "print", "len", "list", "dict",
    "set", "str", "int", "float", "tuple", "bool", "bytes",
    "isinstance", "type", "getattr", "setattr", "hasattr",
    "sorted", "reversed", "enumerate", "range", "zip", "map",
    "filter", "any", "all", "min", "max", "sum", "round",
    "repr", "id", "vars", "dir", "super",
})


def _is_test_function(
    node: ast.AST,
) -> TypeGuard[ast.FunctionDef | ast.AsyncFunctionDef]:
    """True if node is a test function (starts with test_)."""
    return (
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    )


def _is_test_file(path: str) -> bool:
    """Heuristic: is this path likely a test file?"""
    p = path.replace("\\", "/").lower()
    return "test" in p.split("/")[-1].split(".")[0].split("_") or "test_" in p


def _is_pytest_fixture_decorator(dec: ast.expr) -> bool:
    """True if dec looks like @pytest.fixture, @fixture, or variants."""
    if isinstance(dec, ast.Attribute):
        return (
            dec.attr == "fixture"
            and isinstance(dec.value, ast.Name)
            and dec.value.id == "pytest"
        )
    if isinstance(dec, ast.Name):
        return dec.id == "fixture"
    if isinstance(dec, ast.Call):
        return _is_pytest_fixture_decorator(dec.func)
    return False


def _count_sut_calls(node: ast.AST) -> int:
    """Count non-assert, non-setup function calls in a test body."""
    count = 0
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        name = ""
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        if name.startswith("assert"):
            continue
        if name.lower() in _IGNORED_SUT_CALLS:
            continue
        count += 1
    return count


def _is_bare_assert(node: ast.stmt) -> bool:
    """True when node is an assert statement without a message."""
    return isinstance(node, ast.Assert) and node.msg is None


def _max_bare_assert_run(stmts: list[ast.stmt]) -> int:
    """Return the longest run of consecutive bare asserts."""
    run = 0
    best = 0
    for stmt in stmts:
        if _is_bare_assert(stmt):
            run += 1
            if run > best:
                best = run
        else:
            run = 0
            if isinstance(stmt, ast.With):
                nested = _max_bare_assert_run(stmt.body)
                if nested > best:
                    best = nested
    return best


def _contains_assertion(node: ast.AST) -> bool:
    """True if the subtree contains any assertion."""
    for child in ast.walk(node):
        if isinstance(child, ast.Assert):
            return True
        if isinstance(child, ast.Call):
            func = child.func
            name = ""
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name in _ASSERT_PATTERNS:
                return True
    return False


def _walk_skip_nested_funcs(node: ast.AST) -> Iterator[ast.AST]:
    """Walk AST without descending into nested FunctionDef/AsyncFunctionDef."""
    from collections import deque

    todo = deque(ast.iter_child_nodes(node))
    while todo:
        child = todo.popleft()
        yield child
        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            todo.extend(ast.iter_child_nodes(child))


def _is_type_checking_block(node: ast.AST) -> bool:
    """True if node is `if TYPE_CHECKING:` or `if typing.TYPE_CHECKING:`."""
    if not isinstance(node, ast.If):
        return False
    test = node.test
    if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
        return True
    if (isinstance(test, ast.Attribute)
            and test.attr == "TYPE_CHECKING"
            and isinstance(test.value, ast.Name)
            and test.value.id == "typing"):
        return True
    return False


# ---------------------------------------------------------------------------
# PY-TEST-001: Eager tests (too many SUT calls)
# ---------------------------------------------------------------------------

@final
class PythonEagerTestRule(Rule):
    """Detect test functions with too many calls to the system under test.

    Eager tests try to verify too many behaviours in one function,
    making them fragile and hard to understand.
    """

    rule_id = "PY-TEST-001"
    title = "Block eager tests"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    _MAX_SUT_CALLS = 5  # threshold

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        if not _is_test_file(path_value):
            return []
        module = parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []

        findings: list[RuleFinding] = []
        for node in ast.walk(module):
            if not _is_test_function(node):
                continue
            calls = _count_sut_calls(node)
            if calls > self._MAX_SUT_CALLS:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    decision=decision_for_context(ctx),
                    message=(
                        f"Test `{node.name}` in `{path_value}` makes {calls} "
                        f"SUT calls (max: {self._MAX_SUT_CALLS}). "
                        f"Split into focused single-behaviour tests."
                    ),
                    metadata={
                        "path": path_value,
                        "function": node.name,
                        "sut_calls": calls,
                    },
                ))
        return findings

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)


# ---------------------------------------------------------------------------
# PY-TEST-002: Assertion roulette (bare asserts without messages)
# ---------------------------------------------------------------------------

@final
class PythonAssertionRouletteRule(Rule):
    """Detect test functions with long runs of bare ``assert`` (no message).

    When multiple bare asserts fail, it's unclear which one broke.
    Each assert should have a descriptive message or use named matchers.
    """

    rule_id = "PY-TEST-002"
    title = "Block assertion roulette"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    _MAX_CONSECUTIVE = 3  # flag if more than this many bare asserts in a row

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        if not _is_test_file(path_value):
            return []
        module = parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []

        findings: list[RuleFinding] = []
        for node in ast.walk(module):
            if not _is_test_function(node):
                continue
            max_run = _max_bare_assert_run(node.body)
            if max_run > self._MAX_CONSECUTIVE:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    decision=decision_for_context(ctx),
                    message=(
                        f"Test `{node.name}` in `{path_value}` has {max_run} "
                        f"consecutive bare asserts (max: {self._MAX_CONSECUTIVE}). "
                        f"Add descriptive messages or use named matchers."
                    ),
                    metadata={
                        "path": path_value,
                        "function": node.name,
                        "consecutive_bare_asserts": max_run,
                    },
                ))
        return findings

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)


# ---------------------------------------------------------------------------
# PY-TEST-003: Fixtures outside conftest.py
# ---------------------------------------------------------------------------

@final
class PythonFixtureOutsideConftestRule(Rule):
    """Detect @pytest.fixture definitions in files other than conftest.py.

    Fixtures scattered across test files are hard to discover and reuse.
    Centralise them in conftest.py files.
    """

    rule_id = "PY-TEST-003"
    title = "Block fixtures outside conftest"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        from pathlib import Path as _Path

        # Skip conftest.py itself (exact basename match)
        if _Path(path_value).name == "conftest.py":
            return []
        if not _is_test_file(path_value):
            return []
        module = parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []

        findings: list[RuleFinding] = []
        for node in ast.walk(module):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if _is_pytest_fixture_decorator(dec):
                    findings.append(RuleFinding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        decision=decision_for_context(ctx),
                        message=(
                            f"Fixture `{node.name}` defined outside conftest.py "
                            f"in `{path_value}` (line {node.lineno}). "
                            f"Move to the nearest conftest.py for discoverability."
                        ),
                        metadata={
                            "path": path_value,
                            "function": node.name,
                            "line": node.lineno,
                        },
                    ))
                    break  # one finding per function
        return findings

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)


# ---------------------------------------------------------------------------
# PY-TEST-004: Conditional assertions (asserts inside if/for/while)
# ---------------------------------------------------------------------------

@final
class PythonConditionalAssertionRule(Rule):
    """Detect assertions inside if/for/while blocks in test functions.

    Conditional assertions make tests non-deterministic: the same test
    run may execute different assertions depending on runtime state.
    """

    rule_id = "PY-TEST-004"
    title = "Block conditional assertions"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        if not _is_test_file(path_value):
            return []
        module = parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []

        findings: list[RuleFinding] = []
        for node in ast.walk(module):
            if not _is_test_function(node):
                continue
            for child in _walk_skip_nested_funcs(node):
                if isinstance(child, (ast.For, ast.While, ast.If, ast.AsyncFor)):
                    if _is_type_checking_block(child):
                        continue
                    if _contains_assertion(child):
                        findings.append(RuleFinding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            decision=decision_for_context(ctx),
                            message=(
                                f"Test `{node.name}` in `{path_value}` has "
                                f"assertions inside a {type(child).__name__} "
                                f"at line {child.lineno}. "
                                f"Extract into a separate focused test."
                            ),
                            metadata={
                                "path": path_value,
                                "function": node.name,
                                "control_flow": type(child).__name__,
                                "line": child.lineno,
                            },
                        ))
                        break  # one finding per test function
        return findings

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)
