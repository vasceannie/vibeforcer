"""Detectors for test-specific smells.

Long tests, eager tests (too many SUT calls), assertion-free tests,
assertion roulette, conditional assertions, fixtures outside conftest.
"""
from __future__ import annotations

import ast
from pathlib import Path

from .._baseline import Violation
from .._config import get_config
from .._helpers import (
    ParsedFile,
    ensure_parsed,
    find_test_files,
    function_body_lines,
    relative_path,
    safe_parse,
)


# ---------------------------------------------------------------------------
# Long tests
# ---------------------------------------------------------------------------

def detect_long_tests(files: list[Path] | None = None) -> list[Violation]:
    """Find test functions/methods exceeding the configured line-count limit."""
    cfg = get_config()
    files = files if files is not None else find_test_files()
    violations: list[Violation] = []
    for path in files:
        tree = safe_parse(path)
        if tree is None:
            continue
        rel = relative_path(path)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.name.startswith("test_"):
                    continue
                lines = function_body_lines(node)
                if lines > cfg.max_test_lines:
                    violations.append(
                        Violation(
                            rule="long-test",
                            relative_path=rel,
                            identifier=node.name,
                            detail=f"lines={lines}",
                        )
                    )
    return violations


# ---------------------------------------------------------------------------
# Eager tests — too many calls to the SUT in a single test
# ---------------------------------------------------------------------------

def _count_sut_calls(node: ast.AST) -> int:
    """Count non-assert function/method calls in a test body.

    Excludes common setup helpers (``mock``, ``patch``, ``fixture``,
    ``print``, ``len``, ``list``, ``dict``, ``set``, ``str``, ``int``,
    ``isinstance``, ``type``, ``getattr``, ``setattr``, ``hasattr``).
    """
    _IGNORED = frozenset({
        "mock", "patch", "fixture", "print", "len", "list", "dict",
        "set", "str", "int", "float", "tuple", "bool", "bytes",
        "isinstance", "type", "getattr", "setattr", "hasattr",
        "sorted", "reversed", "enumerate", "range", "zip", "map",
        "filter", "any", "all", "min", "max", "sum", "round",
        "repr", "id", "vars", "dir", "super",
    })
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
        if name.lower() in _IGNORED:
            continue
        count += 1
    return count


def detect_eager_tests(files: list[Path] | None = None) -> list[Violation]:
    """Find test functions with too many SUT calls."""
    cfg = get_config()
    files = files if files is not None else find_test_files()
    violations: list[Violation] = []
    for path in files:
        tree = safe_parse(path)
        if tree is None:
            continue
        rel = relative_path(path)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.name.startswith("test_"):
                    continue
                calls = _count_sut_calls(node)
                if calls > cfg.max_eager_test_calls:
                    violations.append(
                        Violation(
                            rule="eager-test",
                            relative_path=rel,
                            identifier=node.name,
                            detail=f"sut_calls={calls}",
                        )
                    )
    return violations


# ---------------------------------------------------------------------------
# Assertion-free tests
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


def _has_assertion(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Check whether a test function contains at least one assertion."""
    for child in ast.walk(node):
        # bare assert statement
        if isinstance(child, ast.Assert):
            return True
        # pytest.raises / unittest assertX / mock assert_*
        if isinstance(child, ast.Call):
            func = child.func
            name = ""
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name in _ASSERT_PATTERNS:
                return True
        # ``with pytest.raises(...)``
        if isinstance(child, ast.With):
            for item in child.items:
                if isinstance(item.context_expr, ast.Call):
                    call_func = item.context_expr.func
                    if isinstance(call_func, ast.Attribute) and call_func.attr == "raises":
                        return True
    return False


def detect_assertion_free_tests(files: list[Path] | None = None) -> list[Violation]:
    """Find test functions that never assert anything."""
    files = files if files is not None else find_test_files()
    violations: list[Violation] = []
    for path in files:
        tree = safe_parse(path)
        if tree is None:
            continue
        rel = relative_path(path)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.name.startswith("test_"):
                    continue
                if not _has_assertion(node):
                    violations.append(
                        Violation(
                            rule="assertion-free-test",
                            relative_path=rel,
                            identifier=node.name,
                        )
                    )
    return violations


# ---------------------------------------------------------------------------
# Assertion roulette — too many bare asserts in a row
# ---------------------------------------------------------------------------

def _is_bare_assert(node: ast.stmt) -> bool:
    """True when *node* is an ``assert`` statement without a message."""
    return isinstance(node, ast.Assert) and node.msg is None


def _max_bare_assert_run(stmts: list[ast.stmt]) -> int:
    """Return the longest run of consecutive bare asserts in *stmts*.

    Recurses into ``with`` blocks so that bare asserts inside
    ``with pytest.raises(...)`` or other context managers are counted.
    """
    run = 0
    best = 0
    for stmt in stmts:
        if _is_bare_assert(stmt):
            run += 1
            if run > best:
                best = run
        else:
            run = 0
            # Recurse into with-block bodies
            if isinstance(stmt, ast.With):
                nested = _max_bare_assert_run(stmt.body)
                if nested > best:
                    best = nested
    return best


def detect_assertion_roulette(
    files: list[Path] | list[ParsedFile] | None = None,
) -> list[Violation]:
    """Find test functions with long runs of bare ``assert`` (no message).

    Flags when more than ``cfg.max_consecutive_bare_asserts`` consecutive
    bare asserts appear in a test function body (including inside ``with``
    blocks).
    """
    cfg = get_config()
    threshold = cfg.max_consecutive_bare_asserts
    parsed = ensure_parsed(files, fallback=find_test_files())
    violations: list[Violation] = []

    for pf in parsed:
        for node in ast.walk(pf.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_"):
                continue
            max_run = _max_bare_assert_run(node.body)
            if max_run > threshold:
                violations.append(
                    Violation(
                        rule="assertion-roulette",
                        relative_path=pf.rel,
                        identifier=node.name,
                        detail=f"consecutive_bare_asserts={max_run}",
                    )
                )
    return violations


# ---------------------------------------------------------------------------
# Conditional assertions — asserts inside if/for/while
# ---------------------------------------------------------------------------

def _contains_assert(node: ast.AST) -> bool:
    """True if the subtree rooted at *node* contains any assertion."""
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


def detect_conditional_assertions(
    files: list[Path] | list[ParsedFile] | None = None,
) -> list[Violation]:
    """Find test functions with assertions inside ``if``/``for``/``while``."""
    cfg = get_config()
    if not cfg.ban_conditional_assertions:
        return []

    parsed = ensure_parsed(files, fallback=find_test_files())
    violations: list[Violation] = []

    for pf in parsed:
        for node in ast.walk(pf.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_"):
                continue
            for child in ast.walk(node):
                if isinstance(child, (ast.For, ast.While, ast.If)):
                    if _contains_assert(child):
                        violations.append(
                            Violation(
                                rule="conditional-assertion",
                                relative_path=pf.rel,
                                identifier=node.name,
                                detail=f"line {child.lineno}",
                            )
                        )
                        break  # one per function
    return violations


# ---------------------------------------------------------------------------
# Fixtures outside conftest.py
# ---------------------------------------------------------------------------

def _is_pytest_fixture_decorator(dec: ast.expr) -> bool:
    """True if *dec* looks like ``@pytest.fixture``, ``@pytest.fixture(...)``,
    or ``@fixture`` / ``@fixture(...)`` (when imported directly).
    """
    # @pytest.fixture
    if isinstance(dec, ast.Attribute):
        return (
            dec.attr == "fixture"
            and isinstance(dec.value, ast.Name)
            and dec.value.id == "pytest"
        )
    # @fixture  (from pytest import fixture)
    if isinstance(dec, ast.Name):
        return dec.id == "fixture"
    # @pytest.fixture(...) or @fixture(...)
    if isinstance(dec, ast.Call):
        return _is_pytest_fixture_decorator(dec.func)
    return False


def detect_fixtures_outside_conftest(
    files: list[Path] | list[ParsedFile] | None = None,
) -> list[Violation]:
    """Find ``@pytest.fixture`` definitions in files other than ``conftest.py``."""
    cfg = get_config()
    if not cfg.ban_fixtures_outside_conftest:
        return []

    parsed = ensure_parsed(files, fallback=find_test_files())
    violations: list[Violation] = []

    for pf in parsed:
        if pf.path.name == "conftest.py":
            continue
        for node in ast.walk(pf.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if _is_pytest_fixture_decorator(dec):
                    violations.append(
                        Violation(
                            rule="fixture-outside-conftest",
                            relative_path=pf.rel,
                            identifier=node.name,
                            detail=f"line {node.lineno}",
                        )
                    )
                    break
    return violations



