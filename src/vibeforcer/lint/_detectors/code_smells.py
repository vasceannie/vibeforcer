"""Detectors for structural code smells.

Cyclomatic complexity, long methods, deep nesting, too many parameters,
oversized modules, and god classes.
"""

from __future__ import annotations

import ast
from pathlib import Path

from vibeforcer.lint._baseline import Violation
from vibeforcer.lint._config import get_config
from vibeforcer.lint._helpers import (
    class_body_lines,
    count_methods,
    find_source_files,
    function_body_lines,
    relative_path,
    safe_parse,
    read_lines,
)


# ---------------------------------------------------------------------------
# Cyclomatic complexity (simplified McCabe)
# ---------------------------------------------------------------------------

_BRANCH_NODES = (
    ast.If,
    ast.For,
    ast.While,
    ast.ExceptHandler,
    ast.With,
    ast.Assert,
    ast.BoolOp,
)


def _complexity(node: ast.AST) -> int:
    """Approximate cyclomatic complexity of a function/method body."""
    count = 1  # base path
    for child in ast.walk(node):
        if isinstance(child, _BRANCH_NODES):
            if isinstance(child, ast.BoolOp):
                # each extra and/or adds a branch
                count += len(child.values) - 1
            else:
                count += 1
        elif isinstance(
            child, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            count += len(child.generators)
    return count


def detect_high_complexity(files: list[Path] | None = None) -> list[Violation]:
    """Find functions/methods exceeding the configured complexity threshold."""
    cfg = get_config()
    files = files if files is not None else find_source_files()
    violations: list[Violation] = []
    for path in files:
        tree = safe_parse(path)
        if tree is None:
            continue
        rel = relative_path(path)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                cc = _complexity(node)
                if cc > cfg.max_complexity:
                    violations.append(
                        Violation(
                            rule="high-complexity",
                            relative_path=rel,
                            identifier=node.name,
                            detail=f"complexity={cc}",
                        )
                    )
    return violations


# ---------------------------------------------------------------------------
# Long methods
# ---------------------------------------------------------------------------


def detect_long_methods(files: list[Path] | None = None) -> list[Violation]:
    """Find functions/methods exceeding the configured line-count threshold."""
    cfg = get_config()
    files = files if files is not None else find_source_files()
    violations: list[Violation] = []
    for path in files:
        tree = safe_parse(path)
        if tree is None:
            continue
        rel = relative_path(path)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                lines = function_body_lines(node)
                if lines > cfg.max_method_lines:
                    violations.append(
                        Violation(
                            rule="long-method",
                            relative_path=rel,
                            identifier=node.name,
                            detail=f"lines={lines}",
                        )
                    )
    return violations


# ---------------------------------------------------------------------------
# Too many parameters
# ---------------------------------------------------------------------------


def detect_too_many_params(files: list[Path] | None = None) -> list[Violation]:
    """Find functions/methods with more parameters than the configured limit."""
    cfg = get_config()
    files = files if files is not None else find_source_files()
    violations: list[Violation] = []
    for path in files:
        tree = safe_parse(path)
        if tree is None:
            continue
        rel = relative_path(path)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args
                param_count = (
                    len(args.args) + len(args.posonlyargs) + len(args.kwonlyargs)
                )
                # Subtract 'self' / 'cls'
                if args.args and args.args[0].arg in ("self", "cls"):
                    param_count -= 1
                if param_count > cfg.max_params:
                    violations.append(
                        Violation(
                            rule="too-many-params",
                            relative_path=rel,
                            identifier=node.name,
                            detail=f"params={param_count}",
                        )
                    )
    return violations


# ---------------------------------------------------------------------------
# Deep nesting
# ---------------------------------------------------------------------------


def _max_nesting(node: ast.AST, current: int = 0) -> int:
    """Return the deepest nesting level inside *node*."""
    nesting_types = (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.ExceptHandler)
    deepest = current
    stack: list[tuple[ast.AST, int]] = []

    for child in ast.iter_child_nodes(node):
        next_depth = current + 1 if isinstance(child, nesting_types) else current
        stack.append((child, next_depth))

    while stack:
        current_node, depth = stack.pop()
        deepest = max(deepest, depth)
        for child in ast.iter_child_nodes(current_node):
            next_depth = depth + 1 if isinstance(child, nesting_types) else depth
            stack.append((child, next_depth))

    return deepest


def detect_deep_nesting(files: list[Path] | None = None) -> list[Violation]:
    """Find functions/methods with nesting deeper than the configured limit."""
    cfg = get_config()
    files = files if files is not None else find_source_files()
    violations: list[Violation] = []
    for path in files:
        tree = safe_parse(path)
        if tree is None:
            continue
        rel = relative_path(path)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                depth = _max_nesting(node)
                if depth > cfg.max_nesting_depth:
                    violations.append(
                        Violation(
                            rule="deep-nesting",
                            relative_path=rel,
                            identifier=node.name,
                            detail=f"depth={depth}",
                        )
                    )
    return violations


# ---------------------------------------------------------------------------
# Oversized modules
# ---------------------------------------------------------------------------


def detect_oversized_modules(files: list[Path] | None = None) -> list[Violation]:
    """Flag modules exceeding the soft or hard line-count thresholds."""
    cfg = get_config()
    files = files if files is not None else find_source_files()
    violations: list[Violation] = []
    for path in files:
        lines = read_lines(path)
        line_count = len(lines)
        rel = relative_path(path)
        if line_count > cfg.max_module_lines_hard:
            violations.append(
                Violation(
                    rule="oversized-module",
                    relative_path=rel,
                    identifier=path.name,
                    detail=f"lines={line_count} (hard limit={cfg.max_module_lines_hard})",
                )
            )
        elif line_count > cfg.max_module_lines_soft:
            violations.append(
                Violation(
                    rule="oversized-module-soft",
                    relative_path=rel,
                    identifier=path.name,
                    detail=f"lines={line_count} (soft limit={cfg.max_module_lines_soft})",
                )
            )
    return violations


# ---------------------------------------------------------------------------
# God classes
# ---------------------------------------------------------------------------


def detect_god_classes(files: list[Path] | None = None) -> list[Violation]:
    """Find classes with too many methods or too many lines."""
    cfg = get_config()
    files = files if files is not None else find_source_files()
    violations: list[Violation] = []
    for path in files:
        tree = safe_parse(path)
        if tree is None:
            continue
        rel = relative_path(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                n_methods = count_methods(node)
                n_lines = class_body_lines(node)
                reasons: list[str] = []
                if n_methods > cfg.max_god_class_methods:
                    reasons.append(f"methods={n_methods}")
                if n_lines > cfg.max_god_class_lines:
                    reasons.append(f"lines={n_lines}")
                if reasons:
                    violations.append(
                        Violation(
                            rule="god-class",
                            relative_path=rel,
                            identifier=node.name,
                            detail=", ".join(reasons),
                        )
                    )
    return violations
