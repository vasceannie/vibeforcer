"""Detector for unnecessary thin wrappers.

A "thin wrapper" is a function whose body is a single ``return other_func(…)``
call that passes through all of its arguments unchanged.
"""

from __future__ import annotations

import ast
from pathlib import Path

from vibeforcer.lint._baseline import Violation
from vibeforcer.lint._config import get_config
from vibeforcer.lint._helpers import find_source_files, relative_path, safe_parse


def _is_simple_delegation(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str | None:
    """If *func_node* is a thin wrapper, return the delegated call as a string.

    Returns ``None`` if the function does meaningful work beyond delegation.
    """
    body = func_node.body
    # Skip docstring
    start = 0
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        start = 1

    stmts = body[start:]
    if len(stmts) != 1:
        return None

    stmt = stmts[0]
    # ``return some_call(...)``
    if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
        call = stmt.value
    # bare ``some_call(...)`` (no return)
    elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        call = stmt.value
    else:
        return None

    # Build the callee name
    callee = call_name(call)
    if not callee:
        return None

    # Check that every argument is just passed through from the params
    param_names = {a.arg for a in func_node.args.args}
    param_names |= {a.arg for a in func_node.args.posonlyargs}
    param_names |= {a.arg for a in func_node.args.kwonlyargs}
    param_names.discard("self")
    param_names.discard("cls")

    for arg in call.args:
        if isinstance(arg, ast.Starred):
            arg = arg.value
        if isinstance(arg, ast.Name) and arg.id in param_names:
            continue
        return None

    for kw in call.keywords:
        if kw.arg is None:
            # **kwargs pass-through
            continue
        if isinstance(kw.value, ast.Name) and kw.value.id in param_names:
            continue
        return None

    return callee


def call_name(call: ast.Call) -> str:
    """Extract a dotted name from a Call node."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = [func.attr]
        node = func.value
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def detect_unnecessary_wrappers(files: list[Path] | None = None) -> list[Violation]:
    """Find thin wrapper functions that simply delegate to another call."""
    cfg = get_config()
    allowed = cfg.allowed_wrappers
    files = files if files is not None else find_source_files()
    violations: list[Violation] = []

    for path in files:
        tree = safe_parse(path)
        if tree is None:
            continue
        rel = relative_path(path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Skip dunder methods, properties, and private overrides
            if node.name.startswith("__") and node.name.endswith("__"):
                continue
            # Skip decorated functions (often @property, @abstractmethod, etc.)
            if node.decorator_list:
                continue
            callee = _is_simple_delegation(node)
            if callee is None:
                continue
            if str((node.name, callee)) in allowed:
                continue
            violations.append(
                Violation(
                    rule="unnecessary-wrapper",
                    relative_path=rel,
                    identifier=node.name,
                    detail=f"delegates to {callee}",
                )
            )

    return violations
