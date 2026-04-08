"""Detector for logging convention violations.

Ensures consistent use of a project-wide logger factory and variable name.
Flags direct ``logging.getLogger()`` calls and disallowed logger variable names.
"""
from __future__ import annotations

import ast
from pathlib import Path

from .._baseline import Violation
from .._config import get_config
from .._helpers import find_source_files, relative_path, safe_parse


def _is_in_infrastructure(rel_path: str) -> bool:
    """Return True if the file is part of logging infrastructure (excluded)."""
    cfg = get_config()
    prefix = cfg.logging_infrastructure_path
    if not prefix:
        return False
    return rel_path.startswith(prefix)


def detect_direct_get_logger(files: list[Path] | None = None) -> list[Violation]:
    """Flag direct ``logging.getLogger(...)`` calls.

    Projects that define a custom logger factory should use it consistently
    instead of calling ``logging.getLogger`` directly.
    """
    cfg = get_config()
    if not cfg.logger_function:
        # No custom factory configured — nothing to enforce
        return []

    files = files if files is not None else find_source_files()
    violations: list[Violation] = []

    for path in files:
        tree = safe_parse(path)
        if tree is None:
            continue
        rel = relative_path(path)
        if _is_in_infrastructure(rel):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # logging.getLogger(...)
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "getLogger"
                and isinstance(func.value, ast.Name)
                and func.value.id == "logging"
            ):
                violations.append(
                    Violation(
                        rule="direct-get-logger",
                        relative_path=rel,
                        identifier=f"L{node.lineno}",
                        detail=f"use {cfg.logger_function}() instead",
                    )
                )

    return violations


def detect_wrong_logger_name(files: list[Path] | None = None) -> list[Violation]:
    """Flag logger variables with disallowed names.

    The project should use a single, consistent variable name (e.g. ``logger``)
    for the module-level logger.
    """
    cfg = get_config()
    disallowed = cfg.disallowed_logger_names
    expected = cfg.logger_variable
    if not disallowed:
        return []

    files = files if files is not None else find_source_files()
    violations: list[Violation] = []

    for path in files:
        tree = safe_parse(path)
        if tree is None:
            continue
        rel = relative_path(path)
        if _is_in_infrastructure(rel):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            # Only look at module-level or class-level assignments
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                name = target.id
                if name in disallowed:
                    # Check if the value is a logger-like call
                    if _is_logger_call(node.value):
                        violations.append(
                            Violation(
                                rule="wrong-logger-name",
                                relative_path=rel,
                                identifier=f"L{node.lineno}",
                                detail=f"'{name}' → use '{expected}'",
                            )
                        )

    return violations


def _is_logger_call(node: ast.AST) -> bool:
    """Heuristic: is *node* a call that returns a logger?"""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute):
        if func.attr in ("getLogger", "get_logger"):
            return True
        # Custom logger factory (e.g. ``make_logger(...)``)
        cfg = get_config()
        if cfg.logger_function and func.attr == cfg.logger_function:
            return True
    if isinstance(func, ast.Name):
        cfg = get_config()
        if func.id in ("getLogger", "get_logger"):
            return True
        if cfg.logger_function and func.id == cfg.logger_function:
            return True
    return False
