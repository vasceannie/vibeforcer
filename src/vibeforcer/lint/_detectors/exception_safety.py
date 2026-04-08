"""Detectors for exception-safety violations.

- ``detect_broad_except_swallow``:  broad ``except`` that silently returns a
  default value (log + return default).
- ``detect_silent_except``:  broad ``except`` that silently swallows with
  ``pass``, ``continue``, bare ``return``, or ``return None`` — no logging.
- ``detect_silent_fallback``:  ``except`` that returns ``datetime.now()`` or
  ``datetime.utcnow()``.
"""
from __future__ import annotations

import ast
from pathlib import Path

from vibeforcer.lint._baseline import Violation
from vibeforcer.lint._config import get_config
from vibeforcer.lint._helpers import (
    ParsedFile,
    enclosing_function,
    ensure_parsed,
    find_source_files,
    relative_path,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_LOGGING_NAMES = frozenset({
    "debug", "info", "warning", "error", "critical", "exception",
    "log", "warn",
})


def _is_logging_call(node: ast.stmt) -> bool:
    """True when *node* is a logging call like ``logger.info(...)``."""
    if not isinstance(node, ast.Expr):
        return False
    if not isinstance(node.value, ast.Call):
        return False
    func = node.value.func
    if isinstance(func, ast.Attribute) and func.attr in _LOGGING_NAMES:
        return True
    if isinstance(func, ast.Name) and func.id in _LOGGING_NAMES:
        return True
    return False


def _is_default_return(node: ast.stmt) -> bool:
    """True when *node* is ``return <sentinel>`` (None, {}, [], "", 0, False)."""
    if not isinstance(node, ast.Return):
        return False
    val = node.value
    if val is None:
        return True  # bare ``return``
    if isinstance(val, ast.Constant):
        if val.value is None or val.value is False or val.value == 0 or val.value == "":
            return True
    # Empty dict: ``return {}``
    if isinstance(val, ast.Dict) and not val.keys:
        return True
    # Empty list: ``return []``
    if isinstance(val, ast.List) and not val.elts:
        return True
    return False


def _is_broad_except(handler: ast.ExceptHandler) -> bool:
    """True for ``except Exception``, ``except BaseException``, bare ``except:``,
    and tuple forms like ``except (Exception, ValueError):``.
    """
    if handler.type is None:
        return True  # bare except
    if isinstance(handler.type, ast.Name) and handler.type.id in (
        "Exception", "BaseException",
    ):
        return True
    # Tuple form: except (Exception, SomeError):
    if isinstance(handler.type, ast.Tuple):
        for elt in handler.type.elts:
            if isinstance(elt, ast.Name) and elt.id in (
                "Exception", "BaseException",
            ):
                return True
    return False


def _body_is_swallow(body: list[ast.stmt]) -> bool:
    """True when the handler body is *only* logging + default return."""
    if not body:
        return False
    has_return = False
    for stmt in body:
        if _is_logging_call(stmt):
            continue
        if isinstance(stmt, ast.Pass):
            continue
        if _is_default_return(stmt):
            has_return = True
            continue
        return False  # some other statement
    return has_return


# ---------------------------------------------------------------------------
# detect_broad_except_swallow
# ---------------------------------------------------------------------------

def detect_broad_except_swallow(
    files: list[Path] | list[ParsedFile] | None = None,
) -> list[Violation]:
    """Find ``except Exception`` blocks that silently swallow and return a default."""
    cfg = get_config()
    if not cfg.ban_broad_except_swallow:
        return []

    parsed = ensure_parsed(files, fallback=find_source_files())
    violations: list[Violation] = []

    for pf in parsed:
        for node in ast.walk(pf.tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if not _is_broad_except(node):
                continue
            if _body_is_swallow(node.body):
                func_name = enclosing_function(node, pf.parent_map)
                violations.append(
                    Violation(
                        rule="broad-except-swallow",
                        relative_path=pf.rel,
                        identifier=func_name,
                        detail=f"line {node.lineno}",
                    )
                )
    return violations


# ---------------------------------------------------------------------------
# detect_silent_fallback
# ---------------------------------------------------------------------------

def _is_datetime_now_return(node: ast.stmt) -> bool:
    """True if *node* is ``return datetime.now()`` or ``return datetime.utcnow()``.

    Matches both import styles:
    - ``from datetime import datetime`` → ``datetime.now()``
    - ``import datetime`` → ``datetime.datetime.now()``
    """
    if not isinstance(node, ast.Return):
        return False
    val = node.value
    if not isinstance(val, ast.Call):
        return False
    func = val.func
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr not in ("now", "utcnow"):
        return False
    # ``datetime.now()`` — from datetime import datetime
    if isinstance(func.value, ast.Name) and func.value.id == "datetime":
        return True
    # ``datetime.datetime.now()`` — import datetime
    if (
        isinstance(func.value, ast.Attribute)
        and func.value.attr == "datetime"
        and isinstance(func.value.value, ast.Name)
        and func.value.value.id == "datetime"
    ):
        return True
    return False


def detect_silent_fallback(
    files: list[Path] | list[ParsedFile] | None = None,
) -> list[Violation]:
    """Find ``except`` handlers that return ``datetime.now()``/``utcnow()``."""
    cfg = get_config()
    if not cfg.ban_silent_fallback:
        return []

    parsed = ensure_parsed(files, fallback=find_source_files())
    violations: list[Violation] = []

    for pf in parsed:
        for node in ast.walk(pf.tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            for stmt in node.body:
                if _is_datetime_now_return(stmt):
                    func_name = enclosing_function(node, pf.parent_map)
                    violations.append(
                        Violation(
                            rule="silent-datetime-fallback",
                            relative_path=pf.rel,
                            identifier=func_name,
                            detail=f"line {node.lineno}",
                        )
                    )
                    break  # one per handler
    return violations


# ---------------------------------------------------------------------------
# detect_silent_except
# ---------------------------------------------------------------------------

def _is_silent_body(body: list["ast.stmt"]) -> str | None:
    """Classify silent handler bodies.  Returns a label or *None*.

    Catches:
    - ``pass`` only
    - ``continue`` only
    - bare ``return`` / ``return None``
    - ``<var> = None`` or ``<var> = <default>``
    - any of the above with only comments (which ast strips)
    """
    if not body:
        return None
    # Strip Pass statements and check what remains
    meaningful = [s for s in body if not isinstance(s, ast.Pass)]
    if not meaningful:
        return "pass"  # body was only pass/comments

    if len(meaningful) == 1:
        stmt = meaningful[0]
        # continue
        if isinstance(stmt, ast.Continue):
            return "continue"
        # bare return / return None
        if isinstance(stmt, ast.Return):
            val = stmt.value
            if val is None:
                return "bare-return"
            if isinstance(val, ast.Constant) and val.value is None:
                return "return-none"
            if isinstance(val, ast.Constant) and val.value in (False, 0, ""):
                return "return-default"
            if isinstance(val, (ast.Dict, ast.List)) and not getattr(val, "keys", None) and not getattr(val, "elts", None):
                return "return-default"
        # <var> = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            if isinstance(stmt.value, ast.Constant) and stmt.value.value is None:
                return "assign-none"

    # If body has logging, it's not "silent" — let other detectors handle it
    for stmt in body:
        if _is_logging_call(stmt):
            return None
    # Check for return-default without logging (broader than _body_is_swallow)
    for stmt in meaningful:
        if _is_default_return(stmt):
            return "return-default-no-log"

    return None


def detect_silent_except(
    files: "list[Path] | list[ParsedFile] | None" = None,
) -> list[Violation]:
    """Find broad ``except`` blocks that silently swallow errors.

    Unlike ``detect_broad_except_swallow`` (which requires logging + default
    return), this catches the completely silent cases: ``pass``, ``continue``,
    bare ``return``, ``return None``, or ``var = None`` with no logging.
    """
    cfg = get_config()
    if not cfg.ban_silent_except:
        return []

    parsed = ensure_parsed(files, fallback=find_source_files())
    violations: list[Violation] = []

    for pf in parsed:
        for node in ast.walk(pf.tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if not _is_broad_except(node):
                continue
            label = _is_silent_body(node.body)
            if label is not None:
                func_name = enclosing_function(node, pf.parent_map)
                violations.append(
                    Violation(
                        rule="silent-except",
                        relative_path=pf.rel,
                        identifier=func_name,
                        detail=f"line {node.lineno}: {label}",
                    )
                )
    return violations
