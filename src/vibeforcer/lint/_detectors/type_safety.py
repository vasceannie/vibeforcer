"""Detectors for type-safety violations.

- ``detect_any_usage``:  flag uses of ``typing.Any`` in annotations.
- ``detect_type_suppressions``:  flag ``# type: ignore`` and similar pragmas.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Sequence
from pathlib import Path

from vibeforcer.lint._baseline import Violation
from vibeforcer.lint._config import get_config
from vibeforcer.lint._helpers import (
    ParsedFile,
    ensure_parsed,
    find_source_files,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _inside_type_checking(node: ast.AST, parent_map: dict[int, ast.AST]) -> bool:
    """Return True if *node* is nested inside an ``if TYPE_CHECKING:`` block."""
    current: ast.AST | None = parent_map.get(id(node))
    while current is not None:
        if isinstance(current, ast.If):
            test = current.test
            if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
                return True
            if isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING":
                return True
        current = parent_map.get(id(current))
    return False


def _annotation_contains_any(node: ast.AST) -> bool:
    """True when the annotation subtree contains a reference to ``Any``.

    Walks the full annotation expression so it catches ``list[Any]``,
    ``dict[str, Any]``, ``Any | str``, ``Optional[Any]``, etc.
    """
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id == "Any":
            return True
        if (
            isinstance(child, ast.Attribute)
            and child.attr == "Any"
            and isinstance(child.value, ast.Name)
            and child.value.id == "typing"
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# detect_any_usage
# ---------------------------------------------------------------------------

_TYPING_MODULES = frozenset({"typing", "typing_extensions"})


def detect_any_usage(
    files: list[Path] | list[ParsedFile] | None = None,
) -> list[Violation]:
    """Find usages of ``typing.Any`` in annotations and imports.

    Walks annotation subtrees so ``list[Any]``, ``dict[str, Any]``,
    ``Any | int``, etc. are all caught.  Skips ``if TYPE_CHECKING:`` blocks.
    """
    cfg = get_config()
    if not cfg.ban_any:
        return []

    parsed = ensure_parsed(files, fallback=find_source_files())
    violations: list[Violation] = []

    for pf in parsed:
        parents = pf.parent_map

        for node in ast.walk(pf.tree):
            # ── from typing import Any ──────────────────────────────
            if isinstance(node, ast.ImportFrom):
                if _inside_type_checking(node, parents):
                    continue
                if node.module and node.module in _TYPING_MODULES:
                    for alias in node.names:
                        if alias.name == "Any":
                            violations.append(
                                Violation(
                                    rule="banned-any",
                                    relative_path=pf.rel,
                                    identifier="import-Any",
                                    detail=f"line {node.lineno}",
                                )
                            )

            # ── Function annotations (args + return) ────────────────
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if _inside_type_checking(node, parents):
                    continue
                # Return annotation
                if node.returns and _annotation_contains_any(node.returns):
                    violations.append(
                        Violation(
                            rule="banned-any",
                            relative_path=pf.rel,
                            identifier=node.name,
                            detail=f"return annotation, line {node.returns.lineno}",
                        )
                    )
                # Argument annotations
                all_args = [
                    *node.args.args,
                    *node.args.posonlyargs,
                    *node.args.kwonlyargs,
                ]
                if node.args.vararg:
                    all_args.append(node.args.vararg)
                if node.args.kwarg:
                    all_args.append(node.args.kwarg)
                for arg in all_args:
                    if arg.annotation and _annotation_contains_any(arg.annotation):
                        violations.append(
                            Violation(
                                rule="banned-any",
                                relative_path=pf.rel,
                                identifier=node.name,
                                detail=f"param {arg.arg}, line {arg.lineno}",
                            )
                        )

            # ── Variable annotations: x: Any = … ───────────────────
            if isinstance(node, ast.AnnAssign):
                if _inside_type_checking(node, parents):
                    continue
                if _annotation_contains_any(node.annotation):
                    target_name = ""
                    if isinstance(node.target, ast.Name):
                        target_name = node.target.id
                    violations.append(
                        Violation(
                            rule="banned-any",
                            relative_path=pf.rel,
                            identifier=target_name or "<annotation>",
                            detail=f"line {node.lineno}",
                        )
                    )

    return violations


# ---------------------------------------------------------------------------
# detect_type_suppressions
# ---------------------------------------------------------------------------

# Cache compiled patterns keyed on the tuple of raw pattern strings.
_compiled_cache: dict[tuple[str, ...], list[re.Pattern[str]]] = {}


def _get_compiled_patterns(raw: Sequence[str]) -> list[re.Pattern[str]]:
    """Return compiled regexes, cached by input."""
    key = tuple(raw)
    if key not in _compiled_cache:
        _compiled_cache[key] = [re.compile(p) for p in raw]
    return _compiled_cache[key]


def detect_type_suppressions(
    files: list[Path] | list[ParsedFile] | None = None,
) -> list[Violation]:
    """Find lines with ``# type: ignore``, ``# noqa``, and similar pragmas.

    Skips lines that fall inside string literals (docstrings, comments
    *about* suppression pragmas that happen to match).
    """
    cfg = get_config()
    if not cfg.ban_type_suppressions:
        return []

    parsed = ensure_parsed(files, fallback=find_source_files())
    patterns = _get_compiled_patterns(cfg.suppression_patterns)
    violations: list[Violation] = []

    for pf in parsed:
        for lineno, line in enumerate(pf.lines, start=1):
            # Skip lines inside string literals (docstrings, etc.)
            if lineno in pf.string_line_ranges:
                continue
            # Only match if the pattern appears in the comment portion
            # of the line (after the #), not in code/strings.
            comment_start = _find_comment_start(line)
            if comment_start < 0:
                continue
            comment_text = line[comment_start:]
            for pat in patterns:
                if pat.search(comment_text):
                    violations.append(
                        Violation(
                            rule="type-suppression",
                            relative_path=pf.rel,
                            identifier=f"line-{lineno}",
                            detail=line.strip()[:80],
                        )
                    )
                    break  # one violation per line
    return violations


def _find_comment_start(line: str) -> int:
    """Return the index of the ``#`` that starts a line-end comment, or -1.

    Skips ``#`` characters inside string literals.
    """
    in_string: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if in_string:
            if ch == "\\" and i + 1 < len(line):
                i += 2  # skip escaped char
                continue
            if ch == in_string:
                in_string = None
        else:
            if ch in ('"', "'"):
                in_string = ch
            elif ch == "#":
                return i
        i += 1
    return -1
