"""Shared helpers for quality-gate detectors and tests."""

from __future__ import annotations

import ast
import fnmatch
import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from vibeforcer.lint._config import get_config


# ---------------------------------------------------------------------------
# Derived paths (resolved once via config singleton)
# ---------------------------------------------------------------------------


def _cfg():
    return get_config()


def project_root() -> Path:
    return _cfg().project_root


def src_root() -> Path:
    return _cfg().src_root


def tests_root() -> Path:
    return _cfg().tests_root


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def _is_excluded_dir(name: str) -> bool:
    return name in _cfg().exclude_dirs


def _is_excluded_file(name: str) -> bool:
    for pat in _cfg().exclude_patterns:
        if fnmatch.fnmatch(name, pat):
            return True
    return False


def _scope() -> str:
    """Return the effective scan scope (all | changed | staged)."""
    return os.environ.get("QUALITY_SCOPE", _cfg().default_scope)


def _git_diff_paths(*args: str) -> set[Path]:
    try:
        result = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            cwd=project_root(),
            check=False,
        )
    except FileNotFoundError:
        return set()

    root = project_root()
    return {root / item.strip() for item in result.stdout.splitlines() if item.strip()}


def _changed_files() -> set[Path]:
    """Return files changed since last commit (unstaged + staged)."""
    return _git_diff_paths("diff", "--name-only", "HEAD")


def _staged_files() -> set[Path]:
    """Return files staged for commit."""
    return _git_diff_paths("diff", "--cached", "--name-only")


def _scope_filter() -> set[Path] | None:
    """Return a set of allowed paths, or None if all files should be scanned."""
    scope = _scope()
    if scope == "changed":
        return _changed_files()
    if scope == "staged":
        return _staged_files()
    return None  # scan everything


def _walk_python_files(root: Path) -> list[Path]:
    """Recursively find *.py files under *root*, respecting exclusions and scope."""
    if not root.exists():
        return []
    scope_set = _scope_filter()
    results: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not _is_excluded_dir(d)]
        for fn in sorted(filenames):
            if not fn.endswith(".py"):
                continue
            if _is_excluded_file(fn):
                continue
            full = Path(dirpath) / fn
            if scope_set is not None and full.resolve() not in {
                p.resolve() for p in scope_set
            }:
                continue
            results.append(full)
    return sorted(results)


def find_source_files() -> list[Path]:
    """Return all non-test Python source files."""
    return _walk_python_files(src_root())


def find_test_files() -> list[Path]:
    """Return all Python test files."""
    return _walk_python_files(tests_root())


def find_all_python_files() -> list[Path]:
    """Return all Python files (source + test)."""
    return find_source_files() + find_test_files()


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def relative_path(p: Path) -> str:
    """Return a POSIX relative path string from the project root."""
    try:
        return p.resolve().relative_to(project_root().resolve()).as_posix()
    except ValueError:
        return p.as_posix()


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def safe_parse(path: Path) -> ast.Module | None:
    """Parse a Python file, returning None on syntax errors."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        return ast.parse(source, filename=str(path))
    except (SyntaxError, UnicodeDecodeError):
        return None


def read_lines(path: Path) -> list[str]:
    """Read a file into a list of lines (empty list on error)."""
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def function_body_lines(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Count the lines in a function body (excluding decorators and docstrings)."""
    if not node.body:
        return 0
    first = node.body[0]
    # Skip docstring
    start_idx = 0
    if (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    ):
        start_idx = 1
    if start_idx >= len(node.body):
        return 0
    first_body = node.body[start_idx]
    last_body = node.body[-1]
    start_line = first_body.lineno
    end_line = getattr(last_body, "end_lineno", last_body.lineno)
    return end_line - start_line + 1


def class_body_lines(node: ast.ClassDef) -> int:
    """Count the total lines spanned by a class body."""
    if not node.body:
        return 0
    first = node.body[0]
    last = node.body[-1]
    start = first.lineno
    end = getattr(last, "end_lineno", last.lineno)
    return end - start + 1


def count_methods(node: ast.ClassDef) -> int:
    """Count the number of method definitions in a class (direct children only)."""
    return sum(
        1
        for child in node.body
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


# ---------------------------------------------------------------------------
# ParsedFile — parse-once infrastructure
# ---------------------------------------------------------------------------


@dataclass
class ParsedFile:
    """A Python file pre-parsed for efficient multi-detector scanning.

    Built once per file, shared across all detectors so we never parse
    the same AST or read the same lines twice.
    """

    path: Path
    rel: str
    tree: ast.Module
    lines: list[str]
    parent_map: dict[int, ast.AST] = field(repr=False)
    string_line_ranges: set[int] = field(repr=False)


def build_parent_map(tree: ast.Module) -> dict[int, ast.AST]:
    """Build a mapping from ``id(child)`` → parent node.

    Walks the full AST once; used for TYPE_CHECKING detection and
    enclosing-function lookups.
    """
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    return parents


def compute_string_line_ranges(tree: ast.Module) -> set[int]:
    """Return the set of line numbers occupied by string constants in the AST.

    This includes docstrings, triple-quoted strings, and any other string
    literal.  Used by line-based detectors (line_length, type_suppressions)
    to skip lines that are inside string literals rather than real code.
    """
    string_lines: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and hasattr(node, "lineno")
            and hasattr(node, "end_lineno")
        ):
            end_line = node.end_lineno if node.end_lineno is not None else node.lineno
            for ln in range(node.lineno, end_line + 1):
                string_lines.add(ln)
    return string_lines


def parse_file(path: Path) -> ParsedFile | None:
    """Parse a Python file into a ``ParsedFile``, or return None on failure."""
    tree = safe_parse(path)
    if tree is None:
        return None
    lines = read_lines(path)
    rel = relative_path(path)
    parent_map = build_parent_map(tree)
    string_lines = compute_string_line_ranges(tree)
    return ParsedFile(
        path=path,
        rel=rel,
        tree=tree,
        lines=lines,
        parent_map=parent_map,
        string_line_ranges=string_lines,
    )


def parse_files(paths: list[Path]) -> list[ParsedFile]:
    """Parse a list of Python files, skipping any that fail to parse."""
    results: list[ParsedFile] = []
    for p in paths:
        pf = parse_file(p)
        if pf is not None:
            results.append(pf)
    return results


def enclosing_function(
    node: ast.AST,
    parent_map: dict[int, ast.AST],
) -> str:
    """Walk up the parent map to find the enclosing function name.

    Returns ``"<module>"`` if the node is at module level.
    """
    current: ast.AST | None = parent_map.get(id(node))
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current.name
        current = parent_map.get(id(current))
    return "<module>"


def ensure_parsed(
    files: Sequence[Path | ParsedFile] | None,
    fallback: list[Path] | None = None,
) -> list[ParsedFile]:
    """Accept raw ``Path`` list, ``ParsedFile`` list, or ``None``.

    Returns a ``ParsedFile`` list.  When *files* is ``None``, falls back
    to *fallback* (which should be an already-discovered path list).
    """
    if files is None:
        if fallback is not None:
            return parse_files(fallback)
        return []
    if not files:
        return []
    first = files[0]
    if isinstance(first, ParsedFile):
        return [f for f in files if isinstance(f, ParsedFile)]
    return parse_files([f for f in files if isinstance(f, Path)])
