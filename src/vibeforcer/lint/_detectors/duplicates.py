"""Detectors for code duplication.

- ``detect_semantic_clones``: functions with identical AST structure
- ``detect_repeated_literals``: magic numbers and strings used excessively
- ``detect_repeated_blocks``: repeated consecutive statement blocks
- ``detect_duplicate_call_sequences``: functions with identical call patterns
"""

from __future__ import annotations

import ast
import copy
import hashlib
from collections import defaultdict
from collections.abc import Callable, Hashable, Set
from pathlib import Path
from typing import TypeGuard, TypeVar, cast
from typing_extensions import override

from vibeforcer.lint._baseline import Violation
from vibeforcer.lint._config import get_config
from vibeforcer.lint._helpers import (
    ParsedFile,
    ensure_parsed,
    find_source_files,
    function_body_lines,
)
from .wrappers import call_name


_BUILTINS = frozenset(
    {
        "len",
        "range",
        "print",
        "str",
        "int",
        "float",
        "bool",
        "list",
        "dict",
        "set",
        "tuple",
        "type",
        "isinstance",
        "issubclass",
        "hasattr",
        "getattr",
        "setattr",
        "delattr",
        "super",
        "property",
        "staticmethod",
        "classmethod",
        "enumerate",
        "zip",
        "map",
        "filter",
        "sorted",
        "reversed",
        "min",
        "max",
        "sum",
        "any",
        "all",
        "abs",
        "round",
        "repr",
        "hash",
        "id",
        "callable",
        "iter",
        "next",
        "open",
        "ValueError",
        "TypeError",
        "KeyError",
        "AttributeError",
        "RuntimeError",
        "NotImplementedError",
        "StopIteration",
        "Exception",
        "True",
        "False",
        "None",
    }
)

_SKIP_DECORATORS = frozenset({"abstractmethod", "overload", "property"})

_CONSTANT_TYPE_MAP: dict[type, str] = {
    bool: "BOOL",
    int: "INT",
    float: "FLOAT",
    str: "STR",
    bytes: "BYTES",
}


class _Normalizer(ast.NodeTransformer):
    """Transform an AST subtree into a canonical form for structural comparison."""

    def __init__(self) -> None:
        self._name_map: dict[str, str] = {}
        self.call_func_ids: set[int] = set()

    @override
    def visit_Name(self, node: ast.Name) -> ast.Name:
        if id(node) not in self.call_func_ids and node.id not in _BUILTINS:
            node.id = self._name_map.setdefault(node.id, f"v{len(self._name_map)}")
        return node

    @override
    def visit_Constant(self, node: ast.Constant) -> ast.Constant:
        # bool must be checked before int (bool is a subclass of int)
        for typ, token in _CONSTANT_TYPE_MAP.items():
            if isinstance(node.value, typ):
                node.value = token
                return node
        if node.value is None:
            node.value = "NONE"
        return node

    @override
    def visit_arg(self, node: ast.arg) -> ast.arg:
        node.arg = self._name_map.setdefault(node.arg, f"v{len(self._name_map)}")
        node.annotation = None
        visited = self.generic_visit(node)
        if not isinstance(visited, ast.arg):
            raise TypeError("expected ast.arg from generic_visit")
        return visited

    @override
    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        node.name = self._name_map.setdefault(node.name, f"v{len(self._name_map)}")
        node.returns = None
        node.decorator_list = []
        visited = self.generic_visit(node)
        if not isinstance(visited, ast.FunctionDef):
            raise TypeError("expected ast.FunctionDef from generic_visit")
        return visited

    @override
    def visit_AsyncFunctionDef(
        self, node: ast.AsyncFunctionDef
    ) -> ast.AsyncFunctionDef:
        node.name = self._name_map.setdefault(node.name, f"v{len(self._name_map)}")
        node.returns = None
        node.decorator_list = []
        visited = self.generic_visit(node)
        if not isinstance(visited, ast.AsyncFunctionDef):
            raise TypeError("expected ast.AsyncFunctionDef from generic_visit")
        return visited


def _normalize_ast(node: ast.AST) -> str:
    """Produce a canonical string from an AST subtree."""
    tree = copy.deepcopy(node)
    normalizer = _Normalizer()
    for child in ast.walk(tree):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
            normalizer.call_func_ids.add(id(child.func))
    _ = cast(object, normalizer.visit(tree))
    _ = ast.fix_missing_locations(tree)
    return ast.dump(tree)


def _structure_hash(canonical: str) -> str:
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _is_import_stmt(stmt: ast.stmt) -> bool:
    """Return True when *stmt* is a plain or from-import statement."""
    return isinstance(stmt, (ast.Import, ast.ImportFrom))


def _is_future_import(stmt: ast.stmt) -> bool:
    """Return True when *stmt* is ``from __future__ import ...``."""
    return isinstance(stmt, ast.ImportFrom) and stmt.module == "__future__"


def _strip_future_imports(body: list[ast.stmt]) -> list[ast.stmt]:
    """Remove leading ``from __future__ import ...`` statements from *body*."""
    return [s for s in body if not _is_future_import(s)]


def _skip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    """Return body with the leading docstring removed, if present."""
    if not body:
        return body
    first = body[0]
    is_doc = (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    )
    return body[1:] if is_doc else body


def _has_skip_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name):
            name = dec.id
        elif isinstance(dec, ast.Attribute):
            name = dec.attr
        else:
            name = ""
        if name in _SKIP_DECORATORS:
            return True
    return False


def _is_docstring_node(node: ast.Constant, parent_map: dict[int, ast.AST]) -> bool:
    if not isinstance(node.value, str):
        return False
    parent = parent_map.get(id(node))
    if not isinstance(parent, ast.Expr):
        return False
    gp = parent_map.get(id(parent))
    if not isinstance(
        gp, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)
    ):
        return False
    return bool(gp.body) and gp.body[0] is parent


_FUNC_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef)


def _is_clone_candidate(
    node: ast.AST,
    min_lines: int,
) -> TypeGuard[ast.FunctionDef | ast.AsyncFunctionDef]:
    """True if node is a function suitable for clone detection."""
    if not isinstance(node, _FUNC_TYPES):
        return False
    if node.name.startswith("__") and node.name.endswith("__"):
        return False
    if _has_skip_decorator(node):
        return False
    return function_body_lines(node) >= min_lines


def _end_lineno(node: ast.stmt, fallback: int) -> int:
    """Return end_lineno if available, else fallback."""
    return node.end_lineno if node.end_lineno is not None else fallback


_K = TypeVar("_K", bound=Hashable)


def _emit_group_violations(
    rule: str,
    groups: dict[_K, list[tuple[str, str, int]]],
    detail_fn: Callable[[_K, list[str]], str],
) -> list[Violation]:
    """Emit one violation per member for each group with 2+ members."""
    violations: list[Violation] = []
    for key, members in groups.items():
        if len(members) < 2:
            continue
        for rel, name, _ in members:
            others = [f"{r}:{n}" for r, n, _ in members if r != rel or n != name]
            violations.append(
                Violation(
                    rule=rule,
                    relative_path=rel,
                    identifier=name,
                    detail=detail_fn(key, others),
                )
            )
    return violations


def detect_semantic_clones(
    files: list[Path] | list[ParsedFile] | None = None,
) -> list[Violation]:
    """Find functions with identical AST structure despite different names."""
    cfg = get_config()
    min_lines = cfg.min_function_body_lines
    parsed = ensure_parsed(files, fallback=find_source_files())

    groups: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
    for pf in parsed:
        for node in ast.walk(pf.tree):
            if not _is_clone_candidate(node, min_lines):
                continue
            body = _skip_docstring(node.body)
            if not body:
                continue
            canonical = "|".join(_normalize_ast(stmt) for stmt in body)
            h = _structure_hash(canonical)
            groups[h].append((pf.rel, node.name, node.lineno))

    return _emit_group_violations(
        "semantic-clone",
        groups,
        lambda h, others: f"hash={h}, clones: {', '.join(others[:3])}",
    )


def _collect_literals(
    parsed: list[ParsedFile],
    allowed_nums: Set[int | float],
    allowed_strs: set[str],
) -> tuple[dict[int | float, set[str]], dict[str, set[str]]]:
    """Walk ASTs and count non-allowed literal occurrences per file."""
    num_counts: dict[int | float, set[str]] = defaultdict(set)
    str_counts: dict[str, set[str]] = defaultdict(set)

    for pf in parsed:
        for node in ast.walk(pf.tree):
            if not isinstance(node, ast.Constant):
                continue
            if isinstance(node.value, bool) or _is_docstring_node(node, pf.parent_map):
                continue
            val = node.value
            if isinstance(val, (int, float)) and val not in allowed_nums:
                num_counts[val].add(pf.rel)
            elif isinstance(val, str) and val not in allowed_strs:
                str_counts[val].add(pf.rel)

    return num_counts, str_counts


def detect_repeated_literals(
    files: list[Path] | list[ParsedFile] | None = None,
) -> list[Violation]:
    """Flag magic numbers and string literals used excessively."""
    cfg = get_config()
    parsed = ensure_parsed(files, fallback=find_source_files())
    num_counts, str_counts = _collect_literals(
        parsed, cfg.allowed_numbers, cfg.allowed_strings
    )

    violations: list[Violation] = []
    for val, fset in num_counts.items():
        if len(fset) > cfg.max_repeated_magic_numbers:
            violations.append(
                Violation(
                    rule="repeated-magic-number",
                    relative_path="<project>",
                    identifier=repr(val),
                    detail=f"appears in {len(fset)} files (max: {cfg.max_repeated_magic_numbers})",
                )
            )
    for val, fset in str_counts.items():
        if len(fset) > cfg.max_repeated_string_literals:
            violations.append(
                Violation(
                    rule="repeated-string-literal",
                    relative_path="<project>",
                    identifier=repr(val)[:40],
                    detail=f"appears in {len(fset)} files (max: {cfg.max_repeated_string_literals})",
                )
            )
    return violations


_MIN_BLOCK_SIZE = 3


def _collect_block_windows(
    parsed: list[ParsedFile],
) -> dict[str, list[tuple[str, str, int, int]]]:
    """Hash sliding windows of consecutive statements across all scopes."""
    groups: dict[str, list[tuple[str, str, int, int]]] = defaultdict(list)
    for pf in parsed:
        for node in ast.walk(pf.tree):
            if isinstance(node, _FUNC_TYPES):
                body, scope = _skip_docstring(node.body), node.name
            elif isinstance(node, ast.Module):
                body, scope = _strip_future_imports(node.body), "<module>"
            else:
                continue
            if len(body) < _MIN_BLOCK_SIZE:
                continue
            norms = [_normalize_ast(stmt) for stmt in body]
            for i in range(len(norms) - _MIN_BLOCK_SIZE + 1):
                if all(_is_import_stmt(body[j]) for j in range(i, i + _MIN_BLOCK_SIZE)):
                    continue
                h = _structure_hash("|".join(norms[i : i + _MIN_BLOCK_SIZE]))
                end = _end_lineno(body[i + _MIN_BLOCK_SIZE - 1], body[i].lineno)
                groups[h].append((pf.rel, scope, body[i].lineno, end))
    return groups


def detect_repeated_blocks(
    files: list[Path] | list[ParsedFile] | None = None,
) -> list[Violation]:
    """Find blocks of consecutive statements that appear in multiple places."""
    parsed = ensure_parsed(files, fallback=find_source_files())
    groups = _collect_block_windows(parsed)

    violations: list[Violation] = []
    for h, members in groups.items():
        if len(members) < 2:
            continue
        for rel, scope, start, end in members:
            violations.append(
                Violation(
                    rule="repeated-code-block",
                    relative_path=rel,
                    identifier=scope,
                    detail=f"lines {start}-{end}, block hash {h}",
                )
            )
    return violations


def _extract_call_sequence(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, ...]:
    """Extract the ordered sequence of call target names from a function."""
    calls: list[tuple[int, str]] = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        name = call_name(child)
        if not name:
            continue
        for prefix in ("self.", "cls."):
            if name.startswith(prefix):
                name = name[len(prefix) :]
                break
        calls.append((child.lineno, name))
    calls.sort(key=lambda c: c[0])
    return tuple(name for _, name in calls)


def detect_duplicate_call_sequences(
    files: list[Path] | list[ParsedFile] | None = None,
) -> list[Violation]:
    """Find functions that make the same ordered sequence of calls."""
    cfg = get_config()
    min_len = cfg.min_call_sequence_length
    parsed = ensure_parsed(files, fallback=find_source_files())

    groups: dict[tuple[str, ...], list[tuple[str, str, int]]] = defaultdict(list)
    for pf in parsed:
        for node in ast.walk(pf.tree):
            if not isinstance(node, _FUNC_TYPES):
                continue
            seq = _extract_call_sequence(node)
            if len(seq) >= min_len:
                groups[seq].append((pf.rel, node.name, node.lineno))

    return _emit_group_violations(
        "duplicate-call-sequence",
        groups,
        lambda seq, others: (
            f"calls [{', '.join(seq[:5])}{'...' if len(seq) > 5 else ''}], "
            f"shared with {', '.join(others[:3])}"
        ),
    )
