"""PY-DUP-001 through PY-DUP-004: Duplicate-code hook rules.

These rules port the lint-only duplicate detectors into reactive hooks so
that repeated code blocks, duplicate call sequences, semantic clones, and
repeated magic numbers are caught at write time, not just at lint time.

Staging: not yet registered in the rule registry.
"""

from __future__ import annotations

import ast
import copy
import hashlib
from collections import defaultdict
from typing import TYPE_CHECKING, final
from typing_extensions import override

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

_BUILTINS = frozenset({
    "len", "range", "print", "str", "int", "float", "bool", "list", "dict",
    "set", "tuple", "type", "isinstance", "issubclass", "hasattr", "getattr",
    "setattr", "delattr", "super", "property", "staticmethod", "classmethod",
    "enumerate", "zip", "map", "filter", "sorted", "reversed", "min", "max",
    "sum", "any", "all", "abs", "round", "repr", "hash", "id", "callable",
    "iter", "next", "open", "ValueError", "TypeError", "KeyError",
    "AttributeError", "RuntimeError", "NotImplementedError", "Exception",
    "True", "False", "None",
})

_SKIP_DECORATORS = frozenset({"abstractmethod", "overload", "property"})

_MIN_BLOCK_SIZE = 3


class _Normalizer(ast.NodeTransformer):
    """Canonicalise an AST subtree for structural comparison."""

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
        if isinstance(node.value, bool):
            node.value = "BOOL"
        elif isinstance(node.value, int):
            node.value = "INT"
        elif isinstance(node.value, float):
            node.value = "FLOAT"
        elif isinstance(node.value, str):
            node.value = "STR"
        elif isinstance(node.value, bytes):
            node.value = "BYTES"
        elif node.value is None:
            node.value = "NONE"
        return node

    @override
    def visit_arg(self, node: ast.arg) -> ast.arg:
        node.arg = self._name_map.setdefault(node.arg, f"v{len(self._name_map)}")
        node.annotation = None
        visited = self.generic_visit(node)
        assert isinstance(visited, ast.arg)
        return visited

    @override
    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        node.name = self._name_map.setdefault(node.name, f"v{len(self._name_map)}")
        node.returns = None
        node.decorator_list = []
        visited = self.generic_visit(node)
        assert isinstance(visited, ast.FunctionDef)
        return visited

    @override
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AsyncFunctionDef:
        node.name = self._name_map.setdefault(node.name, f"v{len(self._name_map)}")
        node.returns = None
        node.decorator_list = []
        visited = self.generic_visit(node)
        assert isinstance(visited, ast.AsyncFunctionDef)
        return visited


def _normalize_ast(node: ast.AST) -> str:
    """Produce a canonical string from an AST subtree."""
    tree = copy.deepcopy(node)
    norm = _Normalizer()
    for child in ast.walk(tree):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
            norm.call_func_ids.add(id(child.func))
    norm.visit(tree)
    ast.fix_missing_locations(tree)
    return ast.dump(tree)


def _structure_hash(canonical: str) -> str:
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _finding_count(finding: RuleFinding) -> int:
    count = finding.metadata.get("count")
    return count if isinstance(count, int) else 0


def _skip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if not body:
        return body
    first = body[0]
    is_doc = (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    )
    return body[1:] if is_doc else body


def _strip_future_imports(body: list[ast.stmt]) -> list[ast.stmt]:
    return [
        s for s in body
        if not (isinstance(s, ast.ImportFrom) and s.module == "__future__")
    ]


def _strip_module_preamble(body: list[ast.stmt]) -> list[ast.stmt]:
    """Remove the contiguous top-of-file docstring/import preamble."""
    idx = 0
    if idx < len(body):
        first = body[idx]
        is_doc = (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        )
        if is_doc:
            idx += 1
    while idx < len(body):
        stmt = body[idx]
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            idx += 1
            continue
        break
    return body[idx:]


def _is_import_stmt(stmt: ast.stmt) -> bool:
    return isinstance(stmt, (ast.Import, ast.ImportFrom))


def _has_skip_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in node.decorator_list:
        name = ""
        if isinstance(dec, ast.Name):
            name = dec.id
        elif isinstance(dec, ast.Attribute):
            name = dec.attr
        if name in _SKIP_DECORATORS:
            return True
    return False


def _call_target_name(node: ast.Call) -> str:
    """Extract a human-readable call target name."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return "<unknown>"


def _extract_call_sequence(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    """Extract ordered sequence of call target names from a function."""
    calls: list[tuple[int, str]] = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        name = _call_target_name(child)
        if not name:
            continue
        for prefix in ("self.", "cls."):
            if name.startswith(prefix):
                name = name[len(prefix):]
                break
        calls.append((child.lineno, name))
    calls.sort(key=lambda c: c[0])
    return tuple(name for _, name in calls)


def _is_docstring_node(node: ast.Constant, parent_map: dict[int, ast.AST]) -> bool:
    if not isinstance(node.value, str):
        return False
    parent = parent_map.get(id(node))
    if not isinstance(parent, ast.Expr):
        return False
    gp = parent_map.get(id(parent))
    if not isinstance(gp, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
        return False
    return bool(gp.body) and gp.body[0] is parent


def _build_parent_map(tree: ast.Module) -> dict[int, ast.AST]:
    """Build id → parent mapping for the AST."""
    parent_map: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_map[id(child)] = parent
    return parent_map


# ---------------------------------------------------------------------------
# PY-DUP-001: Repeated code blocks (inline duplication within a file)
# ---------------------------------------------------------------------------

@final
class PythonRepeatedBlocksRule(Rule):
    """Detect blocks of 3+ consecutive statements that appear multiple times
    in the same file.  Catches copy-paste sprawl at write time.

    This is a single-file check: it only scans the file being written,
    not the whole project.  Full cross-file detection remains a lint-only
    concern (too expensive for a reactive hook).
    """

    rule_id = "PY-DUP-001"
    title = "Block repeated code blocks"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        module = parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []

        # Collect all sliding windows across all scopes in this file
        groups: dict[str, list[tuple[str, int, int]]] = defaultdict(list)
        for node in ast.walk(module):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = _skip_docstring(node.body)
                scope = node.name
            elif isinstance(node, ast.Module):
                body = _strip_module_preamble(node.body)
                scope = "<module>"
            else:
                continue
            if len(body) < _MIN_BLOCK_SIZE:
                continue
            norms = [_normalize_ast(stmt) for stmt in body]
            for i in range(len(norms) - _MIN_BLOCK_SIZE + 1):
                # Skip pure-import blocks
                if all(_is_import_stmt(body[j]) for j in range(i, i + _MIN_BLOCK_SIZE)):
                    continue
                h = _structure_hash("|".join(norms[i : i + _MIN_BLOCK_SIZE]))
                end_lineno = body[i + _MIN_BLOCK_SIZE - 1].end_lineno or body[i].lineno
                groups[h].append((scope, body[i].lineno, end_lineno))

        findings: list[RuleFinding] = []
        for h, members in groups.items():
            if len(members) < 2:
                continue
            # Report the worst offender
            worst = max(members, key=lambda m: m[2] - m[1])
            scope, start, end = worst
            other_locs = [
                f"{s}:{st}-{e}" for s, st, e in members if (s, st, e) != worst
            ]
            findings.append(RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.MEDIUM,
                decision=decision_for_context(ctx),
                message=(
                    f"Repeated code block in `{path_value}` at lines {start}-{end} "
                    f"in `{scope}`. Identical block also appears at: "
                    f"{', '.join(other_locs[:3])}. Extract into a shared helper."
                ),
                metadata={
                    "path": path_value,
                    "scope": scope,
                    "start": start,
                    "end": end,
                    "hash": h,
                    "occurrences": len(members),
                },
            ))
        return findings

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)


# ---------------------------------------------------------------------------
# PY-DUP-002: Duplicate call sequences
# ---------------------------------------------------------------------------

@final
class PythonDuplicateCallSequenceRule(Rule):
    """Detect functions in the same file that make the same ordered sequence
    of calls.  Single-file scope for hook performance.
    """

    rule_id = "PY-DUP-002"
    title = "Block duplicate call sequences"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    _MIN_CALLS = 3  # minimum sequence length to flag

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        module = parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []

        groups: dict[tuple[str, ...], list[tuple[str, int]]] = defaultdict(list)
        for node in ast.walk(module):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            seq = _extract_call_sequence(node)
            if len(seq) >= self._MIN_CALLS:
                groups[seq].append((node.name, node.lineno))

        findings: list[RuleFinding] = []
        for seq, members in groups.items():
            if len(members) < 2:
                continue
            seq_preview = ", ".join(seq[:5]) + ("..." if len(seq) > 5 else "")
            others = [f"{n} (line {l})" for n, l in members[1:]]
            findings.append(RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.MEDIUM,
                decision=decision_for_context(ctx),
                message=(
                    f"Duplicate call sequence in `{path_value}`: "
                    f"`{members[0][0]}` and {len(members) - 1} other function(s) "
                    f"make the same ordered calls [{seq_preview}]. "
                    f"Duplicated in: {', '.join(others[:3])}. Extract shared logic."
                ),
                metadata={
                    "path": path_value,
                    "function": members[0][0],
                    "sequence": list(seq),
                    "duplicates": [n for n, _ in members],
                },
            ))
        return findings

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)


# ---------------------------------------------------------------------------
# PY-DUP-003: Semantic clones (structurally identical functions)
# ---------------------------------------------------------------------------

@final
class PythonSemanticCloneRule(Rule):
    """Detect functions in the same file with identical AST structure
    despite different names.  Catches parameterised copy-paste.
    """

    rule_id = "PY-DUP-003"
    title = "Block semantic clones"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    _MIN_BODY_LINES = 3  # skip trivial one-liners

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        module = parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []

        groups: dict[str, list[tuple[str, int]]] = defaultdict(list)
        for node in ast.walk(module):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Skip dunder methods
            if node.name.startswith("__") and node.name.endswith("__"):
                continue
            if _has_skip_decorator(node):
                continue
            body = _skip_docstring(node.body)
            if not body:
                continue
            # Skip tiny functions
            if node.end_lineno and (node.end_lineno - node.lineno) < self._MIN_BODY_LINES:
                continue
            canonical = "|".join(_normalize_ast(stmt) for stmt in body)
            h = _structure_hash(canonical)
            groups[h].append((node.name, node.lineno))

        findings: list[RuleFinding] = []
        for h, members in groups.items():
            if len(members) < 2:
                continue
            others = [f"{n} (line {l})" for n, l in members[1:]]
            findings.append(RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.MEDIUM,
                decision=decision_for_context(ctx),
                message=(
                    f"Semantic clone in `{path_value}`: `{members[0][0]}` "
                    f"has identical structure to {', '.join(others[:3])}. "
                    f"Parameterise or extract a shared implementation."
                ),
                metadata={
                    "path": path_value,
                    "function": members[0][0],
                    "hash": h,
                    "clones": [n for n, _ in members],
                },
            ))
        return findings

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)


# ---------------------------------------------------------------------------
# PY-DUP-004: Repeated magic numbers (file-local)
# ---------------------------------------------------------------------------

@final
class PythonRepeatedMagicNumberRule(Rule):
    """Detect non-trivial numeric constants used more than N times in a file.

    Only scans the file being written.  Excludes common sentinel values
    (0, 1, -1) and docstrings.
    """

    rule_id = "PY-DUP-004"
    title = "Block repeated magic numbers"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    _ALLOWED_NUMBERS = frozenset({0, 1, -1, 0.0, 1.0, -1.0, 2, 2.0})
    _MAX_OCCURRENCES = 3  # flag if a number appears more than this many times

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        module = parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []

        parent_map = _build_parent_map(module)
        counts: dict[int | float, int] = defaultdict(int)

        for node in ast.walk(module):
            if not isinstance(node, ast.Constant):
                continue
            # Skip booleans (they're ints in Python)
            if isinstance(node.value, bool):
                continue
            # Skip docstrings
            if _is_docstring_node(node, parent_map):
                continue
            if isinstance(node.value, (int, float)) and node.value not in self._ALLOWED_NUMBERS:
                counts[node.value] += 1

        findings: list[RuleFinding] = []
        for val, count in counts.items():
            if count > self._MAX_OCCURRENCES:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.LOW,
                    decision=decision_for_context(ctx),
                    message=(
                        f"Magic number {repr(val)} appears {count} times in "
                        f"`{path_value}`. Extract into a named constant."
                    ),
                    metadata={
                        "path": path_value,
                        "value": val,
                        "count": count,
                    },
                ))
        # Only report the worst offender to avoid noise
        if findings:
            return [max(findings, key=_finding_count)]
        return findings

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)
