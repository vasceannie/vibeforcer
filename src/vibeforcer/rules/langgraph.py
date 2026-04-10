"""LangGraph framework-specific rules.

All rules are advisory (additionalContext only, never decision:block)
because PostToolUse cannot prevent the edit — it already happened.
These nudge Claude toward LangGraph best practices without halting.
"""

from __future__ import annotations

import ast
import re
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from vibeforcer.models import RuleFinding, Severity
from vibeforcer.rules.base import Rule, is_rule_enabled
from vibeforcer.util.payloads import is_edit_like_tool, is_bash_tool

if TYPE_CHECKING:
    from vibeforcer.context import HookContext


_DEPENDENCY_FILES = (
    "pyproject.toml",
    "requirements.txt",
    "requirements.in",
    "requirements-dev.txt",
    "setup.py",
    "setup.cfg",
)

_LANGGRAPH_SOURCE_MARKERS = ("from langgraph", "import langgraph", "StateGraph")


@lru_cache(maxsize=16)
def _is_langgraph_project(cwd: str) -> bool:
    """Check if the project declares langgraph as a dependency.

    Result is cached per cwd to avoid redundant disk reads when
    multiple LangGraph rules evaluate against the same project.
    """
    root = Path(cwd)
    for name in _DEPENDENCY_FILES:
        dep_file = root / name
        if not dep_file.exists():
            continue
        try:
            text = dep_file.read_text(encoding="utf-8")
        except OSError:
            continue
        if "langgraph" in text.lower():
            return True
    return False


def _is_langgraph_context(source: str | None, cwd: str) -> bool:
    """Return True if the source or project is LangGraph-related."""
    if source is not None:
        if any(marker in source for marker in _LANGGRAPH_SOURCE_MARKERS):
            return True
    return _is_langgraph_project(cwd)


def _read_source(path_value: str, ctx: HookContext) -> str | None:
    """Read source safely, return None on failure or oversized files."""
    max_chars = 200_000
    if not path_value.lower().endswith((".py", ".pyi")):
        return None
    full = (
        (ctx.config.root / path_value).resolve()
        if not Path(path_value).is_absolute()
        else Path(path_value)
    )
    if not full.exists():
        return None
    try:
        source = full.read_text(encoding="utf-8")
    except OSError:
        return None
    return source if len(source) <= max_chars else None


def _is_applicable_tool(ctx: HookContext) -> bool:
    """Return True if the tool is an edit or bash tool."""
    return is_edit_like_tool(ctx.tool_name) or is_bash_tool(ctx.tool_name)


def _iter_langgraph_sources(
    ctx: HookContext,
) -> list[tuple[str, str]]:
    """Yield (path, source) pairs for candidate paths in a LangGraph context."""
    pairs: list[tuple[str, str]] = []
    cwd = str(ctx.cwd)
    for path_value in ctx.candidate_paths:
        source = _read_source(path_value, ctx)
        if source is None:
            continue
        if not _is_langgraph_context(source, cwd):
            continue
        pairs.append((path_value, source))
    return pairs


# ---------------------------------------------------------------------------
# AST helpers for state reducer detection
# ---------------------------------------------------------------------------


def _is_typed_dict_base(base: ast.expr) -> bool:
    """Check if an AST base class node refers to TypedDict."""
    match base:
        case ast.Name(id="TypedDict"):
            return True
        case ast.Attribute(attr="TypedDict"):
            return True
        case ast.Call(func=ast.Name(id="TypedDict")):
            return True
        case _:
            return False


def _is_bare_list_annotation(ann: ast.expr) -> bool:
    """Return True if annotation is a bare ``list`` or ``list[X]``."""
    match ann:
        case ast.Name(id="list"):
            return True
        case ast.Subscript(value=ast.Name(id="list")):
            return True
        case _:
            return False


def _is_annotated_wrapper(ann: ast.expr) -> bool:
    """Return True if annotation is ``Annotated[...]``."""
    if isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name):
        return ann.value.id == "Annotated"
    return False


def _bare_list_fields(class_node: ast.ClassDef) -> list[str]:
    """Collect names of list-typed fields missing an Annotated reducer."""
    fields: list[str] = []
    for item in class_node.body:
        if not isinstance(item, ast.AnnAssign):
            continue
        if not isinstance(item.target, ast.Name):
            continue
        ann = item.annotation
        if _is_bare_list_annotation(ann) and not _is_annotated_wrapper(ann):
            fields.append(item.target.id)
    return fields


def _find_reducer_findings(
    path_value: str,
    source: str,
    rule: LangGraphStateReducerRule,
) -> list[RuleFinding]:
    """Scan parsed source for TypedDict classes with bare list fields."""
    try:
        module = ast.parse(source)
    except SyntaxError:
        return []
    findings: list[RuleFinding] = []
    for node in ast.walk(module):
        if not isinstance(node, ast.ClassDef):
            continue
        if not any(_is_typed_dict_base(b) for b in node.bases):
            continue
        bare = _bare_list_fields(node)
        if not bare:
            continue
        fields_str = ", ".join(f"`{f}`" for f in bare[:5])
        findings.append(
            RuleFinding(
                rule_id=rule.rule_id,
                title=rule.title,
                severity=Severity.LOW,
                additional_context=(
                    f"LangGraph state class `{node.name}` in `{path_value}` "
                    f"has list fields without reducers: {fields_str}. "
                    f"Consider using `Annotated[list[X], operator.add]` or "
                    f"`Annotated[list[AnyMessage], add_messages]` for "
                    f"automatic accumulation."
                ),
                metadata={
                    "class": node.name,
                    "fields": bare,
                    "path": path_value,
                },
            )
        )
    return findings


class LangGraphStateReducerRule(Rule):
    """Detect TypedDict state schemas with list fields missing reducers."""

    rule_id = "LG-STATE-001"
    title = "LangGraph state list field without reducer"
    events = ("PostToolUse",)

    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id) or not _is_applicable_tool(ctx):
            return []
        findings: list[RuleFinding] = []
        for path_value, source in _iter_langgraph_sources(ctx):
            findings.extend(_find_reducer_findings(path_value, source, self))
        return findings


# ---------------------------------------------------------------------------
# State mutation detection
# ---------------------------------------------------------------------------

# Compiled once at import time — patterns that indicate direct state mutation.
# These are regex *definitions*, not actual state mutation code.
_STATE_MUTATION_PATTERNS = [
    re.compile(r"\bstate\s*\[.+\]\s*="),
    re.compile(r"\bstate\s*\[.+\]\.append\b"),
    re.compile(r"\bstate\s*\[.+\]\.extend\b"),
    re.compile(r"\bstate\s*\[.+\]\.update\b"),
    re.compile(r"\bstate\.update\s*\("),
    re.compile(r"\bstate\s*\[.+\]\.pop\b"),
    re.compile(r"\bstate\s*\[.+\]\.clear\b"),
    re.compile(r"\bstate\s*\[.+\]\s*\+="),
]


def _find_mutations(source: str) -> list[tuple[int, str]]:
    """Scan source lines for state mutation patterns."""
    mutations: list[tuple[int, str]] = []
    for i, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pattern in _STATE_MUTATION_PATTERNS:
            if pattern.search(line):
                mutations.append((i, stripped[:80]))
                break
    return mutations


def _mutation_finding(
    path_value: str,
    mutations: list[tuple[int, str]],
    rule: LangGraphStateMutationRule,
) -> RuleFinding:
    """Build a single finding from detected mutations."""
    examples = mutations[:3]
    example_str = "; ".join(f"L{ln}: {code}" for ln, code in examples)
    return RuleFinding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=Severity.MEDIUM,
        additional_context=(
            f"Possible direct state mutation in `{path_value}`: "
            f"{example_str}. LangGraph nodes should return partial "
            f'state updates (e.g., return {{"field": new_value}}) '
            f"instead of mutating state directly. Direct mutation can "
            f"cause checkpoint corruption and non-deterministic behavior."
        ),
        metadata={
            "path": path_value,
            "mutation_count": len(mutations),
            "examples": [m[1] for m in examples],
        },
    )


class LangGraphStateMutationRule(Rule):
    """Detect direct state mutation in LangGraph node functions."""

    rule_id = "LG-NODE-001"
    title = "Direct state mutation in LangGraph node"
    events = ("PostToolUse",)

    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id) or not _is_applicable_tool(ctx):
            return []
        findings: list[RuleFinding] = []
        for path_value, source in _iter_langgraph_sources(ctx):
            mutations = _find_mutations(source)
            if mutations:
                findings.append(_mutation_finding(path_value, mutations, self))
        return findings


# ---------------------------------------------------------------------------
# Deprecated API detection
# ---------------------------------------------------------------------------

_DEPRECATED_APIS = [
    (
        re.compile(r"\.set_entry_point\s*\("),
        "set_entry_point()",
        'add_edge(START, "node")',
    ),
    (
        re.compile(r"\.set_finish_point\s*\("),
        "set_finish_point()",
        'add_edge("node", END)',
    ),
]


class LangGraphDeprecatedAPIRule(Rule):
    """Flag deprecated LangGraph API usage."""

    rule_id = "LG-API-001"
    title = "Deprecated LangGraph API usage"
    events = ("PostToolUse",)

    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id) or not _is_applicable_tool(ctx):
            return []
        findings: list[RuleFinding] = []
        for path_value, source in _iter_langgraph_sources(ctx):
            for pattern, old_api, new_api in _DEPRECATED_APIS:
                if pattern.search(source):
                    findings.append(
                        RuleFinding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=Severity.LOW,
                            additional_context=(
                                f"`{old_api}` in `{path_value}` is the older "
                                f"LangGraph API. Consider using `{new_api}` "
                                f"instead."
                            ),
                            metadata={
                                "path": path_value,
                                "old_api": old_api,
                                "new_api": new_api,
                            },
                        )
                    )
        return findings
