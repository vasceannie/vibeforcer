"""LangGraph framework-specific rules.

All rules are advisory (additionalContext only, never decision:block)
because PostToolUse cannot prevent the edit — it already happened.
These nudge Claude toward LangGraph best practices without halting.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from vibeforcer.models import RuleFinding, Severity
from vibeforcer.rules.base import Rule
from vibeforcer.util.payloads import is_edit_like_tool, is_bash_tool


def _is_enabled(ctx: "HookContext", rule_id: str, default: bool = True) -> bool:
    value = ctx.config.enabled_rules.get(rule_id)
    return default if value is None else bool(value)


def _is_langgraph_project(cwd: str) -> bool:
    """Check if the project declares langgraph as a dependency.

    Scans pyproject.toml, requirements*.txt, setup.py, and setup.cfg
    for a langgraph dependency declaration.
    """

    from pathlib import Path as _Path
    root = _Path(cwd)
    result = False

    # Check pyproject.toml
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            text = pyproject.read_text(encoding="utf-8")
            if "langgraph" in text.lower():
                result = True
        except OSError:
            pass

    # Check requirements files
    if not result:
        for name in ("requirements.txt", "requirements.in", "requirements-dev.txt"):
            req = root / name
            if req.exists():
                try:
                    text = req.read_text(encoding="utf-8")
                    if "langgraph" in text.lower():
                        result = True
                        break
                except OSError:
                    pass

    # Check setup.py / setup.cfg
    if not result:
        for name in ("setup.py", "setup.cfg"):
            setup = root / name
            if setup.exists():
                try:
                    text = setup.read_text(encoding="utf-8")
                    if "langgraph" in text.lower():
                        result = True
                        break
                except OSError:
                    pass

    return result


def _is_langgraph_file(path: str, source: str | None = None) -> bool:
    """Check if a file belongs to a LangGraph project.

    Returns True only if the project declares langgraph as a dependency.
    This avoids false positives on non-LangGraph projects that happen
    to have graph/ directories or TypedDict state classes.
    """
    # Fast path: if source contains direct langgraph references, it is one
    if source is not None and any(marker in source for marker in (
        "from langgraph",
        "import langgraph",
        "StateGraph",
    )):
        return True
    # Otherwise: not detectable from file alone, defer to project check
    return False


def _read_source(path_value: str, ctx: "HookContext", max_chars: int = 200_000) -> str | None:
    """Read source safely, return None on failure."""
    full = (
        (ctx.config.root / path_value).resolve()
        if not Path(path_value).is_absolute()
        else Path(path_value)
    )
    if not full.exists() or not path_value.lower().endswith((".py", ".pyi")):
        return None
    try:
        source = full.read_text(encoding="utf-8")
    except OSError:
        return None
    return source if len(source) <= max_chars else None


class LangGraphStateReducerRule(Rule):
    """Detect TypedDict state schemas with list fields missing reducers.

    LangGraph best practice: list fields in state schemas should use
    Annotated[list[X], add] or Annotated[list[X], add_messages] to
    enable automatic accumulation instead of manual copy-extend-return.
    """

    rule_id = "LG-STATE-001"
    title = "LangGraph state list field without reducer"
    events = ("PostToolUse",)

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not _is_enabled(ctx, self.rule_id):
            return []
        if not (is_edit_like_tool(ctx.tool_name) or is_bash_tool(ctx.tool_name)):
            return []
        findings: list[RuleFinding] = []
        for path_value in ctx.candidate_paths:
            source = _read_source(path_value, ctx)
            if not _is_langgraph_file(path_value, source) and not _is_langgraph_project(ctx.cwd):
                continue
            if source is None:
                continue
            try:
                module = ast.parse(source)
            except SyntaxError:
                continue
            for node in ast.walk(module):
                if not isinstance(node, ast.ClassDef):
                    continue
                # Check if it inherits from TypedDict
                is_typed_dict = any(
                    (isinstance(b, ast.Name) and b.id == "TypedDict")
                    or (isinstance(b, ast.Attribute) and b.attr == "TypedDict")
                    or (
                        isinstance(b, ast.Call)
                        and isinstance(b.func, ast.Name)
                        and b.func.id == "TypedDict"
                    )
                    for b in node.bases
                )
                if not is_typed_dict:
                    continue
                # Check for list fields without Annotated reducers
                bare_list_fields: list[str] = []
                for item in node.body:
                    if not isinstance(item, ast.AnnAssign):
                        continue
                    if not isinstance(item.target, ast.Name):
                        continue
                    field_name = item.target.id
                    ann = item.annotation
                    # Check if annotation is a bare list type (list[X])
                    is_list = (
                        (isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name) and ann.value.id == "list")
                        or (isinstance(ann, ast.Name) and ann.id == "list")
                    )
                    # Check if it's wrapped in Annotated (has a reducer)
                    is_annotated = (
                        isinstance(ann, ast.Subscript)
                        and isinstance(ann.value, ast.Name)
                        and ann.value.id == "Annotated"
                    )
                    if is_list and not is_annotated:
                        bare_list_fields.append(field_name)
                if bare_list_fields:
                    fields_str = ", ".join(f"`{f}`" for f in bare_list_fields[:5])
                    findings.append(
                        RuleFinding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=Severity.LOW,
                            additional_context=(
                                f"LangGraph state class `{node.name}` in `{path_value}` has list fields "
                                f"without reducers: {fields_str}. "
                                f"Consider using `Annotated[list[X], operator.add]` or "
                                f"`Annotated[list[AnyMessage], add_messages]` for automatic accumulation "
                                f"instead of manual copy-extend-return patterns."
                            ),
                            metadata={"class": node.name, "fields": bare_list_fields, "path": path_value},
                        )
                    )
        return findings


class LangGraphStateMutationRule(Rule):
    """Detect direct state mutation in LangGraph node functions.

    LangGraph nodes should return partial state updates, never mutate
    the input state directly. Patterns like state["x"] = ...,
    state["x"].append(...), or state.update(...) are bugs.
    """

    rule_id = "LG-NODE-001"
    title = "Direct state mutation in LangGraph node"
    events = ("PostToolUse",)

    # Patterns that indicate state mutation
    _MUTATION_PATTERNS = [
        re.compile(r'\bstate\s*\[.+\]\s*='),          # state["x"] = ...
        re.compile(r'\bstate\s*\[.+\]\.append\b'),     # state["x"].append(...)
        re.compile(r'\bstate\s*\[.+\]\.extend\b'),     # state["x"].extend(...)
        re.compile(r'\bstate\s*\[.+\]\.update\b'),     # state["x"].update(...)
        re.compile(r'\bstate\.update\s*\('),            # state.update(...)
        re.compile(r'\bstate\s*\[.+\]\.pop\b'),        # state["x"].pop(...)
        re.compile(r'\bstate\s*\[.+\]\.clear\b'),      # state["x"].clear()
        re.compile(r'\bstate\s*\[.+\]\s*\+='),         # state["x"] += ...
    ]

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not _is_enabled(ctx, self.rule_id):
            return []
        if not (is_edit_like_tool(ctx.tool_name) or is_bash_tool(ctx.tool_name)):
            return []
        findings: list[RuleFinding] = []
        for path_value in ctx.candidate_paths:
            source = _read_source(path_value, ctx)
            if not _is_langgraph_file(path_value, source) and not _is_langgraph_project(ctx.cwd):
                continue
            if source is None:
                continue
            # Find mutation patterns with line numbers
            mutations: list[tuple[int, str]] = []
            for i, line in enumerate(source.splitlines(), 1):
                stripped = line.strip()
                # Skip comments
                if stripped.startswith("#"):
                    continue
                for pattern in self._MUTATION_PATTERNS:
                    if pattern.search(line):
                        mutations.append((i, stripped[:80]))
                        break
            if mutations:
                examples = mutations[:3]
                example_str = "; ".join(f"L{ln}: {code}" for ln, code in examples)
                findings.append(
                    RuleFinding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        additional_context=(
                            f"Possible direct state mutation in `{path_value}`: {example_str}. "
                            f"LangGraph nodes should return partial state updates (e.g., "
                            f'return {{"field": new_value}}) instead of mutating state directly. '
                            f"Direct mutation can cause checkpoint corruption and non-deterministic behavior."
                        ),
                        metadata={"path": path_value, "mutation_count": len(mutations), "examples": [m[1] for m in examples]},
                    )
                )
        return findings


class LangGraphDeprecatedAPIRule(Rule):
    """Flag deprecated LangGraph API usage.

    set_entry_point() is the old API — use add_edge(START, "node") instead.
    set_finish_point() is the old API — use add_edge("node", END) instead.
    """

    rule_id = "LG-API-001"
    title = "Deprecated LangGraph API usage"
    events = ("PostToolUse",)

    _DEPRECATED = [
        (re.compile(r'\.set_entry_point\s*\('), "set_entry_point()", "add_edge(START, \"node\")"),
        (re.compile(r'\.set_finish_point\s*\('), "set_finish_point()", "add_edge(\"node\", END)"),
    ]

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not _is_enabled(ctx, self.rule_id):
            return []
        if not (is_edit_like_tool(ctx.tool_name) or is_bash_tool(ctx.tool_name)):
            return []
        findings: list[RuleFinding] = []
        for path_value in ctx.candidate_paths:
            if not path_value.lower().endswith(".py"):
                continue
            source = _read_source(path_value, ctx)
            if source is None:
                continue
            if not _is_langgraph_file(path_value, source) and not _is_langgraph_project(ctx.cwd):
                continue
            for pattern, old_api, new_api in self._DEPRECATED:
                if pattern.search(source):
                    findings.append(
                        RuleFinding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=Severity.LOW,
                            additional_context=(
                                f"`{old_api}` in `{path_value}` is the older LangGraph API. "
                                f"Consider using `{new_api}` instead."
                            ),
                            metadata={"path": path_value, "old_api": old_api, "new_api": new_api},
                        )
                    )
        return findings
