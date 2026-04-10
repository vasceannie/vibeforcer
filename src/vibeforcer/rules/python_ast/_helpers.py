from __future__ import annotations

import ast
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from vibeforcer.models import RuleFinding
from vibeforcer.rules.base import Rule, is_rule_enabled
from vibeforcer.util.payloads import is_bash_tool, is_edit_like_tool

if TYPE_CHECKING:
    from vibeforcer.context import HookContext

    CheckFn = Callable[[str, str, "HookContext"], list[RuleFinding]]


# Paths containing any of these segments are third-party / vendored code
# and should be excluded from quality analysis.
_THIRD_PARTY_SEGMENTS = (
    ".venv/",
    "site-packages/",
    "node_modules/",
    ".tox/",
    ".nox/",
    "/.eggs/",
)

# Prefixes that signal a function family (parse_*, build_*, validate_*, …)
_FAMILY_PREFIXES = (
    "parse_",
    "build_",
    "create_",
    "make_",
    "get_",
    "set_",
    "validate_",
    "check_",
    "format_",
    "render_",
    "load_",
    "save_",
    "encode_",
    "decode_",
    "serialize_",
    "deserialize_",
)


def _is_third_party_path(path: str) -> bool:
    """Return True if path points to third-party / vendored code."""
    normalised = path.replace("\\", "/")
    return any(seg in normalised for seg in _THIRD_PARTY_SEGMENTS)


def decision_for_context(ctx: HookContext) -> str:
    return "deny" if ctx.event_name in ("PreToolUse", "PermissionRequest") else "block"


def parse_module(source: str, max_chars: int) -> ast.Module | None:
    """Parse source into an AST module, respecting size limit."""
    if len(source) > max_chars:
        return None
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def evaluate_common(
    rule: Rule,
    ctx: HookContext,
    check_fn: CheckFn,
) -> list[RuleFinding]:
    """Shared evaluate logic for all Python AST rules."""
    if not is_rule_enabled(ctx, rule.rule_id):
        return []
    if not ctx.config.python_ast_enabled:
        return []
    findings: list[RuleFinding] = []
    is_pre = ctx.event_name in ("PreToolUse", "PermissionRequest")
    if is_pre:
        for ct in ctx.content_targets:
            if not ct.path.lower().endswith((".py", ".pyi")):
                continue
            if _is_third_party_path(ct.path):
                continue
            findings.extend(check_fn(ct.content, ct.path, ctx))
    else:
        # Only run PostToolUse AST analysis for edit-like/bash tools, not Read/Grep/Glob
        if not (is_edit_like_tool(ctx.tool_name) or is_bash_tool(ctx.tool_name)):
            return []
        for path_value in ctx.candidate_paths:
            if not path_value.lower().endswith((".py", ".pyi")):
                continue
            # Skip third-party / vendored code — not authored by the agent
            if _is_third_party_path(path_value):
                continue
            full_path = (
                (ctx.config.root / path_value).resolve()
                if not Path(path_value).is_absolute()
                else Path(path_value)
            )
            try:
                source = full_path.read_text(encoding="utf-8")
            except OSError:
                continue
            findings.extend(check_fn(source, path_value, ctx))
    return findings


def detect_family_prefix(names: list[str]) -> str | None:
    """Return the shared prefix if 3+ names share one, else None."""
    prefix_counts: Counter[str] = Counter()
    for name in names:
        for prefix in _FAMILY_PREFIXES:
            if name.startswith(prefix):
                prefix_counts[prefix] += 1
                break
    for prefix, count in prefix_counts.most_common(1):
        if count >= 3:
            return prefix
    return None
