"""Shared helpers for enrichment package internals.

These helpers intentionally keep failures silent (best effort) to avoid
breaking the hook pipeline.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING

from vibeforcer.constants import ENRICHMENT_MAX_READ_BYTES

if TYPE_CHECKING:
    from vibeforcer.context import HookContext
    from vibeforcer.models import RuleFinding


_ast_parse_count = 0


def append_enrichment_message(finding: "RuleFinding", lines: list[str]) -> None:
    """Append enrichment lines to a finding message."""
    if not lines:
        return
    base_message = finding.message or ""
    finding.message = base_message.rstrip() + "\n" + "\n".join(lines)


def first_target_content(ctx: "HookContext") -> str:
    """Return the content of the first target, if available."""
    for target in ctx.content_targets:
        return target.content
    return ""


def safe_read(path: Path, max_bytes: int = ENRICHMENT_MAX_READ_BYTES) -> str:
    """Read a file, returning empty string on any error."""
    try:
        if path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def safe_parse(source: str) -> ast.Module | None:
    """Parse Python source, returning ``None`` on syntax errors."""
    global _ast_parse_count
    _ast_parse_count += 1
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def reset_parse_count() -> None:
    """Reset the package-level AST parse counter."""
    global _ast_parse_count
    _ast_parse_count = 0


def get_parse_count() -> int:
    """Return the number of ``_safe_parse`` calls since the last reset."""
    return _ast_parse_count


def resolve_path(path_str: str, root: Path) -> Path:
    """Resolve a possibly-relative path against ``root``."""
    path = Path(path_str)
    if path.is_absolute():
        return path
    return (root / path).resolve()


def relative_path(path: Path, root: Path) -> str:
    """Return a path relative to root when possible."""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
