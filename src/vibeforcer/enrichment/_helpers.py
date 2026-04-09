"""Shared helpers for enrichment package internals.

These helpers intentionally keep failures silent (best effort) to avoid
breaking the hook pipeline.
"""

from __future__ import annotations

import ast
from pathlib import Path

from vibeforcer.constants import ENRICHMENT_MAX_READ_BYTES


def _safe_read(path: Path, max_bytes: int = ENRICHMENT_MAX_READ_BYTES) -> str:
    """Read a file, returning empty string on any error."""
    try:
        if path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _safe_parse(source: str) -> ast.Module | None:
    """Parse Python source, returning ``None`` on syntax errors."""
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def _resolve_path(path_str: str, root: Path) -> Path:
    """Resolve a possibly-relative path against ``root``."""
    path = Path(path_str)
    if path.is_absolute():
        return path
    return (root / path).resolve()


def _is_under(path: Path, root: Path) -> bool:
    """Return ``True`` if ``path`` is inside ``root``."""
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
