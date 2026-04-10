"""Local enrichment for silent-except rule (PY-EXC-002)."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from vibeforcer.enrichment._helpers import (
    append_enrichment_message,
    first_target_content,
    safe_parse,
)

if TYPE_CHECKING:
    from vibeforcer.context import HookContext
    from vibeforcer.models import RuleFinding


def _extract_called_functions(tree: ast.AST) -> list[str]:
    called: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            if isinstance(child.func, ast.Name):
                called.append(child.func.id)
                continue
            if isinstance(child.func, ast.Attribute):
                called.append(child.func.attr)
    unique: list[str] = []
    for name in called:
        if name not in unique:
            unique.append(name)
    return unique[:5]


def enrich_silent_except(finding: RuleFinding, ctx: HookContext) -> None:
    """Enrich PY-EXC-002 with specific exception guidance."""
    paths = finding.metadata.get("hits", [])
    if not paths:
        return

    content = first_target_content(ctx)
    extras: list[str] = []

    if content:
        tree = safe_parse(content)
        if tree is not None:
            called = _extract_called_functions(tree)
            if called:
                formatted = ", ".join(f"`{name}`" for name in called)
                extras.append(f"\nFunctions called in try block: {formatted}")
                extras.append(
                    "Check what exceptions these functions raise and catch those specifically."
                )

    extras.append(
        "\nCommon specific exceptions:\n"
        + "  • File I/O: `FileNotFoundError`, `PermissionError`, `IsADirectoryError`\n"
        + "  • Network: `ConnectionError`, `TimeoutError`, `httpx.HTTPError`\n"
        + "  • Parsing: `json.JSONDecodeError`, `ValueError`, `KeyError`\n"
        + "  • Encoding: `UnicodeDecodeError`, `UnicodeEncodeError`"
    )

    append_enrichment_message(finding, extras)
