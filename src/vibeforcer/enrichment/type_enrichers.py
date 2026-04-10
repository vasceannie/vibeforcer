"""Local enrichment helpers for typing-related rule IDs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from vibeforcer.enrichment._helpers import (
    _append_enrichment_message,
    _first_target_content,
)

if TYPE_CHECKING:
    from vibeforcer.context import HookContext
    from vibeforcer.models import RuleFinding


def _is_dict_or_mapping(content: str) -> bool:
    return "dict" in content or "mapping" in content


def _is_callback_or_handler(content: str) -> bool:
    return "def " in content and (
        "callback" in content
        or "callable" in content
        or "func" in content
        or "handler" in content
    )


def _is_duck_typed_class(content: str) -> bool:
    return "class " in content and (
        "__getattr__" in content or "__getitem__" in content
    )


def _enrich_python_any(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-TYPE-001 with nearby type pattern hints."""
    content_hint = _first_target_content(ctx)
    if not content_hint:
        return

    lower = content_hint.lower()
    extras: list[str] = []
    if _is_dict_or_mapping(lower):
        extras.append(
            "\nTIP: For dict-like structures, consider TypedDict:\n"
            "    class UserData(TypedDict):\n"
            "        name: str\n"
            "        email: str"
        )
    if _is_callback_or_handler(lower):
        extras.append(
            "\nTIP: For callbacks/handlers, use Callable with specific signatures:\n"
            "    Callable[[str, int], bool]"
        )
    if _is_duck_typed_class(lower):
        extras.append(
            "\nTIP: For duck-typed interfaces, define a Protocol:\n"
            "    class Readable(Protocol):\n"
            "        def read(self, n: int = -1) -> bytes: ..."
        )

    _append_enrichment_message(finding, extras)
