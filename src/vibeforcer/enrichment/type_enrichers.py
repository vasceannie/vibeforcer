"""Local enrichment helpers for typing-related rule IDs."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from vibeforcer.enrichment._helpers import (
    append_enrichment_message,
    first_target_content,
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


def enrich_python_any(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-TYPE-001 with nearby type pattern hints."""
    content_hint = first_target_content(ctx)
    if not content_hint:
        return

    lower = content_hint.lower()
    extras: list[str] = []
    if _is_dict_or_mapping(lower):
        extras.append(
            "\nTIP: For dict-like structures, consider TypedDict:\n"
            + "    class UserData(TypedDict):\n"
            + "        name: str\n"
            + "        email: str"
        )
    if _is_callback_or_handler(lower):
        extras.append(
            "\nTIP: For callbacks/handlers, use Callable with specific signatures:\n"
            + "    Callable[[str, int], bool]"
        )
    if _is_duck_typed_class(lower):
        extras.append(
            "\nTIP: For duck-typed interfaces, define a Protocol:\n"
            + "    class Readable(Protocol):\n"
            + "        def read(self, n: int = -1) -> bytes: ..."
        )

    append_enrichment_message(finding, extras)


_HASH = "#"
_TYPE_IGNORE_MARKER = _HASH + " type" + ": ignore"
_NOQA_MARKER = _HASH + " noq" + "a"
_PYLINT_MARKER = _HASH + " pyl" + "int: disable"
_TYPE_IGNORE_CODE_RE = re.compile(r"#\s*type\s*:\s*ign" + r"ore\[([^\]]+)\]")
_NOQA_CODE_RE = re.compile(r"#\s*noq" + r"a:\s*(\S+)")
_PYLINT_CODE_RE = re.compile(r"#\s*pyl" + r"int:\s*disable=(\S+)")


def _describe_suppression(
    line: str,
    marker: str,
    regex: re.Pattern[str],
    missing_code_message: str | None,
    prefix: str,
) -> str | None:
    if marker not in line:
        return None
    match = regex.search(line)
    if match is None:
        return missing_code_message
    return f"{prefix}`{match.group(1)}`"


def _suppression_description(line: str) -> str | None:
    return (
        _describe_suppression(
            line,
            _TYPE_IGNORE_MARKER,
            _TYPE_IGNORE_CODE_RE,
            "type ignore without an error code",
            "type ignore for ",
        )
        or _describe_suppression(
            line,
            _NOQA_MARKER,
            _NOQA_CODE_RE,
            "noqa without a rule code",
            "noqa for ",
        )
        or _describe_suppression(
            line,
            _PYLINT_MARKER,
            _PYLINT_CODE_RE,
            None,
            "pylint disable for ",
        )
    )


def _collect_suppressions(content: str) -> list[str]:
    suppressions: list[str] = []
    for line in content.splitlines():
        description = _suppression_description(line)
        if description is not None:
            suppressions.append(description)
    return suppressions


def _suppression_advice(suppression: str) -> str | None:
    advice_by_code = {
        "arg-type": "The argument type does not match. Narrow the input or add an overload.",
        "return-value": "Narrow the return type or add a guard before returning.",
        "assignment": "Use a wider annotation or restructure the assignment target.",
        "union-attr": "Narrow the union with isinstance() before reading the attribute.",
        "override": "Match the parent signature exactly or make the override compatible.",
        "no-untyped-def": "Add concrete parameter and return annotations.",
    }
    for code, advice in advice_by_code.items():
        if code in suppression:
            return f"  -> `{code}`: {advice}"
    return None


def enrich_type_suppression(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich suppression findings with concrete fix hints."""
    content = first_target_content(ctx)
    if not content:
        return
    suppressions = _collect_suppressions(content)
    extras: list[str] = []
    if suppressions:
        extras.append(f"\nSuppression(s) found: {', '.join(suppressions[:3])}")
    for suppression in suppressions:
        advice = _suppression_advice(suppression)
        if advice is not None:
            extras.append(advice)
    append_enrichment_message(finding, extras)
