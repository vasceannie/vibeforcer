"""Non-destructive config updater for quality_gate.toml.

`quality-gate update` merges new defaults into an existing config file
without overwriting user-customised values.  New keys are injected at
the end of their existing section; entirely new sections are appended.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path
from typing import cast

_toml_parser_module = None
for module_name in ("tomllib", "tomli"):
    try:
        _module = importlib.import_module(module_name)
    except ModuleNotFoundError:
        continue
    if callable(getattr(_module, "loads", None)):
        _toml_parser_module = _module
        break

from vibeforcer.lint import __version__
from vibeforcer.policy_defaults import (
    LINT_DEPRECATED_PATTERNS_DEFAULTS,
    LINT_EXCEPTION_SAFETY_DEFAULTS,
    LINT_MAGIC_DEFAULTS,
    LINT_PATH_DEFAULTS,
    LINT_LOGGING_DEFAULTS,
    LINT_SCOPE_DEFAULTS,
    LINT_TESTING_DEFAULTS,
    LINT_THRESHOLD_DEFAULTS,
    LINT_TYPE_SAFETY_DEFAULTS,
    LINT_WRAPPERS_DEFAULTS,
)

# ---------------------------------------------------------------------------
# Canonical defaults — single source of truth
# ---------------------------------------------------------------------------

CANONICAL_DEFAULTS: dict[str, dict[str, object]] = {
    "quality_gate": {
        "version": __version__,
    },
    "paths": {
        **LINT_PATH_DEFAULTS,
        "exclude_dirs": list(LINT_PATH_DEFAULTS["exclude_dirs"]),
        "exclude_patterns": list(LINT_PATH_DEFAULTS["exclude_patterns"]),
    },
    "thresholds": {
        **LINT_THRESHOLD_DEFAULTS,
    },
    "magic_values": {
        "allowed_numbers": list(LINT_MAGIC_DEFAULTS["allowed_numbers"]),
        "allowed_strings": list(LINT_MAGIC_DEFAULTS["allowed_strings"]),
    },
    "wrappers": {
        "allowed": list(LINT_WRAPPERS_DEFAULTS["allowed"]),
    },
    "logging": {
        **LINT_LOGGING_DEFAULTS,
        "disallowed_names": list(LINT_LOGGING_DEFAULTS["disallowed_names"]),
    },
    "type_safety": {
        **LINT_TYPE_SAFETY_DEFAULTS,
        "suppression_patterns": list(LINT_TYPE_SAFETY_DEFAULTS["suppression_patterns"]),
    },
    "exception_safety": {
        **LINT_EXCEPTION_SAFETY_DEFAULTS,
    },
    "test_smells": {**LINT_TESTING_DEFAULTS},
    "deprecated_patterns": {
        "patterns": [
            list(entry) for entry in LINT_DEPRECATED_PATTERNS_DEFAULTS["patterns"]
        ],
    },
    "scope": {
        "default": LINT_SCOPE_DEFAULTS["default"],
    },
}


def render_quality_gate_toml(*, version: str | None = None) -> str:
    """Render a canonical quality-gate TOML body from defaults.

    This keeps ``vibeforcer lint init`` coupled to the central defaults.
    """
    defaults = CANONICAL_DEFAULTS
    if version is not None:
        defaults = dict(defaults)
        quality_gate = dict(defaults["quality_gate"])
        quality_gate["version"] = version
        defaults["quality_gate"] = quality_gate

    lines: list[str] = [
        "# Quality Gate Configuration",
        "# vibeforcer lint",
        "",
    ]
    for section, keys in defaults.items():
        lines.append(f"[{section}]")
        for key, value in keys.items():
            lines.append(f"{key} = {_toml_value(value)}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# TOML serialisation helpers (stdlib has no tomllib writer)
# ---------------------------------------------------------------------------


def _toml_str(v: str) -> str:
    """Serialize a string to TOML syntax."""
    escaped = v.encode("unicode_escape").decode("ascii").replace('"', '\\"')
    return f'"{escaped}"'


def _toml_list_of_lists(v: list[object]) -> str:
    """Serialize a list-of-lists (e.g. deprecated_patterns) to TOML syntax."""
    lines = ["["]
    for item in v:
        typed_item = cast(list[object], item)
        inner = ", ".join(_toml_value(x) for x in typed_item)
        lines.append(f"    [{inner}],")
    lines.append("]")
    return "\n".join(lines)


def _toml_list(v: list[object]) -> str:
    """Serialize a list to TOML syntax."""
    if not v:
        return "[]"
    if all(isinstance(item, list) for item in v):
        return _toml_list_of_lists(v)
    if len(v) <= 6 and all(isinstance(x, (int, float)) for x in v):
        inner = ", ".join(_toml_value(x) for x in v)
        return f"[{inner}]"
    lines = ["["]
    for item in v:
        lines.append(f"    {_toml_value(item)},")
    lines.append("]")
    return "\n".join(lines)


def _toml_value(v: object) -> str:
    """Serialize a single value to TOML syntax."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return str(v)
    if isinstance(v, str):
        return _toml_str(v)
    if isinstance(v, list):
        return _toml_list(v)
    return repr(v)


def _render_keys(keys: dict[str, object]) -> list[str]:
    """Render key=value lines for injection."""
    result: list[str] = []
    for key, value in keys.items():
        result.append(f"{key} = {_toml_value(value)}")
    return result


# ---------------------------------------------------------------------------
# Diff logic
# ---------------------------------------------------------------------------


def diff_config(existing: dict[str, dict[str, object]]) -> dict[str, dict[str, object]]:
    """Return only the keys/sections missing from *existing*."""
    missing: dict[str, dict[str, object]] = {}
    for section, defaults in CANONICAL_DEFAULTS.items():
        existing_section = existing.get(section, {})
        if not existing_section:
            missing[section] = dict(defaults)
            continue
        new_keys = {}
        for key, default_val in defaults.items():
            if key not in existing_section:
                new_keys[key] = default_val
        if new_keys:
            missing[section] = new_keys
    return missing


# ---------------------------------------------------------------------------
# Section boundary finder
# ---------------------------------------------------------------------------

_SECTION_RE = re.compile(r"^\s*\[([A-Za-z_][A-Za-z0-9_.]*)\]\s*(?:#.*)?$")


def _find_section_ranges(lines: list[str]) -> dict[str, tuple[int, int]]:
    """Map section name → (start_line_idx, end_line_idx).

    end_line_idx is the last line that belongs to the section (before
    the next section header or EOF).
    """
    sections: list[tuple[str, int]] = []
    for i, line in enumerate(lines):
        m = _SECTION_RE.match(line)
        if m:
            sections.append((m.group(1), i))

    ranges: dict[str, tuple[int, int]] = {}
    for idx, (name, start) in enumerate(sections):
        if idx + 1 < len(sections):
            end = sections[idx + 1][1] - 1
        else:
            end = len(lines) - 1
        # Trim trailing blank lines from the section
        while end > start and not lines[end].strip():
            end -= 1
        ranges[name] = (start, end)
    return ranges


# ---------------------------------------------------------------------------
# In-place merge
# ---------------------------------------------------------------------------


def _parse_existing(text: str) -> dict[str, dict[str, object]] | None:
    """Parse the TOML text and return a typed dict, or None on failure."""
    if _toml_parser_module is None:
        return None
    raw = _toml_parser_module.loads(text)
    if not isinstance(raw, dict):
        return None
    return cast(dict[str, dict[str, object]], raw)


def _build_injection_plan(
    missing: dict[str, dict[str, object]],
    ranges: dict[str, tuple[int, int]],
) -> tuple[list[tuple[int, list[str]]], list[str]]:
    """Partition missing keys into in-place injections and new-section appends."""
    inject_existing: list[tuple[int, list[str]]] = []
    append_new: list[str] = []
    for section, keys in missing.items():
        if section in ranges:
            _, end_idx = ranges[section]
            inject_existing.append((end_idx, _render_keys(keys)))
        else:
            append_new.append("")
            append_new.append(f"[{section}]")
            append_new.extend(_render_keys(keys))
    return inject_existing, append_new


def _apply_injections(lines: list[str], inject_existing: list[tuple[int, list[str]]]) -> None:
    """Insert new key lines into *lines* at the correct positions (in reverse order)."""
    inject_existing.sort(key=lambda x: x[0], reverse=True)
    for after_idx, new_lines in inject_existing:
        for i, nl in enumerate(new_lines):
            lines.insert(after_idx + 1 + i, nl)


def _write_updated(path: Path, lines: list[str], append_new: list[str]) -> None:
    """Extend *lines* with any new sections and write the result to *path*."""
    if append_new:
        lines.extend(append_new)
    new_text = "\n".join(lines)
    if not new_text.endswith("\n"):
        new_text += "\n"
    _ = path.write_text(new_text, encoding="utf-8")


def update_toml_file(
    path: Path, *, dry_run: bool = False
) -> dict[str, dict[str, object]]:
    """Merge missing defaults into an existing quality_gate.toml.

    - New keys for existing sections are injected at the end of that section.
    - Entirely new sections are appended at the end of the file.
    - Existing values are never modified.

    Returns the dict of keys that were (or would be) added.
    """
    text = path.read_text(encoding="utf-8")
    existing = _parse_existing(text)
    if existing is None:
        return {}

    missing = diff_config(existing)
    if not missing or dry_run:
        return missing

    lines = text.splitlines()
    ranges = _find_section_ranges(lines)
    inject_existing, append_new = _build_injection_plan(missing, ranges)
    _apply_injections(lines, inject_existing)
    _write_updated(path, lines, append_new)
    return missing
