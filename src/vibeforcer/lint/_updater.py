"""Non-destructive config updater for quality_gate.toml.

`quality-gate update` merges new defaults into an existing config file
without overwriting user-customised values.  New keys are injected at
the end of their existing section; entirely new sections are appended.
"""
from __future__ import annotations

import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

from vibeforcer.lint import __version__

# ---------------------------------------------------------------------------
# Canonical defaults — single source of truth
# ---------------------------------------------------------------------------

CANONICAL_DEFAULTS: dict[str, dict[str, object]] = {
    "quality_gate": {
        "version": __version__,
    },
    "paths": {
        "src": "src",
        "tests": "tests",
        "exclude_dirs": [".venv", "__pycache__", "node_modules", ".git"],
        "exclude_patterns": ["*_pb2.py", "*_pb2_grpc.py", "*_pb2.pyi"],
    },
    "thresholds": {
        "max_complexity": 12,
        "max_params": 4,
        "max_method_lines": 50,
        "max_test_lines": 35,
        "max_module_lines_soft": 350,
        "max_module_lines_hard": 600,
        "max_nesting_depth": 4,
        "max_god_class_methods": 15,
        "max_god_class_lines": 400,
        "max_eager_test_calls": 7,
        "max_repeated_magic_numbers": 5,
        "max_repeated_string_literals": 10,
        "max_scattered_helpers": 5,
        "max_duplicate_helper_signatures": 10,
        "max_repeated_code_patterns": 50,
        "min_function_body_lines": 5,
        "min_call_sequence_length": 3,
        "max_line_length": 120,
        "feature_envy_threshold": 0.60,
        "feature_envy_min_accesses": 6,
    },
    "magic_values": {
        "allowed_numbers": [0, 1, 2, 3, 4, 5, -1, 10, 100, 200, 255, 1000, 1024, 0.5],
        "allowed_strings": [
            "", " ", "\n", "\t", "utf-8",
            "r", "w", "rb", "wb",
            "GET", "POST", "PUT", "DELETE", "PATCH",
            "id", "name", "type", "value", "text", "status",
        ],
    },
    "wrappers": {
        "allowed": [],
    },
    "logging": {
        "logger_function": "",
        "logger_variable": "logger",
        "infrastructure_path": "",
        "disallowed_names": ["_log", "_logger", "log", "LOG"],
    },
    "type_safety": {
        "ban_any": True,
        "ban_type_suppressions": True,
        "suppression_patterns": [
            r"(?i)#\s*type:\s*ignore",
            r"(?i)#\s*pyright:\s*ignore",
            r"(?i)#\s*pyre-ignore",
            r"(?i)#\s*noqa\b",
        ],
    },
    "exception_safety": {
        "ban_broad_except_swallow": True,
        "ban_silent_except": True,
        "ban_silent_fallback": True,
    },
    "test_smells": {
        "max_consecutive_bare_asserts": 3,
        "ban_conditional_assertions": True,
        "ban_fixtures_outside_conftest": True,
    },
    "deprecated_patterns": {
        "patterns": [
            ["from typing import Optional", "Optional[X] → X | None"],
            ["from typing import Union", "Union[X, Y] → X | Y"],
            [r"from typing import List\b", "List[X] → list[X]"],
            [r"from typing import Dict\b", "Dict[K, V] → dict[K, V]"],
            [r"from typing import Tuple\b", "Tuple[X] → tuple[X]"],
            [r"from typing import Set\b", "Set[X] → set[X]"],
        ],
    },
    "scope": {
        "default": "all",
    },
}


# ---------------------------------------------------------------------------
# TOML serialisation helpers (stdlib has no tomllib writer)
# ---------------------------------------------------------------------------

def _toml_value(v: object) -> str:
    """Serialize a single value to TOML syntax."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return str(v)
    if isinstance(v, str):
        escaped = v.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(v, list):
        if not v:
            return "[]"
        # List of lists (e.g. deprecated_patterns)
        if v and isinstance(v[0], list):
            lines = ["["]
            for item in v:
                inner = ", ".join(_toml_value(x) for x in item)
                lines.append(f"    [{inner}],")
            lines.append("]")
            return "\n".join(lines)
        # Short numeric lists inline
        if len(v) <= 6 and all(isinstance(x, (int, float)) for x in v):
            inner = ", ".join(_toml_value(x) for x in v)
            return f"[{inner}]"
        lines = ["["]
        for item in v:
            lines.append(f"    {_toml_value(item)},")
        lines.append("]")
        return "\n".join(lines)
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

def update_toml_file(path: Path, *, dry_run: bool = False) -> dict[str, dict[str, object]]:
    """Merge missing defaults into an existing quality_gate.toml.

    - New keys for existing sections are injected at the end of that section.
    - Entirely new sections are appended at the end of the file.
    - Existing values are never modified.

    Returns the dict of keys that were (or would be) added.
    """
    text = path.read_text(encoding="utf-8")
    existing = tomllib.loads(text)

    missing = diff_config(existing)
    if not missing or dry_run:
        return missing

    lines = text.splitlines()
    ranges = _find_section_ranges(lines)

    # Process existing sections: inject keys at the section end.
    # Work backwards so line indices stay valid after insertions.
    inject_existing: list[tuple[int, list[str]]] = []
    append_new_sections: list[str] = []

    for section, keys in missing.items():
        if section in ranges:
            _, end_idx = ranges[section]
            inject_lines = _render_keys(keys)
            inject_existing.append((end_idx, inject_lines))
        else:
            # Entirely new section
            append_new_sections.append("")
            append_new_sections.append(f"[{section}]")
            append_new_sections.extend(_render_keys(keys))

    # Sort injections by position descending so earlier inserts don't shift later ones
    inject_existing.sort(key=lambda x: x[0], reverse=True)
    for after_idx, new_lines in inject_existing:
        for i, nl in enumerate(new_lines):
            lines.insert(after_idx + 1 + i, nl)

    # Append new sections at the end
    if append_new_sections:
        lines.extend(append_new_sections)

    new_text = "\n".join(lines)
    if not new_text.endswith("\n"):
        new_text += "\n"
    path.write_text(new_text, encoding="utf-8")

    return missing
