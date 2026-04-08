"""Detector for stale / deprecated code patterns.

Flags lines matching configurable regex patterns (e.g. old-style typing
imports that should use modern ``X | Y`` syntax).
"""
from __future__ import annotations

import re
from pathlib import Path

from vibeforcer.lint._baseline import Violation
from vibeforcer.lint._config import get_config
from vibeforcer.lint._helpers import find_source_files, read_lines, relative_path


def detect_deprecated_patterns(files: list[Path] | None = None) -> list[Violation]:
    """Scan source files for lines matching deprecated-pattern regexes."""
    cfg = get_config()
    if not cfg.deprecated_patterns:
        return []

    compiled: list[tuple[re.Pattern[str], str]] = []
    for pattern_str, description in cfg.deprecated_patterns:
        try:
            compiled.append((re.compile(pattern_str), description))
        except re.error:
            continue

    files = files if files is not None else find_source_files()
    violations: list[Violation] = []

    for path in files:
        rel = relative_path(path)
        lines = read_lines(path)
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith("#"):
                continue
            for regex, desc in compiled:
                if regex.search(line):
                    violations.append(
                        Violation(
                            rule="deprecated-pattern",
                            relative_path=rel,
                            identifier=f"L{lineno}",
                            detail=desc,
                        )
                    )
                    break  # one violation per line

    return violations
