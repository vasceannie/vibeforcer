"""Local enrichment helpers for logger-related rule IDs."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from vibeforcer.enrichment._helpers import (
    append_enrichment_message,
    relative_path,
    safe_read,
)

if TYPE_CHECKING:
    from vibeforcer.context import HookContext
    from vibeforcer.models import RuleFinding


_LOGGER_CANDIDATES = (
    Path("src/logger.py"),
    Path("src/log.py"),
    Path("src/logging_config.py"),
    Path("src/utils/logger.py"),
    Path("src/utils/logging.py"),
    Path("src/core/logger.py"),
    Path("lib/logger.py"),
    Path("app/logger.py"),
)


def _dependency_hints(root: Path) -> list[str]:
    hints: list[str] = []
    for name in ("structlog", "loguru"):
        if _dependency_in_requirements(root, name) or _dependency_in_pyproject(
            root, name
        ):
            hints.append(name)
    return hints


def _dependency_in_requirements(root: Path, name: str) -> bool:
    for req_file in root.glob("requirements*.txt"):
        if name in safe_read(req_file, max_bytes=10_000).lower():
            return True
    return False


def _dependency_in_pyproject(root: Path, name: str) -> bool:
    return name in safe_read(root / "pyproject.toml", max_bytes=30_000).lower()


def _candidate_logger_path(root: Path) -> Path | None:
    for relative in _LOGGER_CANDIDATES:
        candidate = root / relative
        if candidate.exists():
            return candidate
    return None


def _first_logger_pattern(candidate: Path) -> str | None:
    content = safe_read(candidate, max_bytes=5_000)
    if not content:
        return None

    for line in content.splitlines()[:30]:
        stripped = line.strip()
        if (
            "get_logger" not in stripped
            and "getLogger" not in stripped
            and "logger" not in stripped.lower()
        ):
            continue
        if (
            stripped.startswith("def ")
            or stripped.startswith("class ")
            or "=" in stripped
        ):
            return stripped[:100]
    return None


def _append_dependency_hints(extras: list[str], hints: list[str]) -> None:
    if not hints:
        return
    extras.append(f"\nProject uses: {', '.join(hints)}")
    if "structlog" in hints:
        extras.append(
            "  Import with: `import structlog; logger = structlog.get_logger()`"
        )
    if "loguru" in hints:
        extras.append("  Import with: `from loguru import logger`")


def _append_logger_path_hints(extras: list[str], root: Path) -> None:
    candidate = _candidate_logger_path(root)
    if candidate is None:
        return

    extras.append(f"\nProject logger found at: `{relative_path(candidate, root)}`")
    pattern = _first_logger_pattern(candidate)
    if pattern is not None:
        extras.append(f"  Pattern: `{pattern}`")


def enrich_stdlib_logger(finding: RuleFinding, ctx: HookContext) -> None:
    """Enrich PY-LOG-001 by finding project logging abstractions."""

    extras: list[str] = []
    root = ctx.config.root

    _append_dependency_hints(extras, _dependency_hints(root))
    _append_logger_path_hints(extras, root)

    if not extras:
        extras.append(
            "\nNo project logger abstraction found. Consider creating one, "
            + "or use structlog/loguru instead of stdlib logging."
        )

    append_enrichment_message(finding, extras)
