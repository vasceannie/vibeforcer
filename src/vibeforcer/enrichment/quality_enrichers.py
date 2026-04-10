"""Local enrichment helpers for quality-related rule IDs."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from typing import cast

from vibeforcer.enrichment._helpers import (
    append_enrichment_message,
    relative_path,
    resolve_path,
    safe_read,
)

if TYPE_CHECKING:
    from vibeforcer.context import HookContext
    from vibeforcer.models import RuleFinding


_CONFIG_FILE_NAMES = (
    "constants.py",
    "config.py",
    "settings.py",
    "defaults.py",
)

_PATH_HINT_FILES = (
    "config.py",
    "settings.py",
    "paths.py",
    "constants.py",
    "env.py",
)

_PATH_HINT_TOKENS = ("PATH", "DIR", "ROOT", "BASE_PATH", "DATA_DIR")


def _find_constants_module(file_path: Path, root: Path) -> Path | None:
    search_dirs = (file_path.parent, file_path.parent.parent, root / "src")
    for base_dir in search_dirs:
        if not base_dir.exists():
            continue
        for name in _CONFIG_FILE_NAMES:
            candidate = base_dir / name
            if candidate.exists():
                return candidate
    return None


def _metadata_source_paths(finding: RuleFinding, root: Path) -> list[Path]:
    paths: list[Path] = []

    file_path = finding.metadata.get("file_path")
    if isinstance(file_path, str) and file_path:
        paths.append(resolve_path(file_path, root))

    hits = finding.metadata.get("hits")
    if isinstance(hits, list):
        raw_hits = cast(list[object], hits)
        for hit in raw_hits:
            if isinstance(hit, str) and hit:
                paths.append(resolve_path(hit, root))

    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _path_hint_lines(content: str, max_lines: int = 4) -> list[str]:
    lines: list[str] = []
    for raw_line in content.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if any(token in stripped for token in _PATH_HINT_TOKENS):
            lines.append(stripped)
            if len(lines) >= max_lines:
                break
    return lines


def _iter_path_config_candidates(root: Path) -> list[Path]:
    candidates: list[Path] = []
    for base_dir in (root / "src", root / "app", root / "config", root):
        for name in _PATH_HINT_FILES:
            candidate = base_dir / name
            if candidate.exists():
                candidates.append(candidate)
    return candidates


def enrich_magic_numbers(finding: RuleFinding, ctx: HookContext) -> None:
    """Enrich PY-QUALITY-010 with constants-module hints."""

    extras: list[str] = []
    for source_path in _metadata_source_paths(finding, ctx.config.root):
        constants_file = _find_constants_module(source_path, ctx.config.root)
        if constants_file is not None:
            relative = relative_path(constants_file, ctx.config.root)
            extras.append(f"\nProject constants module found: `{relative}`")
            break

    if not extras:
        extras.append(
            "\nDefine repeated literals in a constants/config module "
            + "instead of inline magic values."
        )

    append_enrichment_message(finding, extras)


def enrich_hardcoded_paths(finding: RuleFinding, ctx: HookContext) -> None:
    """Enrich PY-QUALITY-009 with central path-config hints."""

    extras: list[str] = []
    for candidate in _iter_path_config_candidates(ctx.config.root):
        content = safe_read(candidate, max_bytes=10_000)
        if not content:
            continue
        lines = _path_hint_lines(content)
        if not lines:
            continue

        relative = relative_path(candidate, ctx.config.root)
        extras.append(f"\nPath configuration found in `{relative}`:")
        extras.extend(f"  {line}" for line in lines)
        break

    if not extras:
        extras.append(
            "\nNo central path config found. Consider defining paths in a config module "
            + "or using environment variables."
        )

    append_enrichment_message(finding, extras)
