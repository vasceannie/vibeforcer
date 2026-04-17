"""Shared project-level index of string constants for quality checks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

_KNOWN_CONSTANT_GLOBS: tuple[str, ...] = (
    "constants.py",
    "config.py",
    "settings.py",
    "defaults.py",
    "*_constants.py",
    "config/*.py",
)

_DEFAULT_MAX_FILE_SIZE = 128_000


@dataclass(frozen=True, slots=True)
class StringConstantMatch:
    """A discovered module-level string constant definition."""

    name: str
    path: Path
    lineno: int


@dataclass(frozen=True, slots=True)
class ConstantIndex:
    """Index of project constants discovered from bounded file scans."""

    root: Path
    string_constants: dict[str, list[StringConstantMatch]]
    files: tuple[Path, ...]

    def find_string_constant(self, value: str) -> StringConstantMatch | None:
        matches = self.string_constants.get(value)
        if not matches:
            return None
        return matches[0]

    def first_constants_file(self) -> Path | None:
        if not self.files:
            return None
        return self.files[0]


_FILE_CACHE: dict[Path, tuple[int, int, dict[str, list[StringConstantMatch]]]] = {}
_SESSION_INDEX: ConstantIndex | None = None


def set_session_constant_index(index: ConstantIndex) -> None:
    global _SESSION_INDEX
    _SESSION_INDEX = index


def get_session_constant_index() -> ConstantIndex | None:
    return _SESSION_INDEX


def _iter_constant_candidates(root: Path) -> list[Path]:
    found: list[Path] = []
    seen: set[Path] = set()
    for glob in _KNOWN_CONSTANT_GLOBS:
        for candidate in root.rglob(glob):
            if not candidate.is_file() or candidate in seen:
                continue
            seen.add(candidate)
            found.append(candidate)
    return sorted(found)


def _extract_string_constants(path: Path) -> dict[str, list[StringConstantMatch]]:
    source = path.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source)
    constants: dict[str, list[StringConstantMatch]] = {}
    for node in tree.body:
        target_name: str | None = None
        value_node: ast.AST | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                target_name = target.id
                value_node = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_name = node.target.id
            value_node = node.value
        if (
            target_name is None
            or value_node is None
            or not target_name.isupper()
            or not isinstance(value_node, ast.Constant)
            or not isinstance(value_node.value, str)
        ):
            continue
        value = value_node.value
        match = StringConstantMatch(
            name=target_name,
            path=path,
            lineno=getattr(node, "lineno", 1),
        )
        constants.setdefault(value, []).append(match)
    return constants


def _merge_constants(
    target: dict[str, list[StringConstantMatch]],
    incoming: dict[str, list[StringConstantMatch]],
) -> None:
    for value, matches in incoming.items():
        target.setdefault(value, []).extend(matches)


def build_project_constant_index(
    root: Path,
    *,
    max_file_size: int | None = _DEFAULT_MAX_FILE_SIZE,
    use_mtime_cache: bool = True,
) -> ConstantIndex:
    """Build a bounded project-level constant index.

    Scans only known config/constant filename patterns. Individual file reads can
    be bounded with ``max_file_size``. If ``use_mtime_cache`` is enabled, file-level
    extracted constants are reused until file mtime/size changes.
    """

    root = root.resolve()
    collected: dict[str, list[StringConstantMatch]] = {}
    files: list[Path] = []
    for candidate in _iter_constant_candidates(root):
        try:
            stat = candidate.stat()
        except OSError:
            continue
        if max_file_size is not None and stat.st_size > max_file_size:
            continue

        extracted: dict[str, list[StringConstantMatch]]
        cache_entry = _FILE_CACHE.get(candidate)
        if use_mtime_cache and cache_entry is not None:
            cached_mtime, cached_size, cached_values = cache_entry
            if cached_mtime == stat.st_mtime_ns and cached_size == stat.st_size:
                extracted = cached_values
            else:
                extracted = {}
        else:
            extracted = {}

        if not extracted:
            try:
                extracted = _extract_string_constants(candidate)
            except (OSError, SyntaxError, UnicodeError):
                continue
            if use_mtime_cache:
                _FILE_CACHE[candidate] = (stat.st_mtime_ns, stat.st_size, extracted)
        _merge_constants(collected, extracted)
        files.append(candidate)

    for matches in collected.values():
        matches.sort(key=lambda m: (str(m.path), m.lineno, m.name))
    return ConstantIndex(root=root, string_constants=collected, files=tuple(files))


def find_string_constant(value: str, *, root: Path | None = None) -> StringConstantMatch | None:
    """Find a string constant by value from the active/session index."""

    index = get_session_constant_index()
    if index is None:
        if root is None:
            return None
        index = build_project_constant_index(root)
        set_session_constant_index(index)
    return index.find_string_constant(value)


def suggest_constant_name(value: str) -> str:
    """Build a stable, uppercase candidate constant name from a string value."""

    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", value.strip()).strip("_").upper()
    if not cleaned:
        return "EXTRACTED_STRING"
    if cleaned[0].isdigit():
        cleaned = f"STR_{cleaned}"
    return cleaned[:48]
