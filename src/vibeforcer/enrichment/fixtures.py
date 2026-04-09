"""Fixture and parametrize discovery helpers for enrichment."""

from __future__ import annotations

import ast
from pathlib import Path
import re

from vibeforcer.constants import (
    ENRICHMENT_FIXTURE_PARENT_DEPTH,
    ENRICHMENT_MAX_FIXTURES,
    ENRICHMENT_MAX_PARAMETRIZE_EXAMPLES,
    ENRICHMENT_MAX_PARAMETRIZE_SNIPPET,
)
from vibeforcer.enrichment._helpers import _is_under, _safe_parse, _safe_read
from vibeforcer.enrichment._types import FixtureInfo, ParametrizeExample


_PARAMETRIZE_RE = re.compile(
    r"(@pytest\.mark\.parametrize\(.+?\))\s*\n\s*(def\s+\w+\([^)]*\))",
    re.DOTALL,
)


def _decorator_target(decorator: ast.expr) -> ast.expr:
    if isinstance(decorator, ast.Call):
        return decorator.func
    return decorator


def _is_fixture_target(target: ast.expr) -> bool:
    if isinstance(target, ast.Name):
        return target.id == "fixture"
    if isinstance(target, ast.Attribute):
        return target.attr == "fixture"
    return False


def _has_fixture_decorator(node: ast.FunctionDef) -> bool:
    for decorator in node.decorator_list:
        if _is_fixture_target(_decorator_target(decorator)):
            return True
    return False


def _fixture_has_params(node: ast.FunctionDef) -> bool:
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        for keyword in decorator.keywords:
            if keyword.arg == "params":
                return True
    return False


def _iter_conftest_paths(start_dir: Path, root: Path) -> list[Path]:
    paths: list[Path] = []
    current = start_dir
    for _ in range(ENRICHMENT_FIXTURE_PARENT_DEPTH):
        conftest = current / "conftest.py"
        if conftest.exists() and _is_under(conftest, root):
            paths.append(conftest)
        if current == root or current.parent == current:
            break
        current = current.parent
    return paths


def _relative_name(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _discover_fixtures(test_path: Path, root: Path) -> list[FixtureInfo]:
    fixtures: list[FixtureInfo] = []
    seen_names: set[str] = set()

    for conftest in _iter_conftest_paths(test_path.parent, root):
        content = _safe_read(conftest)
        if not content:
            continue

        module = _safe_parse(content)
        if module is None:
            continue

        for node in module.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            if not _has_fixture_decorator(node):
                continue
            if node.name in seen_names:
                continue

            seen_names.add(node.name)
            fixtures.append(
                {
                    "name": node.name,
                    "conftest": _relative_name(conftest, root),
                    "has_params": _fixture_has_params(node),
                }
            )
            if len(fixtures) >= ENRICHMENT_MAX_FIXTURES:
                return fixtures

    return fixtures


def _find_parametrize_examples(
    test_path: Path,
    root: Path,
    max_examples: int = ENRICHMENT_MAX_PARAMETRIZE_EXAMPLES,
) -> list[ParametrizeExample]:
    examples: list[ParametrizeExample] = []
    for candidate in sorted(test_path.parent.glob("test_*.py")):
        if candidate == test_path or candidate.name == "conftest.py":
            continue

        content = _safe_read(candidate)
        if not content:
            continue

        for match in _PARAMETRIZE_RE.finditer(content):
            snippet = match.group(0).strip()
            if len(snippet) > ENRICHMENT_MAX_PARAMETRIZE_SNIPPET:
                cutoff = ENRICHMENT_MAX_PARAMETRIZE_SNIPPET - 3
                snippet = f"{snippet[:cutoff]}..."

            examples.append(
                {
                    "file": candidate.name,
                    "snippet": snippet,
                }
            )
            if len(examples) >= max_examples:
                return examples

    return examples
