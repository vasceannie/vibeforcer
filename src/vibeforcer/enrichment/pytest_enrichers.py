"""Enrichment handlers for pytest-related rule IDs."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from vibeforcer.enrichment._helpers import (
    _append_enrichment_message,
    _relative_path,
    _resolve_path,
    _safe_read,
)
from vibeforcer.enrichment._types import FixtureInfo, ParametrizeExample
from vibeforcer.enrichment.fixtures import (
    _discover_fixtures,
    _find_parametrize_examples,
)

if TYPE_CHECKING:
    from vibeforcer.context import HookContext
    from vibeforcer.models import RuleFinding


def _first_hit_path(finding: RuleFinding) -> str | None:
    hits = finding.metadata.get("hits")
    if not isinstance(hits, list):
        return None
    for hit in hits:
        if isinstance(hit, str) and hit:
            return hit
    return None


def _append_context(finding: RuleFinding, parts: Sequence[str]) -> None:
    if not parts:
        return
    existing = finding.additional_context or ""
    finding.additional_context = (existing + "\n\n" + "\n".join(parts)).strip()


def _project_mentions(root: Path, dependency: str) -> bool:
    for req_file in root.glob("requirements*.txt"):
        content = _safe_read(req_file, max_bytes=20_000)
        if dependency in content.lower():
            return True
    pyproject = root / "pyproject.toml"
    return dependency in _safe_read(pyproject, max_bytes=30_000).lower()


def _time_utils(root: Path) -> list[str]:
    return [
        dependency
        for dependency in ("freezegun", "pytest-freezegun", "time_machine")
        if _project_mentions(root, dependency)
    ]


def _build_test_loop_message_extras(
    fixtures: Sequence[FixtureInfo],
    examples: Sequence[ParametrizeExample],
) -> list[str]:
    extras: list[str] = []
    if fixtures:
        conftest_paths = sorted({fixture["conftest"] for fixture in fixtures})
        names = ", ".join(f"`{fixture['name']}`" for fixture in fixtures[:6])
        prefix = f"\nAvailable fixtures (from {conftest_paths[0]}): "
        if len(conftest_paths) != 1:
            prefix = "\nAvailable fixtures: "
        extras.append(prefix + names)
        parametrized = [fixture for fixture in fixtures if fixture["has_params"]]
        if parametrized:
            extras.append(
                "  Fixtures with params (already data-driven): "
                + ", ".join(f"`{fixture['name']}`" for fixture in parametrized[:3])
            )
    if examples:
        extras.append("\nExisting parametrize patterns in sibling tests:")
        for example in examples[:2]:
            snippet = "\n".join(
                f"    {line}" for line in example["snippet"].splitlines()
            )
            extras.append(f"  # From {example['file']}:\n{snippet}")
    return extras


def _build_test_loop_context_parts(
    fixtures: Sequence[FixtureInfo],
    examples: Sequence[ParametrizeExample],
) -> list[str]:
    parts: list[str] = []
    if fixtures:
        parts.append("AVAILABLE FIXTURES:")
        for fixture in fixtures:
            note = " (parametrized)" if fixture["has_params"] else ""
            parts.append(f"  • {fixture['name']}{note}  — from {fixture['conftest']}")
    if examples:
        parts.append("\nEXISTING PARAMETRIZE PATTERNS IN THIS DIRECTORY:")
        for example in examples:
            parts.append(f"  # {example['file']}:\n{example['snippet']}")
    parts.append(
        "\nCOMPLIANT ALTERNATIVES:\n"
        "1. pytest parameterization for simple data-driven cases\n"
        "2. indirect parameterization when a fixture should receive the data\n"
        "3. subtests when each case needs its own report boundary\n"
        "4. parametrized fixtures defined in conftest.py"
    )
    return parts


def _enrich_test_loop(finding: RuleFinding, ctx: HookContext) -> None:
    """Enrich loop-based tests with fixture and parametrize context."""
    path_str = _first_hit_path(finding)
    if path_str is None:
        return
    test_path = _resolve_path(path_str, ctx.config.root)
    fixtures = _discover_fixtures(test_path, ctx.config.root)
    examples = _find_parametrize_examples(test_path, ctx.config.root)
    _append_enrichment_message(
        finding, _build_test_loop_message_extras(fixtures, examples)
    )
    _append_context(finding, _build_test_loop_context_parts(fixtures, examples))


def _enrich_assertion_roulette(finding: RuleFinding, ctx: HookContext) -> None:
    """Enrich multi-assertion tests with nearby fixture hints."""
    path_str = _first_hit_path(finding)
    if path_str is None:
        return
    test_path = _resolve_path(path_str, ctx.config.root)
    fixtures = _discover_fixtures(test_path, ctx.config.root)
    extras = [
        "\nTIP: If assertions test different aspects of one result, consider "
        "splitting into focused test functions (one concept per test)."
    ]
    if fixtures:
        names = ", ".join(f"`{fixture['name']}`" for fixture in fixtures[:6])
        extras.insert(0, f"\nAvailable fixtures: {names}")
    _append_enrichment_message(finding, extras)


def _enrich_test_smells(finding: RuleFinding, ctx: HookContext) -> None:
    """Enrich general test-smell findings with local alternatives."""
    path_str = _first_hit_path(finding)
    if path_str is None:
        return
    test_path = _resolve_path(path_str, ctx.config.root)
    fixtures = _discover_fixtures(test_path, ctx.config.root)
    extras: list[str] = []
    if fixtures:
        names = ", ".join(f"`{fixture['name']}`" for fixture in fixtures[:6])
        extras.append(f"\nAvailable fixtures: {names}")
    found = _time_utils(ctx.config.root)
    if found:
        extras.append(
            f"\nProject has time utilities: {', '.join(found)} — "
            "prefer frozen or polled time controls over sleep-based timing."
        )
    _append_enrichment_message(finding, extras)


def _enrich_fixture_outside_conftest(finding: RuleFinding, ctx: HookContext) -> None:
    """Enrich fixture-placement findings with the nearest conftest target."""
    path_str = _first_hit_path(finding)
    if path_str is None:
        return
    test_path = _resolve_path(path_str, ctx.config.root)
    conftest = test_path.parent / "conftest.py"
    extras: list[str] = []
    if conftest.exists():
        fixtures = _discover_fixtures(test_path, ctx.config.root)
        if fixtures:
            names = ", ".join(f"`{fixture['name']}`" for fixture in fixtures[:6])
            extras.append(f"\nExisting fixtures in conftest.py: {names}")
        extras.append(
            f"\nMove the fixture to: {_relative_path(conftest, ctx.config.root)}"
        )
    else:
        directory = _relative_path(test_path.parent, ctx.config.root)
        extras.append(
            f"\nNo conftest.py exists yet in {directory}/. Create one and define the fixture there."
        )
    _append_enrichment_message(finding, extras)
