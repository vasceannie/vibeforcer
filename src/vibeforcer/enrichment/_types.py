"""Type definitions for enrichment package internals."""

from __future__ import annotations

from typing import TypedDict


class FixtureInfo(TypedDict):
    """Fixture metadata returned by enrichment fixture discovery."""

    name: str
    conftest: str
    has_params: bool


class ParametrizeExample(TypedDict):
    """Parametrize snippet metadata discovered from sibling tests."""

    file: str
    snippet: str
