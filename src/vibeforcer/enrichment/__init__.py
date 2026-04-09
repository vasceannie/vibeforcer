"""Compatibility façade for enrichment APIs.

This package-level module preserves imports from ``vibeforcer.enrichment``
while the legacy enrichment implementation remains in ``enrichment.py``.
"""

from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys
from types import ModuleType
from typing import TYPE_CHECKING, Callable, cast

from vibeforcer.enrichment._types import FixtureInfo, ParametrizeExample
from vibeforcer.enrichment.fixtures import (
    _discover_fixtures,
    _find_parametrize_examples,
)

if TYPE_CHECKING:
    from vibeforcer.context import HookContext
    from vibeforcer.models import RuleFinding


_LEGACY_MODULE_NAME = "vibeforcer._legacy_enrichment"
_LEGACY_FILE_NAME = "enrichment.py"


def _legacy_module_path() -> Path:
    return Path(__file__).resolve().parent.parent / _LEGACY_FILE_NAME


def _load_legacy_module() -> ModuleType:
    loaded = sys.modules.get(_LEGACY_MODULE_NAME)
    if loaded is not None:
        return loaded

    module_path = _legacy_module_path()
    spec = spec_from_file_location(_LEGACY_MODULE_NAME, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load legacy enrichment module at {module_path}")

    module = module_from_spec(spec)
    sys.modules[_LEGACY_MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


def _resolve_callable(name: str) -> Callable[..., object]:
    module = _load_legacy_module()
    resolved = getattr(module, name, None)
    if not callable(resolved):
        raise AttributeError(
            f"Legacy enrichment symbol '{name}' is missing or not callable"
        )
    return cast(Callable[..., object], resolved)


def enrich_findings(findings: list["RuleFinding"], ctx: "HookContext") -> None:
    resolved = _resolve_callable("enrich_findings")
    typed = cast(Callable[[list["RuleFinding"], "HookContext"], None], resolved)
    typed(findings, ctx)


__all__ = [
    "FixtureInfo",
    "ParametrizeExample",
    "_discover_fixtures",
    "_find_parametrize_examples",
    "enrich_findings",
]
