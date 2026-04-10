"""Compatibility façade for enrichment APIs.

This package module preserves imports from ``vibeforcer.enrichment``.
The legacy implementation remains in a separate legacy module.
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
from vibeforcer.enrichment.logger_enrichers import _enrich_stdlib_logger
from vibeforcer.enrichment.quality_enrichers import (
    _enrich_hardcoded_paths,
    _enrich_magic_numbers,
)
from vibeforcer.enrichment.silent_except import _enrich_silent_except
from vibeforcer.enrichment.type_enrichers import _enrich_python_any

if TYPE_CHECKING:
    from vibeforcer.context import HookContext
    from vibeforcer.models import RuleFinding


_LEGACY_MODULE_NAME = "vibeforcer._legacy_enrichment"


_LOCAL_OVERRIDES: dict[str, Callable[..., None]] = {
    "PY-EXC-002": _enrich_silent_except,
    "PY-LOG-001": _enrich_stdlib_logger,
    "PY-QUALITY-009": _enrich_hardcoded_paths,
    "PY-QUALITY-010": _enrich_magic_numbers,
    "PY-TYPE-001": _enrich_python_any,
}


def _install_local_enrichers(module: ModuleType) -> None:
    registry = getattr(module, "_ENRICHERS", None)
    if not isinstance(registry, dict):
        return
    # Enable only parity-safe local overrides; keep all others on legacy implementations.
    for rule_id, enricher in _LOCAL_OVERRIDES.items():
        registry[rule_id] = enricher


def _legacy_module_path() -> Path:
    current_file = Path(__file__).resolve()
    package_name = current_file.parent.name
    return current_file.parent.parent / f"{package_name}.py"


def _load_legacy_module() -> ModuleType:
    loaded = sys.modules.get(_LEGACY_MODULE_NAME)
    if loaded is not None:
        _install_local_enrichers(loaded)
        return loaded

    module_path = _legacy_module_path()
    spec = spec_from_file_location(_LEGACY_MODULE_NAME, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load legacy enrichment module at {module_path}")

    module = module_from_spec(spec)
    sys.modules[_LEGACY_MODULE_NAME] = module
    spec.loader.exec_module(module)
    _install_local_enrichers(module)
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
