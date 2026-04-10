"""Native enrichment package API."""

from __future__ import annotations

from collections import Counter
from time import monotonic
from typing import TYPE_CHECKING, Callable, TypeAlias

from vibeforcer.enrichment._helpers import get_parse_count, reset_parse_count
from vibeforcer.enrichment._types import FixtureInfo, ParametrizeExample
from vibeforcer.enrichment.code_enrichers import (
    enrich_cyclomatic_complexity,
    enrich_feature_envy,
    enrich_long_method,
    enrich_long_params,
    enrich_thin_wrapper,
)
from vibeforcer.enrichment.fixtures import (
    discover_fixtures,
    find_parametrize_examples,
)
from vibeforcer.enrichment.logger_enrichers import enrich_stdlib_logger
from vibeforcer.enrichment.pytest_enrichers import (
    enrich_assertion_roulette,
    enrich_fixture_outside_conftest,
    enrich_test_loop,
    enrich_test_smells,
)
from vibeforcer.enrichment.quality_enrichers import (
    enrich_hardcoded_paths,
    enrich_magic_numbers,
)
from vibeforcer.enrichment.silent_except import enrich_silent_except
from vibeforcer.enrichment.type_enrichers import (
    enrich_python_any,
    enrich_type_suppression,
)
from vibeforcer.util import warning

if TYPE_CHECKING:
    from vibeforcer.context import HookContext
    from vibeforcer.models import RuleFinding


Enricher: TypeAlias = Callable[["RuleFinding", "HookContext"], None]


_ENRICHERS: dict[str, Enricher] = {
    "PY-TEST-001": enrich_assertion_roulette,
    "PY-TEST-002": enrich_test_smells,
    "PY-TEST-003": enrich_test_loop,
    "PY-TEST-004": enrich_fixture_outside_conftest,
    "PY-TYPE-001": enrich_python_any,
    "PY-TYPE-002": enrich_type_suppression,
    "PY-CODE-008": enrich_long_method,
    "PY-CODE-009": enrich_long_params,
    "PY-CODE-012": enrich_feature_envy,
    "PY-CODE-013": enrich_thin_wrapper,
    "PY-CODE-015": enrich_cyclomatic_complexity,
    "PY-EXC-002": enrich_silent_except,
    "PY-LOG-001": enrich_stdlib_logger,
    "PY-QUALITY-009": enrich_hardcoded_paths,
    "PY-QUALITY-010": enrich_magic_numbers,
}


def _record_enrichment_failure(finding: "RuleFinding", exc: Exception) -> None:
    existing = finding.additional_context or ""
    detail = f"Enrichment skipped due to {type(exc).__name__}."
    finding.additional_context = (existing + "\n" + detail).strip()


def _enricher_metric_name(enricher: Enricher) -> str:
    name = getattr(enricher, "__name__", "enricher")
    return str(name).removeprefix("_enrich_")


def _finding_changed(
    finding: "RuleFinding",
    message_before: str | None,
    context_before: str | None,
) -> bool:
    return (
        finding.message != message_before
        or finding.additional_context != context_before
    )


def _metrics_payload(
    elapsed_ms: float,
    enrichers_fired: Counter[str],
) -> dict[str, object]:
    return {
        "rule_id": "_ENRICHMENT_METRICS",
        "title": "Enrichment metrics",
        "elapsed_ms": elapsed_ms,
        "enrichers_fired": dict(enrichers_fired),
        "ast_parses": get_parse_count(),
        "decision": "info",
        "severity": "info",
    }


def enrich_findings(findings: list["RuleFinding"], ctx: "HookContext") -> None:
    """Enrich findings in-place with project-specific context."""
    enrichers_fired: Counter[str] = Counter()
    start = monotonic()
    reset_parse_count()
    for finding in findings:
        enricher = _ENRICHERS.get(finding.rule_id)
        if enricher is None:
            continue
        message_before = finding.message
        context_before = finding.additional_context
        try:
            enricher(finding, ctx)
            if _finding_changed(finding, message_before, context_before):
                enrichers_fired[_enricher_metric_name(enricher)] += 1
        except (
            AttributeError,
            KeyError,
            OSError,
            SyntaxError,
            TypeError,
            ValueError,
        ) as exc:
            _record_enrichment_failure(finding, exc)
            warning(
                "enrichment handler failed",
                rule_id=finding.rule_id,
                enricher=_enricher_metric_name(enricher),
                error=str(exc),
            )
    elapsed_ms = round((monotonic() - start) * 1000.0, 3)
    ctx.trace.rule(_metrics_payload(elapsed_ms, enrichers_fired))


__all__ = [
    "FixtureInfo",
    "ParametrizeExample",
    "discover_fixtures",
    "find_parametrize_examples",
    "enrich_findings",
]
