from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic

from vibeforcer.adapters import get_adapter
from vibeforcer.adapters.base import PlatformAdapter
from vibeforcer.config import is_path_skipped, is_repo_disabled
from vibeforcer.context import HookContext, build_context
from vibeforcer.enrichment import enrich_findings
from vibeforcer.models import EngineResult, RuleFinding, Severity
from vibeforcer.rules import build_rules
from vibeforcer.rules.base import Rule
from vibeforcer.util import warning


DECISION_ORDER: dict[str | None, int] = {
    "deny": 4,
    "block": 4,
    "ask": 3,
    "allow": 2,
    None: 0,
}


def _finding_sort_key(item: RuleFinding) -> tuple[int, int]:
    return (DECISION_ORDER.get(item.decision, 0), int(item.severity))


def _merge_updated_input(findings: list[RuleFinding]) -> dict[str, object]:
    merged: dict[str, object] = {}
    for finding in findings:
        merged.update(finding.updated_input)
    return merged


def _collect_context(findings: list[RuleFinding]) -> str | None:
    parts = [item.additional_context for item in findings if item.additional_context]
    if not parts:
        return None
    return "\n\n".join(dict.fromkeys(parts))


def _top_decision(findings: list[RuleFinding]) -> str | None:
    if not findings:
        return None
    return max(findings, key=_finding_sort_key).decision


def _apply_severity_overrides(
    findings: list[RuleFinding],
    overrides: dict[str, str],
) -> None:
    """Mutate findings in-place to apply per-repo severity overrides."""
    for finding in findings:
        if finding.rule_id not in overrides:
            continue
        override = overrides[finding.rule_id]
        if override.lower() == "warn":
            finding.severity = Severity.LOW
            finding.decision = None
        else:
            finding.severity = Severity.from_value(override)


def _serialize_findings(findings: list[RuleFinding]) -> list[dict[str, object]]:
    return [
        {
            "rule_id": item.rule_id,
            "severity": item.severity.as_name(),
            "decision": item.decision,
            "message": item.message,
            "additional_context": item.additional_context,
            "metadata": item.metadata,
        }
        for item in findings
    ]


def _trace_identity(ctx: HookContext, platform: str) -> dict[str, object]:
    return {
        "platform": platform,
        "event_name": ctx.event_name,
        "session_id": ctx.session_id,
        "tool_name": ctx.tool_name,
    }


def _error_trace_payload(
    identity: dict[str, object],
    rule_id: str,
    exc: Exception,
    elapsed_ms: float,
) -> dict[str, object]:
    """Build the trace payload dict for a rule evaluation error."""
    payload = dict(identity)
    payload.update(
        {
            "rule_id": rule_id,
            "elapsed_ms": elapsed_ms,
            "error": repr(exc),
        }
    )
    return payload


@dataclass(slots=True)
class _EvalAccumulator:
    """Groups mutable state passed through the evaluation pipeline."""

    findings: list[RuleFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _trace_findings(
    ctx: HookContext,
    platform: str,
    items: list[RuleFinding],
    elapsed_ms: float,
) -> None:
    identity = _trace_identity(ctx, platform)
    for item in items:
        payload = dict(identity)
        payload.update(
            {
                "rule_id": item.rule_id,
                "elapsed_ms": elapsed_ms,
                "severity": item.severity.as_name(),
                "decision": item.decision,
                "message": item.message,
                "additional_context": item.additional_context,
                "metadata": item.metadata,
            }
        )
        ctx.trace.rule(payload)


def _run_rule(
    rule: Rule,
    ctx: HookContext,
    platform: str,
    acc: _EvalAccumulator,
) -> None:
    """Evaluate a single rule, collecting findings and errors."""
    identity = _trace_identity(ctx, platform)
    start = monotonic()
    try:
        result = rule.evaluate(ctx)
        elapsed_ms = round((monotonic() - start) * 1000.0, 3)
        if not result:
            return
        _apply_severity_overrides(result, ctx.config.severity_overrides)
        acc.findings.extend(result)
        _trace_findings(ctx, platform, result, elapsed_ms)
    except Exception as exc:
        elapsed_ms = round((monotonic() - start) * 1000.0, 3)
        acc.errors.append(f"{rule.rule_id}: {exc}")
        warning(
            "rule evaluation failed",
            rule_id=rule.rule_id,
            event_name=ctx.event_name,
            tool_name=ctx.tool_name,
            error=str(exc),
        )
        ctx.trace.rule(_error_trace_payload(identity, rule.rule_id, exc, elapsed_ms))


def _safe_enrich(
    ctx: HookContext,
    platform: str,
    acc: _EvalAccumulator,
) -> None:
    """Run enrichment with error capture instead of silent swallow."""
    identity = _trace_identity(ctx, platform)
    findings_before = len(acc.findings)
    start = monotonic()
    try:
        enrich_findings(acc.findings, ctx)
        elapsed_ms = round((monotonic() - start) * 1000.0, 3)
        findings_after = len(acc.findings)
        payload = dict(identity)
        payload.update(
            {
                "rule_id": "ENRICHMENT",
                "elapsed_ms": elapsed_ms,
                "metadata": {
                    "findings_before": findings_before,
                    "findings_after": findings_after,
                    "findings_delta": findings_after - findings_before,
                },
            }
        )
        ctx.trace.rule(payload)
    except Exception as exc:
        elapsed_ms = round((monotonic() - start) * 1000.0, 3)
        acc.errors.append(f"enrichment: {exc}")
        warning(
            "enrichment failed",
            event_name=ctx.event_name,
            tool_name=ctx.tool_name,
            error=str(exc),
        )
        ctx.trace.rule(_error_trace_payload(identity, "ENRICHMENT", exc, elapsed_ms))


def _run_rules(ctx: HookContext, platform: str) -> _EvalAccumulator:
    """Build and evaluate all applicable rules."""
    acc = _EvalAccumulator()
    disabled = set(ctx.config.disabled_rules)
    for rule in build_rules(ctx):
        if rule.supports(ctx.event_name) and rule.rule_id not in disabled:
            _run_rule(rule, ctx, platform, acc)
    _safe_enrich(ctx, platform, acc)
    return acc


def render_output(
    ctx: HookContext,
    findings: list[RuleFinding],
    adapter: PlatformAdapter | None = None,
) -> dict[str, object] | None:
    if not findings:
        return None

    adapter = adapter or get_adapter("claude")
    return adapter.render_output(
        ctx.event_name,
        findings,
        context=_collect_context(findings),
        updated_input=_merge_updated_input(findings),
        decision=_top_decision(findings),
    )


def _check_skip(ctx: HookContext, platform: str) -> EngineResult | None:
    """Return an early EngineResult if the repo is disabled or skipped."""
    repo_cwd = Path(ctx.cwd) if ctx.cwd else Path.cwd()
    if not (
        is_repo_disabled(repo_cwd) or is_path_skipped(repo_cwd, ctx.config.skip_paths)
    ):
        return None
    ctx.trace.result(
        {
            "platform": platform,
            "event_name": ctx.event_name,
            "session_id": ctx.session_id,
            "skipped": True,
            "reason": "repo disabled or path skipped",
            "cwd": str(repo_cwd),
        }
    )
    return EngineResult(event_name=ctx.event_name)


def evaluate_payload(
    payload_dict: dict[str, object],
    platform: str = "claude",
) -> EngineResult:
    adapter = get_adapter(platform)
    ctx = build_context(adapter.normalize_payload(payload_dict))

    skipped = _check_skip(ctx, platform)
    if skipped is not None:
        return skipped

    ctx.trace.event(
        {
            "platform": platform,
            "event_name": ctx.event_name,
            "session_id": ctx.session_id,
            "tool_name": ctx.tool_name,
            "candidate_paths": ctx.candidate_paths,
            "languages": sorted(ctx.languages),
        }
    )

    acc = _run_rules(ctx, platform)
    output = render_output(ctx, acc.findings, adapter=adapter)

    ctx.trace.result(
        {
            "platform": platform,
            "event_name": ctx.event_name,
            "session_id": ctx.session_id,
            "tool_name": ctx.tool_name,
            "findings": _serialize_findings(acc.findings),
            "errors": acc.errors,
            "output": output,
        }
    )
    return EngineResult(
        event_name=ctx.event_name,
        findings=acc.findings,
        output=output,
        errors=acc.errors,
    )
