from __future__ import annotations

from typing import Any

from pathlib import Path

from vibeforcer.adapters import get_adapter
from vibeforcer.adapters.base import PlatformAdapter
from vibeforcer.config import is_path_skipped, is_repo_disabled
from vibeforcer.context import HookContext, build_context
from vibeforcer.enrichment import enrich_findings
from vibeforcer.models import EngineResult, RuleFinding
from vibeforcer.rules import build_rules


DECISION_ORDER = {
    "deny": 4,
    "block": 4,
    "ask": 3,
    "allow": 2,
    None: 0,
}


def _sort_findings(findings: list[RuleFinding]) -> list[RuleFinding]:
    return sorted(
        findings,
        key=lambda item: (DECISION_ORDER.get(item.decision, 0), int(item.severity)),
        reverse=True,
    )


def _merge_updated_input(findings: list[RuleFinding]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for finding in findings:
        merged.update(finding.updated_input)
    return merged


def _collect_context(findings: list[RuleFinding]) -> str | None:
    parts = [item.additional_context for item in findings if item.additional_context]
    if not parts:
        return None
    return "\n\n".join(dict.fromkeys(parts))


def _top_decision(findings: list[RuleFinding]) -> str | None:
    ordered = _sort_findings(findings)
    return ordered[0].decision if ordered else None


def render_output(
    ctx: HookContext,
    findings: list[RuleFinding],
    adapter: PlatformAdapter | None = None,
) -> dict[str, Any] | None:
    if not findings:
        return None

    adapter = adapter or get_adapter("claude")
    decision = _top_decision(findings)
    context = _collect_context(findings)
    updated_input = _merge_updated_input(findings)

    return adapter.render_output(
        ctx.event_name,
        findings,
        context=context,
        updated_input=updated_input,
        decision=decision,
    )


def evaluate_payload(
    payload_dict: dict[str, Any],
    platform: str = "claude",
) -> EngineResult:
    adapter = get_adapter(platform)
    canonical = adapter.normalize_payload(payload_dict)
    ctx = build_context(canonical)

    repo_cwd = Path(ctx.cwd) if ctx.cwd else Path.cwd()
    if is_repo_disabled(repo_cwd) or is_path_skipped(repo_cwd, ctx.config.skip_paths):
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

    findings: list[RuleFinding] = []
    errors: list[str] = []

    disabled_rules = set(ctx.config.disabled_rules)
    sev_overrides = ctx.config.severity_overrides

    for rule in build_rules(ctx):
        if not rule.supports(ctx.event_name):
            continue
        if rule.rule_id in disabled_rules:
            continue
        try:
            result = rule.evaluate(ctx)
            if result:
                for finding in result:
                    if finding.rule_id in sev_overrides:
                        from vibeforcer.models import Severity
                        override = sev_overrides[finding.rule_id]
                        if override.lower() == "warn":
                            finding.severity = Severity.LOW
                            finding.decision = None
                        else:
                            finding.severity = Severity.from_value(override)
                findings.extend(result)
                for item in result:
                    ctx.trace.rule(
                        {
                            "platform": platform,
                            "event_name": ctx.event_name,
                            "session_id": ctx.session_id,
                            "tool_name": ctx.tool_name,
                            "rule_id": item.rule_id,
                            "severity": item.severity.as_name(),
                            "decision": item.decision,
                            "message": item.message,
                            "additional_context": item.additional_context,
                            "metadata": item.metadata,
                        }
                    )
        except Exception as exc:
            errors.append(f"{rule.rule_id}: {exc}")
            ctx.trace.rule(
                {
                    "platform": platform,
                    "event_name": ctx.event_name,
                    "session_id": ctx.session_id,
                    "tool_name": ctx.tool_name,
                    "rule_id": getattr(rule, "rule_id", type(rule).__name__),
                    "error": repr(exc),
                }
            )

    try:
        enrich_findings(findings, ctx)
    except Exception:
        pass

    output = render_output(ctx, findings, adapter=adapter)
    ctx.trace.result(
        {
            "platform": platform,
            "event_name": ctx.event_name,
            "session_id": ctx.session_id,
            "tool_name": ctx.tool_name,
            "findings": [
                {
                    "rule_id": item.rule_id,
                    "severity": item.severity.as_name(),
                    "decision": item.decision,
                    "message": item.message,
                    "additional_context": item.additional_context,
                    "metadata": item.metadata,
                }
                for item in findings
            ],
            "errors": errors,
            "output": output,
        }
    )
    return EngineResult(event_name=ctx.event_name, findings=findings, output=output, errors=errors)
