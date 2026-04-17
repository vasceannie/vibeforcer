from __future__ import annotations

from vibeforcer.context import HookContext
from vibeforcer.rules.base import Rule
from vibeforcer.rules.common import (
    FullFileReadRule,
    GitNoVerifyRule,
    PostEditQualityRule,
    PromptContextRule,
    ProtectedPathsRule,
    SearchReminderRule,
    SensitiveDataRule,
    SystemProtectionRule,
)
from vibeforcer.rules.regex_rule import RegexRule
from vibeforcer.rules.langgraph import (
    LangGraphDeprecatedAPIRule,
    LangGraphStateMutationRule,
    LangGraphStateReducerRule,
)
from vibeforcer.rules.baseline_guard import BaselineGuardRule
from vibeforcer.rules.error_rules import (
    BashFailureReinforcementRule,
    BashOutputErrorRule,
)
from vibeforcer.rules.stop_rules import (
    ConfigChangeGuardRule,
    SessionStartContextRule,
    HookInfraExecProtectionRule,
    IgnorePreexistingRule,
    RequireQualityCheckRule,
    RulebookSecurityRule,
    WarnLargeFileRule,
)


_PYTHON_AST_IMPORT_ERROR: Exception | None = None
_PYTHON_AST_IMPORT_REPORTED = False

# Backward-compatible aliases for older internal references.
_python_ast_import_error: Exception | None = None
_python_ast_import_reported = False


def _build_python_ast_rules(ctx: HookContext) -> list[Rule]:
    global _python_ast_import_error, _python_ast_import_reported

    current_error = _PYTHON_AST_IMPORT_ERROR or _python_ast_import_error
    already_reported = _PYTHON_AST_IMPORT_REPORTED or _python_ast_import_reported

    if current_error is not None:
        if not already_reported:
            _python_ast_import_reported = True
            ctx.trace.rule(
                {
                    "platform": "any",
                    "event_name": ctx.event_name,
                    "session_id": ctx.session_id,
                    "tool_name": ctx.tool_name,
                    "rule_id": "PY-AST-IMPORT-001",
                    "severity": "high",
                    "decision": None,
                    "message": "Python AST rules disabled due to import error",
                    "additional_context": repr(current_error),
                    "metadata": {"kind": "import_error"},
                }
            )
        return []

    try:
        from vibeforcer.rules.python_ast import (
            PythonCyclomaticComplexityRule,
            PythonDeadCodeRule,
            PythonDeepNestingRule,
            PythonFeatureEnvyRule,
            PythonFlatFileSiblingsRule,
            PythonGodClassRule,
            PythonImportFanoutRule,
            PythonLongLineRule,
            PythonLongMethodRule,
            PythonLongParameterRule,
            PythonThinWrapperRule,
        )
    except Exception as exc:  # pragma: no cover - exercised in import-failure test
        _python_ast_import_error = exc
        return _build_python_ast_rules(ctx)

    python_ast_rules: list[Rule] = [
        PythonLongMethodRule(),
        PythonLongParameterRule(),
        PythonLongLineRule(),
        PythonDeepNestingRule(),
        PythonFeatureEnvyRule(),
        PythonThinWrapperRule(),
        PythonGodClassRule(),
        PythonCyclomaticComplexityRule(),
        PythonDeadCodeRule(),
        PythonFlatFileSiblingsRule(),
        PythonImportFanoutRule(),
    ]
    return python_ast_rules


def build_always_on_rules(ctx: HookContext) -> list[Rule]:
    return [
        ProtectedPathsRule(),
        SensitiveDataRule(),
        SystemProtectionRule(),
    ]


def build_repo_strict_rules(ctx: HookContext) -> list[Rule]:
    rules: list[Rule] = [
        PromptContextRule(),
        FullFileReadRule(),
        GitNoVerifyRule(),
        SearchReminderRule(),
        PostEditQualityRule(),
        BaselineGuardRule(),
        IgnorePreexistingRule(),
        RequireQualityCheckRule(),
        WarnLargeFileRule(),
        HookInfraExecProtectionRule(),
        RulebookSecurityRule(),
        ConfigChangeGuardRule(),
        SessionStartContextRule(),
        BashOutputErrorRule(),
        BashFailureReinforcementRule(),
        LangGraphStateReducerRule(),
        LangGraphStateMutationRule(),
        LangGraphDeprecatedAPIRule(),
    ]
    rules.extend(_build_python_ast_rules(ctx))
    rules.extend(
        RegexRule(
            config=regex_rule,
            enabled=ctx.config.enabled_rules.get(regex_rule.rule_id, True),
        )
        for regex_rule in ctx.config.regex_rules
    )
    return rules


def build_rules(ctx: HookContext) -> list[Rule]:
    """Backward-compatible aggregate of always-on and repo-strict rules."""
    return [*build_always_on_rules(ctx), *build_repo_strict_rules(ctx)]
