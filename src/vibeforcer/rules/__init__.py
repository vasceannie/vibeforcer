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
try:
    from vibeforcer.rules.python_ast import (
        PythonCyclomaticComplexityRule,
        PythonDeadCodeRule,
        PythonDeepNestingRule,
        PythonFeatureEnvyRule,
        PythonGodClassRule,
        PythonLongLineRule,
        PythonLongMethodRule,
        PythonLongParameterRule,
        PythonThinWrapperRule,
        PythonFlatFileSiblingsRule,
        PythonImportFanoutRule,
    )
    _PYTHON_AST_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - exercised in import-failure test
    _PYTHON_AST_IMPORT_ERROR = exc
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


_PYTHON_AST_IMPORT_REPORTED = False


def _build_python_ast_rules(ctx: HookContext) -> list[Rule]:
    global _PYTHON_AST_IMPORT_REPORTED

    if _PYTHON_AST_IMPORT_ERROR is not None:
        if not _PYTHON_AST_IMPORT_REPORTED:
            _PYTHON_AST_IMPORT_REPORTED = True
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
                    "additional_context": repr(_PYTHON_AST_IMPORT_ERROR),
                    "metadata": {"kind": "import_error"},
                }
            )
        return []

    return [
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


def build_rules(ctx: HookContext) -> list[Rule]:
    rules: list[Rule] = [
        PromptContextRule(),
        FullFileReadRule(),
        ProtectedPathsRule(),
        SensitiveDataRule(),
        SystemProtectionRule(),
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
