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
)
from vibeforcer.rules.regex_rule import RegexRule
from vibeforcer.rules.langgraph import (
    LangGraphDeprecatedAPIRule,
    LangGraphStateMutationRule,
    LangGraphStateReducerRule,
)
from vibeforcer.rules.baseline_guard import BaselineGuardRule
from vibeforcer.rules.error_rules import BashFailureReinforcementRule, BashOutputErrorRule
from vibeforcer.rules.stop_rules import (
    ConfigChangeGuardRule,
    SessionStartContextRule,
    HookInfraExecProtectionRule,
    IgnorePreexistingRule,
    RequireMakeQualityRule,
    RulebookSecurityRule,
    WarnLargeFileRule,
)


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
        BaselineGuardRule(),
        IgnorePreexistingRule(),
        RequireMakeQualityRule(),
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
    rules.extend(
        RegexRule(config=regex_rule, enabled=ctx.config.enabled_rules.get(regex_rule.rule_id, True))
        for regex_rule in ctx.config.regex_rules
    )
    return rules
