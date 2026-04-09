from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any

from .policy_defaults import RUNTIME_POLICY_DEFAULTS


class Severity(IntEnum):
    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40

    @classmethod
    def from_value(cls, value: str | int | None) -> "Severity":
        if isinstance(value, int):
            try:
                return cls(value)
            except ValueError:
                return cls.MEDIUM
        if isinstance(value, str):
            upper = value.strip().upper()
            return getattr(cls, upper, cls.MEDIUM)
        return cls.MEDIUM

    def as_name(self) -> str:
        return self.name


@dataclass(slots=True)
class RuleFinding:
    rule_id: str
    title: str
    severity: Severity
    decision: str | None = None
    message: str | None = None
    additional_context: str | None = None
    updated_input: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ContentTarget:
    path: str
    content: str
    source: str


@dataclass(slots=True)
class RegexRuleConfig:
    rule_id: str
    title: str
    severity: str = "MEDIUM"
    events: list[str] = field(default_factory=lambda: ["PreToolUse"])
    target: str = "content"
    action: str = "deny"
    message: str = ""
    additional_context: str | None = None
    patterns: list[str] = field(default_factory=list)
    path_globs: list[str] = field(default_factory=list)
    exclude_path_globs: list[str] = field(default_factory=list)
    tool_matchers: list[str] = field(default_factory=list)
    case_sensitive: bool = False
    multiline: bool = True


@dataclass(slots=True)
class RuntimeConfig:
    root: Path
    trace_dir: Path
    prompt_context_files: list[str]
    search_reminder_message: str
    protected_paths: list[str]
    sensitive_path_patterns: list[str]
    system_path_prefixes: list[str]
    python_ast_enabled: bool
    python_ast_max_parse_chars: int
    python_long_method_lines: int
    python_long_parameter_limit: int
    post_edit_quality_enabled: bool
    post_edit_quality_block_on_failure: bool
    post_edit_quality_commands: dict[str, list[str]]
    async_jobs_enabled: bool
    async_jobs_commands: dict[str, list[str]]
    # -- quality_gate.toml overrides --
    python_max_complexity: int = int(RUNTIME_POLICY_DEFAULTS["max_complexity"])
    python_max_nesting_depth: int = int(RUNTIME_POLICY_DEFAULTS["max_nesting_depth"])
    python_max_god_class_methods: int = int(
        RUNTIME_POLICY_DEFAULTS["max_god_class_methods"]
    )
    python_max_line_length: int = int(RUNTIME_POLICY_DEFAULTS["max_line_length"])
    python_feature_envy_threshold: float = float(
        RUNTIME_POLICY_DEFAULTS["feature_envy_threshold"]
    )
    python_feature_envy_min_accesses: int = int(
        RUNTIME_POLICY_DEFAULTS["feature_envy_min_accesses"]
    )
    python_import_fanout_limit: int = int(
        RUNTIME_POLICY_DEFAULTS["import_fanout_limit"]
    )
    # Global skip / per-repo exception support
    skip_paths: list[str] = field(default_factory=list)
    skip_if_file_exists: list[str] = field(
        default_factory=lambda: [".noqualitygate", ".no-quality-gate"]
    )
    disabled_rules: list[str] = field(default_factory=list)
    severity_overrides: dict[str, str] = field(default_factory=dict)
    enabled_rules: dict[str, bool] = field(default_factory=dict)
    regex_rules: list[RegexRuleConfig] = field(default_factory=list)


@dataclass(slots=True)
class EngineResult:
    event_name: str
    findings: list[RuleFinding] = field(default_factory=list)
    output: dict[str, Any] | None = None
    errors: list[str] = field(default_factory=list)
