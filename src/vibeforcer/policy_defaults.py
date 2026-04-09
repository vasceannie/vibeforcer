"""Shared policy defaults for runtime and lint quality-gate settings.

These values are the canonical source for runtime policy, lint thresholds,
magic-value defaults, and test-smell defaults.
"""

from __future__ import annotations

from typing import Final, TypedDict

from .constants import (
    LINT_ALLOWED_NUMBERS,
    LINT_ALLOWED_STRINGS,
    LINT_BAN_CONDITIONAL_ASSERTIONS,
    LINT_BAN_FIXTURES_OUTSIDE_CONFTEXT,
    LINT_FEATURE_ENVY_MIN_ACCESSES,
    LINT_FEATURE_ENVY_THRESHOLD,
    LINT_MAX_CONSECUTIVE_BARE_ASSERTS,
    LINT_MAX_DUPLICATE_HELPER_SIGNATURES,
    LINT_MAX_EAGER_TEST_CALLS,
    LINT_MAX_GOD_CLASS_LINES,
    LINT_MAX_GOD_CLASS_METHODS,
    LINT_MAX_LINE_LENGTH,
    LINT_MAX_METHOD_LINES,
    LINT_MIN_CALL_SEQUENCE_LENGTH,
    LINT_MIN_FUNCTION_BODY_LINES,
    LINT_MAX_MODULE_LINES_HARD,
    LINT_MAX_MODULE_LINES_SOFT,
    LINT_MAX_NESTING_DEPTH,
    LINT_MAX_PARAMS,
    LINT_MAX_REPEATED_CODE_PATTERNS,
    LINT_MAX_REPEATED_MAGIC_NUMBERS,
    LINT_MAX_REPEATED_STRING_LITERALS,
    LINT_MAX_SCATTERED_HELPERS,
    LINT_MAX_TEST_LINES,
    LINT_MAX_COMPLEXITY,
    RUNTIME_FEATURE_ENVY_MIN_ACCESSES,
    RUNTIME_FEATURE_ENVY_THRESHOLD,
    RUNTIME_IMPORT_FANOUT_LIMIT,
    RUNTIME_LONG_METHOD_LINES,
    RUNTIME_LONG_PARAMETER_LIMIT,
    RUNTIME_MAX_COMPLEXITY,
    RUNTIME_MAX_GOD_CLASS_METHODS,
    RUNTIME_MAX_LINE_LENGTH,
    RUNTIME_MAX_NESTING_DEPTH,
    RUNTIME_MAX_PARSE_CHARS,
)


class _LintMagicDefaults(TypedDict):
    """Shape of shared magic value defaults."""

    allowed_numbers: list[int | float]
    allowed_strings: list[str]


class _LintTestingDefaults(TypedDict):
    """Shape of shared test-smell defaults."""

    max_consecutive_bare_asserts: int
    ban_conditional_assertions: bool
    ban_fixtures_outside_conftest: bool


class _LintPathDefaults(TypedDict):
    """Shape of shared path defaults."""

    src: str
    tests: str
    exclude_dirs: list[str]
    exclude_patterns: list[str]


class _LintWrappersDefaults(TypedDict):
    """Shape of shared wrapper defaults."""

    allowed: list[list[str]]


class _LintLoggingDefaults(TypedDict):
    """Shape of shared logging defaults."""

    logger_function: str
    logger_variable: str
    infrastructure_path: str
    disallowed_names: list[str]


class _LintTypeSafetyDefaults(TypedDict):
    """Shape of shared type-safety defaults."""

    ban_any: bool
    ban_type_suppressions: bool
    suppression_patterns: list[str]


class _LintExceptionSafetyDefaults(TypedDict):
    """Shape of shared exception-safety defaults."""

    ban_broad_except_swallow: bool
    ban_silent_except: bool
    ban_silent_fallback: bool


class _LintDeprecatedPatternsDefaults(TypedDict):
    """Shape of shared deprecated-pattern defaults."""

    patterns: list[list[str]]


class _LintScopeDefaults(TypedDict):
    """Shape of shared scope defaults."""

    default: str


LINT_PATH_DEFAULTS: Final[_LintPathDefaults] = {
    "src": "src",
    "tests": "tests",
    "exclude_dirs": [".venv", "__pycache__", "node_modules", ".git"],
    "exclude_patterns": ["*_pb2.py", "*_pb2_grpc.py", "*_pb2.pyi"],
}


LINT_WRAPPERS_DEFAULTS: Final[_LintWrappersDefaults] = {
    "allowed": [],
}


LINT_LOGGING_DEFAULTS: Final[_LintLoggingDefaults] = {
    "logger_function": "",
    "logger_variable": "logger",
    "infrastructure_path": "",
    "disallowed_names": ["_log", "_logger", "log", "LOG"],
}


LINT_TYPE_SAFETY_DEFAULTS: Final[_LintTypeSafetyDefaults] = {
    "ban_any": True,
    "ban_type_suppressions": True,
    "suppression_patterns": [
        r"(?i)#\s*type:\s*ignore",
        r"(?i)#\s*pyright:\s*ignore",
        r"(?i)#\s*pyre-ignore",
        r"(?i)#\s*noqa\b",
    ],
}


LINT_EXCEPTION_SAFETY_DEFAULTS: Final[_LintExceptionSafetyDefaults] = {
    "ban_broad_except_swallow": True,
    "ban_silent_except": True,
    "ban_silent_fallback": True,
}


LINT_DEPRECATED_PATTERNS_DEFAULTS: Final[_LintDeprecatedPatternsDefaults] = {
    "patterns": [
        ["from typing import Optional", "Optional[X] → X | None"],
        ["from typing import Union", "Union[X, Y] → X | Y"],
        [r"from typing import List\b", "List[X] → list[X]"],
        [r"from typing import Dict\b", "Dict[K, V] → dict[K, V]"],
        [r"from typing import Tuple\b", "Tuple[X] → tuple[X]"],
        [r"from typing import Set\b", "Set[X] → set[X]"],
    ],
}


LINT_SCOPE_DEFAULTS: Final[_LintScopeDefaults] = {
    "default": "all",
}


RUNTIME_POLICY_DEFAULTS: dict[str, int | float] = {
    "max_complexity": RUNTIME_MAX_COMPLEXITY,
    "max_nesting_depth": RUNTIME_MAX_NESTING_DEPTH,
    "max_god_class_methods": RUNTIME_MAX_GOD_CLASS_METHODS,
    "max_line_length": RUNTIME_MAX_LINE_LENGTH,
    "feature_envy_threshold": RUNTIME_FEATURE_ENVY_THRESHOLD,
    "feature_envy_min_accesses": RUNTIME_FEATURE_ENVY_MIN_ACCESSES,
    "import_fanout_limit": RUNTIME_IMPORT_FANOUT_LIMIT,
    "long_method_lines": RUNTIME_LONG_METHOD_LINES,
    "long_parameter_limit": RUNTIME_LONG_PARAMETER_LIMIT,
    "max_parse_chars": RUNTIME_MAX_PARSE_CHARS,
}


LINT_THRESHOLD_DEFAULTS: dict[str, int | float] = {
    "max_complexity": LINT_MAX_COMPLEXITY,
    "max_params": LINT_MAX_PARAMS,
    "max_method_lines": LINT_MAX_METHOD_LINES,
    "max_test_lines": LINT_MAX_TEST_LINES,
    "max_module_lines_soft": LINT_MAX_MODULE_LINES_SOFT,
    "max_module_lines_hard": LINT_MAX_MODULE_LINES_HARD,
    "max_nesting_depth": LINT_MAX_NESTING_DEPTH,
    "max_god_class_methods": LINT_MAX_GOD_CLASS_METHODS,
    "max_god_class_lines": LINT_MAX_GOD_CLASS_LINES,
    "max_eager_test_calls": LINT_MAX_EAGER_TEST_CALLS,
    "max_repeated_magic_numbers": LINT_MAX_REPEATED_MAGIC_NUMBERS,
    "max_repeated_string_literals": LINT_MAX_REPEATED_STRING_LITERALS,
    "max_scattered_helpers": LINT_MAX_SCATTERED_HELPERS,
    "max_duplicate_helper_signatures": LINT_MAX_DUPLICATE_HELPER_SIGNATURES,
    "max_repeated_code_patterns": LINT_MAX_REPEATED_CODE_PATTERNS,
    "min_function_body_lines": LINT_MIN_FUNCTION_BODY_LINES,
    "min_call_sequence_length": LINT_MIN_CALL_SEQUENCE_LENGTH,
    "max_line_length": LINT_MAX_LINE_LENGTH,
    "feature_envy_threshold": LINT_FEATURE_ENVY_THRESHOLD,
    "feature_envy_min_accesses": LINT_FEATURE_ENVY_MIN_ACCESSES,
}


LINT_MAGIC_DEFAULTS: Final[_LintMagicDefaults] = {
    "allowed_numbers": list(LINT_ALLOWED_NUMBERS),
    "allowed_strings": list(LINT_ALLOWED_STRINGS),
}


LINT_TESTING_DEFAULTS: Final[_LintTestingDefaults] = {
    "max_consecutive_bare_asserts": LINT_MAX_CONSECUTIVE_BARE_ASSERTS,
    "ban_conditional_assertions": LINT_BAN_CONDITIONAL_ASSERTIONS,
    "ban_fixtures_outside_conftest": LINT_BAN_FIXTURES_OUTSIDE_CONFTEXT,
}


__all__ = [
    "RUNTIME_POLICY_DEFAULTS",
    "LINT_THRESHOLD_DEFAULTS",
    "LINT_MAGIC_DEFAULTS",
    "LINT_TESTING_DEFAULTS",
    "LINT_PATH_DEFAULTS",
    "LINT_WRAPPERS_DEFAULTS",
    "LINT_LOGGING_DEFAULTS",
    "LINT_TYPE_SAFETY_DEFAULTS",
    "LINT_EXCEPTION_SAFETY_DEFAULTS",
    "LINT_DEPRECATED_PATTERNS_DEFAULTS",
    "LINT_SCOPE_DEFAULTS",
]
