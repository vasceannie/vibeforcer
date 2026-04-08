"""Quality gate detectors — each module scans for a specific category of issues."""
from __future__ import annotations

from .duplicates import (
    detect_duplicate_call_sequences,
    detect_repeated_blocks,
    detect_repeated_literals,
    detect_semantic_clones,
)
from .code_smells import (
    detect_deep_nesting,
    detect_god_classes,
    detect_high_complexity,
    detect_long_methods,
    detect_oversized_modules,
    detect_too_many_params,
)
from .exception_safety import (
    detect_broad_except_swallow,
    detect_silent_fallback,
)
from .line_length import detect_long_lines
from .logging_conventions import (
    detect_direct_get_logger,
    detect_wrong_logger_name,
)
from .stale_code import detect_deprecated_patterns
from .test_smells import (
    detect_assertion_free_tests,
    detect_assertion_roulette,
    detect_conditional_assertions,
    detect_eager_tests,
    detect_fixtures_outside_conftest,
    detect_long_tests,
)
from .type_safety import (
    detect_any_usage,
    detect_type_suppressions,
)
from .wrappers import detect_unnecessary_wrappers

__all__ = [
    "detect_any_usage",
    "detect_duplicate_call_sequences",
    "detect_repeated_blocks",
    "detect_repeated_literals",
    "detect_semantic_clones",
    "detect_assertion_free_tests",
    "detect_assertion_roulette",
    "detect_broad_except_swallow",
    "detect_conditional_assertions",
    "detect_deep_nesting",
    "detect_deprecated_patterns",
    "detect_direct_get_logger",
    "detect_eager_tests",
    "detect_fixtures_outside_conftest",
    "detect_god_classes",
    "detect_high_complexity",
    "detect_long_lines",
    "detect_long_methods",
    "detect_long_tests",
    "detect_oversized_modules",
    "detect_silent_fallback",
    "detect_too_many_params",
    "detect_type_suppressions",
    "detect_unnecessary_wrappers",
    "detect_wrong_logger_name",
]
