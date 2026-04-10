"""Collector registry — runs all detectors and returns (rule_name, violations) pairs.

Pre-parses files once so AST-based detectors share the same parse result.
"""
from __future__ import annotations

from pathlib import Path

from vibeforcer.lint._baseline import Violation
from vibeforcer.lint._helpers import ParsedFile, parse_files


def _ast_src_collectors(
    src_files: list[Path],
    parsed_src: list[ParsedFile],
) -> list[tuple[str, list[Violation]]]:
    """Collect AST-based source violations (type safety, exceptions, logging, etc.)."""
    from vibeforcer.lint._detectors.exception_safety import (
        detect_broad_except_swallow,
        detect_silent_except,
        detect_silent_fallback,
    )
    from vibeforcer.lint._detectors.line_length import detect_long_lines
    from vibeforcer.lint._detectors.logging_conventions import (
        detect_direct_get_logger,
        detect_wrong_logger_name,
    )
    from vibeforcer.lint._detectors.stale_code import detect_deprecated_patterns
    from vibeforcer.lint._detectors.type_safety import (
        detect_any_usage,
        detect_type_suppressions,
    )
    from vibeforcer.lint._detectors.wrappers import detect_unnecessary_wrappers
    return [
        ("unnecessary-wrapper", detect_unnecessary_wrappers(src_files)),
        ("deprecated-pattern", detect_deprecated_patterns(src_files)),
        ("direct-get-logger", detect_direct_get_logger(src_files)),
        ("wrong-logger-name", detect_wrong_logger_name(src_files)),
        ("banned-any", detect_any_usage(parsed_src)),
        ("type-suppression", detect_type_suppressions(parsed_src)),
        ("broad-except-swallow", detect_broad_except_swallow(parsed_src)),
        ("silent-datetime-fallback", detect_silent_fallback(parsed_src)),
        ("silent-except", detect_silent_except(parsed_src)),
        ("long-line", detect_long_lines(parsed_src)),
    ]


def _structure_src_collectors(
    src_files: list[Path],
    parsed_src: list[ParsedFile],
    oversized: list[Violation],
    literals: list[Violation],
) -> list[tuple[str, list[Violation]]]:
    """Collect structure/complexity/duplicate source violations."""
    from vibeforcer.lint._detectors.code_smells import (
        detect_deep_nesting,
        detect_god_classes,
        detect_high_complexity,
        detect_long_methods,
        detect_too_many_params,
    )
    from vibeforcer.lint._detectors.duplicates import (
        detect_duplicate_call_sequences,
        detect_repeated_blocks,
        detect_semantic_clones,
    )
    return [
        ("high-complexity", detect_high_complexity(src_files)),
        ("long-method", detect_long_methods(src_files)),
        ("too-many-params", detect_too_many_params(src_files)),
        ("deep-nesting", detect_deep_nesting(src_files)),
        ("god-class", detect_god_classes(src_files)),
        ("oversized-module", [v for v in oversized if v.rule == "oversized-module"]),
        ("oversized-module-soft", [v for v in oversized if v.rule == "oversized-module-soft"]),
        ("semantic-clone", detect_semantic_clones(parsed_src)),
        ("repeated-magic-number", [v for v in literals if v.rule == "repeated-magic-number"]),
        ("repeated-string-literal", [v for v in literals if v.rule == "repeated-string-literal"]),
        ("repeated-code-block", detect_repeated_blocks(parsed_src)),
        ("duplicate-call-sequence", detect_duplicate_call_sequences(parsed_src)),
    ]


def _test_collectors(
    test_files: list[Path],
    parsed_tests: list[ParsedFile],
) -> list[tuple[str, list[Violation]]]:
    """Collect all test-file violation pairs."""
    from vibeforcer.lint._detectors.test_smells import (
        detect_assertion_free_tests,
        detect_assertion_roulette,
        detect_conditional_assertions,
        detect_eager_tests,
        detect_fixtures_outside_conftest,
        detect_long_tests,
    )
    return [
        ("long-test", detect_long_tests(test_files)),
        ("eager-test", detect_eager_tests(test_files)),
        ("assertion-free-test", detect_assertion_free_tests(test_files)),
        ("assertion-roulette", detect_assertion_roulette(parsed_tests)),
        ("conditional-assertion", detect_conditional_assertions(parsed_tests)),
        ("fixture-outside-conftest", detect_fixtures_outside_conftest(parsed_tests)),
    ]


def run_all_collectors(
    src_files: list[Path],
    test_files: list[Path],
) -> list[tuple[str, list[Violation]]]:
    """Run all detectors and return (rule_name, violations) pairs."""
    from vibeforcer.lint._detectors.code_smells import detect_oversized_modules
    from vibeforcer.lint._detectors.duplicates import detect_repeated_literals

    parsed_src = parse_files(src_files)
    parsed_tests = parse_files(test_files)
    oversized = detect_oversized_modules(src_files)
    literals = detect_repeated_literals(parsed_src)

    return [
        *_structure_src_collectors(src_files, parsed_src, oversized, literals),
        *_ast_src_collectors(src_files, parsed_src),
        *_test_collectors(test_files, parsed_tests),
    ]
