"""CLI parser smoke tests."""

from __future__ import annotations

from vibeforcer.cli import build_parser


def test_lint_check_defaults_to_current_directory() -> None:
    parser = build_parser()
    parsed = parser.parse_args(["lint", "check", "."])

    assert (parsed.lint_command, parsed.path) == ("check", ".")


def test_lint_init_respects_explicit_path() -> None:
    parser = build_parser()
    parsed = parser.parse_args(["lint", "init", "/tmp/example"])

    assert (parsed.lint_command, parsed.path) == ("init", "/tmp/example")


def test_lint_baseline_respects_explicit_path() -> None:
    parser = build_parser()
    parsed = parser.parse_args(["lint", "baseline", "/tmp/example"])

    assert (parsed.lint_command, parsed.path) == ("baseline", "/tmp/example")


def test_lint_update_respects_explicit_path() -> None:
    parser = build_parser()
    parsed = parser.parse_args(["lint", "update", "/tmp/example"])

    assert (parsed.lint_command, parsed.path) == ("update", "/tmp/example")


def test_lint_check_respects_explicit_path() -> None:
    parser = build_parser()
    parsed = parser.parse_args(["lint", "check", "/tmp/example"])

    assert (parsed.lint_command, parsed.path) == ("check", "/tmp/example")


def test_lint_no_subcommand_defaults_to_check() -> None:
    parser = build_parser()
    parsed = parser.parse_args(["lint"])

    assert parsed.lint_command == "check"
