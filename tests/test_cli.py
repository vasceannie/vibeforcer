"""CLI parser smoke tests."""

from __future__ import annotations

import pytest

from vibeforcer.cli.cli import build_parser
from vibeforcer._types import object_dict, string_value


def _parse_lint(argv: list[str]) -> tuple[str, str | None]:
    parsed = build_parser().parse_args(argv)
    values = object_dict(vars(parsed))
    lint_command = string_value(values.get("lint_command"))
    path = string_value(values.get("path"))
    assert lint_command is not None, f"Expected lint_command in parsed args: {values}"
    return lint_command, path


def test_lint_check_defaults_to_current_directory() -> None:
    assert _parse_lint(["lint", "check", "."]) == ("check", ".")


def test_lint_init_respects_explicit_path() -> None:
    assert _parse_lint(["lint", "init", "/tmp/example"]) == ("init", "/tmp/example")


def test_lint_baseline_respects_explicit_path() -> None:
    assert _parse_lint(["lint", "baseline", "/tmp/example"]) == (
        "baseline",
        "/tmp/example",
    )


def test_lint_baseline_help_marks_command_disabled(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["lint", "baseline", "--help"])
    captured = capsys.readouterr()
    assert "Disabled: repo-wide rebaselining is not allowed" in captured.out


def test_lint_update_respects_explicit_path() -> None:
    assert _parse_lint(["lint", "update", "/tmp/example"]) == ("update", "/tmp/example")


def test_lint_check_respects_explicit_path() -> None:
    assert _parse_lint(["lint", "check", "/tmp/example"]) == ("check", "/tmp/example")


def test_lint_no_subcommand_defaults_to_check() -> None:
    lint_command, _path = _parse_lint(["lint"])
    assert lint_command == "check"
