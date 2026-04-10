from __future__ import annotations

import argparse

from vibeforcer.cli.commands import (
    VALID_PLATFORMS,
    _PLATFORM_HELP,
    cmd_check,
    cmd_config_init,
    cmd_config_path,
    cmd_config_show,
    cmd_handle,
    cmd_handle_async,
    cmd_install,
    cmd_replay,
    cmd_stats,
    cmd_test,
    cmd_uninstall,
    cmd_version,
)
from vibeforcer.cli.lint import cmd_lint


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vibeforcer",
        description="Global CLI guardrails engine for AI coding agents",
    )
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    sub = parser.add_subparsers(dest="command")
    _add_core_parsers(sub)
    _add_config_parsers(sub)
    _add_lint_parsers(sub)

    from vibeforcer.search.cli import build_search_parser

    build_search_parser(sub)
    version = sub.add_parser("version", help="Print version")
    version.set_defaults(func=cmd_version)
    return parser


def _add_core_parsers(sub: argparse._SubParsersAction) -> None:
    handle = sub.add_parser("handle", help="Read hook payload from stdin")
    handle.add_argument(
        "--platform", choices=VALID_PLATFORMS, default="claude", help=_PLATFORM_HELP
    )
    handle.set_defaults(func=cmd_handle)

    handle_async = sub.add_parser("handle-async", help="Run async post-edit jobs")
    handle_async.set_defaults(func=cmd_handle_async)

    check = sub.add_parser("check", help="Check quality gate for a repo")
    check.add_argument("path", nargs="?", default=".")
    check.set_defaults(func=cmd_check)

    replay = sub.add_parser("replay", help="Replay a saved payload")
    replay.add_argument("--payload", required=True)
    replay.add_argument("--pretty", action="store_true")
    replay.add_argument(
        "--platform", choices=VALID_PLATFORMS, default="claude", help=_PLATFORM_HELP
    )
    replay.set_defaults(func=cmd_replay)

    install = sub.add_parser("install", help="Install hooks for a platform")
    install.add_argument("platform", choices=VALID_PLATFORMS)
    install.add_argument("--dry-run", action="store_true")
    install.set_defaults(func=cmd_install)

    uninstall = sub.add_parser("uninstall", help="Remove hooks from a platform")
    uninstall.add_argument("platform", choices=VALID_PLATFORMS)
    uninstall.add_argument("--dry-run", action="store_true")
    uninstall.set_defaults(func=cmd_uninstall)

    stats = sub.add_parser("stats", help="Analyze hook activity logs")
    stats.add_argument("--log")
    stats.add_argument("--days", type=int)
    stats.add_argument("--json", action="store_true")
    stats.set_defaults(func=cmd_stats)

    test = sub.add_parser("test", help="Run self-test / smoke test")
    test.set_defaults(func=cmd_test)


def _add_config_parsers(sub: argparse._SubParsersAction) -> None:
    config_parser = sub.add_parser("config", help="Configuration management")
    config_sub = config_parser.add_subparsers(dest="config_command")

    show = config_sub.add_parser("show", help="Show effective configuration")
    show.set_defaults(func=cmd_config_show)

    init = config_sub.add_parser("init", help="Create config from defaults")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_config_init)

    path = config_sub.add_parser("path", help="Print config file path")
    path.set_defaults(func=cmd_config_path)


def _add_lint_parsers(sub: argparse._SubParsersAction) -> None:
    lint = sub.add_parser("lint", help="Batch code quality analysis")
    lint_sub = lint.add_subparsers(dest="lint_command")

    check = lint_sub.add_parser("check", help="Lint a project")
    check.add_argument("path", nargs="?", default=".")
    check.set_defaults(func=cmd_lint, lint_command="check")

    baseline = lint_sub.add_parser("baseline", help="Generate baselines.json")
    baseline.add_argument("path", nargs="?", default=".")
    baseline.set_defaults(func=cmd_lint, lint_command="baseline")

    init = lint_sub.add_parser("init", help="Scaffold quality_gate.toml")
    init.add_argument("path", nargs="?", default=".")
    init.set_defaults(func=cmd_lint, lint_command="init")

    update = lint_sub.add_parser("update", help="Add missing config keys")
    update.add_argument("path", nargs="?", default=".")
    update.add_argument("--dry-run", action="store_true")
    update.set_defaults(func=cmd_lint, lint_command="update")

    lint.set_defaults(func=cmd_lint, lint_command="check")
