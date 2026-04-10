from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from typing import cast

from vibeforcer.cli.parsers import build_parser
from vibeforcer.constants import EXIT_KEYBOARD_INTERRUPT


CommandFunc = Callable[[argparse.Namespace], int]


def _string_attr(args: argparse.Namespace, name: str) -> str | None:
    value = getattr(args, name, None)
    return value if isinstance(value, str) and value else None


def _bool_attr(args: argparse.Namespace, name: str) -> bool:
    value = getattr(args, name, False)
    return value if isinstance(value, bool) else False


def _callable_attr(args: argparse.Namespace, name: str) -> CommandFunc | None:
    value = getattr(args, name, None)
    return cast(CommandFunc, value) if callable(value) else None


def _string_list_attr(args: argparse.Namespace, name: str) -> list[str] | None:
    raw_value = getattr(args, name, None)
    if not isinstance(raw_value, list):
        return None
    values: list[str] = []
    raw_items = cast(list[object], raw_value)
    for item in raw_items:
        if not isinstance(item, str):
            return None
        values.append(item)
    return values or None


def _run_search_func(args: argparse.Namespace) -> int:
    from vibeforcer.search.config import IsxError

    try:
        func = _callable_attr(args, "func")
        if func is None:
            return 0
        return func(args)
    except IsxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _dispatch_search(args: argparse.Namespace) -> int:
    search_cmd = _string_attr(args, "search_command")
    if search_cmd and _callable_attr(args, "func") is not None:
        return _run_search_func(args)

    query_args = _string_list_attr(args, "query_args")
    if query_args:
        from vibeforcer.search.cli import cmd_search

        args.query = query_args
        args.func = cmd_search
        return _run_search_func(args)
    return 0


def _isx_main(argv: list[str] | None = None) -> int:
    from vibeforcer.search.cli import build_search_parser, cmd_search

    parser = build_search_parser(subparsers=None)
    args = parser.parse_args(argv)
    search_cmd = _string_attr(args, "search_command")
    if search_cmd and _callable_attr(args, "func") is not None:
        return _run_search_func(args)

    query_args = _string_list_attr(args, "query_args")
    if query_args:
        args.query = query_args
        args.func = cmd_search
        return _run_search_func(args)

    parser.print_help()
    return 0


def main(argv: list[str] | None = None) -> int:
    prog_name = os.path.basename(sys.argv[0]) if sys.argv else ""
    if prog_name == "isx":
        return _isx_main(argv)

    parser = build_parser()
    args = parser.parse_args(argv)
    if _bool_attr(args, "version"):
        from vibeforcer.cli.commands import cmd_version

        return cmd_version(args)
    command = _string_attr(args, "command")
    if command is None:
        parser.print_help()
        return 0
    if command == "search":
        return _dispatch_search(args)
    func = _callable_attr(args, "func")
    if func is None:
        _ = parser.parse_args([command, "--help"])
        return 0
    return func(args)


def safe_main(argv: list[str] | None = None) -> int:
    try:
        return main(argv)
    except KeyboardInterrupt:
        return EXIT_KEYBOARD_INTERRUPT
