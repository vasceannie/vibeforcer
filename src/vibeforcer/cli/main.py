from __future__ import annotations

import argparse
import os
import sys

from vibeforcer.cli.parsers import build_parser
from vibeforcer.constants import EXIT_KEYBOARD_INTERRUPT


def _run_search_func(args: argparse.Namespace) -> int:
    from vibeforcer.search.config import IsxError

    try:
        return int(args.func(args) or 0)
    except IsxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _dispatch_search(args: argparse.Namespace) -> int:
    search_cmd = getattr(args, "search_command", None)
    if search_cmd and hasattr(args, "func"):
        return _run_search_func(args)

    query_args = getattr(args, "query_args", None)
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
    search_cmd = getattr(args, "search_command", None)
    if search_cmd and hasattr(args, "func"):
        return _run_search_func(args)

    query_args = getattr(args, "query_args", None)
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
    if args.version:
        from vibeforcer.cli.commands import cmd_version

        return cmd_version(args)
    if not args.command:
        parser.print_help()
        return 0
    if args.command == "search":
        return _dispatch_search(args)
    if not hasattr(args, "func"):
        parser.parse_args([args.command, "--help"])
        return 0
    return args.func(args)


def safe_main(argv: list[str] | None = None) -> int:
    try:
        return main(argv)
    except KeyboardInterrupt:
        return EXIT_KEYBOARD_INTERRUPT
