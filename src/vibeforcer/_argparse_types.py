from __future__ import annotations

import argparse
from collections.abc import Sequence
from typing import Protocol


class SubparserRegistry(Protocol):
    """Structural type for objects that can register argparse subparsers."""

    def add_parser(
        self,
        name: str,
        *,
        prog: str | None = None,
        usage: str | None = None,
        description: str | None = None,
        epilog: str | None = None,
        parents: Sequence[argparse.ArgumentParser] = (),
        formatter_class: type[argparse.HelpFormatter] = argparse.HelpFormatter,
        prefix_chars: str = "-",
        fromfile_prefix_chars: str | None = None,
        argument_default: object | None = None,
        conflict_handler: str = "error",
        add_help: bool = True,
        allow_abbrev: bool = True,
        aliases: Sequence[str] = (),
        help: str | None = None,
        deprecated: bool = False,
    ) -> argparse.ArgumentParser: ...
