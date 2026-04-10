from __future__ import annotations

from vibeforcer.constants import EXIT_KEYBOARD_INTERRUPT
from vibeforcer.cli.main import main as _main
from vibeforcer.cli.parsers import build_parser

__all__ = ["build_parser", "main", "safe_main"]


def main(argv: list[str] | None = None) -> int:
    return _main(argv)


def safe_main(argv: list[str] | None = None) -> int:
    try:
        return main(argv)
    except KeyboardInterrupt:
        return EXIT_KEYBOARD_INTERRUPT


if __name__ == "__main__":
    raise SystemExit(safe_main())
