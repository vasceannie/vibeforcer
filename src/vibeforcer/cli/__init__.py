from __future__ import annotations

from vibeforcer.cli.main import main, safe_main
from vibeforcer.cli.parsers import build_parser

__all__ = ["build_parser", "main", "safe_main"]


if __name__ == "__main__":
    raise SystemExit(safe_main())
