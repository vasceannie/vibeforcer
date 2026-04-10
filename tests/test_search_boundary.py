from __future__ import annotations

import subprocess
from pathlib import Path


def _search_boundary_output() -> str:
    search_root = Path(__file__).resolve().parents[1] / "src" / "vibeforcer" / "search"
    result = subprocess.run(
        [
            "rg",
            "-n",
            r"vibeforcer\.(rules|engine|enrichment|lint)",
            str(search_root),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def test_search_imports_no_core_modules() -> None:
    """search/ must not import rules, engine, enrichment, or lint modules."""
    output = _search_boundary_output()
    assert output == "", f"search package imported forbidden core modules:\n{output}"
