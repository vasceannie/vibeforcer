"""Tests for repeated-block import canonicalization behavior."""
# pyright: reportPrivateUsage=false
from __future__ import annotations

import ast
from pathlib import Path

from vibeforcer.lint._detectors.duplicates import _collect_block_windows
from vibeforcer.lint._helpers import (
    ParsedFile,
    build_parent_map,
    compute_string_line_ranges,
)


def _make_parsed(source: str, rel: str = "test.py") -> ParsedFile:
    tree = ast.parse(source)
    return ParsedFile(
        path=Path(rel),
        rel=rel,
        tree=tree,
        lines=source.splitlines(),
        parent_map=build_parent_map(tree),
        string_line_ranges=compute_string_line_ranges(tree),
    )


class TestCollectBlockWindowsImportExclusion:
    def test_pure_import_window_not_hashed(self):
        """A module-level body of 3 import statements produces no block windows."""
        source = "import os\nimport sys\nimport json\n"
        groups = _collect_block_windows([_make_parsed(source)])
        assert len(groups) == 0

    def test_same_import_block_in_two_files_no_violation(self):
        """Identical 3-import headers across files produce no repeated-code-block."""
        source = "import os\nimport sys\nimport json\n"
        pf1 = _make_parsed(source, rel="a.py")
        pf2 = _make_parsed(source, rel="b.py")
        groups = _collect_block_windows([pf1, pf2])
        assert len(groups) == 0

    def test_windows_overlapping_leading_import_block_are_excluded(self):
        """Boundary windows that include the leading import block are excluded."""
        source = "import os\nimport sys\nx = 1\n"
        groups = _collect_block_windows([_make_parsed(source)])
        assert len(groups) == 0

    def test_from_import_window_excluded(self):
        """from-import statements are also excluded when all-import."""
        source = (
            "from os import path\n"
            "from sys import argv\n"
            "from json import dumps\n"
        )
        groups = _collect_block_windows([_make_parsed(source)])
        assert len(groups) == 0

    def test_all_import_body_in_function_excluded(self):
        """Import statements inside a function body are also excluded."""
        source = (
            "def setup():\n"
            "    import os\n"
            "    import sys\n"
            "    import json\n"
        )
        groups = _collect_block_windows([_make_parsed(source)])
        assert len(groups) == 0


class TestCollectBlockWindowsImportCanonicalization:
    def test_same_imports_different_order_no_duplicate_alert(self):
        """Same leading imports in different order do not affect body scoring."""
        source_a = (
            "import os\n"
            "import json\n"
            "import sys\n"
            "x = normalize(data)\n"
            "y = x + 1\n"
            "return y\n"
        )
        source_b = (
            "import sys\n"
            "import os\n"
            "import json\n"
            "x = normalize(payload)\n"
            "y = x + 1\n"
            "return y\n"
        )

        groups = _collect_block_windows(
            [_make_parsed(source_a, rel="a.py"), _make_parsed(source_b, rel="b.py")]
        )

        assert groups
        members = [member for group in groups.values() for member in group]
        assert any(rel == "a.py" and start == 4 for rel, _, start, _ in members)
        assert any(rel == "b.py" and start == 4 for rel, _, start, _ in members)

    def test_same_body_different_imports_duplicate_alert_still_fires(self):
        """Body-only duplicate detection still works when imports differ."""
        source_a = (
            "import os\n"
            "import json\n"
            "import sys\n"
            "x = normalize(data)\n"
            "y = x + 1\n"
            "return y\n"
        )
        source_b = (
            "import requests\n"
            "from pathlib import Path\n"
            "from vibeforcer.engine import evaluate_payload\n"
            "x = normalize(payload)\n"
            "y = x + 1\n"
            "return y\n"
        )

        groups = _collect_block_windows(
            [_make_parsed(source_a, rel="a.py"), _make_parsed(source_b, rel="b.py")]
        )

        assert groups
        members = [member for group in groups.values() for member in group]
        assert any(rel == "a.py" and start == 4 for rel, _, start, _ in members)
        assert any(rel == "b.py" and start == 4 for rel, _, start, _ in members)
