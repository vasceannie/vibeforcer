"""Tests for import-only window exclusion in _collect_block_windows."""
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

    def test_mixed_window_still_detected(self):
        """A window with 2 imports + 1 assignment IS included."""
        source = "import os\nimport sys\nx = 1\n"
        groups = _collect_block_windows([_make_parsed(source)])
        assert len(groups) > 0

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
