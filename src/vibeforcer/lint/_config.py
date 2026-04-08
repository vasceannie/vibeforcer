"""Configuration loader for quality gate."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


def _find_project_root(start: Path | None = None) -> Path:
    """Walk up from *start* (default: cwd) looking for project-root markers."""
    candidate = (start or Path.cwd()).resolve()
    markers = ("pyproject.toml", "setup.py", "setup.cfg", ".git", "quality_gate.toml")
    # Walk up until we hit a marker or the filesystem root
    for directory in (candidate, *candidate.parents):
        if any((directory / m).exists() for m in markers):
            return directory
    return candidate


@dataclass
class QualityConfig:
    """Central configuration for every quality-gate detector."""

    project_root: Path
    src_root: Path
    tests_root: Path
    exclude_dirs: set[str]
    exclude_patterns: set[str]

    # -- thresholds --
    max_complexity: int = 12
    max_params: int = 4
    max_method_lines: int = 50
    max_test_lines: int = 35
    max_module_lines_soft: int = 350
    max_module_lines_hard: int = 600
    max_nesting_depth: int = 4
    max_god_class_methods: int = 15
    max_god_class_lines: int = 400
    max_eager_test_calls: int = 7
    max_repeated_magic_numbers: int = 5
    max_repeated_string_literals: int = 10
    max_scattered_helpers: int = 5
    max_duplicate_helper_signatures: int = 10
    max_repeated_code_patterns: int = 50
    min_function_body_lines: int = 5
    min_call_sequence_length: int = 3

    # -- magic values --
    allowed_numbers: set[int | float] = field(
        default_factory=lambda: {0, 1, 2, 3, -1, 10, 100, 1000},
    )
    allowed_strings: set[str] = field(
        default_factory=lambda: {"", " ", "\n", "\t", "utf-8"},
    )

    # -- wrappers --
    allowed_wrappers: set[tuple[str, str]] = field(default_factory=set)

    # -- logging --
    logger_function: str = ""
    logger_variable: str = "logger"
    logging_infrastructure_path: str = ""
    disallowed_logger_names: frozenset[str] = frozenset({"_log", "_logger", "log", "LOG"})

    # -- thresholds (extended) --
    max_line_length: int = 120
    feature_envy_threshold: float = 0.60
    feature_envy_min_accesses: int = 6

    # -- type safety --
    ban_any: bool = True
    ban_type_suppressions: bool = True
    suppression_patterns: list[str] = field(default_factory=lambda: [
        r'(?i)#\s*type:\s*ignore',
        r'(?i)#\s*pyright:\s*ignore',
        r'(?i)#\s*pyre-ignore',
        r'(?i)#\s*noqa\b',
    ])

    # -- exception safety --
    ban_broad_except_swallow: bool = True
    ban_silent_except: bool = True
    ban_silent_fallback: bool = True

    # -- test smells --
    max_consecutive_bare_asserts: int = 3
    ban_conditional_assertions: bool = True
    ban_fixtures_outside_conftest: bool = True

    # -- deprecated patterns --
    deprecated_patterns: list[tuple[str, str]] = field(default_factory=list)

    # -- scope --
    default_scope: str = "all"

    # -- baseline --
    baseline_path: Path | None = None


# ---------------------------------------------------------------------------
# Raw config loading
# ---------------------------------------------------------------------------

_DEFAULT_DEPRECATED: list[list[str]] = [
    ["from typing import Optional", "Optional[X] → X | None"],
    ["from typing import Union", "Union[X, Y] → X | Y"],
    [r"from typing import List\b", "List[X] → list[X]"],
    [r"from typing import Dict\b", "Dict[K, V] → dict[K, V]"],
    [r"from typing import Tuple\b", "Tuple[X] → tuple[X]"],
    [r"from typing import Set\b", "Set[X] → set[X]"],
]


def _load_raw_config(project_root: Path) -> dict[str, Any]:
    """Load raw TOML dict from vibeforcer.lint.toml or pyproject.toml."""
    qg_path = project_root / "quality_gate.toml"
    if qg_path.exists():
        return tomllib.loads(qg_path.read_text(encoding="utf-8"))

    pp_path = project_root / "pyproject.toml"
    if pp_path.exists():
        data = tomllib.loads(pp_path.read_text(encoding="utf-8"))
        return data.get("tool", {}).get("quality-gate", {})

    return {}


def load_config(project_root: Path | None = None) -> QualityConfig:
    """Build a ``QualityConfig`` from the project's TOML files.

    Args:
        project_root: Explicit project root.  When *None* the root is
            auto-detected by walking up from cwd.
    """
    if project_root is None:
        project_root = _find_project_root()
    project_root = project_root.resolve()
    raw = _load_raw_config(project_root)

    paths = raw.get("paths", {})
    src_rel = paths.get("src", "src")
    tests_rel = paths.get("tests", "tests")
    exclude_dirs = set(paths.get("exclude_dirs", [".venv", "__pycache__", "node_modules", ".git"]))
    exclude_patterns = set(paths.get("exclude_patterns", ["*_pb2.py", "*_pb2_grpc.py", "*_pb2.pyi"]))

    thresholds = raw.get("thresholds", {})
    magic = raw.get("magic_values", {})
    wrappers_raw = raw.get("wrappers", {})
    logging_raw = raw.get("logging", {})
    deprecated_raw = raw.get("deprecated_patterns", {})
    scope_raw = raw.get("scope", {})
    type_safety_raw = raw.get("type_safety", {})
    exception_safety_raw = raw.get("exception_safety", {})
    test_smells_raw = raw.get("test_smells", {})

    allowed_nums: set[int | float] = set()
    for n in magic.get("allowed_numbers", [0, 1, 2, 3, -1, 10, 100, 1000]):
        allowed_nums.add(n)

    allowed_strs = set(magic.get("allowed_strings", ["", " ", "\n", "\t", "utf-8"]))
    allowed_wraps: set[tuple[str, str]] = {tuple(pair) for pair in wrappers_raw.get("allowed", [])}

    deprecated = [
        (p, d)
        for p, d in deprecated_raw.get("patterns", _DEFAULT_DEPRECATED)
    ]

    return QualityConfig(
        project_root=project_root,
        src_root=project_root / src_rel,
        tests_root=project_root / tests_rel,
        exclude_dirs=exclude_dirs,
        exclude_patterns=exclude_patterns,
        max_complexity=thresholds.get("max_complexity", 12),
        max_params=thresholds.get("max_params", 4),
        max_method_lines=thresholds.get("max_method_lines", 50),
        max_test_lines=thresholds.get("max_test_lines", 35),
        max_module_lines_soft=thresholds.get("max_module_lines_soft", 350),
        max_module_lines_hard=thresholds.get("max_module_lines_hard", 600),
        max_nesting_depth=thresholds.get("max_nesting_depth", 4),
        max_god_class_methods=thresholds.get("max_god_class_methods", 15),
        max_god_class_lines=thresholds.get("max_god_class_lines", 400),
        max_eager_test_calls=thresholds.get("max_eager_test_calls", 7),
        max_repeated_magic_numbers=thresholds.get("max_repeated_magic_numbers", 5),
        max_repeated_string_literals=thresholds.get("max_repeated_string_literals", 10),
        max_scattered_helpers=thresholds.get("max_scattered_helpers", 5),
        max_duplicate_helper_signatures=thresholds.get("max_duplicate_helper_signatures", 10),
        max_repeated_code_patterns=thresholds.get("max_repeated_code_patterns", 50),
        min_function_body_lines=thresholds.get("min_function_body_lines", 5),
        min_call_sequence_length=thresholds.get("min_call_sequence_length", 3),
        max_line_length=thresholds.get("max_line_length", 120),
        feature_envy_threshold=thresholds.get("feature_envy_threshold", 0.60),
        feature_envy_min_accesses=thresholds.get("feature_envy_min_accesses", 6),
        allowed_numbers=allowed_nums,
        allowed_strings=allowed_strs,
        allowed_wrappers=allowed_wraps,
        logger_function=logging_raw.get("logger_function", ""),
        logger_variable=logging_raw.get("logger_variable", "logger"),
        logging_infrastructure_path=logging_raw.get("infrastructure_path", ""),
        disallowed_logger_names=frozenset(
            logging_raw.get("disallowed_names", ["_log", "_logger", "log", "LOG"]),
        ),
        ban_any=type_safety_raw.get("ban_any", True),
        ban_type_suppressions=type_safety_raw.get("ban_type_suppressions", True),
        suppression_patterns=type_safety_raw.get("suppression_patterns", [
            r'(?i)#\s*type:\s*ignore',
            r'(?i)#\s*pyright:\s*ignore',
            r'(?i)#\s*pyre-ignore',
            r'(?i)#\s*noqa\b',
        ]),
        ban_broad_except_swallow=exception_safety_raw.get("ban_broad_except_swallow", True),
        ban_silent_except=exception_safety_raw.get("ban_silent_except", True),
        ban_silent_fallback=exception_safety_raw.get("ban_silent_fallback", True),
        max_consecutive_bare_asserts=test_smells_raw.get("max_consecutive_bare_asserts", 3),
        ban_conditional_assertions=test_smells_raw.get("ban_conditional_assertions", True),
        ban_fixtures_outside_conftest=test_smells_raw.get("ban_fixtures_outside_conftest", True),
        deprecated_patterns=deprecated,
        default_scope=scope_raw.get("default", "all"),
    )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_config: QualityConfig | None = None


def get_config() -> QualityConfig:
    """Return the cached ``QualityConfig`` singleton."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def set_config(config: QualityConfig) -> None:
    """Replace the singleton — used by CLI to inject an explicit root."""
    global _config
    _config = config


def reset_config() -> None:
    """Clear the singleton (for testing)."""
    global _config
    _config = None
