from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]  # pyright: ignore[reportMissingImports]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

from vibeforcer.models import RegexRuleConfig, RuntimeConfig

# Sentinel filenames that disable the quality gate for a repo.
_DISABLE_SENTINELS = (".noqualitygate", ".no-quality-gate")


# ---------------------------------------------------------------------------
# XDG / config discovery
# ---------------------------------------------------------------------------


def config_dir() -> Path:
    """Return the vibeforcer config directory.

    Priority:
      1. $VIBEFORCER_CONFIG_DIR
      2. $XDG_CONFIG_HOME/vibeforcer
      3. ~/.config/vibeforcer
    """
    explicit = os.getenv("VIBEFORCER_CONFIG_DIR")
    if explicit:
        return Path(explicit).resolve()
    xdg = os.getenv("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg).resolve() / "vibeforcer"
    return Path.home() / ".config" / "vibeforcer"


def resolve_config_path() -> Path:
    """Resolve the config.json file path.

    Priority:
      1. $VIBEFORCER_CONFIG env var (explicit file path)
      2. config_dir() / config.json
      3. Legacy: $CLAUDE_HOOK_LAYER_ROOT / .claude/hook-layer/config.json
      4. Bundled defaults (resources/defaults.json)
    """
    # Explicit file override
    explicit_file = os.getenv("VIBEFORCER_CONFIG")
    if explicit_file:
        p = Path(explicit_file).resolve()
        if p.exists():
            return p

    # XDG location
    xdg_config = config_dir() / "config.json"
    if xdg_config.exists():
        return xdg_config

    # Legacy hook-layer location
    legacy_root = os.getenv("CLAUDE_HOOK_LAYER_ROOT") or os.getenv("HOOK_LAYER_ROOT")
    if legacy_root:
        legacy_path = Path(legacy_root) / ".claude" / "hook-layer" / "config.json"
        if legacy_path.exists():
            return legacy_path

    # Default legacy location
    legacy_default = Path.home() / ".claude" / "hooks" / "enforcer" / ".claude" / "hook-layer" / "config.json"
    if legacy_default.exists():
        return legacy_default

    # Bundled defaults
    from vibeforcer.resources import resource_path
    return resource_path("defaults.json")


def detect_root() -> Path:
    """Resolve the vibeforcer root directory for traces and prompt context.

    Priority:
      1. $VIBEFORCER_ROOT
      2. config_dir()
      3. Legacy: $CLAUDE_HOOK_LAYER_ROOT / $HOOK_LAYER_ROOT
    """
    explicit = os.getenv("VIBEFORCER_ROOT")
    if explicit:
        return Path(explicit).resolve()

    cfg = config_dir()
    if cfg.exists():
        return cfg

    legacy = os.getenv("CLAUDE_HOOK_LAYER_ROOT") or os.getenv("HOOK_LAYER_ROOT")
    if legacy:
        return Path(legacy).resolve()

    return cfg  # XDG default even if it doesn't exist yet


def _load_toml(root: Path) -> dict[str, Any]:
    """Load quality_gate.toml from project root if available."""
    if tomllib is None:
        return {}
    for name in ("quality_gate.toml",):
        toml_path = root / name
        if toml_path.exists():
            try:
                return tomllib.loads(toml_path.read_text(encoding="utf-8"))
            except Exception:
                return {}
    return {}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in {path}: {exc}") from exc


def is_repo_disabled(repo_root: Path | None = None) -> bool:
    """Check if the quality gate is disabled for a repo."""
    if repo_root is None:
        repo_root = Path.cwd().resolve()
    else:
        repo_root = repo_root.resolve()

    for sentinel in _DISABLE_SENTINELS:
        if (repo_root / sentinel).exists():
            return True

    toml_data = _load_toml(repo_root)
    qg_section = toml_data.get("quality_gate", {})
    if isinstance(qg_section, dict) and qg_section.get("enabled") is False:
        return True

    return False


def is_path_skipped(repo_path: Path, skip_paths: list[str]) -> bool:
    """Check if *repo_path* matches any glob in the central skip_paths list."""
    import fnmatch
    resolved = str(repo_path.resolve())
    for pattern in skip_paths:
        if fnmatch.fnmatch(resolved, pattern):
            return True
    return False


def load_config(root: Path | None = None) -> RuntimeConfig:
    """Load configuration with XDG discovery chain.

    Config is loaded from resolve_config_path(). Root is used for
    trace directory and prompt context file resolution.
    """
    actual_root = (root or detect_root()).resolve()
    config_path = resolve_config_path()
    raw = _load_json(config_path)

    regex_rules = [
        RegexRuleConfig(**item)
        for item in raw.get("regex_rules", [])
        if isinstance(item, dict)
    ]

    python_ast: dict[str, Any] = raw.get("python_ast", {})
    post_edit_quality: dict[str, Any] = raw.get("post_edit_quality", {})
    async_jobs: dict[str, Any] = raw.get("async_jobs", {})

    # Trace directory: relative to root, or absolute
    trace_dir_raw: str = str(raw.get("trace_dir", "logs"))
    trace_dir_path = Path(trace_dir_raw)
    if trace_dir_path.is_absolute():
        trace_dir = trace_dir_path
    else:
        trace_dir = actual_root / trace_dir_raw
    trace_dir.mkdir(parents=True, exist_ok=True)
    (trace_dir / "async").mkdir(parents=True, exist_ok=True)

    # Prompt context: resolve relative to config_path's parent or root
    prompt_context_files: list[str] = [str(p) for p in raw.get("prompt_context_files", [])]

    # Overlay thresholds from quality_gate.toml (per-repo)
    repo_root = Path.cwd().resolve()
    toml_data = _load_toml(repo_root)
    toml_thresholds: dict[str, Any] = toml_data.get("thresholds", {})

    # Per-repo rule overrides
    qg_section: dict[str, Any] = toml_data.get("quality_gate", {})
    disabled_rules_list: list[str] = []
    severity_overrides_map: dict[str, str] = {}
    if isinstance(qg_section, dict):
        disabled_rules_list = list(qg_section.get("disabled_rules", []))
        raw_sev = qg_section.get("severity_overrides", {})
        if isinstance(raw_sev, dict):
            severity_overrides_map = {str(k): str(v) for k, v in raw_sev.items()}

    skip_paths = [str(p) for p in raw.get("skip_paths", [])]
    skip_if_file_exists = [str(s) for s in raw.get("skip_if_file_exists", list(_DISABLE_SENTINELS))]

    return RuntimeConfig(
        root=actual_root,
        trace_dir=trace_dir,
        prompt_context_files=prompt_context_files,
        search_reminder_message=str(raw.get("search_reminder_message", "")).strip(),
        protected_paths=list(raw.get("protected_paths", [])),
        sensitive_path_patterns=list(raw.get("sensitive_path_patterns", [])),
        system_path_prefixes=list(raw.get("system_path_prefixes", [])),
        python_ast_enabled=bool(python_ast.get("enabled", True)),
        python_ast_max_parse_chars=int(python_ast.get("max_parse_chars", 200000)),
        python_long_method_lines=int(toml_thresholds.get("max_method_lines", python_ast.get("long_method_lines", 50))),
        python_long_parameter_limit=int(toml_thresholds.get("max_params", python_ast.get("long_parameter_limit", 4))),
        post_edit_quality_enabled=bool(post_edit_quality.get("enabled", False)),
        post_edit_quality_block_on_failure=bool(post_edit_quality.get("block_on_failure", True)),
        post_edit_quality_commands={
            str(key): [str(item) for item in value]
            for key, value in post_edit_quality.get("commands_by_language", {}).items()
            if isinstance(value, list)
        },
        async_jobs_enabled=bool(async_jobs.get("enabled", False)),
        async_jobs_commands={
            str(key): [str(item) for item in value]
            for key, value in async_jobs.get("commands_by_language", {}).items()
            if isinstance(value, list)
        },
        python_max_complexity=int(toml_thresholds.get("max_complexity", 10)),
        python_max_nesting_depth=int(toml_thresholds.get("max_nesting_depth", 4)),
        python_max_god_class_methods=int(toml_thresholds.get("max_god_class_methods", 10)),
        python_max_line_length=int(toml_thresholds.get("max_line_length", 120)),
        python_feature_envy_threshold=float(toml_thresholds.get("feature_envy_threshold", 0.60)),
        python_feature_envy_min_accesses=int(toml_thresholds.get("feature_envy_min_accesses", 6)),
        python_import_fanout_limit=int(toml_thresholds.get("import_fanout_limit", 5)),
        skip_paths=skip_paths,
        skip_if_file_exists=skip_if_file_exists,
        disabled_rules=disabled_rules_list,
        severity_overrides=severity_overrides_map,
        enabled_rules={
            str(key): bool(value)
            for key, value in raw.get("enabled_rules", {}).items()
        },
        regex_rules=regex_rules,
    )
