from __future__ import annotations

import json
import importlib
import os
from pathlib import Path

_TOML_PARSER = None
for module_name in ("tomllib", "tomli"):
    try:
        _module = importlib.import_module(module_name)
    except ModuleNotFoundError:
        continue
    if callable(getattr(_module, "loads", None)):
        _TOML_PARSER = _module
        break

from vibeforcer.models import RegexRuleConfig, RuntimeConfig
from vibeforcer.policy_defaults import RUNTIME_POLICY_DEFAULTS
from vibeforcer.util import warning

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
    legacy_default = (
        Path.home()
        / ".claude"
        / "hooks"
        / "enforcer"
        / ".claude"
        / "hook-layer"
        / "config.json"
    )
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


def _load_toml(root: Path) -> dict[str, object]:
    """Load quality_gate.toml from project root if available."""
    if _TOML_PARSER is None:
        return {}
    for name in ("quality_gate.toml",):
        toml_path = root / name
        if toml_path.exists():
            try:
                return _TOML_PARSER.loads(toml_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                warning(
                    "quality gate TOML load failed",
                    path=str(toml_path),
                    error=str(exc),
                )
                return {}
    return {}


def _load_json(path: Path) -> dict[str, object]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        warning(
            "quality gate JSON load failed",
            path=str(path),
            error=str(exc),
        )
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
    qg_section = _object_dict(toml_data.get("quality_gate", {}))
    if _bool_value(qg_section.get("enabled"), True) is False:
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


def _object_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items()}


def _string_value(value: object, default: str = "") -> str:
    return default if value is None else str(value)


def _bool_value(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return bool(value)


def _int_value(value: object, default: int) -> int:
    if value is None:
        return default
    return int(str(value))


def _float_value(value: object, default: float) -> float:
    if value is None:
        return default
    return float(str(value))


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _command_map(value: object) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        return {}

    commands: dict[str, list[str]] = {}
    for key, item in value.items():
        if isinstance(item, list):
            commands[str(key)] = [str(entry) for entry in item]
    return commands


def _resolve_trace_dir(raw: dict[str, object], root: Path) -> Path:
    trace_dir_raw = str(raw.get("trace_dir", "logs"))
    trace_dir_path = Path(trace_dir_raw)
    if trace_dir_path.is_absolute():
        return trace_dir_path
    return root / trace_dir_raw


def ensure_trace_directories(config: RuntimeConfig) -> None:
    config.trace_dir.mkdir(parents=True, exist_ok=True)
    (config.trace_dir / "async").mkdir(parents=True, exist_ok=True)


def _regex_rule_configs(value: object) -> list[RegexRuleConfig]:
    if not isinstance(value, list):
        return []

    regex_rules: list[RegexRuleConfig] = []
    for item in value:
        if isinstance(item, dict):
            data = _object_dict(item)
            regex_rules.append(
                RegexRuleConfig(
                    rule_id=_string_value(data.get("rule_id")),
                    title=_string_value(data.get("title")),
                    severity=_string_value(data.get("severity"), "MEDIUM"),
                    events=_string_list(data.get("events")) or ["PreToolUse"],
                    target=_string_value(data.get("target"), "content"),
                    action=_string_value(data.get("action"), "deny"),
                    message=_string_value(data.get("message")),
                    additional_context=(
                        _string_value(data.get("additional_context"))
                        if data.get("additional_context") is not None
                        else None
                    ),
                    patterns=_string_list(data.get("patterns")),
                    path_globs=_string_list(data.get("path_globs")),
                    exclude_path_globs=_string_list(data.get("exclude_path_globs")),
                    tool_matchers=_string_list(data.get("tool_matchers")),
                    case_sensitive=_bool_value(data.get("case_sensitive"), False),
                    multiline=_bool_value(data.get("multiline"), True),
                )
            )
    return regex_rules


def _merge_config(
    actual_root: Path,
    raw: dict[str, object],
    repo_root: Path,
) -> RuntimeConfig:
    regex_rules = _regex_rule_configs(raw.get("regex_rules", []))
    python_ast = _object_dict(raw.get("python_ast", {}))
    post_edit_quality = _object_dict(raw.get("post_edit_quality", {}))
    async_jobs = _object_dict(raw.get("async_jobs", {}))
    trace_dir = _resolve_trace_dir(raw, actual_root)
    prompt_context_files = _string_list(raw.get("prompt_context_files", []))

    toml_data = _load_toml(repo_root)
    toml_thresholds = _object_dict(toml_data.get("thresholds", {}))
    qg_section = _object_dict(toml_data.get("quality_gate", {}))
    disabled_rules_list = _string_list(qg_section.get("disabled_rules", []))
    severity_overrides_map = {
        str(key): str(value)
        for key, value in _object_dict(qg_section.get("severity_overrides", {})).items()
    }
    skip_paths = _string_list(raw.get("skip_paths", []))
    skip_if_file_exists = _string_list(
        raw.get("skip_if_file_exists", list(_DISABLE_SENTINELS))
    )
    enabled_rules = {
        str(key): bool(value)
        for key, value in _object_dict(raw.get("enabled_rules", {})).items()
    }

    return RuntimeConfig(
        root=actual_root,
        trace_dir=trace_dir,
        prompt_context_files=prompt_context_files,
        search_reminder_message=_string_value(
            raw.get("search_reminder_message")
        ).strip(),
        protected_paths=_string_list(raw.get("protected_paths", [])),
        sensitive_path_patterns=_string_list(raw.get("sensitive_path_patterns", [])),
        system_path_prefixes=_string_list(raw.get("system_path_prefixes", [])),
        python_ast_enabled=_bool_value(python_ast.get("enabled"), True),
        python_ast_max_parse_chars=_int_value(
            python_ast.get("max_parse_chars"),
            int(RUNTIME_POLICY_DEFAULTS["max_parse_chars"]),
        ),
        python_long_method_lines=_int_value(
            toml_thresholds.get(
                "max_method_lines",
                python_ast.get(
                    "long_method_lines",
                    RUNTIME_POLICY_DEFAULTS["long_method_lines"],
                ),
            ),
            int(RUNTIME_POLICY_DEFAULTS["long_method_lines"]),
        ),
        python_long_parameter_limit=_int_value(
            toml_thresholds.get(
                "max_params",
                python_ast.get(
                    "long_parameter_limit",
                    RUNTIME_POLICY_DEFAULTS["long_parameter_limit"],
                ),
            ),
            int(RUNTIME_POLICY_DEFAULTS["long_parameter_limit"]),
        ),
        post_edit_quality_enabled=_bool_value(post_edit_quality.get("enabled"), False),
        post_edit_quality_block_on_failure=_bool_value(
            post_edit_quality.get("block_on_failure"),
            True,
        ),
        post_edit_quality_commands=_command_map(
            post_edit_quality.get("commands_by_language", {})
        ),
        async_jobs_enabled=_bool_value(async_jobs.get("enabled"), False),
        async_jobs_commands=_command_map(async_jobs.get("commands_by_language", {})),
        python_max_complexity=_int_value(
            toml_thresholds.get("max_complexity"),
            int(RUNTIME_POLICY_DEFAULTS["max_complexity"]),
        ),
        python_max_nesting_depth=_int_value(
            toml_thresholds.get("max_nesting_depth"),
            int(RUNTIME_POLICY_DEFAULTS["max_nesting_depth"]),
        ),
        python_max_god_class_methods=_int_value(
            toml_thresholds.get("max_god_class_methods"),
            int(RUNTIME_POLICY_DEFAULTS["max_god_class_methods"]),
        ),
        python_max_line_length=_int_value(
            toml_thresholds.get("max_line_length"),
            int(RUNTIME_POLICY_DEFAULTS["max_line_length"]),
        ),
        python_feature_envy_threshold=_float_value(
            toml_thresholds.get("feature_envy_threshold"),
            float(RUNTIME_POLICY_DEFAULTS["feature_envy_threshold"]),
        ),
        python_feature_envy_min_accesses=_int_value(
            toml_thresholds.get("feature_envy_min_accesses"),
            int(RUNTIME_POLICY_DEFAULTS["feature_envy_min_accesses"]),
        ),
        python_import_fanout_limit=_int_value(
            toml_thresholds.get("import_fanout_limit"),
            int(RUNTIME_POLICY_DEFAULTS["import_fanout_limit"]),
        ),
        skip_paths=skip_paths,
        skip_if_file_exists=skip_if_file_exists,
        disabled_rules=disabled_rules_list,
        severity_overrides=severity_overrides_map,
        enabled_rules=enabled_rules,
        regex_rules=regex_rules,
    )


def load_config(root: Path | None = None) -> RuntimeConfig:
    """Load configuration with XDG discovery chain.

    Config is loaded from resolve_config_path(). Root is used for
    trace directory and prompt context file resolution.
    """
    actual_root = (root or detect_root()).resolve()
    config_path = resolve_config_path()
    raw = _load_json(config_path)
    repo_root = Path.cwd().resolve()
    config = _merge_config(actual_root, raw, repo_root)
    ensure_trace_directories(config)
    return config
