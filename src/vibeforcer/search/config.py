"""Configuration, constants, and path defaults for the search subsystem."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import cast

from vibeforcer._types import object_dict, object_list, string_value


class IsxError(RuntimeError):
    """Raised for recoverable search-subsystem errors."""


# -- well-known paths --------------------------------------------------------

APP_NAME = "isx"
APP_DIR = Path.home() / ".config" / APP_NAME
APP_CONFIG = APP_DIR / "config.json"

DEFAULT_ISLANDS_CONFIG = Path.home() / ".config" / "islands" / "isx.yaml"
DEFAULT_REPOS_PATH = Path.home() / ".local" / "share" / "islands" / "repos"
DEFAULT_INDEXES_PATH = Path.home() / ".local" / "share" / "islands" / "indexes"

DEFAULT_CLAUDE_SKILLS_DIR = Path.home() / ".claude" / "skills"
DEFAULT_OPENCODE_SKILLS_DIR = Path.home() / ".config" / "opencode" / "skills"
DEFAULT_OPENCODE_PLUGIN_PATH = (
    Path.home() / ".config" / "opencode" / "plugins" / "isx-tools.ts"
)
DEFAULT_OPENCODE_CONFIG = Path.home() / ".config" / "opencode" / "opencode.json"
DEFAULT_SKILL_NAME = "isx-cli"

DEFAULT_EXTENSIONS = [
    "py",
    "js",
    "ts",
    "jsx",
    "tsx",
    "java",
    "go",
    "rs",
    "c",
    "cpp",
    "h",
    "hpp",
    "cs",
    "rb",
    "php",
    "swift",
    "kt",
    "scala",
    "sql",
    "sh",
    "bash",
    "yaml",
    "yml",
    "json",
    "toml",
    "md",
    "rst",
    "txt",
]

PREFERRED_LITELLM_MODELS = [
    "ollama/nomic-embed-text",
    "ollama/qwen3-embedding:4b",
    "nomic",
    "embeddings",
    "text-embedding-3-small",
    "text-embedding-3-large",
]

COMMANDS = [
    "init",
    "doctor",
    "models",
    "use",
    "list",
    "add",
    "search",
    "remove",
    "sync",
    "reindex",
    "completions",
]

SearchConfig = dict[str, str | list[str] | dict[str, str] | None]


def _coerce_search_config(value: object) -> SearchConfig:
    data = object_dict(value)
    config: SearchConfig = {}
    for key, raw_value in data.items():
        string_item = string_value(raw_value)
        if string_item is not None:
            config[key] = string_item
            continue
        if raw_value is None:
            config[key] = None
            continue
        string_list = object_list(raw_value)
        if string_list and all(isinstance(item, str) for item in string_list):
            config[key] = cast(list[str], string_list)
            continue
        nested = object_dict(raw_value)
        if nested and all(isinstance(item, str) for item in nested.values()):
            config[key] = cast(dict[str, str], nested)
    return config


# -- path helpers ------------------------------------------------------------


def expand(path_str: str | None, default: Path | None = None) -> Path:
    """Expand a user-provided path string, falling back to *default*."""
    if path_str is None:
        if default is None:
            raise IsxError("missing path")
        return default
    return Path(path_str).expanduser().resolve()


# -- config I/O --------------------------------------------------------------


def load_config() -> SearchConfig:
    """Load the persistent isx config from ``~/.config/isx/config.json``."""
    if not APP_CONFIG.exists():
        raise IsxError(f"{APP_CONFIG} does not exist. Run `isx init` first.")
    raw_config = cast(object, json.loads(APP_CONFIG.read_text()))
    return _coerce_search_config(raw_config)


def save_config(
    data: SearchConfig,
) -> None:
    """Write *data* to the isx config file."""
    APP_DIR.mkdir(parents=True, exist_ok=True)
    _ = APP_CONFIG.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def detect_provider() -> str:
    """Auto-detect whether the user has a LiteLLM or Ollama environment."""
    if os.environ.get("LITELLM_BASE_URL") or os.environ.get("LITELLM_API_KEY"):
        return "litellm"
    return "ollama"
