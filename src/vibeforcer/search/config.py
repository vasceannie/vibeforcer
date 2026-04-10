"""Configuration, constants, and path defaults for the search subsystem."""

from __future__ import annotations

import json
import os
from pathlib import Path


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
    return json.loads(APP_CONFIG.read_text())


def save_config(
    data: SearchConfig,
) -> None:
    """Write *data* to the isx config file."""
    APP_DIR.mkdir(parents=True, exist_ok=True)
    APP_CONFIG.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def detect_provider() -> str:
    """Auto-detect whether the user has a LiteLLM or Ollama environment."""
    if os.environ.get("LITELLM_BASE_URL") or os.environ.get("LITELLM_API_KEY"):
        return "litellm"
    return "ollama"
