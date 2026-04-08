"""Runtime helpers: islands binary execution, env setup, model fetching."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from vibeforcer.search.config import (
    APP_NAME,
    DEFAULT_INDEXES_PATH,
    DEFAULT_ISLANDS_CONFIG,
    IsxError,
    expand,
)
from vibeforcer.search.config import (
    PREFERRED_LITELLM_MODELS,
)


def fetch_models(base_url: str, api_key: str | None, timeout: int = 10) -> list[str]:
    """Fetch model list from an OpenAI-compatible /v1/models endpoint."""
    url = base_url.rstrip("/") + "/v1/models"
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.load(resp)
    data = payload.get("data", [])
    return [item.get("id") for item in data if item.get("id")]


def embedding_like(model: str) -> bool:
    """Heuristic: is this model likely an embedding model?"""
    lowered = model.lower()
    return (
        "embed" in lowered
        or model in PREFERRED_LITELLM_MODELS
        or lowered.startswith("ollama/") and "embedding" in lowered
        or lowered == "nomic"
    )


def choose_litellm_model(
    base_url: str,
    api_key_env: str | None,
    explicit_model: str | None,
) -> tuple[str, list[str] | None, str | None]:
    """Pick a sensible embedding model for LiteLLM setups.

    Returns ``(model, discovered_models, warning)``.
    """
    if explicit_model:
        return explicit_model, None, None

    api_key = os.environ.get(api_key_env or "") if api_key_env else None
    if not api_key:
        return "ollama/nomic-embed-text", None, f"{api_key_env or 'LITELLM_API_KEY'} is not set, using default model"

    try:
        models = fetch_models(base_url, api_key)
    except Exception as exc:
        return "ollama/nomic-embed-text", None, f"could not query {base_url}/v1/models: {exc}"

    for candidate in PREFERRED_LITELLM_MODELS:
        if candidate in models:
            return candidate, models, None
    return "ollama/nomic-embed-text", models, "preferred embedding routes not found in /v1/models, using default"


def render_islands_yaml(model: str) -> str:
    """Render an islands config YAML string for *model*."""
    lines = [
        "# Managed by isx. You can edit this later if you want.",
        "debug: false",
        "log_level: info",
        "indexer:",
        f"  repos_path: {DEFAULT_INDEXES_PATH.parent / 'repos'}",
        f"  indexes_path: {DEFAULT_INDEXES_PATH}",
        "  max_concurrent_syncs: 4",
        "  sync_interval_secs: 300",
        "  index_extensions:",
    ]
    from vibeforcer.search.config import DEFAULT_EXTENSIONS
    lines.extend(f"  - {ext}" for ext in DEFAULT_EXTENSIONS)
    lines.extend(
        [
            "  embedding:",
            "    provider: openai",
            f"    model: {model}",
            "    batch_size: 4",
            "mcp_host: 0.0.0.0",
            "mcp_port: 8080",
        ]
    )
    return "\n".join(lines) + "\n"


def write_islands_config(path: Path, model: str) -> None:
    """Write the managed islands YAML config."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_islands_yaml(model))


def runtime_env(
    cfg: dict, extra_env: dict[str, str] | None = None
) -> dict[str, str]:
    """Build the environment dict for an islands-ollama subprocess."""
    env = os.environ.copy()
    base_url = cfg.get("base_url")
    if base_url:
        env["OPENAI_BASE_URL"] = base_url

    api_key_env = cfg.get("api_key_env")
    api_key_value = cfg.get("api_key_value")
    if api_key_env:
        value = os.environ.get(api_key_env)
        if not value:
            raise IsxError(f"required env var {api_key_env} is not set")
        env["OPENAI_API_KEY"] = value
    elif api_key_value:
        env["OPENAI_API_KEY"] = api_key_value

    for token_var in (
        "ISLANDS_GIT_TOKEN",
        "GITLAB_TOKEN",
        "GIT_TOKEN",
        "GITHUB_TOKEN",
    ):
        if token_var in env and env[token_var]:
            continue
        for key, val in os.environ.items():
            if key == token_var or (key.endswith("_TOKEN") and "git" in key.lower()):
                env[key] = val
                break

    if extra_env:
        env.update(extra_env)

    return env


def islands_binary(cfg: dict) -> str:
    """Resolve the islands binary path."""
    binary = cfg.get("binary", "islands-ollama")
    resolved = shutil.which(binary)
    if not resolved:
        raise IsxError(f"could not find binary: {binary}")
    return resolved


def current_islands_config_path(cfg: dict) -> Path:
    """Return the islands YAML config path from *cfg*."""
    return expand(cfg.get("islands_config"), DEFAULT_ISLANDS_CONFIG)


def save_runtime_model(cfg: dict, model: str) -> None:
    """Persist a model change to both isx config and islands YAML."""
    from vibeforcer.search.config import save_config

    cfg["model"] = model
    save_config(cfg)
    write_islands_config(current_islands_config_path(cfg), model)


def fetch_runtime_models(cfg: dict) -> list[str]:
    """Fetch the model list using the runtime environment."""
    env = runtime_env(cfg)
    return fetch_models(cfg["base_url"], env.get("OPENAI_API_KEY"))


def run_islands(
    cfg: dict, args: list[str], extra_env: dict[str, str] | None = None
) -> int:
    """Execute islands-ollama with the given args and return its exit code."""
    binary = islands_binary(cfg)
    env = runtime_env(cfg, extra_env=extra_env)
    config_path = str(current_islands_config_path(cfg))
    command = [binary, "--config", config_path, *args]
    proc = subprocess.run(command, env=env)
    return proc.returncode
