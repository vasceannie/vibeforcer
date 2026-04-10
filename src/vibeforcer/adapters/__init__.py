"""Platform adapters for the vibeforcer engine.

Each adapter translates between a specific CLI tool's hook protocol
and the enforcer's internal canonical representation.

Supported platforms:
  - claude   : Anthropic Claude Code (default)
  - codex    : OpenAI Codex CLI
  - opencode : OpenCode (Anomaly)
"""

from __future__ import annotations

from vibeforcer.adapters.base import PlatformAdapter
from vibeforcer.adapters.claude import ClaudeAdapter
from vibeforcer.adapters.codex import CodexAdapter
from vibeforcer.adapters.opencode import OpenCodeAdapter

ADAPTERS: dict[str, type[PlatformAdapter]] = {
    "claude": ClaudeAdapter,
    "codex": CodexAdapter,
    "opencode": OpenCodeAdapter,
}

_ADAPTER_CACHE: dict[str, PlatformAdapter] = {}


def get_adapter(platform: str) -> PlatformAdapter:
    """Return the singleton adapter instance for the given platform name."""
    cached = _ADAPTER_CACHE.get(platform)
    if cached is not None:
        return cached
    cls = ADAPTERS.get(platform)
    if cls is None:
        valid_options = ", ".join(sorted(ADAPTERS))
        raise ValueError(
            f"Unknown platform {platform!r}. Valid options: {valid_options}"
        )
    instance = cls()
    _ADAPTER_CACHE[platform] = instance
    return instance
