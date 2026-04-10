"""Semantic code search isolated from rule, engine, lint, and enrichment runtime code."""

from __future__ import annotations

__all__ = [
    "IsxError",
    "load_config",
    "save_config",
]

from vibeforcer.search.config import IsxError, load_config, save_config
