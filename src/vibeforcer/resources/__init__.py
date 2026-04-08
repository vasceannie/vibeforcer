"""Bundled resources: default config, prompt context, platform shims."""
from pathlib import Path

RESOURCES_DIR = Path(__file__).parent

def resource_path(name: str) -> Path:
    """Return the absolute path to a bundled resource file."""
    return RESOURCES_DIR / name
