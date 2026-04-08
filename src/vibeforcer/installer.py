"""Platform installer — patches settings files to wire vibeforcer hooks.

Supports:
  vibeforcer install claude    → patches ~/.claude/settings.json
  vibeforcer install codex     → patches ~/.codex/hooks.json
  vibeforcer install opencode  → copies TS plugin to ~/.config/opencode/plugins/
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path


def _find_binary() -> str:
    """Find the vibeforcer binary on PATH."""
    binary = shutil.which("vibeforcer")
    if binary:
        return binary
    # Fallback: python -m vibeforcer.cli handle
    return "vibeforcer"


# ---------------------------------------------------------------------------
# Claude Code
# ---------------------------------------------------------------------------

_CLAUDE_EVENTS = (
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PostToolUseFailure",
    "Stop",
    "SubagentStop",
    "TaskCompleted",
    "TeammateIdle",
    "InstructionsLoaded",
    "ConfigChange",
)


def _claude_hooks_block(binary: str) -> dict:
    """Build the hooks block for Claude Code settings.json."""
    hooks: dict[str, list] = {}
    for event in _CLAUDE_EVENTS:
        entry: dict = {
            "hooks": [
                {
                    "type": "command",
                    "command": f"{binary} handle",
                }
            ]
        }
        if event == "SessionStart":
            entry["matcher"] = "startup|resume"
        hooks[event] = [entry]
    return hooks


def _install_claude(dry_run: bool = False) -> int:
    binary = _find_binary()
    settings_path = Path.home() / ".claude" / "settings.json"

    hooks = _claude_hooks_block(binary)

    if dry_run:
        print(f"Would patch: {settings_path}")
        print(f"Binary: {binary}")
        print(json.dumps({"hooks": hooks}, indent=2))
        return 0

    # Load existing settings or start fresh
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            settings = {}
    else:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings = {}

    settings["hooks"] = hooks
    settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    print(f"Installed vibeforcer hooks into {settings_path}")
    print(f"Binary: {binary}")
    print(f"Events: {len(_CLAUDE_EVENTS)}")
    return 0


def _uninstall_claude(dry_run: bool = False) -> int:
    settings_path = Path.home() / ".claude" / "settings.json"
    if not settings_path.exists():
        print("No Claude settings found.")
        return 0

    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    if "hooks" not in settings:
        print("No hooks found in Claude settings.")
        return 0

    if dry_run:
        print(f"Would remove 'hooks' key from {settings_path}")
        return 0

    del settings["hooks"]
    settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    print(f"Removed vibeforcer hooks from {settings_path}")
    return 0


# ---------------------------------------------------------------------------
# Codex CLI
# ---------------------------------------------------------------------------

_CODEX_EVENTS = {
    "SessionStart": {"matcher": "startup|resume", "timeout": 10, "statusMessage": "Loading vibeforcer context"},
    "PreToolUse": {"matcher": "Bash", "timeout": 10, "statusMessage": "vibeforcer: checking command"},
    "PostToolUse": {"matcher": "Bash", "timeout": 10, "statusMessage": "vibeforcer: reviewing output"},
    "UserPromptSubmit": {"timeout": 10},
    "Stop": {"timeout": 30},
}


def _codex_hooks_block(binary: str) -> dict:
    hooks: dict[str, list] = {}
    for event, meta in _CODEX_EVENTS.items():
        entry: dict = {
            "hooks": [
                {
                    "type": "command",
                    "command": f"{binary} handle --platform codex",
                }
            ]
        }
        if "matcher" in meta:
            entry["matcher"] = meta["matcher"]
        if "statusMessage" in meta:
            entry["hooks"][0]["statusMessage"] = meta["statusMessage"]
        if "timeout" in meta:
            entry["hooks"][0]["timeout"] = meta["timeout"]
        hooks[event] = [entry]
    return hooks


def _install_codex(dry_run: bool = False) -> int:
    binary = _find_binary()
    hooks_path = Path.home() / ".codex" / "hooks.json"

    hooks = _codex_hooks_block(binary)

    if dry_run:
        print(f"Would write: {hooks_path}")
        print(json.dumps({"hooks": hooks}, indent=2))
        return 0

    hooks_path.parent.mkdir(parents=True, exist_ok=True)

    if hooks_path.exists():
        try:
            existing = json.loads(hooks_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = {}
    else:
        existing = {}

    existing["hooks"] = hooks
    hooks_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")

    # Enable hooks feature flag
    config_path = Path.home() / ".codex" / "config.json"
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            config = {}
    else:
        config = {}

    if "features" not in config:
        config["features"] = {}
    config["features"]["hooks"] = True
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    print(f"Installed vibeforcer hooks into {hooks_path}")
    print(f"Enabled hooks feature flag in {config_path}")
    print(f"Binary: {binary}")
    return 0


def _uninstall_codex(dry_run: bool = False) -> int:
    hooks_path = Path.home() / ".codex" / "hooks.json"
    if not hooks_path.exists():
        print("No Codex hooks found.")
        return 0

    if dry_run:
        print(f"Would delete: {hooks_path}")
        return 0

    hooks_path.unlink()
    print(f"Removed: {hooks_path}")
    return 0


# ---------------------------------------------------------------------------
# OpenCode
# ---------------------------------------------------------------------------


def _install_opencode(dry_run: bool = False) -> int:
    from vibeforcer.resources import resource_path

    template = resource_path("opencode_plugin.ts")
    if not template.exists():
        print(f"OpenCode plugin template not found at {template}")
        return 1

    binary = _find_binary()
    target_dir = Path.home() / ".config" / "opencode" / "plugins"
    target = target_dir / "vibeforcer-plugin.ts"

    content = template.read_text(encoding="utf-8")
    # Bake in the binary path
    content = content.replace("__VIBEFORCER_BIN__", binary)

    if dry_run:
        print(f"Would write: {target}")
        print(f"Binary: {binary}")
        print(content[:500] + "...")
        return 0

    target_dir.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    print(f"Installed vibeforcer plugin to {target}")
    print(f"Binary: {binary}")
    return 0


def _uninstall_opencode(dry_run: bool = False) -> int:
    target = Path.home() / ".config" / "opencode" / "plugins" / "vibeforcer-plugin.ts"
    if not target.exists():
        print("No OpenCode vibeforcer plugin found.")
        return 0

    if dry_run:
        print(f"Would delete: {target}")
        return 0

    target.unlink()
    print(f"Removed: {target}")
    return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


_INSTALLERS = {
    "claude": (_install_claude, _uninstall_claude),
    "codex": (_install_codex, _uninstall_codex),
    "opencode": (_install_opencode, _uninstall_opencode),
}


def install_platform(platform: str, dry_run: bool = False) -> int:
    installer, _ = _INSTALLERS[platform]
    return installer(dry_run=dry_run)


def uninstall_platform(platform: str, dry_run: bool = False) -> int:
    _, uninstaller = _INSTALLERS[platform]
    return uninstaller(dry_run=dry_run)
