# Cutover from Enforcer

## What changes

| Before (enforcer) | After (vibeforcer) |
|---|---|
| `~/.claude/hooks/enforcer/` (install root) | `~/.config/vibeforcer/` (config) + binary on PATH |
| 14 shell wrappers (`.claude/hooks/*.sh`) | `vibeforcer handle` called directly |
| `CLAUDE_HOOK_LAYER_ROOT` env var | `VIBEFORCER_ROOT` / `VIBEFORCER_CONFIG` (optional) |
| `hook-layer` entry point | `vibeforcer` entry point |
| `config.json` at `.claude/hook-layer/config.json` | `config.json` at `~/.config/vibeforcer/config.json` |
| Separate `hook-stats.py` script | `vibeforcer stats` |
| Per-platform install scripts | `vibeforcer install <platform>` |
| Manual settings.json patching | Automatic via `vibeforcer install claude` |

## What stays the same

- All 30 Python rules — identical behavior
- All 39 regex rules — loaded from same config format
- All 3 adapters (claude, codex, opencode) — identical
- `quality_gate.toml` per-repo overrides — identical
- JSONL trace format — identical
- Fixture format — identical

## Step-by-step cutover

### 1. Install vibeforcer globally

```bash
# From the vibeforcer source directory
pipx install .

# Verify
vibeforcer version
vibeforcer test
```

### 2. Initialize config

```bash
# Create ~/.config/vibeforcer/ with default config
vibeforcer config init

# Or copy your existing enforcer config
mkdir -p ~/.config/vibeforcer/logs/async
cp ~/.claude/hooks/enforcer/.claude/hook-layer/config.json ~/.config/vibeforcer/
```

If copying your existing config, update `prompt_context_files` paths:
```json
"prompt_context_files": [
    "prompt_context/organization.md",
    "prompt_context/repo.md"
]
```

And copy prompt context:
```bash
cp -r ~/.claude/hooks/enforcer/.claude/hook-layer/prompt_context ~/.config/vibeforcer/
```

### 3. Install platform hooks

```bash
# Preview what will change
vibeforcer install claude --dry-run

# Apply — replaces shell wrapper references with direct vibeforcer call
vibeforcer install claude
```

This patches `~/.claude/settings.json` to call `vibeforcer handle` for all hook events, replacing the old shell wrapper paths.

For Codex:
```bash
vibeforcer install codex
```

For OpenCode:
```bash
vibeforcer install opencode
```

### 4. Verify

```bash
# Self-test
vibeforcer test

# Check that stats still work (reads from legacy log location if XDG doesn't exist yet)
vibeforcer stats --days 1

# Test a real hook invocation
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git commit --no-verify"},"cwd":"/tmp","session_id":"cutover-test"}' | vibeforcer handle
```

### 5. Clean up (optional)

Once you're confident vibeforcer is working:

```bash
# Remove old shell wrappers and enforcer installation
# (keep for a while as backup if you prefer)
rm -rf ~/.claude/hooks/enforcer
```

## Rollback

If something breaks:

```bash
# Restore enforcer by re-running its install
cd ~/.claude/hooks/enforcer
bash scripts/install.sh

# Or manually restore settings.json from backup
# (vibeforcer install doesn't delete the old settings, just overwrites hooks)
```

## Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `VIBEFORCER_CONFIG` | Explicit config file path | (discovery chain) |
| `VIBEFORCER_CONFIG_DIR` | Config directory override | `~/.config/vibeforcer` |
| `VIBEFORCER_ROOT` | Root for traces/prompt context | config dir |
| `CLAUDE_HOOK_LAYER_ROOT` | Legacy fallback (backward compat) | — |
