# vibeforcer

Global CLI guardrails engine for AI coding agents. One rule set, three platforms.

## Install

```bash
pipx install .
# or
pip install -e .
```

## Quick Start

```bash
# Initialize config (creates ~/.config/vibeforcer/)
vibeforcer config init

# Install hooks for your platform
vibeforcer install claude    # patches ~/.claude/settings.json
vibeforcer install codex     # patches ~/.codex/hooks.json
vibeforcer install opencode  # copies plugin to ~/.config/opencode/plugins/

# Run self-test
vibeforcer test

# Check stats
vibeforcer stats --days 7
```

## Supported Platforms

| Platform | Status | Install |
|---|---|---|
| **Claude Code** | ✅ Production | `vibeforcer install claude` |
| **Codex CLI** | ✅ Ready | `vibeforcer install codex` |
| **OpenCode** | ✅ Ready | `vibeforcer install opencode` |

## Architecture

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ Claude Code  │  │  Codex CLI  │  │  OpenCode   │
│ settings.json│  │ hooks.json  │  │  TS plugin  │
└──────┬───────┘  └──────┬──────┘  └──────┬──────┘
       │                 │                 │
       └─────────────────┼─────────────────┘
                         ▼
              ┌────────────────────┐
              │  vibeforcer handle │
              │  --platform X      │
              └─────────┬──────────┘
                        ▼
              ┌────────────────────┐
              │   Rule Engine      │
              │  (30 Python rules  │
              │   + 39 regex rules)│
              └─────────┬──────────┘
                        ▼
              ┌────────────────────┐
              │  Platform Adapter  │
              │  (per-platform)    │
              └────────────────────┘
```

No shell wrappers. No bootstrap scripts. Just `vibeforcer handle` on PATH.

## CLI

```bash
# Core hook handler (called by platform hooks)
vibeforcer handle [--platform claude|codex|opencode]

# Replay a captured payload
vibeforcer replay --payload fixture.json [--platform codex] [--pretty]

# Check quality gate status for a repo
vibeforcer check [path]

# Install/uninstall hooks
vibeforcer install <platform> [--dry-run]
vibeforcer uninstall <platform> [--dry-run]

# Activity analysis
vibeforcer stats [--log results.jsonl] [--days N] [--json]

# Configuration
vibeforcer config show        # show effective config
vibeforcer config init        # create from defaults
vibeforcer config path        # print config file location

# Self-test
vibeforcer test

# Version
vibeforcer version
```

## Config Discovery

vibeforcer resolves config in this order:

1. `$VIBEFORCER_CONFIG` (explicit file path)
2. `~/.config/vibeforcer/config.json` (XDG)
3. `$CLAUDE_HOOK_LAYER_ROOT/.claude/hook-layer/config.json` (legacy)
4. `~/.claude/hooks/enforcer/.claude/hook-layer/config.json` (legacy default)
5. Bundled defaults

Per-repo overrides via `quality_gate.toml` in the repo root.

## Rules

### Built-in Python Rules (30)
- Path protection (protected, sensitive, system)
- Git safety (--no-verify, stash ban)
- Python AST quality (long methods, deep nesting, complexity, dead code, god class, feature envy, thin wrappers)
- Test quality (assertion roulette, test loops, fixtures placement, test smells)
- Error handling (bash output errors, failure reinforcement)
- Session controls (stop checks, config change guard)
- LangGraph best practices (state reducers, mutation detection, deprecated API)
- Baseline inflation guard

### Declarative Regex Rules (39)
Configured in `config.json` — covers:
- Python type safety (Any ban, suppression ban)
- Exception handling patterns
- Shell quality bypasses
- Linter config protection
- TODO/FIXME markers
- And more

## Per-Repo Overrides

Create `quality_gate.toml` in your repo root:

```toml
[quality_gate]
# Disable specific rules
disabled_rules = ["PY-CODE-013", "PY-TEST-004"]

# Downgrade rules to advisory
[quality_gate.severity_overrides]
"PY-CODE-008" = "warn"

[thresholds]
max_method_lines = 80
max_params = 6
max_complexity = 15
max_nesting_depth = 5
max_line_length = 140
```

Or opt out entirely:

```bash
touch .noqualitygate
```

## Testing

```bash
cd vibeforcer
PYTHONPATH=src pytest tests/ -q
```

## Cutover from Enforcer

```bash
# 1. Install vibeforcer globally
pipx install ~/path/to/vibeforcer

# 2. Copy your config
mkdir -p ~/.config/vibeforcer
cp ~/.claude/hooks/enforcer/.claude/hook-layer/config.json ~/.config/vibeforcer/

# 3. Install hooks (replaces shell wrappers)
vibeforcer install claude

# 4. Test
vibeforcer test

# 5. Remove old enforcer (optional)
# rm -rf ~/.claude/hooks/enforcer
```
