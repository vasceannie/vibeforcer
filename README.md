# vibeforcer

Global CLI guardrails engine for AI coding agents. **Real-time hook enforcement + batch code quality linting.** One tool, three platforms.

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

# Lint a project for code quality
vibeforcer lint check .           # scan for violations
vibeforcer lint baseline .         # freeze current state
vibeforcer lint init .             # scaffold quality_gate.toml
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

### Hook Enforcement (real-time)

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

### Code Quality Linting (batch)

```bash
# Scan a project for violations (compares against baseline)
vibeforcer lint check [path]

# Generate/update baselines.json (freeze current violations)
vibeforcer lint baseline [path]

# Scaffold a quality_gate.toml config
vibeforcer lint init [path]

# Merge missing config keys into existing quality_gate.toml
vibeforcer lint update [path] [--dry-run]
```

#### 28 Batch Detectors

| Category | Detectors |
|---|---|
| **Code smells** | high-complexity, long-method, too-many-params, deep-nesting, god-class, oversized-module |
| **Type safety** | banned-any (typing.Any), type-suppression (# type: ignore) |
| **Exception safety** | broad-except-swallow, silent-except, silent-datetime-fallback |
| **Test smells** | long-test, eager-test, assertion-free-test, assertion-roulette, conditional-assertion, fixture-outside-conftest |
| **Duplication** | semantic-clone, repeated-magic-number, repeated-string-literal, repeated-code-block, duplicate-call-sequence |
| **Logging** | direct-get-logger, wrong-logger-name |
| **Stale code** | deprecated-pattern |
| **Wrappers** | unnecessary-wrapper |
| **Style** | long-line |

## Config Discovery

vibeforcer resolves config in this order:

1. `$VIBEFORCER_CONFIG` (explicit file path)
2. `~/.config/vibeforcer/config.json` (XDG)
3. `$CLAUDE_HOOK_LAYER_ROOT/.claude/hook-layer/config.json` (legacy)
4. `~/.claude/hooks/enforcer/.claude/hook-layer/config.json` (legacy default)
5. Bundled defaults

Per-repo overrides via `quality_gate.toml` in the repo root.

## Rules

### Real-time Hook Rules (30 Python + 39 regex)
- Path protection (protected, sensitive, system)
- Git safety (--no-verify, stash ban)
- Python AST quality (long methods, deep nesting, complexity, dead code, god class, feature envy, thin wrappers)
- Test quality (assertion roulette, test loops, fixtures placement, test smells)
- Error handling (bash output errors, failure reinforcement)
- Session controls (stop checks, config change guard)
- LangGraph best practices (state reducers, mutation detection, deprecated API)
- Baseline inflation guard

### Batch Lint Rules (28 detectors)
- See "28 Batch Detectors" table above
- Configured via `quality_gate.toml` in each project
- Baseline tracking: only *new* violations fail the gate

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
