# Rules Reference

## Built-in Python Rules (30)

### Path & System Protection

| Rule ID | Severity | Events | Description |
|---|---|---|---|
| BUILTIN-PROTECTED-PATHS | HIGH | PreToolUse, PermissionRequest | Blocks writes to configured protected paths |
| GLOBAL-BUILTIN-SENSITIVE-DATA | HIGH | PreToolUse, PermissionRequest | Blocks access to sensitive files (.env, SSH keys, etc.) |
| GLOBAL-BUILTIN-SYSTEM-PROTECTION | CRITICAL | PreToolUse, PermissionRequest | Blocks access to system paths (/etc, /usr, etc.) |
| GLOBAL-BUILTIN-HOOK-INFRA-EXEC | CRITICAL | PreToolUse, PermissionRequest | Blocks modification of vibeforcer infrastructure |

### Git Safety

| Rule ID | Severity | Events | Description |
|---|---|---|---|
| GIT-001 | HIGH | PreToolUse, PermissionRequest | Blocks `--no-verify`, `-n`, `core.hookspath` bypasses |

### Read & Edit Quality

| Rule ID | Severity | Events | Description |
|---|---|---|---|
| BUILTIN-ENFORCE-FULL-READ | MEDIUM | PreToolUse, PermissionRequest | Requires full file read before partial reads |
| BUILTIN-INJECT-PROMPT | LOW | UserPromptSubmit | Injects prompt context files on each prompt |
| REMIND-SEARCH-001 | LOW | PreToolUse | Adds reminder message on search operations |
| QUALITY-POST-001 | HIGH | PostToolUse | Runs configured quality commands after edits |
| WARN-LARGE-001 | MEDIUM | PreToolUse, PermissionRequest | Warns on edits to files > 50K characters |

### Python AST Quality

| Rule ID | Severity | Events | Description |
|---|---|---|---|
| PY-CODE-008 | HIGH | Pre/Post ToolUse | Functions over N lines (default: 50) |
| PY-CODE-009 | MEDIUM | Pre/Post ToolUse | Functions with N+ params (default: 4) |
| PY-CODE-010 | MEDIUM | Pre/Post ToolUse | Lines over N chars (default: 120) |
| PY-CODE-011 | HIGH | Pre/Post ToolUse | Nesting depth over N (default: 4) |
| PY-CODE-012 | LOW | Pre/Post ToolUse | Feature envy (>60% accesses on one object) |
| PY-CODE-013 | MEDIUM | Pre/Post ToolUse | Thin wrappers (single delegating call) |
| PY-CODE-014 | HIGH | Pre/Post ToolUse | God class (>10 non-dunder methods) |
| PY-CODE-015 | HIGH | Pre/Post ToolUse | Cyclomatic complexity >N (default: 10) |
| PY-CODE-016 | HIGH | Pre/Post ToolUse | Dead code after return/raise/break/continue |
| PY-CODE-017 | HIGH | PostToolUse | Flat `_prefix_*` sibling file sprawl |

### Session & Stop Controls

| Rule ID | Severity | Events | Description |
|---|---|---|---|
| STOP-001 | HIGH | Stop, SubagentStop | Blocks dismissing issues as "pre-existing" |
| STOP-002 | LOW | Stop, SubagentStop | Reminds to run quality gate before stopping |
| SESSION-001 | LOW | SessionStart | Injects git context on session start |
| CONFIG-001 | CRITICAL | ConfigChange | Blocks disabling hooks via config changes |

### Error Handling

| Rule ID | Severity | Events | Description |
|---|---|---|---|
| ERRORS-BASH-001 | HIGH | PostToolUse | Catches errors in exit-0 bash output |
| ERRORS-FAIL-001 | HIGH | PostToolUseFailure | Reinforces fixing non-zero exit commands |

### Security

| Rule ID | Severity | Events | Description |
|---|---|---|---|
| BUILTIN-RULEBOOK-SECURITY | HIGH | PreToolUse, PermissionRequest | Blocks weakening security guardrails |

### Baseline Protection

| Rule ID | Severity | Events | Description |
|---|---|---|---|
| BASELINE-001 | HIGH | PreToolUse | Blocks baseline inflation (only decreases allowed) |

### LangGraph

| Rule ID | Severity | Events | Description |
|---|---|---|---|
| LG-STATE-001 | LOW | PostToolUse | List fields in state without reducers |
| LG-NODE-001 | MEDIUM | PostToolUse | Direct state mutation in node functions |
| LG-API-001 | LOW | PostToolUse | Deprecated API usage (set_entry_point, etc.) |

## Declarative Regex Rules (39)

Configured in `config.json` under `regex_rules`. Each rule specifies patterns, target, and action.

### Categories

- **Python types** — PY-TYPE-001 (Any ban), PY-TYPE-002 (suppression ban)
- **Python exceptions** — PY-EXC-001 (broad except), PY-EXC-002 (silent swallow)
- **Python logging** — PY-LOG-001 (stdlib logger ban)
- **Python quality** — PY-QUALITY-006 through PY-QUALITY-010 (TODO, commented code, paths, magic numbers)
- **Python tests** — PY-TEST-001 through PY-TEST-004 (assertion roulette, test smells, loops, fixtures)
- **JS/TS** — TS-TYPE-001 (any ban), TS-LINT-001/002 (eslint/ts-ignore), TS-QUALITY-001 (TODO)
- **Rust** — RS-QUALITY-001 (TODO), RS-QUALITY-002 (unwrap)
- **Frontend** — FE-STYLE-001 (inline styles), FE-STYLE-002 (hardcoded design values)
- **Shell** — SHELL-001 (quality bypasses)
- **Git** — GIT-003 (stash ban), GIT-004 (commit/push reminder)
- **Config protection** — CONFIG-002 (enforcer config), LINT-CONFIG-001/002 (linter configs)
- **Test protection** — TEST-QUALITY-001 (test path protection)
- **Infrastructure** — REMIND-PYTEST-MP (multiprocessing reminder)

## Enrichment

Several rules have automatic enrichment that adds project-specific context to findings:

- **PY-TEST-***: discovers available fixtures from conftest.py, shows parametrize patterns
- **PY-TYPE-***: suggests TypedDict, Protocol, Callable based on content
- **PY-CODE-008**: shows function structure with extraction points
- **PY-CODE-009**: lists parameters, finds existing dataclass patterns
- **PY-CODE-012**: shows envied object context and import location
- **PY-CODE-015**: breaks down complexity sources (ifs, loops, excepts, boolops)
- **PY-EXC-002**: lists functions called in try blocks, suggests specific exceptions
- **PY-LOG-001**: finds project logger module, detects structlog/loguru usage
- **PY-QUALITY-009**: finds existing path configuration patterns
- **PY-QUALITY-010**: finds constants module or suggests creating one
