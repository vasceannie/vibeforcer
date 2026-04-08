# Extension Guide

## Adding a regex rule

Edit `~/.config/vibeforcer/config.json` (or the bundled `defaults.json` for permanent rules) and add an entry under `regex_rules`.

### Example

```json
{
  "rule_id": "CUSTOM-001",
  "title": "Block TODO markers in Python",
  "severity": "HIGH",
  "events": ["PreToolUse", "PermissionRequest"],
  "target": "content",
  "path_globs": ["**/*.py"],
  "patterns": ["(?i)#\\s*(TODO|FIXME|HACK|XXX)\\b"],
  "action": "deny",
  "message": "TODO/FIXME/HACK/XXX comments are blocked in {path}."
}
```

### Fields

| Field | Required | Description |
|---|---|---|
| `rule_id` | Yes | Unique ID (appears in logs and deny messages) |
| `title` | Yes | Human-readable description |
| `severity` | No | LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM) |
| `events` | No | Hook events to run on (default: ["PreToolUse"]) |
| `target` | No | What to match: content, command, path, prompt (default: content) |
| `patterns` | Yes | List of regex patterns |
| `action` | No | deny, block, ask, context (default: deny) |
| `message` | No | Message shown on match. Supports `{path}`, `{matched_paths}`, `{rule_id}` |
| `additional_context` | No | Extra context injected (Claude Code bonus channel) |
| `path_globs` | No | Only match files matching these globs |
| `exclude_path_globs` | No | Skip files matching these globs |
| `tool_matchers` | No | Only match specific tools (regex) |
| `case_sensitive` | No | Default: false |
| `multiline` | No | Default: true |

### Targets

- **content** — the text being written/edited/patched
- **command** — the Bash command string
- **path** — file paths involved in the operation
- **prompt** — the user's prompt text (UserPromptSubmit only)

## Adding a Python rule

1. Create a file in `src/vibeforcer/rules/` (or add to an existing one)
2. Subclass `Rule` from `vibeforcer.rules.base`
3. Set `rule_id`, `title`, and `events`
4. Implement `evaluate()` returning `list[RuleFinding]`
5. Register in `src/vibeforcer/rules/__init__.py`
6. Add tests

### Example

```python
from vibeforcer.models import RuleFinding, Severity
from vibeforcer.rules.base import Rule

class NoSleepInTestsRule(Rule):
    rule_id = "CUSTOM-TEST-001"
    title = "Block time.sleep in tests"
    events = ("PreToolUse", "PermissionRequest")

    def evaluate(self, ctx):
        findings = []
        for target in ctx.content_targets:
            if "test_" not in target.path:
                continue
            if "time.sleep" in target.content:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.HIGH,
                    decision="deny",
                    message=f"time.sleep() in {target.path} — use mocking instead.",
                    metadata={"path": target.path},
                ))
        return findings
```

## Choosing PreToolUse vs PostToolUse

**PreToolUse** — the edit/command hasn't happened yet. You can deny it.
- Use when: the payload contains enough info to decide (content, command, paths)
- Advantage: blocks before damage

**PostToolUse** — the edit already happened. You can block (force undo) or advise.
- Use when: you need the actual file on disk, or want to run linters/tests
- Advantage: sees the real result

**Both** — some rules (like AST quality) run on both: pre to catch proposed edits, post to validate the result on disk.

## Per-repo overrides

Projects can override rules via `quality_gate.toml` in their root:

```toml
[quality_gate]
enabled = true                     # false = disable all rules for this repo
disabled_rules = ["PY-CODE-013"]   # disable specific rules

[quality_gate.severity_overrides]
"PY-CODE-008" = "warn"            # downgrade to advisory

[thresholds]
max_method_lines = 80              # override default 50
max_params = 6                     # override default 4
max_complexity = 15                # override default 10
```

Or opt out entirely with a sentinel file:

```bash
touch .noqualitygate
```

## Tips

- Keep rule IDs stable — they appear in logs, configs, and per-repo overrides
- Prefer config (regex rules) over code when the pattern is simple
- Put repo-specific paths/patterns in config, not hardcoded in rules
- Use `additional_context` for helpful guidance that doesn't block
- Always add metadata to findings — it powers enrichment and log analysis
- Test with `vibeforcer replay --payload fixture.json --pretty`
