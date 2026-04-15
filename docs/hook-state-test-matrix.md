# Hook State Test Matrix

This matrix locks the intended behavior before changing hook runtime logic.
It focuses on reducing repeated interruption without hiding debt.

## Scope

1. Stateful full-file read enforcement
2. Search reminder deduplication
3. Repeated debt escalation for advisory quality hooks
4. Security rule boundary cases
5. Cross-session and cross-platform invariants
6. State store design constraints

## Current behavior mismatches to resolve

- `REMIND-SEARCH-001` currently emits on native `Grep` and `WebSearch`; the future spec intentionally reverses that behavior.
- `BUILTIN-ENFORCE-FULL-READ` currently exempts `*.json` but not `*.jsonl`; the future spec adds `*.jsonl` because partial reads are the normal access pattern for trace logs.
- `BUILTIN-RULEBOOK-SECURITY` currently excludes fixture and test-like paths, but not `docs/` or `docs/examples/`; any carveout there must be explicit and path-based.

## 1. Full-File Read Enforcement

Goal: keep the first-read rule for source files, but avoid forcing full reads for structured data and allow partial follow-up reads after a full read in the same session.

### Primary cases

- First partial read of `*.py` in a session is denied when `BUILTIN-ENFORCE-FULL-READ` is enabled.
- Full read of `*.py` in a session unlocks later partial reads of the same file in that same session.
- Full read of `file_a.py` does not unlock partial reads of `file_b.py`.
- Full read in session `s1` does not unlock partial reads in session `s2`.
- Large source files above the size threshold stay exempt.

### Structured-data carveouts

- `*.json` is exempt from the first-read deny rule.
- `*.jsonl` is exempt from the first-read deny rule.
- Existing exemptions keep working for `*.md`, `*.yaml`, `*.yml`, `*.txt`, `*.log`, and `*.csv`.
- Case-insensitive suffix handling stays correct.

### Edge cases

- A full read with explicit `offset=1` or `limit` does not count as a full read.
- Relative and absolute paths resolve to the same per-session unlock state.
- Symlinked paths do not create duplicate unlock entries for the same file.
- Missing files do not create unlock state.

## 2. Search Reminder Deduplication

Goal: remind once when the model falls back to shell `grep`, but do not self-remind when it already uses native search tools.

### Primary cases

- First shell `grep` in a session emits `REMIND-SEARCH-001`.
- Second shell `grep` in the same session does not emit the same reminder again.
- A new session emits the reminder again.
- `rg` does not emit the reminder.

### Native tool behavior

- Native `Grep` does not emit the reminder.
- Native `WebSearch` does not emit the reminder.
- Native `Read` does not emit the reminder.

### Edge cases

- `grep` in chained shell commands still counts as one reminder site.
- Case-insensitive `GREP` matching still works.
- `grep` embedded inside another token does not falsely match.
- Reminder dedupe is keyed by session, not cwd.

## 3. Repeated Debt Escalation

Goal: do not hide preexisting debt, but stop blasting the same advisory text on every repeat. Repeats should become more actionable.

### Primary cases

- First `PY-CODE-012` or `PY-CODE-013` hit on a given `(session, rule, path)` emits an advisory finding.
- Second hit on the same `(session, rule, path)` includes repeat metadata instead of emitting an indistinguishable first-hit message.
- Third hit on the same `(session, rule, path)` escalates severity or decision.
- Repeats on different files are tracked independently.
- Repeats for different rules on the same file are tracked independently.
- A new session resets the repeat counter.

### Debt visibility cases

- Repeated hits remain visible in findings metadata and trace output.
- Repeated hits can be aggregated into stop-time or summary context without suppressing the underlying debt.
- Fixing the violation clears the repeat counter for that `(session, rule, path)`.
- Reintroducing the violation after a fix starts a fresh counter.

### Edge cases

- MultiEdit touching the same path once counts as one hit.
- Patch-based edits count against the resolved target path.
- Worktree paths and main-repo paths do not collapse into one counter unless they resolve to the same file.

## 4. Security Rule Boundary Cases

Goal: keep hard blocks for real guardrail weakening while reducing false positives in docs, fixtures, and examples.

### Primary cases

- Real source changes that introduce `bypass_permissions` are denied.
- Real source changes that introduce `allowManagedHooksOnly` are denied when they are actual config/code changes.
- Markdown docs describing these settings are allowed.
- JSON examples under docs/examples are allowed.
- Fixtures and test data that mention these strings are allowed.

### Edge cases

- Comment-only mentions in non-hook source files are allowed.
- Example code in fenced markdown blocks is allowed.
- Hook and vibeforcer implementation paths remain protected by the stronger infra rules.

## 5. Cross-Platform Invariants

Goal: stateful behavior must hold across Claude, Codex, and OpenCode payloads.

### Primary cases

- Session-based dedupe keys off normalized `session_id` for each platform.
- Full-read unlock behavior is the same after adapter normalization.
- Search reminder dedupe is the same after adapter normalization.
- Output shape remains valid for each platform after any stateful changes.

### Edge cases

- OpenCode `session.idle` and mapped Stop events do not corrupt per-session state.
- Codex payload normalization does not drop paths needed for dedupe keys.
- Relative and absolute path variants normalize to one state key.
- Session state survives multiple tool events in-process and across hook subprocess invocations.

## 6. State Store Design Constraints

Goal: keep the spec behavioral, while forcing the implementation to fit the real hook execution model.

### Required properties

- State must survive separate hook subprocess invocations for the same session.
- State keys must include normalized session identity and normalized target path when path-sensitive.
- State updates must be safe under concurrent hook calls for the same session.
- State must have an eviction policy so long-lived sessions do not leak memory or disk.
- Clearing a violation must clear or reset the matching repeat counter.

### Open design questions

- In-memory cache, file-backed store, or another lightweight IPC mechanism?

  File-backed state under the existing trace directory, with locking around updates. Hooks run in separate subprocesses, so in-memory state would not satisfy the subprocess-boundary spec.

- What is the canonical path key for symlinks, worktrees, and relative paths?

  Resolve relative paths against `cwd` and normalize to the resolved absolute path. Keep worktrees distinct unless they resolve to the same underlying file.

- What is the retention policy for abandoned sessions?

  Expire idle state after 1 hour.

- Should repeat metadata live only in findings, or also in trace output and stop-time summaries?

  Trace and summary output as well as findings metadata.

## Execution Order

1. Add executable spec tests for the settled behavior.
2. Add subprocess-aware spec coverage for any stateful feature.
3. Keep unsettled behavior in strict xfail tests until the runtime design is chosen.
4. Only after the spec exists, modify hook logic.
5. Run `vfc test` before and after implementation.
