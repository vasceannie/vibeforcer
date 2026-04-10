# Modularity & Observability Refactor Plan

> Status: **draft** (v3 — revised after second Momus review)
> Last validated: 2026-04-09 against full codebase read

## Context

Vibeforcer's core modules have grown organically — `enrichment.py` (928 lines), `python_ast.py` (902 lines), `cli.py` (668 lines). This plan addresses modularity, deduplication, side-effect isolation, threshold synchronization, and observability gaps.

All splits MUST use **sub-packages** (directory with `__init__.py`), not flat `_prefix_*.py` sibling files — per repo rules.

### Verification Infrastructure

This repo has **no Makefile**. The only verification tool is:
```
pytest tests/ -x          # run all tests, stop on first failure
pytest tests/test_X.py -x # run specific test file
```
No ruff, mypy, or basedpyright is configured. Every QA step below uses pytest exclusively.

### Threshold Divergence (pre-existing bug)

Hook-time config (`models.py` → `RuntimeConfig`) and batch lint config (`lint/_config.py` → `QualityConfig`) define the same thresholds with **different defaults**:

| Metric         | `RuntimeConfig` default | `QualityConfig` default | Gap |
| -------------- | ----------------------- | ----------------------- | --- |
| max_complexity | 10                      | 12                      | +2  |
| max_god_class_methods | 10               | 15                      | +5  |
| max_method_lines | (not set)             | 50                      | N/A |

Step 1.2 resolves this by establishing single-source constants that both configs reference.

---

## Phase 1: Quick Wins (Bug Prevention & Deduplication)

### Step 1.1 — Deduplicate `_is_rule_enabled()` (10 min)

**Problem**: 4 identical copies of the same function across rule files:
- `rules/common.py` line 14: `_is_rule_enabled`
- `rules/python_ast.py` line 38: `_is_enabled`
- `rules/langgraph.py` line 23: `_is_enabled`
- `rules/baseline_guard.py` line 13: `_is_rule_enabled`

All identical: `value = ctx.config.enabled_rules.get(rule_id); return default if value is None else bool(value)`

**Implementation**:
- Add standalone helper `is_rule_enabled(ctx, rule_id, default=True)` to `rules/base.py` (currently 33 lines — natural home)
- Update all 4 call sites to import from `base`
- Remove the 4 local copies

**Files changed**: `rules/base.py`, `rules/common.py`, `rules/python_ast.py`, `rules/langgraph.py`, `rules/baseline_guard.py`

**QA**:
- Command: `pytest tests/ -x`
- Artifact: zero test failures
- Grep verification: `grep -rn "_is_rule_enabled\|_is_enabled" src/vibeforcer/rules/ --include="*.py"` returns only the single definition in `base.py`
- Import verification: `python -c "from vibeforcer.rules.base import is_rule_enabled; print('OK')"` succeeds

---

### Step 1.2 — Unify threshold constants (30 min)

**Problem**: Hook-time config and batch lint config define identical thresholds independently. `constants.py` has no thresholds. Defaults diverge (see Context section above).

**Implementation**:
- Add threshold constants to `constants.py`:
  ```python
  # --- Quality thresholds (single source of truth) ---
  MAX_COMPLEXITY: Final = 12
  MAX_PARAMS: Final = 4
  MAX_METHOD_LINES: Final = 50
  MAX_NESTING_DEPTH: Final = 4
  MAX_GOD_CLASS_METHODS: Final = 15
  MAX_GOD_CLASS_LINES: Final = 400
  ```
- Update `models.py` `RuntimeConfig` field defaults to reference `constants.MAX_*`
- Update `lint/_config.py` `QualityConfig` field defaults to reference `constants.MAX_*`
- **Critical**: Update `config.py:233-239` hardcoded `.get()` fallback literals to reference `constants.MAX_*` — these are the LIVE runtime defaults, not the `RuntimeConfig` dataclass defaults. The `.get("python_max_complexity", 10)` pattern at line 233 is what actually feeds the config, and it currently hardcodes 10 (not the RuntimeConfig default). All 7 threshold `.get()` calls at lines 233-239 must be updated.
- This resolves the divergence: config.py fallbacks, RuntimeConfig defaults, and QualityConfig defaults all read from the same source

**Decision**: Use the `QualityConfig` values (12/15) as canonical — they are the more permissive and were likely tuned for batch lint. The stricter `RuntimeConfig` values (10/10) were probably placeholders.

**Files changed**: `constants.py`, `models.py`, `lint/_config.py`, `config.py`

**QA**:
- Command: `pytest tests/ -x`
- Artifact: zero test failures
- Cross-check: `python -c "from vibeforcer.constants import MAX_COMPLEXITY; from vibeforcer.models import RuntimeConfig; from vibeforcer.lint._config import QualityConfig; rc=RuntimeConfig.__dataclass_fields__; qc=QualityConfig.__dataclass_fields__; assert rc['python_max_complexity'].default == MAX_COMPLEXITY == qc['max_complexity'].default; print('OK')"` succeeds
- Fallback verification: `grep -n "python_max_complexity" src/vibeforcer/config.py` shows the `.get()` fallback referencing `constants.MAX_COMPLEXITY`, not a hardcoded integer

---

## Phase 2: Modularity Sprint

### Step 2.1 — Split `enrichment.py` into sub-package (1-2 hrs)

**Problem**: 928-line monolith with 14 enricher functions + registry.

**Implementation**: Create `enrichment/` sub-package:

```
src/vibeforcer/enrichment/
├── __init__.py          # re-exports: enrich_findings, ENRICHERS
├── _fixtures.py         # _safe_read, _safe_parse, _resolve_path, fixture discovery, parametrize examples (lines 28-178)
├── _test_enrichers.py   # _enrich_test_loop, _enrich_assertion_roulette, _enrich_test_smells, _enrich_fixture_outside_conftest (lines 185-345)
├── _type_enrichers.py   # _enrich_python_any (lines 347-379)
├── _ast_enrichers.py    # _enrich_long_method, _enrich_long_params, _enrich_cyclomatic_complexity, _enrich_feature_envy, _enrich_thin_wrapper (lines 385-643)
├── _regex_enrichers.py  # _enrich_silent_except, _enrich_stdlib_logger, _enrich_type_suppression, _enrich_magic_numbers, _enrich_hardcoded_paths (lines 645-885)
└── _routing.py          # ENRICHERS registry dict + enrich_findings() entry point (lines 891-928)
```

**Rules**:
- `__init__.py` re-exports public API so external imports remain unchanged:
  ```python
  # Public API (imported by engine, tests, etc.)
  from vibeforcer.enrichment._routing import enrich_findings, ENRICHERS
  from vibeforcer.enrichment._fixtures import _discover_fixtures, _find_parametrize_examples
  ```
  - `enrich_findings`, `ENRICHERS`: used by engine.py
  - `_discover_fixtures`, `_find_parametrize_examples`: imported by `tests/test_enrichment.py:15`
- Internal modules use `_` prefix — not part of public API
- No logic changes — pure file reorganization
- Shared helpers (`_safe_read`, `_safe_parse`, `_resolve_path`) stay in `_fixtures.py`; other modules import from it
**Files changed**: Delete `enrichment.py`, create `enrichment/` package with 7 files

**QA**:
- Command: `pytest tests/test_enrichment.py -x`
- Artifact: all enrichment tests pass, zero failures
- Import verification: `python -c "from vibeforcer.enrichment import enrich_findings, ENRICHERS; print(f'{len(ENRICHERS)} enrichers loaded')"` succeeds and shows same enricher count as before
- Smoke test: `pytest tests/ -x` — all tests pass (not just enrichment)

---

### Step 2.2 — Split `python_ast.py` helpers into sub-package (1 hr)

**Problem**: 902 lines with 11 rule classes + shared helpers. Two rules (`PY-CODE-008`, `PY-CODE-009`) bypass the shared `_evaluate_common()` — leftover from a refactor.

**Implementation**: Create `rules/python_ast/` sub-package:

```
src/vibeforcer/rules/python_ast/
├── __init__.py          # re-exports all 11 rule classes
├── _helpers.py          # _is_third_party_path, _decision, _parse_module, _evaluate_common (lines 32-92)
└── _rules.py            # All 11 rule classes (lines 94-902)
```

**Additional fix**: Migrate `PY-CODE-008` (LongMethod) and `PY-CODE-009` (LongParameter) to use `_evaluate_common()` like the other 9 rules. If there's a reason they can't (different signature needs), add a `# NOTE:` comment explaining why — do NOT leave it undocumented.

**Note on `_is_enabled`**: After Step 1.1, this is already deduplicated to `base.py`, so it won't be in `_helpers.py`.

**Files changed**: Delete `rules/python_ast.py`, create `rules/python_ast/` package with 3 files

**QA**:
- Command: `pytest tests/test_ast_rules.py -x`
- Artifact: all AST rule tests pass, zero failures
- Import verification: `python -c "from vibeforcer.rules.python_ast import PythonLongMethodRule, PythonImportFanoutRule; print('OK')"` succeeds
- Smoke test: `pytest tests/ -x` — all tests pass

---

### Step 2.3 — Extract `load_config()` side effects (30 min)

**Problem**: `load_config()` (93 lines, config.py:157-249) interleaves pure config merging with directory creation side effects (lines 184-185).

**Implementation**:
- Extract `_merge_config(config_path, root)` → returns merged config dict (pure function)
- Extract `ensure_trace_directories(config)` → creates trace dirs from config (side effect)
- `load_config()` becomes: `cfg = _merge_config(...); ensure_trace_directories(cfg); return cfg`
- No logic changes — pure extraction

**Files changed**: `config.py`

**QA**:
- Command: `pytest tests/test_error_and_config_rules.py -x`
- Artifact: zero test failures
- Side-effect verification: `python -c "from vibeforcer.config import load_config, _merge_config, ensure_trace_directories; print('OK')"` succeeds
- Smoke test: `pytest tests/ -x`

---

## Phase 3: Observability Sprint

### Step 3.1 — Add per-rule timing to engine (30 min)

**Problem**: `_run_rule()` (engine.py:117) evaluates rules with no timing. Trace captures results but not duration.

**Implementation**:
- In `_run_rule()`, wrap the `rule.evaluate(ctx)` call with `time.monotonic()` before/after
- Add `elapsed_ms` field to the trace dict passed to `_trace_findings()`
- Exact insertion point: engine.py line 125 (around `result = rule.evaluate(ctx)`)
- The trace record written to `rules.jsonl` will contain the new `elapsed_ms` field alongside existing fields
- No logic changes — additive instrumentation

**Files changed**: `engine.py`

**QA**:
- Command: `pytest tests/test_engine.py -x`
- Artifact: zero test failures
- Field verification: run vibeforcer against any test file, then `grep -c "elapsed_ms" <trace_dir>/rules.jsonl` returns >0

---

### Step 3.2 — Add enrichment metrics (30 min)

**Problem**: Enrichment runs synchronously after every rule with zero observability. No tracking of which enrichers fired, AST parse count, or wall-clock time.

**Implementation**:
- In `enrich_findings()` entry point (in `enrichment/_routing.py` after Step 2.1), add:
  - `time.monotonic()` for total enrichment wall-clock
  - Dict counter tracking which enrichers produced findings
  - Counter for AST parse calls (track in `_safe_parse`)
- Emit metrics via the existing trace system using this exact record shape:

```python
# Written to rules.jsonl via ctx.trace.rule()
{
    "rule_id": "_ENRICHMENT_METRICS",
    "title": "Enrichment metrics",
    "elapsed_ms": <float>,            # total enrichment wall-clock
    "enrichers_fired": {              # only enrichers that produced findings
        "test_loop": 3,
        "assertion_roulette": 1,
    },
    "ast_parses": 5,                  # number of _safe_parse calls
    "decision": "info",
    "severity": "info",
}
```

- Return enriched findings unchanged — metrics are a side channel via trace
- **If Step 2.1 has not been executed yet**, add metrics to the monolithic `enrichment.py` `enrich_findings()` function instead, at the same location

**Files changed**: `enrichment/_routing.py` (after Step 2.1) or `enrichment.py` (if Step 2.1 not done)

**QA**:
- Command: `pytest tests/test_enrichment.py -x`
- Artifact: zero test failures
- Field verification: run vibeforcer against any test file, then `grep "_ENRICHMENT_METRICS" <trace_dir>/rules.jsonl` returns a valid JSON record with `elapsed_ms`, `enrichers_fired`, and `ast_parses` fields

---

### Step 3.3 — Add structured logging (2-3 hrs)

**Problem**: `trace.py` swallows `OSError` silently (line 29-30: `except OSError: return`). No `logging` module anywhere in the codebase. `util/` is empty (1-line docstring). All observability is JSONL file appending.

**Implementation**:
- Create `util/logger.py` — a minimal structured logging utility (NOT `structlog`, NOT stdlib `logging` — repo has no existing logger):
  ```python
  # util/logger.py
  """Minimal structured logger for vibeforcer internals."""
  import json, sys, time

  def _emit(level: str, message: str, **fields) -> None:
      record = {"ts": time.time(), "level": level, "msg": message, **fields}
      sys.stderr.write(json.dumps(record) + "\n")
      sys.stderr.flush()

  def info(message: str, **fields): _emit("info", message, **fields)
  def warning(message: str, **fields): _emit("warning", message, **fields)
  def error(message: str, **fields): _emit("error", message, **fields)
  def debug(message: str, **fields): _emit("debug", message, **fields)
  ```
- Fix `trace.py`: replace silent `except OSError: return` with:
  ```python
  except OSError as exc:
      from vibeforcer.util.logger import warning
      warning("trace write failed", path=str(path), error=str(exc))
      return
  ```
- Add logging to:
  - `engine.py`: rule evaluation errors (in the existing except block at `_run_rule`)
  - `config.py`: config loading failures (in `_load_json`, `_load_toml`)
  - `enrichment/_routing.py`: enrichment failures (in the existing error capture)
- Do NOT replace the JSONL trace system — logging is complementary (stderr vs file)

**Files changed**: `util/logger.py` (new), `util/__init__.py` (add re-export), `trace.py`, `engine.py`, `config.py`, `enrichment/_routing.py`

**QA**:
- Command: `pytest tests/test_trace.py tests/test_engine.py -x`
- Artifact: zero test failures
- OSError logging verification: `grep -n "except OSError" src/vibeforcer/trace.py` shows the warning call, not a bare `return`
- Import verification: `python -c "from vibeforcer.util.logger import info, warning, error, debug; print('OK')"` succeeds
- Smoke test: `pytest tests/ -x`

---

## Phase 4: Lower Priority Cleanups

### Step 4.1 — Extract cli.py lint commands (1 hr)

**Problem**: 668 lines. Lint commands (lines 255-463, ~210 lines) are a clear extraction candidate.

**Implementation**: Create `cli/` sub-package:

```
src/vibeforcer/cli/
├── __init__.py          # re-exports: main, safe_main, build_parser
├── _commands.py         # Hook/config commands (lines 34-253)
├── _lint.py             # Lint commands (lines 255-463)
├── _parsers.py          # Argument parsers (lines 465-577)
└── _main.py             # Search dispatch + main entry (lines 579-668)
```

**Priority**: Low — do after Phases 1-3 establish the sub-package patterns.

**Files changed**: Delete `cli.py`, create `cli/` package with 5 files

**QA**:
- Command: `pytest tests/ -x`
- Artifact: zero test failures
- CLI verification: `python -m vibeforcer.cli --version` succeeds (or `vibeforcer --version` if installed)

---

### Step 4.2 — Establish search/ package boundary (2 hrs)

**Problem**: `search/` is functionally independent (zero imports from rules/engine/enrichment/lint) but no explicit boundary is declared.

**Implementation**:
- Add boundary documentation to `search/__init__.py` declaring what search may import (only `constants`)
- Add a test in `tests/` that grep-verifies no coupling imports exist:
  ```python
  # tests/test_search_boundary.py
  def test_search_imports_no_core_modules():
      """search/ must not import from rules, engine, enrichment, or lint."""
      ...
  ```
- Consider: does search/ warrant its own `pyproject.toml`? (Out of scope — flag for later)

**Files changed**: `search/__init__.py`, new `tests/test_search_boundary.py`

**QA**:
- Command: `pytest tests/test_search_boundary.py -x`
- Artifact: test passes, confirming no coupling imports

---

## Execution Order

| Order | Step                                      | Phase   | Effort   | Dependencies |
|-------|-------------------------------------------|---------|----------|--------------|
| 1     | 1.1 Deduplicate `_is_rule_enabled`        | Quick   | 10 min   | None         |
| 2     | 1.2 Unify threshold constants             | Quick   | 30 min   | None         |
| 3     | 2.1 Split enrichment.py                   | Modular | 1-2 hrs  | None         |
| 4     | 2.2 Split python_ast.py                   | Modular | 1 hr     | Step 1.1     |
| 5     | 2.3 Extract load_config() side effects    | Modular | 30 min   | None         |
| 6     | 3.1 Engine per-rule timing                | Observ  | 30 min   | None         |
| 7     | 3.2 Enrichment metrics                    | Observ  | 30 min   | Step 2.1     |
| 8     | 3.3 Structured logging                    | Observ  | 2-3 hrs  | Steps 3.1-3.2|
| 9     | 4.1 Extract cli.py lint commands          | Cleanup | 1 hr     | Steps 2.1-2.2|
| 10    | 4.2 Search package boundary               | Cleanup | 2 hrs    | None         |

Steps 1.1, 1.2, 2.3, 3.1, 4.2 are **fully independent** and can run in parallel.
Step 2.1 has no dependencies but is large.
Step 2.2 depends on 1.1 (deduplicated `_is_enabled`).
Step 3.2 depends on 2.1 (enrichment package must exist).
Step 3.3 depends on 3.1-3.2 for context.
Step 4.1 should follow 2.1-2.2 to match established patterns.

## Invariants (must not change)

- External import paths remain identical (`from vibeforcer.enrichment import enrich_findings`, etc.)
- All existing tests pass without modification
- No logic changes in any step — pure reorganization and additive instrumentation
- `pytest tests/ -x` passes at every step boundary
- Baselines do not increase

## Risk Mitigation

- Each step is independently verifiable — if a step breaks, revert only that step
- Sub-package pattern is the same across all splits — establish it once in Step 2.1, copy the pattern
- No step touches more than one "domain" (rules, enrichment, config, engine) at a time
