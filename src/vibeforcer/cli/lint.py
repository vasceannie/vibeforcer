from __future__ import annotations

import argparse
import sys
from pathlib import Path

BASELINE_DISABLED_MESSAGE = (
    "`vibeforcer lint baseline` is disabled. Repo-wide rebaselining hides technical debt. "
    "Fix violations directly, or make a deliberate, human-reviewed baselines.json change that only reduces debt."
)

from vibeforcer.lint._baseline import Violation

from vibeforcer.constants import MAX_LINT_VIOLATIONS_SHOWN


def _colorize(code: str, text: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def _tally_rule(
    rule_name: str,
    violations: list[Violation],
    baseline: dict[str, set[str]],
    color: bool,
) -> tuple[int, int, int]:
    allowed = baseline.get(rule_name, set())
    current_ids = {getattr(v, "stable_id") for v in violations}
    new_ids = current_ids - allowed
    fixed_ids = allowed - current_ids
    new_violations = [v for v in violations if getattr(v, "stable_id") in new_ids]

    status = (
        _colorize("31", f"✗ {rule_name}", color)
        if new_violations
        else _colorize("32", f"✓ {rule_name}", color)
    )
    counts = f"{len(violations)} total"
    if new_violations:
        counts += f", {_colorize('31', f'{len(new_violations)} NEW', color)}"
    if fixed_ids:
        counts += f", {_colorize('32', f'{len(fixed_ids)} fixed', color)}"
    if allowed:
        counts += f" {_colorize('2', f'(baseline: {len(allowed)})', color)}"

    print(f"  {status}  {counts}")
    for violation in new_violations[:MAX_LINT_VIOLATIONS_SHOWN]:
        print(f"    {_colorize('31', '+', color)} {violation}")
    if len(new_violations) > MAX_LINT_VIOLATIONS_SHOWN:
        remaining = len(new_violations) - MAX_LINT_VIOLATIONS_SHOWN
        print(f"    {_colorize('2', f'... and {remaining} more', color)}")
    return len(violations), len(new_violations), len(fixed_ids)


def _print_lint_summary(
    total_v: int,
    total_n: int,
    total_f: int,
    color: bool,
) -> int:
    print()
    if total_n == 0:
        print(
            _colorize(
                "32", f"✓ No new violations ({total_v} total, all baselined)", color
            )
        )
        if total_f:
            print(
                _colorize(
                    "33",
                    f"  ℹ {total_f} fixed — update baselines.json only as a deliberate debt reduction, not via repo-wide rebaselining",
                    color,
                )
            )
        return 0
    print(_colorize("31", f"✗ {total_n} new violation(s) introduced", color))
    print(f"  {total_v} total across all rules")
    return 1


def _lint_check(root: Path) -> int:
    from vibeforcer.lint import __version__ as lint_version
    from vibeforcer.lint._baseline import load_baseline
    from vibeforcer.lint._collectors import run_all_collectors
    from vibeforcer.lint._config import load_config as load_qg_config
    from vibeforcer.lint._config import set_config as set_qg_config
    from vibeforcer.lint._helpers import find_source_files, find_test_files

    cfg = load_qg_config(root)
    set_qg_config(cfg)
    src_files = find_source_files()
    test_files = find_test_files()

    print(f"vibeforcer lint {lint_version}")
    print(f"  project: {cfg.project_root}")
    print(f"  src:     {cfg.src_root}  ({len(src_files)} files)")
    print(f"  tests:   {cfg.tests_root}  ({len(test_files)} files)")
    print()

    baseline = load_baseline()
    collectors = run_all_collectors(src_files, test_files)
    color = hasattr(sys.stderr, "isatty") and sys.stderr.isatty()

    total_v = 0
    total_n = 0
    total_f = 0
    for rule_name, violations in collectors:
        if not violations:
            continue
        count_v, count_n, count_f = _tally_rule(rule_name, violations, baseline, color)
        total_v += count_v
        total_n += count_n
        total_f += count_f
    return _print_lint_summary(total_v, total_n, total_f, color)


def _lint_baseline(_root: Path) -> int:
    print(BASELINE_DISABLED_MESSAGE)
    return 1


def _lint_init(root: Path) -> int:
    from vibeforcer.lint import __version__ as lint_version
    from vibeforcer.lint._updater import render_quality_gate_toml

    root.mkdir(parents=True, exist_ok=True)
    destination = root / "quality_gate.toml"
    if destination.exists():
        print(f"Already exists: {destination}")
        print("  To add missing keys, run: vibeforcer lint update")
        return 1

    _ = destination.write_text(
        render_quality_gate_toml(version=lint_version), encoding="utf-8"
    )
    print(f"✓ Created {destination}")
    print("  Edit it to match your project, then run: vibeforcer lint check")
    return 0


def _lint_update(root: Path, *, dry_run: bool = False) -> int:
    from vibeforcer.lint._updater import update_toml_file

    destination = root / "quality_gate.toml"
    if not destination.exists():
        print(f"No quality_gate.toml found at {root}")
        print("  Run `vibeforcer lint init` first.")
        return 1

    missing = update_toml_file(destination, dry_run=dry_run)
    if not missing:
        print("✓ Config is up to date")
        return 0

    total_keys = sum(len(keys) for keys in missing.values())
    print(
        f"{'Would add' if dry_run else 'Added'} {total_keys} key(s) across {len(missing)} section(s):"
    )
    for section, keys in missing.items():
        for key in keys:
            print(f"  [{section}] {key}")
    if dry_run:
        print("  (dry run)")
    else:
        print(f"✓ Updated {destination}")
    return 0


def cmd_lint(args: argparse.Namespace) -> int:
    raw_lint_command = getattr(args, "lint_command", None)
    lint_command = raw_lint_command if isinstance(raw_lint_command, str) else "check"
    raw_path = getattr(args, "path", ".")
    path_value = raw_path if isinstance(raw_path, str) and raw_path else "."
    args.path = path_value
    root = Path(path_value).resolve()
    dispatch = {
        "check": _lint_check,
        "baseline": _lint_baseline,
        "init": _lint_init,
    }
    handler = dispatch.get(lint_command)
    if handler is not None:
        return handler(root)
    if lint_command == "update":
        raw_dry_run = getattr(args, "dry_run", False)
        return _lint_update(
            root,
            dry_run=raw_dry_run if isinstance(raw_dry_run, bool) else False,
        )
    return 1
