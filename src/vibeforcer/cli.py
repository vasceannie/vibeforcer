from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vibeforcer.constants import (
    EXIT_KEYBOARD_INTERRUPT,
    MAX_LINT_VIOLATIONS_SHOWN,
    SELFTEST_SEPARATOR_WIDTH,
)

VALID_PLATFORMS = ("claude", "codex", "opencode")
_PLATFORM_HELP = (
    "Target platform. Choices: "
    f"{', '.join(VALID_PLATFORMS)} (default: claude)"
)


def _load_stdin_json() -> dict:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    return json.loads(raw)


def _dump_output(output: dict | None) -> int:
    if output:
        sys.stdout.write(json.dumps(output, separators=(",", ":")) + "\n")
    return 0


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def cmd_handle(args: argparse.Namespace) -> int:
    """Core hook handler."""
    from vibeforcer.engine import evaluate_payload

    payload = _load_stdin_json()
    if not payload:
        return 0
    platform = getattr(args, "platform", "claude")
    result = evaluate_payload(payload, platform=platform)
    return _dump_output(result.output)


def cmd_handle_async(args: argparse.Namespace) -> int:
    """Run async post-edit quality jobs."""
    from vibeforcer.async_jobs import run_async_jobs

    payload = _load_stdin_json()
    summary, _errors = run_async_jobs(payload)
    if summary:
        sys.stdout.write(summary + "\n")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Check whether the quality gate is active for a given repo path."""
    from vibeforcer.config import (
        is_path_skipped, is_repo_disabled, load_config,
    )

    target = Path(args.path).resolve()
    config = load_config()
    disabled = is_repo_disabled(target)
    skipped = is_path_skipped(target, config.skip_paths)
    status = "DISABLED" if (disabled or skipped) else "ACTIVE"
    info = {
        "path": str(target), "status": status,
        "repo_disabled": disabled, "path_skipped": skipped,
        "skip_paths": config.skip_paths,
    }
    print(json.dumps(info, indent=2))
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    """Replay a saved payload through the rule engine."""
    from vibeforcer.engine import evaluate_payload

    path = Path(args.payload)
    payload = json.loads(path.read_text(encoding="utf-8"))
    platform = getattr(args, "platform", "claude")
    result = evaluate_payload(payload, platform=platform)
    if args.pretty:
        print(json.dumps(result.output, indent=2))
    else:
        print(json.dumps(result.output, separators=(",", ":")))
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    """Install vibeforcer hooks into a platform's config."""
    from vibeforcer.installer import install_platform
    return install_platform(args.platform, dry_run=args.dry_run)


def cmd_uninstall(args: argparse.Namespace) -> int:
    """Remove vibeforcer hooks from a platform's config."""
    from vibeforcer.installer import uninstall_platform
    return uninstall_platform(args.platform, dry_run=args.dry_run)


def cmd_stats(args: argparse.Namespace) -> int:
    """Analyze hook activity logs and print a report."""
    from vibeforcer.stats import run_stats
    return run_stats(
        log_path=args.log if args.log else None,
        days=args.days, as_json=args.json,
    )


def cmd_config_show(args: argparse.Namespace) -> int:
    """Show the effective configuration."""
    from vibeforcer.config import load_config, resolve_config_path

    config_path = resolve_config_path()
    config = load_config()

    print(f"# Config source: {config_path}")
    print(f"# Trace dir: {config.trace_dir}")
    print(f"# Root: {config.root}")
    rules_msg = (
        f"{len(config.enabled_rules)} toggles, "
        f"{len(config.regex_rules)} regex rules"
    )
    print(f"# Rules: {rules_msg}")
    ast_status = "enabled" if config.python_ast_enabled else "disabled"
    print(f"# Python AST: {ast_status}")
    print()

    info = {
        "config_path": str(config_path),
        "root": str(config.root),
        "trace_dir": str(config.trace_dir),
        "enabled_rules_count": len(config.enabled_rules),
        "regex_rules_count": len(config.regex_rules),
        "python_ast_enabled": config.python_ast_enabled,
        "protected_paths": config.protected_paths,
        "skip_paths": config.skip_paths,
    }
    print(json.dumps(info, indent=2))
    return 0


def cmd_config_init(args: argparse.Namespace) -> int:
    """Create ~/.config/vibeforcer/config.json from bundled defaults."""
    from vibeforcer.config import config_dir
    from vibeforcer.resources import resource_path

    target = config_dir() / "config.json"
    if target.exists() and not args.force:
        print(f"Config already exists: {target}")
        print("Use --force to overwrite.")
        return 1

    defaults_path = resource_path("defaults.json")
    content = defaults_path.read_text(encoding="utf-8")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    print(f"Created: {target}")

    log_dir = config_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "async").mkdir(exist_ok=True)
    print(f"Created: {log_dir}")

    _copy_prompt_context(config_dir(), resource_path)
    return 0


def _copy_prompt_context(base_dir: Path, resource_path) -> None:
    """Copy prompt_context templates if the dir does not exist yet."""
    ctx_dir = base_dir / "prompt_context"
    if ctx_dir.exists():
        return
    ctx_dir.mkdir(parents=True, exist_ok=True)
    for name in ("organization.md", "repo.md"):
        src = resource_path("prompt_context") / name
        if src.exists():
            (ctx_dir / name).write_text(
                src.read_text(encoding="utf-8"), encoding="utf-8",
            )
    print(f"Created: {ctx_dir}")


def cmd_config_path(args: argparse.Namespace) -> int:
    """Print the resolved config file path."""
    from vibeforcer.config import resolve_config_path
    print(resolve_config_path())
    return 0


# ---------------------------------------------------------------------------
# Self-test — data-driven with a helper to reduce complexity
# ---------------------------------------------------------------------------


def _run_one_test(evaluate_payload, case: tuple) -> str:
    """Run one self-test case and return 'PASS' or 'FAIL'."""
    label, event, tool, tool_input, platform, expect_deny = case
    payload = {
        "hook_event_name": event, "tool_name": tool,
        "tool_input": tool_input, "cwd": "/tmp",
        "session_id": "self-test",
    }
    result = evaluate_payload(payload, platform=platform)
    deny_count = sum(1 for f in result.findings if f.decision == "deny")
    passed = (deny_count > 0) if expect_deny else (deny_count == 0)
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {label} ({deny_count} finding(s))")
    return status


def cmd_test(args: argparse.Namespace) -> int:
    """Run self-test / smoke test."""
    from vibeforcer.engine import evaluate_payload

    print("vibeforcer self-test")
    print("=" * SELFTEST_SEPARATOR_WIDTH)

    env_path = str(Path.home() / ".env")
    noverify = {"command": "git commit --no-verify -m 'test'"}
    cases = [
        ("git --no-verify \u2192 deny", "PreToolUse", "Bash",
         noverify, "claude", True),
        (".env write \u2192 deny", "PreToolUse", "Write",
         {"file_path": env_path, "content": "SECRET=x"}, "claude", True),
        ("echo hello \u2192 allow", "PreToolUse", "Bash",
         {"command": "echo hello"}, "claude", False),
        ("codex adapter \u2192 deny", "PreToolUse", "Bash",
         noverify, "codex", True),
        ("opencode adapter \u2192 deny", "tool.execute.before", "bash",
         noverify, "opencode", True),
    ]
    statuses = [_run_one_test(evaluate_payload, c) for c in cases]
    all_pass = all(s == "PASS" for s in statuses)
    print()
    print("All tests passed." if all_pass else "SOME TESTS FAILED.")
    return 0 if all_pass else 1


def cmd_version(args: argparse.Namespace) -> int:
    """Print version."""
    from vibeforcer import __version__
    print(f"vibeforcer {__version__}")
    return 0


def cmd_lint(args: argparse.Namespace) -> int:
    """Run batch code quality analysis on a project."""
    lint_command = getattr(args, "lint_command", None)
    if not lint_command:
        lint_command = "check"
        args.path = args.path if hasattr(args, "path") else "."

    root = Path(getattr(args, "path", ".") or ".").resolve()
    dispatch = {
        "check": _lint_check, "baseline": _lint_baseline,
        "init": _lint_init,
    }
    handler = dispatch.get(lint_command)
    if handler:
        return handler(root)
    if lint_command == "update":
        return _lint_update(root, dry_run=getattr(args, "dry_run", False))
    return 1


# ---------------------------------------------------------------------------
# Lint helpers
# ---------------------------------------------------------------------------


def _colorize(code: str, text: str, enabled: bool) -> str:
    """Apply ANSI color if *enabled*."""
    return f"\033[{code}m{text}\033[0m" if enabled else text


def _tally_rule(
    rule_name: str, violations: list,
    baseline: dict, color: bool,
) -> tuple[int, int, int]:
    """Print one rule's status and return (total, new, fixed)."""
    allowed = baseline.get(rule_name, set())
    current_ids = {v.stable_id for v in violations}
    new_ids = current_ids - allowed
    fixed_ids = allowed - current_ids
    new_violations = [v for v in violations if v.stable_id in new_ids]

    if new_violations:
        status = _colorize("31", f"\u2717 {rule_name}", color)
    else:
        status = _colorize("32", f"\u2713 {rule_name}", color)

    counts = f"{len(violations)} total"
    if new_violations:
        tag = f"{len(new_violations)} NEW"
        counts += f", {_colorize('31', tag, color)}"
    if fixed_ids:
        tag = f"{len(fixed_ids)} fixed"
        counts += f", {_colorize('32', tag, color)}"
    if allowed:
        tag = f"(baseline: {len(allowed)})"
        counts += f" {_colorize('2', tag, color)}"

    print(f"  {status}  {counts}")
    limit = MAX_LINT_VIOLATIONS_SHOWN
    for v in new_violations[:limit]:
        print(f"    {_colorize('31', '+', color)} {v}")
    if len(new_violations) > limit:
        remaining = len(new_violations) - limit
        print(
            f"    {_colorize('2', f'... and {remaining} more', color)}",
        )

    return len(violations), len(new_violations), len(fixed_ids)


def _lint_check(root: Path) -> int:
    from vibeforcer.lint._config import load_config as load_qg_config
    from vibeforcer.lint._config import set_config as set_qg_config
    from vibeforcer.lint._helpers import find_source_files, find_test_files
    from vibeforcer.lint._baseline import load_baseline
    from vibeforcer.lint import __version__ as lint_version
    from vibeforcer.lint._collectors import run_all_collectors

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

    total_v, total_n, total_f = 0, 0, 0
    for rule_name, violations in collectors:
        if not violations:
            continue
        v, n, f = _tally_rule(rule_name, violations, baseline, color)
        total_v += v
        total_n += n
        total_f += f

    return _print_lint_summary(total_v, total_n, total_f, color)


def _print_lint_summary(
    total_v: int, total_n: int, total_f: int, color: bool,
) -> int:
    """Print lint check summary and return exit code."""
    print()
    if total_n == 0:
        msg = (
            f"\u2713 No new violations ({total_v} total, all baselined)"
        )
        print(_colorize("32", msg, color))
        if total_f:
            fix_msg = (
                f"  \u2139 {total_f} fixed \u2014 "
                "run `vibeforcer lint baseline` to lock that in"
            )
            print(_colorize("33", fix_msg, color))
        return 0
    intro = f"\u2717 {total_n} new violation(s) introduced"
    print(_colorize("31", intro, color))
    print(f"  {total_v} total across all rules")
    return 1


def _lint_baseline(root: Path) -> int:
    from vibeforcer.lint._config import load_config as load_qg_config
    from vibeforcer.lint._config import set_config as set_qg_config
    from vibeforcer.lint._helpers import find_source_files, find_test_files
    from vibeforcer.lint._baseline import save_baseline
    from vibeforcer.lint import __version__ as lint_version
    from vibeforcer.lint._collectors import run_all_collectors

    cfg = load_qg_config(root)
    set_qg_config(cfg)
    src_files = find_source_files()
    test_files = find_test_files()

    print(f"vibeforcer lint baseline {lint_version}")
    print(f"  project: {cfg.project_root}")
    print()

    collectors = run_all_collectors(src_files, test_files)
    all_violations = {}
    for rule_name, violations in collectors:
        if violations:
            all_violations[rule_name] = violations
            print(f"  {rule_name}: {len(violations)}")

    save_baseline(all_violations)
    total = sum(len(v) for v in all_violations.values())
    bp = cfg.baseline_path or (cfg.project_root / "baselines.json")
    print()
    rules = len(all_violations)
    print(
        f"\u2713 Baseline saved: {total} violation(s) across {rules} rule(s)",
    )
    print(f"  \u2192 {bp}")
    return 0


def _lint_init(root: Path) -> int:
    from vibeforcer.resources import resource_path

    root.mkdir(parents=True, exist_ok=True)
    dest = root / "quality_gate.toml"
    if dest.exists():
        print(f"Already exists: {dest}")
        print("  To add missing keys, run: vibeforcer lint update")
        return 1

    from vibeforcer.lint import __version__ as lint_version
    template_path = resource_path("quality_gate_template.toml")
    template = template_path.read_text(encoding="utf-8")
    dest.write_text(template.format(version=lint_version), encoding="utf-8")
    print(f"\u2713 Created {dest}")
    print("  Edit it to match your project, then run: vibeforcer lint check")
    return 0


def _lint_update(root: Path, *, dry_run: bool = False) -> int:
    from vibeforcer.lint._updater import update_toml_file

    dest = root / "quality_gate.toml"
    if not dest.exists():
        print(f"No quality_gate.toml found at {root}")
        print("  Run `vibeforcer lint init` first.")
        return 1

    missing = update_toml_file(dest, dry_run=dry_run)
    if not missing:
        print("\u2713 Config is up to date")
        return 0

    total_keys = sum(len(keys) for keys in missing.values())
    action = "Would add" if dry_run else "Added"
    print(f"{action} {total_keys} key(s) across {len(missing)} section(s):")
    for section, keys in missing.items():
        for key in keys:
            print(f"  [{section}] {key}")
    if dry_run:
        print("  (dry run)")
    else:
        print(f"\u2713 Updated {dest}")
    return 0


# ---------------------------------------------------------------------------
# Argument parser — split into per-group helpers
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level vibeforcer CLI parser."""
    parser = argparse.ArgumentParser(
        prog="vibeforcer",
        description="Global CLI guardrails engine for AI coding agents",
    )
    parser.add_argument(
        "--version", action="store_true", help="Print version and exit",
    )
    sub = parser.add_subparsers(dest="command")
    _add_core_parsers(sub)
    _add_config_parsers(sub)
    _add_lint_parsers(sub)

    from vibeforcer.search.cli import build_search_parser
    build_search_parser(sub)

    version = sub.add_parser("version", help="Print version")
    version.set_defaults(func=cmd_version)
    return parser


def _add_core_parsers(sub: argparse._SubParsersAction) -> None:
    """Register handle, handle-async, check, replay, install, uninstall, stats, test."""
    handle = sub.add_parser("handle", help="Read hook payload from stdin")
    handle.add_argument(
        "--platform", choices=VALID_PLATFORMS, default="claude",
        help=_PLATFORM_HELP,
    )
    handle.set_defaults(func=cmd_handle)

    ha = sub.add_parser("handle-async", help="Run async post-edit jobs")
    ha.set_defaults(func=cmd_handle_async)

    check = sub.add_parser("check", help="Check quality gate for a repo")
    check.add_argument("path", nargs="?", default=".")
    check.set_defaults(func=cmd_check)

    replay = sub.add_parser("replay", help="Replay a saved payload")
    replay.add_argument("--payload", required=True)
    replay.add_argument("--pretty", action="store_true")
    replay.add_argument(
        "--platform", choices=VALID_PLATFORMS, default="claude",
        help=_PLATFORM_HELP,
    )
    replay.set_defaults(func=cmd_replay)

    inst = sub.add_parser("install", help="Install hooks for a platform")
    inst.add_argument("platform", choices=VALID_PLATFORMS)
    inst.add_argument("--dry-run", action="store_true")
    inst.set_defaults(func=cmd_install)

    uninst = sub.add_parser("uninstall", help="Remove hooks from a platform")
    uninst.add_argument("platform", choices=VALID_PLATFORMS)
    uninst.add_argument("--dry-run", action="store_true")
    uninst.set_defaults(func=cmd_uninstall)

    stats = sub.add_parser("stats", help="Analyze hook activity logs")
    stats.add_argument("--log")
    stats.add_argument("--days", type=int)
    stats.add_argument("--json", action="store_true")
    stats.set_defaults(func=cmd_stats)

    test = sub.add_parser("test", help="Run self-test / smoke test")
    test.set_defaults(func=cmd_test)


def _add_config_parsers(sub: argparse._SubParsersAction) -> None:
    """Register config show/init/path subcommands."""
    cfg = sub.add_parser("config", help="Configuration management")
    cfg_sub = cfg.add_subparsers(dest="config_command")

    show = cfg_sub.add_parser("show", help="Show effective configuration")
    show.set_defaults(func=cmd_config_show)

    init = cfg_sub.add_parser("init", help="Create config from defaults")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_config_init)

    path = cfg_sub.add_parser("path", help="Print config file path")
    path.set_defaults(func=cmd_config_path)


def _add_lint_parsers(sub: argparse._SubParsersAction) -> None:
    """Register lint check/baseline/init/update subcommands."""
    lint = sub.add_parser("lint", help="Batch code quality analysis")
    lint_sub = lint.add_subparsers(dest="lint_command")

    lc = lint_sub.add_parser("check", help="Lint a project")
    lc.add_argument("path", nargs="?", default=".")
    lc.set_defaults(func=cmd_lint, lint_command="check")

    lb = lint_sub.add_parser("baseline", help="Generate baselines.json")
    lb.add_argument("path", nargs="?", default=".")
    lb.set_defaults(func=cmd_lint, lint_command="baseline")

    li = lint_sub.add_parser("init", help="Scaffold quality_gate.toml")
    li.add_argument("path", nargs="?", default=".")
    li.set_defaults(func=cmd_lint, lint_command="init")

    lu = lint_sub.add_parser("update", help="Add missing config keys")
    lu.add_argument("path", nargs="?", default=".")
    lu.add_argument("--dry-run", action="store_true")
    lu.set_defaults(func=cmd_lint, lint_command="update")

    lint.add_argument("path", nargs="?", default=".")
    lint.set_defaults(func=cmd_lint, lint_command="check")


# ---------------------------------------------------------------------------
# isx compat & search dispatch
# ---------------------------------------------------------------------------


def _run_search_func(args: argparse.Namespace) -> int:
    """Execute a search subcommand with IsxError handling."""
    from vibeforcer.search.config import IsxError

    try:
        return int(args.func(args) or 0)
    except IsxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _dispatch_search(args: argparse.Namespace) -> int:
    """Route ``vibeforcer search`` to the right handler."""
    search_cmd = getattr(args, "search_command", None)
    if search_cmd and hasattr(args, "func"):
        return _run_search_func(args)

    query_args = getattr(args, "query_args", None)
    if query_args:
        from vibeforcer.search.cli import cmd_search
        args.query = query_args
        args.func = cmd_search
        return _run_search_func(args)

    return 0


def _isx_main(argv: list[str] | None = None) -> int:
    """Entry point when invoked as ``isx``."""
    from vibeforcer.search.cli import build_search_parser

    parser = build_search_parser(subparsers=None)
    args = parser.parse_args(argv)

    search_cmd = getattr(args, "search_command", None)
    if search_cmd and hasattr(args, "func"):
        return _run_search_func(args)

    query_args = getattr(args, "query_args", None)
    if query_args:
        from vibeforcer.search.cli import cmd_search
        args.query = query_args
        args.func = cmd_search
        return _run_search_func(args)

    parser.print_help()
    return 0


def main(argv: list[str] | None = None) -> int:
    import os

    prog_name = os.path.basename(sys.argv[0]) if sys.argv else ""
    if prog_name == "isx":
        return _isx_main(argv)

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        return cmd_version(args)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "search":
        return _dispatch_search(args)

    if not hasattr(args, "func"):
        parser.parse_args([args.command, "--help"])
        return 0

    return args.func(args)


def safe_main(argv: list[str] | None = None) -> int:
    try:
        return main(argv)
    except KeyboardInterrupt:
        return EXIT_KEYBOARD_INTERRUPT


if __name__ == "__main__":
    raise SystemExit(safe_main())
