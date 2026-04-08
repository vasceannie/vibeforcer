from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

VALID_PLATFORMS = ("claude", "codex", "opencode")


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
    """Core hook handler — reads stdin JSON, evaluates rules, writes stdout JSON."""
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
    from vibeforcer.config import is_path_skipped, is_repo_disabled, load_config

    target = Path(args.path).resolve()
    config = load_config()

    disabled = is_repo_disabled(target)
    skipped = is_path_skipped(target, config.skip_paths)

    status = "DISABLED" if (disabled or skipped) else "ACTIVE"
    info = {
        "path": str(target),
        "status": status,
        "repo_disabled": disabled,
        "path_skipped": skipped,
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
        days=args.days,
        as_json=args.json,
    )


def cmd_config_show(args: argparse.Namespace) -> int:
    """Show the effective configuration."""
    from vibeforcer.config import load_config, resolve_config_path

    config_path = resolve_config_path()
    config = load_config()

    print(f"# Config source: {config_path}")
    print(f"# Trace dir: {config.trace_dir}")
    print(f"# Root: {config.root}")
    print(f"# Rules: {len(config.enabled_rules)} toggles, {len(config.regex_rules)} regex rules")
    print(f"# Python AST: {'enabled' if config.python_ast_enabled else 'disabled'}")
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
    from vibeforcer.config import config_dir, resolve_config_path
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

    # Also create log directory
    log_dir = config_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "async").mkdir(exist_ok=True)
    print(f"Created: {log_dir}")

    # Copy prompt context if it doesn't exist
    ctx_dir = config_dir() / "prompt_context"
    if not ctx_dir.exists():
        ctx_dir.mkdir(parents=True, exist_ok=True)
        for name in ("organization.md", "repo.md"):
            src = resource_path("prompt_context") / name
            if src.exists():
                (ctx_dir / name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"Created: {ctx_dir}")

    return 0


def cmd_config_path(args: argparse.Namespace) -> int:
    """Print the resolved config file path."""
    from vibeforcer.config import resolve_config_path

    print(resolve_config_path())
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    """Run self-test / smoke test."""
    from vibeforcer.engine import evaluate_payload

    print("vibeforcer self-test")
    print("=" * 40)

    # Test 1: git --no-verify deny
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git commit --no-verify -m 'test'"},
        "cwd": "/tmp",
        "session_id": "self-test",
    }
    result = evaluate_payload(payload, platform="claude")
    deny_count = sum(1 for f in result.findings if f.decision == "deny")
    status = "PASS" if deny_count > 0 else "FAIL"
    print(f"  [{status}] git --no-verify → deny ({deny_count} finding(s))")

    # Test 2: sensitive path deny
    payload2 = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": "/home/user/.env", "content": "SECRET=x"},
        "cwd": "/tmp",
        "session_id": "self-test",
    }
    result2 = evaluate_payload(payload2, platform="claude")
    deny2 = sum(1 for f in result2.findings if f.decision == "deny")
    status2 = "PASS" if deny2 > 0 else "FAIL"
    print(f"  [{status2}] .env write → deny ({deny2} finding(s))")

    # Test 3: clean payload allows
    payload3 = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo hello"},
        "cwd": "/tmp",
        "session_id": "self-test",
    }
    result3 = evaluate_payload(payload3, platform="claude")
    deny3 = sum(1 for f in result3.findings if f.decision == "deny")
    status3 = "PASS" if deny3 == 0 else "FAIL"
    print(f"  [{status3}] echo hello → allow ({deny3} deny finding(s))")

    # Test 4: Codex adapter
    result4 = evaluate_payload(payload, platform="codex")
    deny4 = sum(1 for f in result4.findings if f.decision == "deny")
    status4 = "PASS" if deny4 > 0 else "FAIL"
    print(f"  [{status4}] codex adapter → deny ({deny4} finding(s))")

    # Test 5: OpenCode adapter
    oc_payload = {
        "hook_event_name": "tool.execute.before",
        "tool_name": "bash",
        "tool_input": {"command": "git commit --no-verify -m 'test'"},
        "cwd": "/tmp",
        "session_id": "self-test",
    }
    result5 = evaluate_payload(oc_payload, platform="opencode")
    deny5 = sum(1 for f in result5.findings if f.decision == "deny")
    status5 = "PASS" if deny5 > 0 else "FAIL"
    print(f"  [{status5}] opencode adapter → deny ({deny5} finding(s))")

    all_pass = all(s == "PASS" for s in [status, status2, status3, status4, status5])
    print()
    print(f"{'All tests passed.' if all_pass else 'SOME TESTS FAILED.'}")
    return 0 if all_pass else 1


def cmd_version(args: argparse.Namespace) -> int:
    """Print version."""
    from vibeforcer import __version__
    print(f"vibeforcer {__version__}")
    return 0


def cmd_lint(args: argparse.Namespace) -> int:
    """Run batch code quality analysis on a project.

    Absorbed from the standalone quality-gate tool.
    Supports: check, baseline, init, update
    """
    lint_command = getattr(args, "lint_command", None)
    if not lint_command:
        # Default to check if no subcommand given
        lint_command = "check"
        args.path = args.path if hasattr(args, "path") else "."

    root = Path(getattr(args, "path", ".") or ".").resolve()

    if lint_command == "check":
        return _lint_check(root)
    elif lint_command == "baseline":
        return _lint_baseline(root)
    elif lint_command == "init":
        return _lint_init(root)
    elif lint_command == "update":
        return _lint_update(root, dry_run=getattr(args, "dry_run", False))
    return 1


def _lint_check(root: Path) -> int:
    from vibeforcer.lint._config import load_config as load_qg_config, set_config as set_qg_config
    from vibeforcer.lint._config import QualityConfig
    from vibeforcer.lint._helpers import find_source_files, find_test_files, parse_files
    from vibeforcer.lint._baseline import Violation, load_baseline
    from vibeforcer.lint import __version__ as lint_version

    cfg = load_qg_config(root)
    set_qg_config(cfg)

    src_files = find_source_files()
    test_files = find_test_files()

    print(f"vibeforcer lint {lint_version}")
    print(f"  project: {cfg.project_root}")
    print(f"  src:     {cfg.src_root}  ({len(src_files)} files)")
    print(f"  tests:   {cfg.tests_root}  ({len(test_files)} files)")
    print()

    from vibeforcer.lint._collectors import run_all_collectors

    baseline = load_baseline()
    collectors = run_all_collectors(src_files, test_files)

    total_violations = 0
    total_new = 0
    total_fixed = 0
    _SUPPORTS_COLOR = hasattr(sys.stderr, "isatty") and sys.stderr.isatty()

    def _c(code, text): return f"\033[{code}m{text}\033[0m" if _SUPPORTS_COLOR else text

    for rule_name, violations in collectors:
        if not violations:
            continue
        totals = _tally_rule(
            rule_name, violations, baseline, _c,
        )
        total_violations += totals[0]
        total_new += totals[1]
        total_fixed += totals[2]

    print()
    if total_new == 0:
        print(_c("32", f"\u2713 No new violations ({total_violations} total, all baselined)"))
        if total_fixed:
            print(_c("33", f"  \u2139 {total_fixed} fixed \u2014 run `vibeforcer lint baseline` to lock that in"))
        return 0
    else:
        print(_c("31", f"\u2717 {total_new} new violation(s) introduced"))
        print(f"  {total_violations} total across all rules")
        return 1


def _lint_baseline(root: Path) -> int:
    from vibeforcer.lint._config import load_config as load_qg_config, set_config as set_qg_config
    from vibeforcer.lint._helpers import find_source_files, find_test_files
    from vibeforcer.lint._baseline import save_baseline, Violation
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
    print(f"\u2713 Baseline saved: {total} violation(s) across {len(all_violations)} rule(s)")
    print(f"  \u2192 {bp}")
    return 0


def _lint_init(root: Path) -> int:
    from vibeforcer.lint._config import QualityConfig
    root.mkdir(parents=True, exist_ok=True)
    dest = root / "quality_gate.toml"
    if dest.exists():
        print(f"Already exists: {dest}")
        print("  To add missing keys, run: vibeforcer lint update")
        return 1

    from vibeforcer.lint import __version__ as lint_version
    template = _DEFAULT_QG_TOML.format(version=lint_version)
    dest.write_text(template, encoding="utf-8")
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


_DEFAULT_QG_TOML = """\
# Quality Gate Configuration
# vibeforcer lint

[quality_gate]
version = "{version}"

[paths]
src = "src"
tests = "tests"
exclude_dirs = [".venv", "__pycache__", "node_modules", ".git"]
exclude_patterns = ["*_pb2.py", "*_pb2_grpc.py", "*_pb2.pyi"]

[thresholds]
max_complexity = 12
max_params = 4
max_method_lines = 50
max_line_length = 120
max_nesting_depth = 4
max_god_class_methods = 15
max_god_class_lines = 400
max_module_lines_soft = 350
max_module_lines_hard = 600
max_test_lines = 35
max_eager_test_calls = 7
feature_envy_threshold = 0.60
feature_envy_min_accesses = 6

[magic_values]
allowed_numbers = [0, 1, 2, 3, -1, 10, 100, 1000]
allowed_strings = ["", " ", "\n", "\t", "utf-8"]

[wrappers]
allowed = []

[logging]
logger_variable = "logger"
infrastructure_path = ""
disallowed_names = ["_log", "_logger", "log", "LOG"]

[type_safety]
ban_any = true
ban_type_suppressions = true

[exception_safety]
ban_broad_except_swallow = true
ban_silent_except = true
ban_silent_fallback = true

[test_smells]
max_consecutive_bare_asserts = 3
ban_conditional_assertions = true
ban_fixtures_outside_conftest = true
"""


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _add_platform_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--platform",
        choices=VALID_PLATFORMS,
        default="claude",
        help=f"Target platform. Choices: {', '.join(VALID_PLATFORMS)} (default: claude)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vibeforcer",
        description="Global CLI guardrails engine for AI coding agents",
    )
    parser.add_argument(
        "--version", action="store_true", help="Print version and exit"
    )
    subparsers = parser.add_subparsers(dest="command")

    # -- handle --
    handle = subparsers.add_parser(
        "handle",
        help="Read hook payload from stdin and emit platform-native JSON",
    )
    _add_platform_arg(handle)
    handle.set_defaults(func=cmd_handle)

    # -- handle-async --
    handle_async = subparsers.add_parser(
        "handle-async",
        help="Read hook payload from stdin and run async jobs",
    )
    handle_async.set_defaults(func=cmd_handle_async)

    # -- check --
    check = subparsers.add_parser(
        "check",
        help="Check if quality gate is active for a repo path",
    )
    check.add_argument(
        "path", nargs="?", default=".",
        help="Path to the repo root (default: current directory)",
    )
    check.set_defaults(func=cmd_check)

    # -- replay --
    replay = subparsers.add_parser("replay", help="Replay a saved payload")
    replay.add_argument(
        "--payload", required=True, help="Path to a JSON payload fixture"
    )
    replay.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    _add_platform_arg(replay)
    replay.set_defaults(func=cmd_replay)

    # -- install --
    install = subparsers.add_parser(
        "install",
        help="Install vibeforcer hooks into a platform (claude, codex, opencode)",
    )
    install.add_argument(
        "platform",
        choices=VALID_PLATFORMS,
        help="Platform to install hooks for",
    )
    install.add_argument("--dry-run", action="store_true", help="Show what would change")
    install.set_defaults(func=cmd_install)

    # -- uninstall --
    uninstall = subparsers.add_parser(
        "uninstall",
        help="Remove vibeforcer hooks from a platform",
    )
    uninstall.add_argument(
        "platform",
        choices=VALID_PLATFORMS,
        help="Platform to uninstall hooks from",
    )
    uninstall.add_argument("--dry-run", action="store_true", help="Show what would change")
    uninstall.set_defaults(func=cmd_uninstall)

    # -- stats --
    stats = subparsers.add_parser(
        "stats",
        help="Analyze hook activity logs",
    )
    stats.add_argument("--log", help="Path to results.jsonl (auto-detected if omitted)")
    stats.add_argument("--days", type=int, help="Only include last N days")
    stats.add_argument("--json", action="store_true", help="Output JSON instead of report")
    stats.set_defaults(func=cmd_stats)

    # -- config --
    config_parser = subparsers.add_parser(
        "config",
        help="Configuration management",
    )
    config_sub = config_parser.add_subparsers(dest="config_command")

    config_show = config_sub.add_parser("show", help="Show effective configuration")
    config_show.set_defaults(func=cmd_config_show)

    config_init = config_sub.add_parser("init", help="Create config from defaults")
    config_init.add_argument("--force", action="store_true", help="Overwrite existing config")
    config_init.set_defaults(func=cmd_config_init)

    config_path = config_sub.add_parser("path", help="Print config file path")
    config_path.set_defaults(func=cmd_config_path)

    # -- test --
    test = subparsers.add_parser("test", help="Run self-test / smoke test")
    test.set_defaults(func=cmd_test)

    # -- lint --
    lint_parser = subparsers.add_parser(
        "lint",
        help="Batch code quality analysis (check, baseline, init, update)",
    )
    lint_sub = lint_parser.add_subparsers(dest="lint_command")

    lint_check = lint_sub.add_parser("check", help="Lint a project for violations")
    lint_check.add_argument("path", nargs="?", default=".", help="Project root (default: .)")
    lint_check.set_defaults(func=cmd_lint, lint_command="check")

    lint_baseline = lint_sub.add_parser("baseline", help="Generate/update baselines.json")
    lint_baseline.add_argument("path", nargs="?", default=".", help="Project root (default: .)")
    lint_baseline.set_defaults(func=cmd_lint, lint_command="baseline")

    lint_init = lint_sub.add_parser("init", help="Scaffold quality_gate.toml")
    lint_init.add_argument("path", nargs="?", default=".", help="Target dir (default: .)")
    lint_init.set_defaults(func=cmd_lint, lint_command="init")

    lint_update = lint_sub.add_parser("update", help="Add missing config keys")
    lint_update.add_argument("path", nargs="?", default=".", help="Project root (default: .)")
    lint_update.add_argument("--dry-run", action="store_true")
    lint_update.set_defaults(func=cmd_lint, lint_command="update")

    # Default lint (no subcommand) defaults to check
    lint_parser.add_argument("path", nargs="?", default=".", help="Project root (default: .)")
    lint_parser.set_defaults(func=cmd_lint, lint_command="check")

    # -- search (isx integration) --
    from vibeforcer.search.cli import build_search_parser, cmd_search as _cmd_search
    build_search_parser(subparsers)

    # -- version --
    version = subparsers.add_parser("version", help="Print version")
    version.set_defaults(func=cmd_version)

    return parser


# ---------------------------------------------------------------------------
# isx compat & search dispatch
# ---------------------------------------------------------------------------


def _run_search_func(args: argparse.Namespace) -> int:
    """Execute a search subcommand handler with IsxError handling."""
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

    # Detect invocation name for isx compatibility
    prog_name = os.path.basename(sys.argv[0]) if sys.argv else "vibeforcer"
    is_isx = prog_name in ("isx",)

    if is_isx:
        # When invoked as `isx`, route directly to search subcommands
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
        # Subcommand group without sub-subcommand (e.g. `vibeforcer config`)
        parser.parse_args([args.command, "--help"])
        return 0

    return args.func(args)


def safe_main(argv: list[str] | None = None) -> int:
    try:
        return main(argv)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(safe_main())
