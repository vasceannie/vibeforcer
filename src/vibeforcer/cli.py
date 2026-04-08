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

    # -- version --
    version = subparsers.add_parser("version", help="Print version")
    version.set_defaults(func=cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        return cmd_version(args)

    if not args.command:
        parser.print_help()
        return 0

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
