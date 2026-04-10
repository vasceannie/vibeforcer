from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

from vibeforcer._types import ObjectDict, ObjectMapping, object_dict
from vibeforcer.constants import SELFTEST_SEPARATOR_WIDTH
from vibeforcer.models import EngineResult

VALID_PLATFORMS = ("claude", "codex", "opencode")
PlatformName = str
PLATFORM_HELP = (
    f"Target platform. Choices: {', '.join(VALID_PLATFORMS)} (default: claude)"
)


def _load_stdin_json() -> ObjectDict:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    parsed = cast(object, json.loads(raw))
    return object_dict(parsed)


def _string_arg(args: argparse.Namespace, name: str, default: str = "") -> str:
    value = getattr(args, name, default)
    return value if isinstance(value, str) else default


def _bool_arg(args: argparse.Namespace, name: str, default: bool = False) -> bool:
    value = getattr(args, name, default)
    return value if isinstance(value, bool) else default


def _int_arg(args: argparse.Namespace, name: str) -> int | None:
    value = getattr(args, name, None)
    return value if isinstance(value, int) else None


def _dump_output(output: ObjectMapping | None) -> int:
    if output:
        _ = sys.stdout.write(json.dumps(output, separators=(",", ":")) + "\n")
    return 0


def cmd_handle(args: argparse.Namespace) -> int:
    from vibeforcer.engine import evaluate_payload

    payload = _load_stdin_json()
    if not payload:
        return 0
    platform = _string_arg(args, "platform", "claude")
    result = evaluate_payload(payload, platform=platform)
    return _dump_output(result.output)


def cmd_handle_async(_args: argparse.Namespace) -> int:
    from vibeforcer.async_jobs import run_async_jobs

    payload = _load_stdin_json()
    summary, _errors = run_async_jobs(payload)
    if summary:
        _ = sys.stdout.write(summary + "\n")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    from vibeforcer.config import is_path_skipped, is_repo_disabled, load_config

    target = Path(_string_arg(args, "path", ".")).resolve()
    config = load_config()
    disabled = is_repo_disabled(target)
    skipped = is_path_skipped(target, config.skip_paths)
    status = "DISABLED" if (disabled or skipped) else "ACTIVE"
    print(
        json.dumps(
            {
                "path": str(target),
                "status": status,
                "repo_disabled": disabled,
                "path_skipped": skipped,
                "skip_paths": config.skip_paths,
            },
            indent=2,
        )
    )
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    from vibeforcer.engine import evaluate_payload

    payload_path = Path(_string_arg(args, "payload")).resolve()
    parsed = cast(object, json.loads(payload_path.read_text(encoding="utf-8")))
    payload = object_dict(parsed)
    platform = _string_arg(args, "platform", "claude")
    result = evaluate_payload(payload, platform=platform)
    if _bool_arg(args, "pretty"):
        print(json.dumps(result.output, indent=2))
    else:
        print(json.dumps(result.output, separators=(",", ":")))
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    from vibeforcer.installer import install_platform

    return install_platform(
        _string_arg(args, "platform"),
        dry_run=_bool_arg(args, "dry_run"),
    )


def cmd_uninstall(args: argparse.Namespace) -> int:
    from vibeforcer.installer import uninstall_platform

    return uninstall_platform(
        _string_arg(args, "platform"),
        dry_run=_bool_arg(args, "dry_run"),
    )


def cmd_stats(args: argparse.Namespace) -> int:
    from vibeforcer.stats import run_stats

    return run_stats(
        log_path=_string_arg(args, "log") or None,
        days=_int_arg(args, "days"),
        as_json=_bool_arg(args, "json"),
    )


def cmd_config_show(_args: argparse.Namespace) -> int:
    from vibeforcer.config import load_config, resolve_config_path

    config_path = resolve_config_path()
    config = load_config()
    print(f"# Config source: {config_path}")
    print(f"# Trace dir: {config.trace_dir}")
    print(f"# Root: {config.root}")
    rules_msg = (
        f"{len(config.enabled_rules)} toggles, {len(config.regex_rules)} regex rules"
    )
    print(f"# Rules: {rules_msg}")
    print(f"# Python AST: {'enabled' if config.python_ast_enabled else 'disabled'}")
    print()
    print(
        json.dumps(
            {
                "config_path": str(config_path),
                "root": str(config.root),
                "trace_dir": str(config.trace_dir),
                "enabled_rules_count": len(config.enabled_rules),
                "regex_rules_count": len(config.regex_rules),
                "python_ast_enabled": config.python_ast_enabled,
                "protected_paths": config.protected_paths,
                "skip_paths": config.skip_paths,
            },
            indent=2,
        )
    )
    return 0


def _copy_prompt_context(base_dir: Path, resource_path: Callable[[str], Path]) -> None:
    ctx_dir = base_dir / "prompt_context"
    if ctx_dir.exists():
        return
    ctx_dir.mkdir(parents=True, exist_ok=True)
    for name in ("organization.md", "repo.md"):
        src = resource_path("prompt_context") / name
        if src.exists():
            _ = (ctx_dir / name).write_text(
                src.read_text(encoding="utf-8"), encoding="utf-8"
            )
    print(f"Created: {ctx_dir}")


def cmd_config_init(args: argparse.Namespace) -> int:
    from vibeforcer.config import config_dir
    from vibeforcer.resources import resource_path

    target = config_dir() / "config.json"
    if target.exists() and not _bool_arg(args, "force"):
        print(f"Config already exists: {target}")
        print("Use --force to overwrite.")
        return 1

    defaults_path = resource_path("defaults.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    _ = target.write_text(defaults_path.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Created: {target}")

    log_dir = config_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "async").mkdir(exist_ok=True)
    print(f"Created: {log_dir}")
    _copy_prompt_context(config_dir(), resource_path)
    return 0


def cmd_config_path(_args: argparse.Namespace) -> int:
    from vibeforcer.config import resolve_config_path

    print(resolve_config_path())
    return 0


def _run_one_test(
    evaluate_payload: Callable[[Mapping[str, object], PlatformName], EngineResult],
    case: tuple[str, str, str, ObjectDict, PlatformName, bool],
) -> str:
    label, event, tool, tool_input, platform, expect_deny = case
    payload = {
        "hook_event_name": event,
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": "/tmp",
        "session_id": "self-test",
    }
    result = evaluate_payload(payload, platform)
    deny_count = sum(1 for f in result.findings if f.decision == "deny")
    passed = (deny_count > 0) if bool(expect_deny) else (deny_count == 0)
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {label} ({deny_count} finding(s))")
    return status


def cmd_test(_args: argparse.Namespace) -> int:
    from vibeforcer.engine import evaluate_payload

    print("vibeforcer self-test")
    print("=" * SELFTEST_SEPARATOR_WIDTH)
    env_path = str(Path.home() / ".env")
    noverify: ObjectDict = {"command": "git commit --no-verify -m 'test'"}
    cases: list[tuple[str, str, str, ObjectDict, PlatformName, bool]] = [
        ("git --no-verify → deny", "PreToolUse", "Bash", noverify, "claude", True),
        (
            ".env write → deny",
            "PreToolUse",
            "Write",
            {"file_path": env_path, "content": "SECRET=x"},
            "claude",
            True,
        ),
        (
            "echo hello → allow",
            "PreToolUse",
            "Bash",
            {"command": "echo hello"},
            "claude",
            False,
        ),
        ("codex adapter → deny", "PreToolUse", "Bash", noverify, "codex", True),
        (
            "opencode adapter → deny",
            "tool.execute.before",
            "bash",
            noverify,
            "opencode",
            True,
        ),
    ]
    statuses = [_run_one_test(evaluate_payload, case) for case in cases]
    all_pass = all(status == "PASS" for status in statuses)
    print()
    print("All tests passed." if all_pass else "SOME TESTS FAILED.")
    return 0 if all_pass else 1


def cmd_version(_args: argparse.Namespace) -> int:
    from vibeforcer import __version__

    print(f"vibeforcer {__version__}")
    return 0
