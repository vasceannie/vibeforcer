from __future__ import annotations

import json as _json
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, cast

from typing_extensions import override

from vibeforcer._types import bool_value, object_dict, string_value
from vibeforcer.constants import SAFE_READ_SHELL_VERBS
from vibeforcer.models import RuleFinding, Severity
from vibeforcer.rules.base import Rule, is_rule_enabled

if TYPE_CHECKING:
    from vibeforcer.context import HookContext

# 32 KB tail buffer — large enough to capture the last assistant turn
# even when preceded by a large tool response (e.g., a full file read).
_TAIL_BYTES = 32_768

_VIBEFORCER_REPO_SUFFIX = "/claude/vibeforcer"


def _resolve_candidate_path(path_str: str, cwd: Path | None = None) -> Path:
    """Resolve a candidate path relative to the hook cwd when needed."""
    path = Path(path_str).expanduser()
    if not path.is_absolute() and cwd is not None:
        path = cwd / path
    return path.resolve()


def _git_output(
    args: list[str], cwd: Path | None = None, timeout: int = 3
) -> str | None:
    """Run a git command and return stripped stdout on success."""
    try:
        result = subprocess.run(
            args,
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    output = result.stdout.strip()
    return output or None


def _git_repo_root(path_str: str, cwd: Path | None = None) -> Path | None:
    """Return the git toplevel containing *path_str*, if any."""
    resolved = _resolve_candidate_path(path_str, cwd)
    base = resolved if resolved.is_dir() else resolved.parent
    repo_root = _git_output(
        ["git", "-C", str(base), "rev-parse", "--show-toplevel"], timeout=3
    )
    return Path(repo_root) if repo_root else None


def _normalize_git_remote(url: str) -> str:
    """Normalize a git remote for comparison."""
    raw = url.strip().rstrip("/")
    if raw.endswith(".git"):
        raw = raw[:-4]

    ssh_match = re.match(r"^git@([^:]+):(.+)$", raw)
    if ssh_match:
        host = ssh_match.group(1).lower()
        path = ssh_match.group(2).strip("/")
        return f"{host}/{path}"

    proto_match = re.match(r"^[a-z]+://([^/]+)/(.+)$", raw, re.IGNORECASE)
    if proto_match:
        host = proto_match.group(1).lower()
        path = proto_match.group(2).strip("/")
        return f"{host}/{path}"

    return raw.lower()


def _is_worktree(path_str: str, cwd: Path | None = None) -> bool:
    """Check if a path is inside a git worktree (not the main working tree).

    A worktree has a .git *file* (not directory) containing "gitdir: ..." pointing
    back to the main repo's .git/worktrees/<name>/ directory.
    """
    repo_root = _git_repo_root(path_str, cwd)
    if repo_root is None:
        return False
    git_entry = repo_root / ".git"
    # In a worktree, .git is a file (not a directory) containing "gitdir: ..."
    return git_entry.is_file()


def _is_vibeforcer_repo(path_str: str, cwd: Path | None = None) -> bool:
    """Return True when the target path belongs to the vibeforcer repo."""
    repo_root = _git_repo_root(path_str, cwd)
    if repo_root is None:
        return False
    remote = _git_output(
        ["git", "-C", str(repo_root), "remote", "get-url", "origin"], timeout=5
    )
    if remote is None:
        return False
    normalized = _normalize_git_remote(remote)
    return normalized.endswith(_VIBEFORCER_REPO_SUFFIX)


def _default_branch_name(repo_root: Path) -> str | None:
    """Infer the repository default branch name."""
    remote_head = _git_output(
        ["git", "-C", str(repo_root), "symbolic-ref", "refs/remotes/origin/HEAD"],
        timeout=5,
    )
    if remote_head and remote_head.startswith("refs/remotes/origin/"):
        return remote_head.rsplit("/", 1)[-1]

    local_heads = _git_output(
        [
            "git",
            "-C",
            str(repo_root),
            "for-each-ref",
            "--format=%(refname:short)",
            "refs/heads",
        ],
        timeout=5,
    )
    if not local_heads:
        return None

    branches = {branch.strip() for branch in local_heads.splitlines() if branch.strip()}
    if "main" in branches:
        return "main"
    if "master" in branches:
        return "master"
    if len(branches) == 1:
        return next(iter(branches))
    return None


def _is_non_default_branch(path_str: str, cwd: Path | None = None) -> bool:
    """Return True when the target path is on a branch other than the default."""
    repo_root = _git_repo_root(path_str, cwd)
    if repo_root is None:
        return False
    current_branch = _git_output(
        ["git", "-C", str(repo_root), "branch", "--show-current"], timeout=5
    )
    default_branch = _default_branch_name(repo_root)
    return bool(current_branch and default_branch and current_branch != default_branch)


def _command_has_word(command: str, word: str) -> bool:
    """Check if *word* appears as a standalone token in *command*."""
    escaped = re.escape(word)
    pattern = rf"(^|\s){escaped}(\s|$)"
    return bool(re.search(pattern, command, re.IGNORECASE))


def _is_safe_read_shell(command: str) -> bool:
    lowered = command.lower()
    if "sed -i" in lowered or "tee " in lowered or ">>" in lowered or " > " in lowered:
        return False
    return any(_command_has_word(lowered, verb) for verb in SAFE_READ_SHELL_VERBS)


def _tail_read(file_path: Path, num_bytes: int) -> str:
    """Read the last *num_bytes* of a file as UTF-8 text."""
    with open(file_path, "rb") as fh:
        try:
            _ = fh.seek(-num_bytes, 2)
        except OSError:
            _ = fh.seek(0)
        return fh.read().decode("utf-8", errors="replace")


def _extract_content_text(msg: object) -> str:
    """Extract text from an assistant message content field."""
    if isinstance(msg, str):
        return msg
    if isinstance(msg, list):
        blocks = cast(list[object], msg)
        extracted: list[str] = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            typed_block = cast(dict[str, object], block)
            raw_type = typed_block.get("type")
            if not isinstance(raw_type, str) or raw_type != "text":
                continue
            raw_text = typed_block.get("text")
            if isinstance(raw_text, str):
                extracted.append(raw_text)
        return " ".join(extracted)
    return ""


def _last_assistant_response(transcript_path: str) -> str:
    """Read the last assistant turn from a Claude Code JSONL transcript."""
    tp = Path(transcript_path)
    if not tp.exists():
        return ""
    try:
        tail = _tail_read(tp, _TAIL_BYTES)
    except OSError:
        return ""
    for line in reversed(tail.strip().splitlines()[-20:]):
        try:
            raw_entry: object = cast(object, _json.loads(line))
        except _json.JSONDecodeError:
            continue
        if not isinstance(raw_entry, dict):
            continue
        entry = cast(dict[str, object], raw_entry)
        raw_type = entry.get("type")
        raw_role_field = entry.get("role")
        raw_role: object = raw_type if raw_type is not None else raw_role_field
        if not isinstance(raw_role, str) or raw_role != "assistant":
            continue
        raw_msg_container = entry.get("message")
        if not isinstance(raw_msg_container, dict):
            continue
        msg_container = cast(dict[str, object], raw_msg_container)
        msg: object = msg_container.get("content", "")
        return _extract_content_text(msg)
    return ""


def _get_stop_response(ctx: HookContext) -> str:
    """Extract the assistant response from a Stop/SubagentStop event."""
    transcript_path = ctx.payload.payload.get("transcript_path", "")
    if isinstance(transcript_path, str) and transcript_path:
        response = _last_assistant_response(transcript_path)
        if response:
            return response
    fallback = ctx.payload.payload.get("stop_response", "")
    return str(fallback) if fallback else ""


_PREEXISTING_PHRASES = (
    "pre-existing",
    "preexisting",
    "already existed",
    "was already",
    "existed before",
    "not introduced by",
    "outside the scope",
    "out of scope",
    "not my change",
)


class IgnorePreexistingRule(Rule):
    """Block responses that dismiss issues as pre-existing."""

    rule_id: str = "STOP-001"
    title: str = "Block ignoring pre-existing issues"
    events: tuple[str, ...] = ("Stop", "SubagentStop")

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        response = _get_stop_response(ctx)
        if not response:
            return []
        lowered = response.lower()
        for phrase in _PREEXISTING_PHRASES:
            if phrase in lowered:
                return [
                    RuleFinding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.HIGH,
                        decision="block",
                        message=(
                            "Do not dismiss issues as pre-existing. "
                            "If you found a problem, fix it or "
                            "explicitly flag it for follow-up."
                        ),
                        metadata={"matched_phrase": phrase},
                    )
                ]
        return []


_QUALITY_REMINDER = (
    "Before stopping, verify tests pass and quality gates are clean. "
    "Run `vibeforcer lint check` (or your project-specific quality "
    "command) before finishing this task."
)


class RequireQualityCheckRule(Rule):
    """Remind to run quality gate before stopping."""

    rule_id: str = "STOP-002"
    title: str = "Require quality check reminder"
    events: tuple[str, ...] = ("Stop", "SubagentStop")

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.LOW,
                additional_context=_QUALITY_REMINDER,
            )
        ]


class WarnLargeFileRule(Rule):
    """Warn when editing files that are suspiciously large."""

    rule_id: str = "WARN-LARGE-001"
    title: str = "Warn on large file"
    events: tuple[str, ...] = ("PreToolUse", "PermissionRequest")
    MAX_CHARS: int = 50_000

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        findings: list[RuleFinding] = []
        for target in ctx.content_targets:
            char_count = len(target.content)
            if char_count > self.MAX_CHARS:
                findings.append(
                    RuleFinding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        additional_context=(
                            f"WARNING: File {target.path} content "
                            f"is {char_count:,} characters. Consider "
                            f"splitting into smaller modules."
                        ),
                        metadata={"path": target.path, "chars": char_count},
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# Hook infrastructure protection
# ---------------------------------------------------------------------------

_READ_TOOLS = frozenset({"read", "grep", "glob"})

_INFRA_FRAGMENTS = (
    "hook-layer/config.json",
    "hook_layer/",
    "vibeforcer/",
    ".claude/hooks/",
)

_CONFIG_FRAGMENTS = (
    "config/vibeforcer/config.json",
    "config/vibeforcer/rules",
)


def _is_safe_bash_for_path(ctx: HookContext) -> bool:
    """Return True if the bash command is a safe read-only operation."""
    if not ctx.tool_name or ctx.tool_name.lower() != "bash":
        return False
    return _is_safe_read_shell(ctx.bash_command.lower())


def _is_modifying_tool(ctx: HookContext) -> bool:
    """Return True if the tool can modify files (bash or edit-like)."""
    if ctx.tool_name and ctx.tool_name.lower() == "bash":
        return True
    from vibeforcer.util.payloads import is_edit_like_tool

    return is_edit_like_tool(ctx.tool_name)


def _infra_deny(path_value: str, fragment: str, kind: str) -> list[RuleFinding]:
    label = "config" if kind == "config" else "infrastructure"
    return [
        RuleFinding(
            rule_id="GLOBAL-BUILTIN-HOOK-INFRA-EXEC",
            title="Hook layer execution protection",
            severity=Severity.CRITICAL,
            decision="deny",
            message=(
                f"Modifying the hook layer {label} "
                f"({path_value}) is blocked. "
                f"These files are protected."
            ),
            metadata={"path": path_value, "fragment": fragment, "kind": kind},
        )
    ]


def _check_config_path(path_value: str, ctx: HookContext) -> list[RuleFinding] | None:
    """Check config fragments — always protected, no worktree exception."""
    lowered = path_value.lower()
    for cfrag in _CONFIG_FRAGMENTS:
        if cfrag not in lowered:
            continue
        if _is_safe_bash_for_path(ctx):
            return []
        if _is_modifying_tool(ctx):
            return _infra_deny(path_value, cfrag, "config")
    return None


def _check_infra_path(path_value: str, ctx: HookContext) -> list[RuleFinding] | None:
    """Check infra fragments with a narrow vibeforcer worktree exception."""
    lowered = path_value.lower()
    for frag in _INFRA_FRAGMENTS:
        if frag not in lowered:
            continue
        if (
            _is_worktree(path_value, ctx.cwd)
            and _is_vibeforcer_repo(path_value, ctx.cwd)
            and _is_non_default_branch(path_value, ctx.cwd)
        ):
            return []
        if _is_safe_bash_for_path(ctx):
            return []
        if _is_modifying_tool(ctx):
            return _infra_deny(path_value, frag, "infra")
    return None


class HookInfraExecProtectionRule(Rule):
    """Block modification of hook layer infrastructure and config."""

    rule_id: str = "GLOBAL-BUILTIN-HOOK-INFRA-EXEC"
    title: str = "Hook layer execution protection"
    events: tuple[str, ...] = ("PreToolUse", "PermissionRequest")

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        if ctx.tool_name and ctx.tool_name.lower() in _READ_TOOLS:
            return []
        for path_value in ctx.candidate_paths:
            cfg = _check_config_path(path_value, ctx)
            if cfg is not None:
                return cfg
            infra = _check_infra_path(path_value, ctx)
            if infra is not None:
                return infra
        return []


# ---------------------------------------------------------------------------
# Rulebook security
# ---------------------------------------------------------------------------

import re as _re

_SECURITY_PATTERNS = tuple(
    _re.compile(p, _re.IGNORECASE)
    for p in (
        "bypass_permissions",
        "allowManagedHooksOnly",
        r"disable.*guard",
        r"disable.*rule",
        r"skip.*validation",
    )
)

_SECURITY_EXCLUDED = (
    "hook_layer/",
    "vibeforcer/",
    "hook-layer/",
    ".claude/hooks/",
    "test_",
    "fixture",
)


class RulebookSecurityRule(Rule):
    """Prevent disabling or weakening security guardrails."""

    rule_id: str = "BUILTIN-RULEBOOK-SECURITY"
    title: str = "Rulebook security guardrails"
    events: tuple[str, ...] = ("PreToolUse", "PermissionRequest")

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        for target in ctx.content_targets:
            lowered = target.path.lower()
            if any(f in lowered for f in _SECURITY_EXCLUDED):
                continue
            for pat in _SECURITY_PATTERNS:
                if pat.search(target.content):
                    return [
                        RuleFinding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=Severity.HIGH,
                            decision="deny",
                            message=(
                                "Modifying security guardrail "
                                f"settings is blocked in {target.path}. "
                                "Do not disable rules or "
                                "bypass permissions."
                            ),
                            metadata={
                                "path": target.path,
                                "pattern": pat.pattern,
                            },
                        )
                    ]
        return []


# ---------------------------------------------------------------------------
# Session start context
# ---------------------------------------------------------------------------

_GIT_COMMANDS: list[tuple[list[str], str]] = [
    (["git", "log", "--oneline", "-10"], "## Recent commits\n```\n{output}\n```"),
    (["git", "status", "--short"], "## Working tree status\n```\n{output}\n```"),
    (["git", "branch", "--show-current"], "Current branch: `{output}`"),
]


def _collect_git_context(cwd: str) -> list[str]:
    """Run git commands and collect non-empty output fragments."""
    fragments: list[str] = []
    for cmd, template in _GIT_COMMANDS:
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        output = result.stdout.strip()
        if result.returncode == 0 and output:
            fragments.append(template.format(output=output))
    return fragments


class SessionStartContextRule(Rule):
    """Inject project context on session start."""

    rule_id: str = "SESSION-001"
    title: str = "Session start context injection"
    events: tuple[str, ...] = ("SessionStart",)

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        fragments = _collect_git_context(str(ctx.cwd))
        if not fragments:
            return []
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.LOW,
                additional_context=(
                    "# Project Context (auto-injected)\n\n" + "\n\n".join(fragments)
                ),
            )
        ]


# ---------------------------------------------------------------------------
# Config change guard
# ---------------------------------------------------------------------------

_CONFIG_BLOCKED_SOURCES = (
    "project_settings",
    "local_settings",
    "user_settings",
)


class ConfigChangeGuardRule(Rule):
    """Block config changes that weaken security."""

    rule_id: str = "CONFIG-001"
    title: str = "Config change guard"
    events: tuple[str, ...] = ("ConfigChange",)

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        source = string_value(ctx.payload.payload.get("source")) or ""
        if source not in _CONFIG_BLOCKED_SOURCES:
            return []
        changes = object_dict(ctx.payload.payload.get("changes"))
        if not changes:
            return []
        if bool_value(changes.get("disableAllHooks")) is True:
            return [
                RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.CRITICAL,
                    decision="block",
                    message="Disabling all hooks is blocked.",
                    metadata={"source": source},
                )
            ]
        if "hooks" in changes:
            return [
                RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.HIGH,
                    decision="block",
                    message="Modifying hook config is blocked.",
                    metadata={"source": source},
                )
            ]
        return []
