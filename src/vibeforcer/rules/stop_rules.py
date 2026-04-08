from __future__ import annotations

import subprocess
from pathlib import Path

from vibeforcer.models import RuleFinding, Severity
from vibeforcer.rules.base import Rule


def _is_worktree(path_str: str) -> bool:
    """Check if a path is inside a git worktree (not the main working tree).

    A worktree has a .git *file* (not directory) containing "gitdir: ..." pointing
    back to the main repo's .git/worktrees/<name>/ directory.
    """
    try:
        p = Path(path_str).resolve()
        # Walk up to find the git toplevel
        result = subprocess.run(
            ["git", "-C", str(p) if p.is_dir() else str(p.parent), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode != 0:
            return False
        toplevel = Path(result.stdout.strip())
        git_entry = toplevel / ".git"
        # In a worktree, .git is a file (not a directory) containing "gitdir: ..."
        return git_entry.is_file()
    except (OSError, subprocess.TimeoutExpired):
        return False


class IgnorePreexistingRule(Rule):
    """Block responses that dismiss issues as pre-existing."""
    rule_id = "STOP-001"
    title = "Block ignoring pre-existing issues"
    events = ("Stop", "SubagentStop")

    PHRASES = (
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

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        enabled = ctx.config.enabled_rules.get(self.rule_id)
        if enabled is not None and not enabled:
            return []
        # The Stop event does NOT include the model response text.
        # Per Claude Code docs, we must read transcript_path to inspect
        # the last assistant turn. Fall back to stop_response for tests.
        response = ""
        transcript_path = ctx.payload.payload.get("transcript_path", "")
        if transcript_path:
            import json as _json
            from pathlib import Path as _Path
            tp = _Path(transcript_path)
            if tp.exists():
                try:
                    # Tail-read: only read last 8KB instead of entire transcript
                    _TAIL_BYTES = 8192
                    with open(tp, "rb") as fh:
                        try:
                            fh.seek(-_TAIL_BYTES, 2)
                        except OSError:
                            fh.seek(0)
                        tail = fh.read().decode("utf-8", errors="replace")
                    lines = tail.strip().splitlines()
                    for line in reversed(lines[-20:]):
                        try:
                            entry = _json.loads(line)
                        except _json.JSONDecodeError:
                            continue
                        if entry.get("type") == "assistant" or entry.get("role") == "assistant":
                            msg = entry.get("message", {}).get("content", "")
                            if isinstance(msg, list):
                                response = " ".join(
                                    block.get("text", "")
                                    for block in msg
                                    if isinstance(block, dict) and block.get("type") == "text"
                                )
                            elif isinstance(msg, str):
                                response = msg
                            break
                except OSError:
                    pass
        # Fallback for test fixtures that pass stop_response directly
        if not response:
            response = ctx.payload.payload.get("stop_response", "")
            if not isinstance(response, str):
                response = str(response)
        if not response:
            return []
        lowered = response.lower()
        for phrase in self.PHRASES:
            if phrase in lowered:
                return [
                    RuleFinding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.HIGH,
                        decision="block",
                        message="Do not dismiss issues as pre-existing. If you found a problem, fix it or explicitly flag it for follow-up.",
                        metadata={"matched_phrase": phrase},
                    )
                ]
        return []


class RequireMakeQualityRule(Rule):
    """Remind to run quality gate before stopping."""
    rule_id = "STOP-002"
    title = "Require make quality reminder"
    events = ("Stop", "SubagentStop")

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        enabled = ctx.config.enabled_rules.get(self.rule_id)
        if enabled is not None and not enabled:
            return []
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.LOW,
                additional_context="Before stopping: verify all tests pass and quality gates are clean. Run `make quality` or the project-specific quality command if available.",
            )
        ]


class WarnLargeFileRule(Rule):
    """Warn when editing files that are suspiciously large."""
    rule_id = "WARN-LARGE-001"
    title = "Warn on large file"
    events = ("PreToolUse", "PermissionRequest")

    MAX_CHARS = 50000

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        enabled = ctx.config.enabled_rules.get(self.rule_id)
        if enabled is not None and not enabled:
            return []
        findings = []
        for target in ctx.content_targets:
            if len(target.content) > self.MAX_CHARS:
                findings.append(
                    RuleFinding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        additional_context=f"WARNING: File {target.path} content is {len(target.content):,} characters. Consider splitting into smaller modules.",
                        metadata={"path": target.path, "chars": len(target.content)},
                    )
                )
        return findings


class HookInfraExecProtectionRule(Rule):
    """Block modification of the hook layer infrastructure and config.

    Protects installed vibeforcer paths and its XDG config directory from
    agent-driven edits. The protection is skipped when the target path is
    inside a git worktree — this allows developing vibeforcer in a worktree
    of its source repo without the hooks fighting back.
    """
    rule_id = "GLOBAL-BUILTIN-HOOK-INFRA-EXEC"
    title = "Hook layer execution protection"
    events = ("PreToolUse", "PermissionRequest")

    PROTECTED_FRAGMENTS = (
        "hook-layer/config.json",
        "hook_layer/",
        "vibeforcer/",
        ".claude/hooks/",
    )

    # XDG config paths that should be protected regardless of worktree status
    CONFIG_FRAGMENTS = (
        "config/vibeforcer/config.json",
        "config/vibeforcer/rules",
    )

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        enabled = ctx.config.enabled_rules.get(self.rule_id)
        if enabled is not None and not enabled:
            return []
        if ctx.tool_name and ctx.tool_name.lower() in ("read", "grep", "glob"):
            return []
        for path_value in ctx.candidate_paths:
            lowered = path_value.lower()

            # Check config fragments — always protected (no worktree exception)
            for cfrag in self.CONFIG_FRAGMENTS:
                if cfrag in lowered:
                    if ctx.tool_name and ctx.tool_name.lower() == "bash":
                        cmd = ctx.bash_command.lower()
                        from vibeforcer.rules.common import _is_safe_read_shell
                        if _is_safe_read_shell(cmd):
                            return []
                        return self._deny(path_value, cfrag, "config")
                    from vibeforcer.util.payloads import is_edit_like_tool
                    if is_edit_like_tool(ctx.tool_name):
                        return self._deny(path_value, cfrag, "config")

            # Check source/infra fragments — skip if inside a worktree
            for fragment in self.PROTECTED_FRAGMENTS:
                if fragment in lowered:
                    # Worktree exception: developing in a worktree is allowed
                    if _is_worktree(path_value):
                        return []

                    if ctx.tool_name and ctx.tool_name.lower() == "bash":
                        cmd = ctx.bash_command.lower()
                        from vibeforcer.rules.common import _is_safe_read_shell
                        if _is_safe_read_shell(cmd):
                            return []
                        return self._deny(path_value, fragment, "infra")
                    from vibeforcer.util.payloads import is_edit_like_tool
                    if is_edit_like_tool(ctx.tool_name):
                        return self._deny(path_value, fragment, "infra")
        return []

    @staticmethod
    def _deny(path_value: str, fragment: str, kind: str) -> list[RuleFinding]:
        label = "config" if kind == "config" else "infrastructure"
        return [
            RuleFinding(
                rule_id="GLOBAL-BUILTIN-HOOK-INFRA-EXEC",
                title="Hook layer execution protection",
                severity=Severity.CRITICAL,
                decision="deny",
                message=f"Modifying the hook layer {label} ({path_value}) is blocked. These files are protected.",
                metadata={"path": path_value, "fragment": fragment, "kind": kind},
            )
        ]


class RulebookSecurityRule(Rule):
    """Prevent disabling or weakening security guardrails."""
    rule_id = "BUILTIN-RULEBOOK-SECURITY"
    title = "Rulebook security guardrails"
    events = ("PreToolUse", "PermissionRequest")

    SECURITY_PATTERNS = (
        "bypass_permissions",
        "allowManagedHooksOnly",
        "disable.*guard",
        "disable.*rule",
        "skip.*validation",
    )

    # Paths that legitimately reference security config keys
    EXCLUDED_PATH_FRAGMENTS = (
        "hook_layer/",
        "vibeforcer/",
        "hook-layer/",
        ".claude/hooks/",
        "test_",
        "fixture",
    )

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        enabled = ctx.config.enabled_rules.get(self.rule_id)
        if enabled is not None and not enabled:
            return []
        import re
        for target in ctx.content_targets:
            # Skip hook infrastructure and test files
            lowered_path = target.path.lower()
            if any(frag in lowered_path for frag in self.EXCLUDED_PATH_FRAGMENTS):
                continue
            for pattern in self.SECURITY_PATTERNS:
                if re.search(pattern, target.content, re.IGNORECASE):
                    return [
                        RuleFinding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=Severity.HIGH,
                            decision="deny",
                            message=f"Modifying security guardrail settings is blocked in {target.path}. Do not disable rules or bypass permissions.",
                            metadata={"path": target.path, "pattern": pattern},
                        )
                    ]
        return []


class SessionStartContextRule(Rule):
    """Inject project context on session start."""
    rule_id = "SESSION-001"
    title = "Session start context injection"
    events = ("SessionStart",)

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        enabled = ctx.config.enabled_rules.get(self.rule_id)
        if enabled is not None and not enabled:
            return []
        import subprocess
        fragments = []
        cwd = str(ctx.cwd)

        # Recent git log
        try:
            result = subprocess.run(
                ["git", "log", "--oneline", "-10"],
                cwd=cwd, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                fragments.append(f"## Recent commits\n```\n{result.stdout.strip()}\n```")
        except (OSError, subprocess.TimeoutExpired):
            pass

        # Git status
        try:
            result = subprocess.run(
                ["git", "status", "--short"],
                cwd=cwd, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                fragments.append(f"## Working tree status\n```\n{result.stdout.strip()}\n```")
        except (OSError, subprocess.TimeoutExpired):
            pass

        # Current branch
        try:
            result = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=cwd, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                fragments.append(f"Current branch: `{result.stdout.strip()}`")
        except (OSError, subprocess.TimeoutExpired):
            pass

        if not fragments:
            return []
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.LOW,
                additional_context="# Project Context (auto-injected)\n\n" + "\n\n".join(fragments),
            )
        ]


class ConfigChangeGuardRule(Rule):
    """Block config changes that weaken security."""
    rule_id = "CONFIG-001"
    title = "Config change guard"
    events = ("ConfigChange",)

    BLOCKED_SOURCES = ("project_settings", "local_settings", "user_settings")

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        enabled = ctx.config.enabled_rules.get(self.rule_id)
        if enabled is not None and not enabled:
            return []
        source = ctx.payload.payload.get("source", "")
        # Only guard non-policy changes
        if source not in self.BLOCKED_SOURCES:
            return []
        changes = ctx.payload.payload.get("changes", {})
        if not isinstance(changes, dict):
            return []
        # Block disableAllHooks
        if changes.get("disableAllHooks") is True:
            return [
                RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.CRITICAL,
                    decision="block",
                    message="Disabling all hooks is blocked. Do not set disableAllHooks: true.",
                    metadata={"source": source},
                )
            ]
        # Block hook removal/modification
        if "hooks" in changes:
            return [
                RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.HIGH,
                    decision="block",
                    message="Modifying hook configuration via settings changes is blocked. Edit hook files directly with explicit approval.",
                    metadata={"source": source},
                )
            ]
        return []
