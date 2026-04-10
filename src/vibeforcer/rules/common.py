from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING
from typing_extensions import override

from vibeforcer.constants import SAFE_READ_SHELL_VERBS
from vibeforcer.models import RuleFinding, Severity
from vibeforcer.rules.base import Rule, is_rule_enabled
from vibeforcer.util.payloads import lower_path, path_matches_glob
from vibeforcer.util.subprocesses import run_shell

if TYPE_CHECKING:
    from vibeforcer.context import HookContext


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


def _path_matches_any(path_value: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        if path_matches_glob(path_value, pattern):
            return pattern
    return None


def _read_context_fragment(root: Path, relative: str) -> str | None:
    """Read a prompt context file and return its fragment, or None to skip."""
    path = root / relative
    if not path.exists():
        return None
    try:
        content = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return f"## {relative}\n{content}" if content else None


class PromptContextRule(Rule):
    rule_id: str = "BUILTIN-INJECT-PROMPT"
    title: str = "Inject prompt context"
    events: tuple[str, ...] = ("UserPromptSubmit",)

    @override
    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        fragments = [
            frag
            for relative in ctx.config.prompt_context_files
            if (frag := _read_context_fragment(ctx.config.root, relative)) is not None
        ]
        if not fragments:
            return []
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.LOW,
                additional_context="\n\n".join(fragments),
                metadata={"source_files": ctx.config.prompt_context_files},
            )
        ]


def _find_read_target(
    paths: list[str],
    exempt: tuple[str, ...],
) -> str | None:
    """Return the candidate read path, or None if exempt."""
    target = None
    for path_value in paths:
        if any(path_value.lower().endswith(s) for s in exempt):
            return None
        target = path_value
    return target


def _is_large_file(path_str: str, threshold: int) -> bool:
    try:
        return Path(path_str).stat().st_size > threshold
    except OSError:
        return False


class FullFileReadRule(Rule):
    rule_id = "BUILTIN-ENFORCE-FULL-READ"
    title = "Enforce full file read"
    events = ("PreToolUse", "PermissionRequest")

    EXEMPT_SUFFIXES = (".md", ".json", ".yaml", ".yml", ".txt", ".log", ".csv")
    LARGE_FILE_BYTES = 40_000

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        if ctx.tool_name != "Read":
            return []
        ti = ctx.tool_input
        if "offset" not in ti and "limit" not in ti:
            return []
        target = _find_read_target(ctx.candidate_paths, self.EXEMPT_SUFFIXES)
        if target is None:
            return []
        if _is_large_file(target, self.LARGE_FILE_BYTES):
            return []
        msg = (
            f"Please read `{target}` in full first "
            f"(no offset/limit). Partial reads are blocked "
            f"for initial inspection."
        )
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.MEDIUM,
                decision="deny",
                message=msg,
                metadata={"path": target, "target": "tool_input"},
            )
        ]


def _is_readonly_tool(tool_name: str | None) -> bool:
    from vibeforcer.constants import READ_TOOL_NAMES

    return bool(tool_name and tool_name.lower() in READ_TOOL_NAMES)


def _is_safe_bash_read(tool_name: str | None, bash_command: str | None) -> bool:
    return (
        tool_name is not None
        and tool_name.lower() == "bash"
        and bash_command is not None
        and _is_safe_read_shell(bash_command)
    )


def _find_matched_protected_path(
    candidate_paths: list[str],
    patterns: list[str],
) -> str | None:
    for path_value in candidate_paths:
        if _path_matches_any(path_value, patterns):
            return path_value
    return None


class ProtectedPathsRule(Rule):
    rule_id: str = "BUILTIN-PROTECTED-PATHS"
    title: str = "Protected paths"
    events: tuple[str, ...] = ("PreToolUse", "PermissionRequest")

    @override
    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        patterns = ctx.config.protected_paths
        if not patterns:
            return []
        if _is_readonly_tool(ctx.tool_name):
            return []
        matched_path = _find_matched_protected_path(ctx.candidate_paths, patterns)
        if matched_path is None:
            return []
        if _is_safe_bash_read(ctx.tool_name, ctx.bash_command):
            return []
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.HIGH,
                decision="deny",
                message=(
                    f"Protected path matched: {matched_path}. "
                    f"Modify configuration only with explicit "
                    f"approval or move the check into config.json."
                ),
                metadata={"path": matched_path},
            )
        ]


_META_CHARS = frozenset("[](){}*+?|^$\\")

_compiled_sensitive_cache: dict[tuple[str, ...], list[re.Pattern[str]]] = {}


def _compile_sensitive_patterns(raw: list[str]) -> list[re.Pattern[str]]:
    """Compile sensitive path patterns into regexes (cached).

    Plain substring patterns are auto-escaped; patterns containing
    regex metacharacters are compiled as-is.
    """
    cache_key = tuple(raw)
    cached = _compiled_sensitive_cache.get(cache_key)
    if cached is not None:
        return cached
    compiled: list[re.Pattern[str]] = []
    for raw_pattern in raw:
        stripped = raw_pattern.strip()
        if not stripped:
            continue
        has_meta = any(ch in _META_CHARS for ch in stripped)
        expr = stripped if has_meta else re.escape(stripped)
        compiled.append(re.compile(expr, re.IGNORECASE))
    _compiled_sensitive_cache[cache_key] = compiled
    return compiled


class SensitiveDataRule(Rule):
    rule_id = "GLOBAL-BUILTIN-SENSITIVE-DATA"
    title = "Sensitive data protection"
    events = ("PreToolUse", "PermissionRequest")

    SAFE_SUFFIXES = (
        ".example",
        ".sample",
        ".template",
        ".defaults",
        ".dist",
        ".test",
        ".bak",
    )

    def _is_safe_path(self, path_value: str) -> bool:
        """Return True if the path ends with a safe suffix."""
        lowered = lower_path(path_value)
        return any(lowered.endswith(s) for s in self.SAFE_SUFFIXES)

    def _match_in_paths(
        self,
        paths: list[str],
        compiled: list[re.Pattern[str]],
    ) -> str | None:
        """Return first path matching a sensitive pattern, or None."""
        for path_value in paths:
            if self._is_safe_path(path_value):
                continue
            lowered = lower_path(path_value)
            if any(p.search(lowered) for p in compiled):
                return path_value
        return None

    def _match_in_command(
        self,
        command: str,
        compiled: list[re.Pattern[str]],
    ) -> str | None:
        """Return '[command]' if command contains a sensitive match."""
        lowered = command.lower()
        _WORD_BREAKS = frozenset(" \t\n;|&><")
        for pattern in compiled:
            for m in pattern.finditer(lowered):
                rest = lowered[m.end() :]
                end = next(
                    (i for i, ch in enumerate(rest) if ch in _WORD_BREAKS),
                    len(rest),
                )
                tail = rest[:end]
                is_safe = any(
                    tail.startswith(s) or tail == s.lstrip(".")
                    for s in self.SAFE_SUFFIXES
                )
                if not is_safe:
                    return "[command]"
        return None

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        compiled = _compile_sensitive_patterns(
            ctx.config.sensitive_path_patterns,
        )
        if not compiled:
            return []
        matched = self._match_in_paths(ctx.candidate_paths, compiled)
        if not matched and ctx.bash_command:
            matched = self._match_in_command(ctx.bash_command, compiled)
        if not matched:
            return []
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.HIGH,
                decision="deny",
                message=f"Sensitive data access is blocked: {matched}",
                metadata={"target": matched},
            )
        ]


def _match_system_path(paths: list[str], prefixes: list[str]) -> str | None:
    """Return the first path matching a system prefix, or None."""
    for path_value in paths:
        lowered = lower_path(path_value)
        if any(lowered.startswith(p) for p in prefixes):
            return path_value
    return None


def _match_system_command(command: str, prefixes: list[str]) -> str | None:
    """Return '[command]' if command references a system path."""
    lowered = command.lower()
    for prefix in prefixes:
        if not prefix.startswith("/"):
            if prefix in lowered:
                return "[command]"
            continue
        pat = r"(?:^|[\s;|&(])" + re.escape(prefix)
        if re.search(pat, lowered):
            return "[command]"
    return None


class SystemProtectionRule(Rule):
    rule_id = "GLOBAL-BUILTIN-SYSTEM-PROTECTION"
    title = "System path protection"
    events = ("PreToolUse", "PermissionRequest")

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        prefixes = [i.lower() for i in ctx.config.system_path_prefixes]
        if not prefixes:
            return []
        matched = _match_system_path(ctx.candidate_paths, prefixes)
        if not matched and ctx.bash_command:
            matched = _match_system_command(ctx.bash_command, prefixes)
        if not matched:
            return []
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.CRITICAL,
                decision="deny",
                message=(f"Critical system path access is blocked: {matched}"),
                metadata={"target": matched},
            )
        ]


def _detect_git_bypass(command: str) -> str | None:
    """Return bypass type string, or None if no bypass detected."""
    lowered = command.lower()
    git_cmds = ("git commit", "git push", "git merge")
    if "--no-verify" in lowered and any(k in lowered for k in git_cmds):
        return "--no-verify"
    n_tokens = (" -n ", "\t-n ", " -an ", " -nm ")
    if "git commit" in lowered and any(t in lowered for t in n_tokens):
        return "-n (shorthand for --no-verify)"
    if "core.hookspath" in lowered and "/dev/null" in lowered:
        return "core.hookspath=/dev/null"
    return None


class GitNoVerifyRule(Rule):
    rule_id = "GIT-001"
    title = "Block git --no-verify"
    events = ("PreToolUse", "PermissionRequest")

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        if not ctx.bash_command:
            return []
        bypass = _detect_git_bypass(ctx.bash_command)
        if not bypass:
            return []
        msg = (
            f"Git hook bypass detected: `{bypass}`. "
            "Pre-commit and pre-push hooks exist for a "
            "reason — they run linters, type checks, and "
            "tests.\n\nIf hooks are failing, fix the issues "
            "they found rather than skipping them."
        )
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.HIGH,
                decision="deny",
                message=msg,
                metadata={
                    "bypass_type": bypass,
                    "command": ctx.bash_command[:200],
                },
            )
        ]


class SearchReminderRule(Rule):
    rule_id = "REMIND-SEARCH-001"
    title = "Search reminder"
    events = ("PreToolUse",)

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not ctx.config.search_reminder_message:
            return []
        if ctx.tool_name in {"Grep", "WebSearch"}:
            return [
                RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.LOW,
                    additional_context=ctx.config.search_reminder_message,
                )
            ]
        if ctx.bash_command and _command_has_word(ctx.bash_command.lower(), "grep"):
            return [
                RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.LOW,
                    additional_context=ctx.config.search_reminder_message,
                )
            ]
        return []


def _collect_quality_commands(ctx: "HookContext") -> list[str]:
    """Gather post-edit quality commands for detected languages."""
    commands: list[str] = []
    for language in sorted(ctx.languages):
        commands.extend(
            ctx.config.post_edit_quality_commands.get(language, []),
        )
    return commands


def _run_quality_commands(
    commands: list[str],
    ctx: "HookContext",
) -> list[str]:
    """Run each command and return formatted failure descriptions."""
    failures: list[str] = []
    for command in commands:
        formatted = command.format(
            files=" ".join(ctx.candidate_paths),
            first_file=ctx.candidate_paths[0] if ctx.candidate_paths else "",
            language=",".join(sorted(ctx.languages)),
        )
        result = run_shell(formatted, ctx.config.root)
        ctx.trace.subprocess(
            {
                "event_name": ctx.event_name,
                "session_id": ctx.session_id,
                "command": result.command,
                "cwd": result.cwd,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        )
        if result.returncode != 0:
            desc = (
                f"$ {result.command}\n"
                f"[exit {result.returncode}]\n"
                f"{result.stdout}{result.stderr}"
            ).strip()
            failures.append(desc)
    return failures


class PostEditQualityRule(Rule):
    rule_id = "QUALITY-POST-001"
    title = "Post-edit quality gate"
    events = ("PostToolUse",)

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        if not ctx.config.post_edit_quality_enabled or not ctx.languages:
            return []
        commands = _collect_quality_commands(ctx)
        if not commands:
            return []
        failures = _run_quality_commands(commands, ctx)
        if not failures:
            return []
        joined = "\n\n".join(failures)
        if ctx.config.post_edit_quality_block_on_failure:
            return [
                RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.HIGH,
                    decision="block",
                    message=f"Post-edit quality gate failed.\n\n{joined}",
                )
            ]
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.LOW,
                additional_context=f"Post-edit quality failures:\n\n{joined}",
            )
        ]
