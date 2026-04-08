from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vibeforcer.constants import SAFE_READ_SHELL_VERBS
from vibeforcer.models import RuleFinding, Severity
from vibeforcer.rules.base import Rule
from vibeforcer.util.payloads import lower_path, path_matches_glob
from vibeforcer.util.subprocesses import run_shell


def _is_rule_enabled(ctx: "HookContext", rule_id: str, default: bool = True) -> bool:
    value = ctx.config.enabled_rules.get(rule_id)
    return default if value is None else bool(value)


def _severity(name: str) -> Severity:
    return Severity.from_value(name)


def _command_has_word(command: str, word: str) -> bool:
    import re
    return bool(re.search(rf"(^|\s){re.escape(word)}(\s|$)", command, re.IGNORECASE))


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


class PromptContextRule(Rule):
    rule_id = "BUILTIN-INJECT-PROMPT"
    title = "Inject prompt context"
    events = ("UserPromptSubmit",)

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not _is_rule_enabled(ctx, self.rule_id):
            return []
        fragments: list[str] = []
        for relative in ctx.config.prompt_context_files:
            path = ctx.config.root / relative
            if not path.exists():
                continue
            try:
                content = path.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if not content:
                continue
            fragments.append(f"## {relative}\n{content}")
        if not fragments:
            return []
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=_severity("LOW"),
                additional_context="\n\n".join(fragments),
                metadata={"source_files": ctx.config.prompt_context_files},
            )
        ]


class FullFileReadRule(Rule):
    rule_id = "BUILTIN-ENFORCE-FULL-READ"
    title = "Enforce full file read"
    events = ("PreToolUse", "PermissionRequest")

    EXEMPT_SUFFIXES = (".md", ".json", ".yaml", ".yml", ".txt", ".log", ".csv")
    # ~10k tokens ≈ 40 KB; files above this are too large to force a full read
    LARGE_FILE_BYTES = 40_000

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not _is_rule_enabled(ctx, self.rule_id):
            return []
        if ctx.tool_name != "Read":
            return []
        tool_input = ctx.tool_input
        if "offset" not in tool_input and "limit" not in tool_input:
            return []
        # Allow partial reads for data/doc files that can be very large
        target_path = None
        for path_value in ctx.candidate_paths:
            if any(path_value.lower().endswith(suffix) for suffix in self.EXEMPT_SUFFIXES):
                return []
            target_path = path_value

        # Allow partial reads for large files (>~10k tokens)
        if target_path:
            try:
                size = Path(target_path).stat().st_size
                if size > self.LARGE_FILE_BYTES:
                    return []
            except OSError:
                pass  # file not found / permission error — fall through to deny

        if target_path:
            msg = (
                f"Please read `{target_path}` in full first (no offset/limit). "
                "Partial reads are blocked for initial inspection. "
                "Read the complete file, then use offset/limit for subsequent reads."
            )
        else:
            msg = (
                "Please read the full file first (no offset/limit). "
                "Partial reads are blocked for initial inspection."
            )

        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=_severity("MEDIUM"),
                decision="deny",
                message=msg,
                metadata={"path": target_path or "", "target": "tool_input"},
            )
        ]


class ProtectedPathsRule(Rule):
    rule_id = "BUILTIN-PROTECTED-PATHS"
    title = "Protected paths"
    events = ("PreToolUse", "PermissionRequest")

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not _is_rule_enabled(ctx, self.rule_id):
            return []
        patterns = ctx.config.protected_paths
        if not patterns:
            return []
        # Read-only tools should never be blocked by protected paths
        from vibeforcer.constants import READ_TOOL_NAMES
        if ctx.tool_name and ctx.tool_name.lower() in READ_TOOL_NAMES:
            return []

        matched_path = None
        for path_value in ctx.candidate_paths:
            pattern = _path_matches_any(path_value, patterns)
            if pattern:
                matched_path = path_value
                break

        if matched_path:
            if ctx.tool_name and ctx.tool_name.lower() == "bash":
                command = ctx.bash_command
                if command and _is_safe_read_shell(command):
                    return []
            return [
                RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=_severity("HIGH"),
                    decision="deny",
                    message=f"Protected path matched: {matched_path}. Modify configuration only with explicit approval or move the check into config.json.",
                    metadata={"path": matched_path},
                )
            ]
        return []


class SensitiveDataRule(Rule):
    rule_id = "GLOBAL-BUILTIN-SENSITIVE-DATA"
    title = "Sensitive data protection"
    events = ("PreToolUse", "PermissionRequest")

    # Suffixes that make an otherwise-sensitive path safe (templates, examples).
    SAFE_SUFFIXES = (
        ".example",
        ".sample",
        ".template",
        ".defaults",
        ".dist",
        ".test",
        ".bak",
    )

    def _compile_patterns(self, raw: list[str]) -> list[re.Pattern[str]]:
        """Compile sensitive path patterns into regexes.

        Each raw pattern is treated as a regex.  For backward compatibility,
        plain substring patterns (no regex metacharacters) are auto-wrapped
        so they match as before — e.g. ``/.env`` becomes ``/\\.env`` with
        proper escaping.  Patterns that already contain regex metacharacters
        (``[``, ``(``, ``\\d``, etc.) are compiled as-is.
        """
        compiled: list[re.Pattern[str]] = []
        meta_chars = set("[](){}*+?|^$\\")
        for raw_pattern in raw:
            stripped = raw_pattern.strip()
            if not stripped:
                continue
            has_meta = any(ch in meta_chars for ch in stripped)
            if has_meta:
                expr = stripped
            else:
                expr = re.escape(stripped)
            compiled.append(re.compile(expr, re.IGNORECASE))
        return compiled

    def _is_safe_path(self, path_value: str) -> bool:
        """Return True if the path ends with a safe suffix like .example."""
        lowered = lower_path(path_value)
        return any(lowered.endswith(suffix) for suffix in self.SAFE_SUFFIXES)

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not _is_rule_enabled(ctx, self.rule_id):
            return []
        compiled = self._compile_patterns(ctx.config.sensitive_path_patterns)
        if not compiled:
            return []
        matched = None
        for path_value in ctx.candidate_paths:
            if self._is_safe_path(path_value):
                continue
            lowered = lower_path(path_value)
            if any(pattern.search(lowered) for pattern in compiled):
                matched = path_value
                break
        if not matched and ctx.bash_command:
            lowered_command = ctx.bash_command.lower()
            for pattern in compiled:
                for m in pattern.finditer(lowered_command):
                    # Check the text after the match for a safe suffix
                    rest = lowered_command[m.end():]
                    # Extract the next "word" boundary (up to whitespace/end)
                    end_idx = len(rest)
                    for i, ch in enumerate(rest):
                        if ch in (" ", "\t", "\n", ";", "|", "&", ">", "<"):
                            end_idx = i
                            break
                    tail = rest[:end_idx]
                    if not any(tail.startswith(suffix) or tail == suffix.lstrip(".")
                              for suffix in self.SAFE_SUFFIXES):
                        matched = "[command]"
                        break
                if matched:
                    break
        if not matched:
            return []
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=_severity("HIGH"),
                decision="deny",
                message=f"Sensitive data access is blocked: {matched}",
                metadata={"target": matched},
            )
        ]


class SystemProtectionRule(Rule):
    rule_id = "GLOBAL-BUILTIN-SYSTEM-PROTECTION"
    title = "System path protection"
    events = ("PreToolUse", "PermissionRequest")

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not _is_rule_enabled(ctx, self.rule_id):
            return []
        prefixes = [item.lower() for item in ctx.config.system_path_prefixes]
        if not prefixes:
            return []
        matched = None
        for path_value in ctx.candidate_paths:
            lowered = lower_path(path_value)
            if any(lowered.startswith(prefix) for prefix in prefixes):
                matched = path_value
                break
        if not matched and ctx.bash_command:
            lowered_command = ctx.bash_command.lower()
            # Only match system prefixes that appear as actual absolute paths,
            # not as substrings of project-relative paths like .venv/bin/
            for prefix in prefixes:
                # Must be preceded by whitespace, shell operator, or start of string
                # AND the prefix must start with / (absolute path)
                if not prefix.startswith("/"):
                    if prefix in lowered_command:
                        matched = "[command]"
                        break
                    continue
                pattern = r"(?:^|[\s;|&(])" + re.escape(prefix)
                if re.search(pattern, lowered_command):
                    matched = "[command]"
                    break
        if not matched:
            return []
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=_severity("CRITICAL"),
                decision="deny",
                message=f"Critical system path access is blocked: {matched}",
                metadata={"target": matched},
            )
        ]


class GitNoVerifyRule(Rule):
    rule_id = "GIT-001"
    title = "Block git --no-verify"
    events = ("PreToolUse", "PermissionRequest")

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not _is_rule_enabled(ctx, self.rule_id):
            return []
        command = ctx.bash_command
        if not command:
            return []
        lowered = command.lower()
        bypass_type = None
        if "--no-verify" in lowered and any(keyword in lowered for keyword in ("git commit", "git push", "git merge")):
            bypass_type = "--no-verify"
        elif "git commit" in lowered and any(token in lowered for token in (" -n ", "\t-n ", " -an ", " -nm ")):
            bypass_type = "-n (shorthand for --no-verify)"
        elif "core.hookspath" in lowered and "/dev/null" in lowered:
            bypass_type = "core.hookspath=/dev/null"
        else:
            return []

        msg = (
            f"Git hook bypass detected: `{bypass_type}`. "
            "Pre-commit and pre-push hooks exist for a reason — "
            "they run linters, type checks, and tests.\n\n"
            "Instead of:\n"
            "    git commit --no-verify -m 'quick fix'\n\n"
            "Use:\n"
            "    git commit -m 'fix: resolve type error in parser'\n\n"
            "If hooks are failing, fix the issues they found rather than skipping them."
        )
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=_severity("HIGH"),
                decision="deny",
                message=msg,
                metadata={"bypass_type": bypass_type, "command": command[:200]},
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
                    severity=_severity("LOW"),
                    additional_context=ctx.config.search_reminder_message,
                )
            ]
        if ctx.bash_command and _command_has_word(ctx.bash_command.lower(), "grep"):
            return [
                RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=_severity("LOW"),
                    additional_context=ctx.config.search_reminder_message,
                )
            ]
        return []


class PostEditQualityRule(Rule):
    rule_id = "QUALITY-POST-001"
    title = "Post-edit quality gate"
    events = ("PostToolUse",)

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        if not _is_rule_enabled(ctx, self.rule_id):
            return []
        if not ctx.config.post_edit_quality_enabled:
            return []
        if not ctx.languages:
            return []
        commands: list[str] = []
        for language in sorted(ctx.languages):
            commands.extend(ctx.config.post_edit_quality_commands.get(language, []))
        if not commands:
            return []
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
                failures.append(
                    f"$ {result.command}\n[exit {result.returncode}]\n{result.stdout}{result.stderr}".strip()
                )

        if failures and ctx.config.post_edit_quality_block_on_failure:
            return [
                RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=_severity("HIGH"),
                    decision="block",
                    message="Post-edit quality gate failed.\n\n" + "\n\n".join(failures),
                )
            ]
        if failures:
            return [
                RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=_severity("LOW"),
                    additional_context="Post-edit quality commands reported failures:\n\n" + "\n\n".join(failures),
                )
            ]
        return []
