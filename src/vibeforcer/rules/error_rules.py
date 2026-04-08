"""Rules for enforcing error resolution behavior.

ERRORS-BASH-001: PostToolUse Bash — catches exit-0 commands with error output
ERRORS-FAIL-001: PostToolUseFailure Bash — catches non-zero exit commands

Both inject context telling Claude to fix errors instead of dismissing them.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from vibeforcer.models import RuleFinding, Severity
from vibeforcer.rules.base import Rule

if TYPE_CHECKING:
    from vibeforcer.context import HookContext


# ── Command classification ───────────────────────────────────────────────

# Commands whose output should NEVER trigger error detection
# (read-only / informational — output naturally contains "error" as data)
_READ_ONLY_PREFIXES = (
    "grep ", "grep\t", "egrep ", "fgrep ", "rg ", "ag ", "ack ",
    "cat ", "head ", "tail ", "less ", "more ", "bat ",
    "ls ", "ls\t", "ll ", "dir ", "tree ", "du ", "df ", "wc ",
    "find ", "locate ", "fd ",
    "git log", "git show", "git diff", "git status", "git blame",
    "git branch", "git tag", "git remote", "git stash list",
    "which ", "whereis ", "type ", "file ", "stat ",
    "echo ", "printf ", "env", "printenv",
    "man ", "help ",
    "pwd",
)

# Start-of-command matchers (the command might have flags before the verb)
_READ_ONLY_PATTERNS = re.compile(
    r"^(?:command\s+-v|type\s+|hash\s+|readlink\s+|realpath\s+|basename\s+|dirname\s+)",
    re.IGNORECASE,
)


def _is_read_only_command(command: str) -> bool:
    """Check if a Bash command is read-only / informational."""
    stripped = command.strip()
    lowered = stripped.lower()

    # Direct prefix match
    for prefix in _READ_ONLY_PREFIXES:
        if lowered.startswith(prefix) or lowered == prefix.strip():
            return True

    # Pattern match
    if _READ_ONLY_PATTERNS.match(lowered):
        return True

    # Piped commands: if the first command is read-only, the whole pipeline is
    first_cmd = stripped.split("|")[0].strip()
    if first_cmd != stripped:
        first_lowered = first_cmd.lower()
        for prefix in _READ_ONLY_PREFIXES:
            if first_lowered.startswith(prefix) or first_lowered == prefix.strip():
                return True

    return False


# Commands where non-zero exit is normal behavior (not an error)
_BENIGN_FAIL_PATTERNS = (
    # grep/rg: exit 1 = no match
    re.compile(r"^(grep|egrep|fgrep|rg|ag|ack)\b", re.IGNORECASE),
    # diff: exit 1 = files differ
    re.compile(r"^diff\b", re.IGNORECASE),
    # test / [ ]: exit 1 = condition false
    re.compile(r"^(test\s|\[\s)", re.IGNORECASE),
    # which / command -v: exit 1 = not found
    re.compile(r"^(which|command\s+-v|type\s+|hash\s+)\b", re.IGNORECASE),
    # git diff --exit-code: exit 1 = changes exist
    re.compile(r"^git\s+diff\b.*--exit-code", re.IGNORECASE),
    # curl with --fail: exit 22 = HTTP error (often used for probing)
    re.compile(r"^curl\b.*--fail", re.IGNORECASE),
)


def _is_benign_failure(command: str) -> bool:
    """Check if a non-zero exit is expected/normal for this command."""
    stripped = command.strip()
    for pattern in _BENIGN_FAIL_PATTERNS:
        if pattern.search(stripped):
            return True
    return False


# ── Error signal detection in output ────────────────────────────────────

# Patterns that indicate real errors in command output (for exit-0 commands)
_ERROR_PATTERNS = [
    # Test frameworks
    re.compile(r"\bFAILED\b.*test", re.IGNORECASE),
    re.compile(r"\bFAIL\s+(?:src/|tests/)", re.IGNORECASE),
    re.compile(r"Tests?:\s+\d+\s+failed", re.IGNORECASE),
    re.compile(r"test result: FAILED", re.IGNORECASE),
    re.compile(r"\d+\s+failed,\s+\d+\s+passed", re.IGNORECASE),
    # Compilation / build errors
    re.compile(r"^.*:\d+:\d+:\s+error:", re.MULTILINE),
    re.compile(r"make:\s+\*\*\*.*Error\s+\d+", re.IGNORECASE),
    re.compile(r"Build FAILED", re.IGNORECASE),
    re.compile(r"compilation\s+error", re.IGNORECASE),
    # Python tracebacks
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"(?:SyntaxError|TypeError|NameError|ValueError|AttributeError|ImportError|KeyError|IndexError|RuntimeError|AssertionError|FileNotFoundError|ModuleNotFoundError|OSError|PermissionError):", re.MULTILINE),
    # Lint / type-check
    re.compile(r"Found\s+\d+\s+error", re.IGNORECASE),
    re.compile(r"error\[E\d+\]", re.IGNORECASE),  # Rust compiler
    re.compile(r"✗|✘"),  # Failure symbols
]

# Patterns that look like errors but aren't (for suppression)
_FALSE_POSITIVE_PATTERNS = [
    # "X passed" with no failures
    re.compile(r"^\s*\d+\s+passed(?:\s+in\s+[\d.]+s)?\s*$", re.MULTILINE),
    # Deprecation/pip warnings are not actionable errors
    re.compile(r"DEPRECATION:|DeprecationWarning|PendingDeprecationWarning", re.IGNORECASE),
    # Docker build warnings (non-fatal)
    re.compile(r"\d+\s+warnings?\s+found\s+\(use\s+docker", re.IGNORECASE),
    # "Successfully" anything
    re.compile(r"Successfully\s+(built|installed|tagged|created)", re.IGNORECASE),
]


def _has_error_signals(output: str) -> bool:
    """Check if command output contains real error signals."""
    if not output or len(output.strip()) < 10:
        return False

    # Check for false-positive suppressors first
    has_success = any(p.search(output) for p in _FALSE_POSITIVE_PATTERNS)

    # Check for error patterns
    error_hits = sum(1 for p in _ERROR_PATTERNS if p.search(output))

    if error_hits == 0:
        return False

    # If we have success signals and only weak error matches, suppress
    # (e.g., "4 passed" + test file names containing "error")
    if has_success and error_hits <= 1:
        # Check if the only hit is in a filename/path context
        return False

    return True


# ── Context message ─────────────────────────────────────────────────────

_ERROR_CONTEXT = (
    "⚠️ ERRORS DETECTED — You MUST fix these errors. Rules:\n"
    "1. Do NOT run git blame, git log, or any investigation into whether "
    "these errors are 'pre-existing' or 'introduced by your changes'.\n"
    "2. Do NOT dismiss errors as 'out of scope', 'unrelated', or "
    "'for a separate PR'.\n"
    "3. Fix them now, or spawn a subagent to fix them if it would "
    "derail your current task.\n"
    "4. If you genuinely cannot fix something (e.g., missing credentials, "
    "external service down), say so explicitly and add a TODO comment."
)

_FAILURE_CONTEXT = (
    "⚠️ COMMAND FAILED — You MUST resolve this failure. Rules:\n"
    "1. Do NOT run git blame, git log, or any investigation into whether "
    "this failure is 'pre-existing' or 'introduced by your changes'.\n"
    "2. Do NOT dismiss as 'out of scope' or 'unrelated to my changes'.\n"
    "3. Fix the underlying issue now, or spawn a subagent if the fix "
    "would derail your current task.\n"
    "4. If you genuinely cannot fix it (e.g., missing credentials, "
    "external service down), say so explicitly and add a TODO comment."
)


# ── Rules ───────────────────────────────────────────────────────────────

class BashOutputErrorRule(Rule):
    """Detect errors in Bash output even when exit code is 0.

    PostToolUse fires for exit-0 commands. Some tools (ruff --exit-zero,
    eslint --max-warnings, etc.) exit 0 despite reporting errors.
    """
    rule_id = "ERRORS-BASH-001"
    title = "Bash output error interceptor"
    events = ("PostToolUse",)

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        enabled = ctx.config.enabled_rules.get(self.rule_id)
        if enabled is not None and not enabled:
            return []

        # Only Bash tool
        if not ctx.tool_name or ctx.tool_name != "Bash":
            return []

        command = ctx.bash_command
        if not command:
            return []

        # Skip read-only commands
        if _is_read_only_command(command):
            return []

        # Get stdout from tool_response
        tool_response = ctx.payload.payload.get("tool_response")
        if not isinstance(tool_response, dict):
            return []

        stdout = tool_response.get("stdout", "")
        stderr = tool_response.get("stderr", "")
        output = f"{stdout}\n{stderr}".strip()

        if not output:
            return []

        if _has_error_signals(output):
            return [
                RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.HIGH,
                    additional_context=_ERROR_CONTEXT,
                    metadata={"command": command[:200]},
                )
            ]

        return []


class BashFailureReinforcementRule(Rule):
    """Reinforce that non-zero Bash exits must be resolved.

    PostToolUseFailure fires for ANY non-zero exit. We filter out
    commands where non-zero exit is normal (grep, diff, test, etc.).
    """
    rule_id = "ERRORS-FAIL-001"
    title = "Bash failure reinforcement"
    events = ("PostToolUseFailure",)

    def evaluate(self, ctx: "HookContext") -> list[RuleFinding]:
        enabled = ctx.config.enabled_rules.get(self.rule_id)
        if enabled is not None and not enabled:
            return []

        # Only Bash tool
        if not ctx.tool_name or ctx.tool_name != "Bash":
            return []

        command = ctx.bash_command
        if not command:
            return []

        # Skip commands where non-zero exit is expected behavior
        if _is_benign_failure(command):
            return []

        # Skip read-only commands that failed (e.g., cat nonexistent_file)
        if _is_read_only_command(command):
            return []

        # Skip interrupted commands
        if ctx.payload.payload.get("is_interrupt", False):
            return []

        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.HIGH,
                additional_context=_FAILURE_CONTEXT,
                metadata={"command": command[:200]},
            )
        ]
