from __future__ import annotations

from vibeforcer.context import build_context
from vibeforcer.util.subprocesses import run_shell


def run_async_jobs(payload_dict: dict) -> tuple[str, list[str]]:
    ctx = build_context(payload_dict)
    if ctx.event_name != "PostToolUse" or not ctx.config.async_jobs_enabled or not ctx.languages:
        return ("", [])
    commands: list[str] = []
    for language in sorted(ctx.languages):
        commands.extend(ctx.config.async_jobs_commands.get(language, []))
    if not commands:
        return ("", [])
    summaries: list[str] = []
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
            },
            async_mode=True,
        )
        status = "PASS" if result.returncode == 0 else "FAIL"
        output = (result.stdout + result.stderr).strip()
        if output:
            summaries.append(f"[{status}] {result.command}\n{output}")
        else:
            summaries.append(f"[{status}] {result.command}")
    return ("\n\n".join(summaries), [])
