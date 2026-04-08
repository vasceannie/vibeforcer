/**
 * OpenCode Vibeforcer Plugin
 *
 * Thin TypeScript shim that bridges OpenCode's plugin system to the
 * vibeforcer hook engine via subprocess.
 *
 * The plugin intercepts tool.execute.before and tool.execute.after events,
 * listens to session lifecycle and permission events, translates them into
 * vibeforcer's canonical JSON format, and applies the engine's decisions
 * (block, modify args, or allow with context).
 *
 * Platform limitations (vs Claude Code / Codex):
 *   - session.idle (Stop): vibeforcer can advise "continue" but OpenCode's
 *     plugin system has no mechanism to force continuation. Findings are
 *     logged as warnings.
 *   - permission.asked: blocking is handled at tool.execute.before; the
 *     event handler provides observability only.
 *   - No UserPromptSubmit equivalent: OpenCode doesn't expose a hook for
 *     intercepting user prompts before they're sent to the model. Rules
 *     like BUILTIN-INJECT-PROMPT are inactive on OpenCode.
 *   - transcript_path: not available from OpenCode's plugin context.
 *     Rules that read the transcript (e.g. STOP-001) operate in
 *     advisory mode without full transcript access.
 *
 * Reference: https://opencode.ai/docs/plugins/
 * Bun.spawn: https://bun.sh/docs/api/spawn
 */

import type { Plugin } from "@opencode-ai/plugin"

const VIBEFORCER_BIN = Bun.env.VIBEFORCER_BIN || "vibeforcer"

// Generate a unique session ID per plugin load (= per OpenCode session).
const SESSION_ID = `opencode-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

interface EnforcerResult {
  action?: "block" | "allow" | "warn" | "context" | "continue"
  reason?: string
  context?: string
  updated_args?: Record<string, unknown>
}

async function callEnforcer(payload: Record<string, unknown>): Promise<EnforcerResult | null> {
  try {
    const proc = Bun.spawn(
      [VIBEFORCER_BIN, "handle", "--platform", "opencode"],
      {
        env: Bun.env,
        stdin: "pipe",
        stdout: "pipe",
        stderr: "pipe",
      },
    )

    // Bun.spawn with stdin:"pipe" returns a FileSink, not a WritableStream.
    // FileSink API: .write(data), .flush(), .end()
    proc.stdin.write(JSON.stringify(payload))
    proc.stdin.flush()
    proc.stdin.end()

    // Read stdout and stderr as text
    const output = await new Response(proc.stdout).text()
    const stderr = await new Response(proc.stderr).text()

    const exitCode = await proc.exited

    if (exitCode !== 0) {
      console.error(`[vibeforcer] exit ${exitCode}: ${stderr}`)
      return null
    }

    const trimmed = output.trim()
    if (!trimmed) return null

    return JSON.parse(trimmed) as EnforcerResult
  } catch (err) {
    // Catch subprocess failures, JSON parse errors, Bun API changes, etc.
    // Fail open: a broken enforcer should not crash the OpenCode session.
    console.error(`[vibeforcer] callEnforcer failed: ${err}`)
    return null
  }
}

export const EnforcerPlugin: Plugin = async ({ project, client, $, directory, worktree }) => {
  // `directory` is set at init time. OpenCode may change CWD mid-session;
  // tool hooks receive the current CWD via their input object.
  // For event hooks (session.idle, etc.), we fall back to the init-time value.
  let currentDirectory = directory

  await client.app.log({
    body: {
      service: "vibeforcer",
      level: "info",
      message: `Vibeforcer plugin loaded (${VIBEFORCER_BIN}, session: ${SESSION_ID})`,
    },
  })

  return {
    // -- Pre-tool: intercept before execution ---------------------------------
    "tool.execute.before": async (input: any, output: any) => {
      if (input.cwd && typeof input.cwd === "string") {
        currentDirectory = input.cwd
      }

      const payload = {
        hook_event_name: "tool.execute.before",
        tool_name: input.tool,
        tool_input: { ...output.args },
        cwd: currentDirectory,
        session_id: SESSION_ID,
        transcript_path: null,
      }

      const result = await callEnforcer(payload)
      if (!result) return

      switch (result.action) {
        case "block":
          throw new Error(`[vibeforcer] ${result.reason || "Blocked by policy"}`)

        case "allow":
          if (result.updated_args) {
            Object.assign(output.args, result.updated_args)
          }
          break

        case "context":
          if (result.context) {
            await client.app.log({
              body: {
                service: "vibeforcer",
                level: "info",
                message: result.context,
              },
            })
          }
          break
      }
    },

    // -- Post-tool: review after execution ------------------------------------
    "tool.execute.after": async (input: any, output: any) => {
      if (input.cwd && typeof input.cwd === "string") {
        currentDirectory = input.cwd
      }

      const payload = {
        hook_event_name: "tool.execute.after",
        tool_name: input.tool,
        tool_input: { ...output.args },
        cwd: currentDirectory,
        session_id: SESSION_ID,
        transcript_path: null,
        tool_result: output.result,
        tool_response: output.result,
      }

      const result = await callEnforcer(payload)
      if (!result) return

      if (result.action === "warn" || result.action === "context") {
        const message = result.reason || result.context
        if (message) {
          await client.app.log({
            body: {
              service: "vibeforcer",
              level: "warn",
              message,
            },
          })
        }
      }
    },

    // -- Events: session lifecycle + permissions --------------------------------
    event: async ({ event }: { event: { type: string; [key: string]: unknown } }) => {
      // -- SessionStart (session.created) ------------------------------------
      if (event.type === "session.created") {
        const payload = {
          hook_event_name: "session.created",
          tool_name: "",
          tool_input: {},
          cwd: currentDirectory,
          session_id: SESSION_ID,
          transcript_path: null,
        }

        const result = await callEnforcer(payload)
        if (result?.context) {
          await client.app.log({
            body: {
              service: "vibeforcer",
              level: "info",
              message: `[session-start] ${result.context}`,
            },
          })
        }
      }

      // -- Stop (session.idle) -----------------------------------------------
      if (event.type === "session.idle") {
        const payload = {
          hook_event_name: "session.idle",
          tool_name: "",
          tool_input: {},
          cwd: currentDirectory,
          session_id: SESSION_ID,
          transcript_path: null,
        }

        const result = await callEnforcer(payload)
        if (!result) return

        if (result.action === "continue") {
          // Can't force continuation — log as a prominent warning
          await client.app.log({
            body: {
              service: "vibeforcer",
              level: "warn",
              message: `[stop-advisory] Vibeforcer recommends continuing: ${result.reason || "unfinished work detected"}`,
            },
          })
        } else if (result.context) {
          await client.app.log({
            body: {
              service: "vibeforcer",
              level: "info",
              message: `[stop] ${result.context}`,
            },
          })
        }
      }

      // -- PermissionRequest (permission.asked) -------------------------------
      if (event.type === "permission.asked") {
        const toolName = typeof event.tool === "string" ? event.tool : ""
        const toolArgs = (
          event.args && typeof event.args === "object" && !Array.isArray(event.args)
        ) ? event.args as Record<string, unknown> : {}

        const payload = {
          hook_event_name: "permission.asked",
          tool_name: toolName,
          tool_input: toolArgs,
          cwd: currentDirectory,
          session_id: SESSION_ID,
          transcript_path: null,
        }

        const result = await callEnforcer(payload)
        if (!result) return

        if (result.action === "block") {
          await client.app.log({
            body: {
              service: "vibeforcer",
              level: "error",
              message: `[permission-advisory] Vibeforcer would deny this permission: ${result.reason}`,
            },
          })
        }
      }
    },
  }
}
