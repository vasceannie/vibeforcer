/**
 * OpenCode Vibeforcer Plugin
 *
 * Thin TypeScript shim that bridges OpenCode's plugin system to the
 * vibeforcer engine via subprocess.
 *
 * Installation:
 *   vibeforcer install opencode
 *
 * Or manually:
 *   1. Copy to ~/.config/opencode/plugins/vibeforcer-plugin.ts
 *   2. Ensure vibeforcer is on PATH (pipx install vibeforcer)
 */

import type { Plugin } from "@opencode-ai/plugin"

const VIBEFORCER_BIN = "__VIBEFORCER_BIN__" !== "__" + "VIBEFORCER_BIN__"
  ? "__VIBEFORCER_BIN__"
  : (Bun.env.VIBEFORCER_BIN || "vibeforcer")

const SESSION_ID = `opencode-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

interface EnforcerResult {
  action?: "block" | "allow" | "warn" | "context" | "continue"
  reason?: string
  context?: string
  updated_args?: Record<string, unknown>
}

async function callVibeforcer(payload: Record<string, unknown>): Promise<EnforcerResult | null> {
  try {
    const proc = Bun.spawn(
      [VIBEFORCER_BIN, "handle", "--platform", "opencode"],
      {
        env: { ...Bun.env },
        stdin: "pipe",
        stdout: "pipe",
        stderr: "pipe",
      },
    )

    proc.stdin.write(JSON.stringify(payload))
    proc.stdin.flush()
    proc.stdin.end()

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
    console.error(`[vibeforcer] callVibeforcer failed: ${err}`)
    return null
  }
}

export const VibeforcerPlugin: Plugin = async ({ project, client, $, directory, worktree }) => {
  let currentDirectory = directory

  await client.app.log({
    body: {
      service: "vibeforcer",
      level: "info",
      message: `Vibeforcer plugin loaded (session: ${SESSION_ID})`,
    },
  })

  return {
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

      const result = await callVibeforcer(payload)
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
              body: { service: "vibeforcer", level: "info", message: result.context },
            })
          }
          break
      }
    },

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

      const result = await callVibeforcer(payload)
      if (!result) return

      if (result.action === "warn" || result.action === "context") {
        const message = result.reason || result.context
        if (message) {
          await client.app.log({
            body: { service: "vibeforcer", level: "warn", message },
          })
        }
      }
    },

    event: async ({ event }: { event: { type: string; [key: string]: unknown } }) => {
      if (event.type === "session.created") {
        const payload = {
          hook_event_name: "session.created",
          tool_name: "",
          tool_input: {},
          cwd: currentDirectory,
          session_id: SESSION_ID,
          transcript_path: null,
        }
        const result = await callVibeforcer(payload)
        if (result?.context) {
          await client.app.log({
            body: { service: "vibeforcer", level: "info", message: `[session-start] ${result.context}` },
          })
        }
      }

      if (event.type === "session.idle") {
        const payload = {
          hook_event_name: "session.idle",
          tool_name: "",
          tool_input: {},
          cwd: currentDirectory,
          session_id: SESSION_ID,
          transcript_path: null,
        }
        const result = await callVibeforcer(payload)
        if (!result) return
        if (result.action === "continue") {
          await client.app.log({
            body: { service: "vibeforcer", level: "warn", message: `[stop-advisory] ${result.reason || "unfinished work"}` },
          })
        } else if (result.context) {
          await client.app.log({
            body: { service: "vibeforcer", level: "info", message: `[stop] ${result.context}` },
          })
        }
      }

      if (event.type === "permission.asked") {
        const toolName = typeof event.tool === "string" ? event.tool : ""
        const toolArgs = (event.args && typeof event.args === "object" && !Array.isArray(event.args))
          ? event.args as Record<string, unknown> : {}

        const payload = {
          hook_event_name: "permission.asked",
          tool_name: toolName,
          tool_input: toolArgs,
          cwd: currentDirectory,
          session_id: SESSION_ID,
          transcript_path: null,
        }
        const result = await callVibeforcer(payload)
        if (!result) return
        if (result.action === "block") {
          await client.app.log({
            body: { service: "vibeforcer", level: "error", message: `[permission-advisory] ${result.reason}` },
          })
        }
      }
    },
  }
}
