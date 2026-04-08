"""Skill and plugin scaffolding for search integration."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

from vibeforcer.search.config import (
    DEFAULT_CLAUDE_SKILLS_DIR,
    DEFAULT_OPENCODE_CONFIG,
    DEFAULT_OPENCODE_PLUGIN_PATH,
    DEFAULT_OPENCODE_SKILLS_DIR,
    DEFAULT_SKILL_NAME,
    IsxError,
)


def write_text_file(path: Path, content: str, force: bool) -> None:
    """Write *content* to *path*, erroring if it exists and *force* is False."""
    if path.exists() and not force:
        raise IsxError(f"{path} already exists. Re-run with --force to overwrite it.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def append_unique_json_list(path: Path, key: str, value: str) -> None:
    """Append *value* to a JSON array at *key* in *path*."""
    if path.exists():
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise IsxError(f"could not parse {path} as JSON: {exc}") from exc
    else:
        data = {"$schema": "https://opencode.ai/config.json"}

    items = data.get(key)
    if items is None:
        items = []
    if not isinstance(items, list):
        raise IsxError(f"expected {path}:{key} to be a JSON array")
    if value not in items:
        items.append(value)
    data[key] = items

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def render_isx_skill(skill_name: str) -> str:
    """Render the SKILL.md content for the isx skill."""
    return textwrap.dedent(
        f"""\
        ---
        name: {skill_name}
        description: Use when the user asks to index repositories, run semantic code search, switch embedding models, or rebuild islands indexes via the local `isx` CLI. Triggers on requests like "search this repo semantically", "index this repo with islands", "switch embedding model", or "reindex after changing models".
        ---

        # {skill_name}

        Use the local `isx` CLI instead of reconstructing islands commands by hand.

        ## Workflow

        1. Run `isx doctor` if the runtime may not be configured yet.
        2. Use `isx list` to see known indexes.
        3. Use `isx add <repo-url>` to index a repository.
        4. Use `isx search "query"` for semantic search.
        5. Use `isx models` and `isx use <model>` when changing embedding routes.
        6. After changing to a model with a different embedding dimension, run `isx reindex <repo-or-index>` before searching again.

        ## Notes

        - Prefer `isx` over raw `islands-ollama` unless you specifically need upstream-only flags.
        - `isx` already injects the configured OpenAI-compatible base URL and API key.
        - `isx reindex` is the safe recovery path after model changes.
        """
    )


def render_opencode_plugin() -> str:
    """Render the OpenCode plugin TypeScript source."""
    return textwrap.dedent(
        """\
        import { existsSync } from "node:fs"
        import type { Plugin } from "@opencode-ai/plugin"
        import { tool } from "@opencode-ai/plugin"
        import { z } from "zod"

        const ISX_CONFIG = `${Bun.env.HOME}/.config/isx/config.json`

        type IndexInfo = {
          name: string
          repository?: {
            clone_url?: string
            ssh_url?: string
            full_name?: string
            name?: string
          }
        }

        const runCommand = async (command: string[], cwd?: string): Promise<string> => {
          const proc = Bun.spawn(command, {
            cwd,
            stdin: "ignore",
            stdout: "pipe",
            stderr: "pipe",
            env: Bun.env,
          })

          const stdout = await new Response(proc.stdout).text()
          const stderr = await new Response(proc.stderr).text()
          const exitCode = await proc.exited
          const combined = [stdout.trim(), stderr.trim()].filter(Boolean).join("\\n")

          if (exitCode !== 0) {
            throw new Error(combined || `${command[0]} exited with code ${exitCode}`)
          }

          return combined || "ok"
        }

        const runIsx = async (args: string[]): Promise<string> => {
          if (!existsSync(ISX_CONFIG)) {
            throw new Error("isx is not initialized yet. Run `isx init --provider litellm --integration opencode-tool` first.")
          }
          return runCommand(["isx", ...args])
        }

        const maybeCurrentRepoRemote = async (cwd: string): Promise<string | null> => {
          try {
            const value = await runCommand(["git", "config", "--get", "remote.origin.url"], cwd)
            return value.trim() || null
          } catch {
            return null
          }
        }

        const repoTokens = (value?: string | null): string[] => {
          const raw = value?.trim()
          if (!raw) return []

          const tokens = new Set<string>()
          const add = (item?: string | null) => {
            const text = item?.trim()
            if (!text) return
            tokens.add(text)
            tokens.add(text.replace(/\\.git$/, ""))
          }

          add(raw)

          const sshMatch = raw.match(/^git@[^:]+:(.+?)(?:\\.git)?$/)
          if (sshMatch) add(sshMatch[1])

          const httpsMatch = raw.match(/^[a-z]+:\\/\\/[^/]+\\/(.+?)(?:\\.git)?$/i)
          if (httpsMatch) add(httpsMatch[1])

          return [...tokens]
        }

        const listIndexes = async (): Promise<IndexInfo[]> => {
          const raw = await runIsx(["list", "--json"])
          return JSON.parse(raw) as IndexInfo[]
        }

        const findIndexForRepo = async (repo: string): Promise<IndexInfo | null> => {
          const wanted = new Set(repoTokens(repo))
          const indexes = await listIndexes()

          for (const item of indexes) {
            const repoInfo = item.repository ?? {}
            const candidates = [
              item.name,
              repoInfo.clone_url,
              repoInfo.ssh_url,
              repoInfo.full_name,
              repoInfo.name,
            ]
            for (const candidate of candidates) {
              for (const token of repoTokens(candidate)) {
                if (wanted.has(token)) {
                  return item
                }
              }
            }
          }

          return null
        }

        const requireRepoRemote = async (cwd: string): Promise<string> => {
          const remote = await maybeCurrentRepoRemote(cwd)
          if (!remote) {
            throw new Error("This action needs a git repo with an origin remote, or an explicit repo/target argument.")
          }
          return remote
        }

        const requireIndexedCurrentRepo = async (cwd: string, action: string): Promise<{ remote: string; index: IndexInfo }> => {
          const remote = await requireRepoRemote(cwd)
          const index = await findIndexForRepo(remote)
          if (!index) {
            throw new Error(`Current repo is not indexed in isx yet (${remote}). Run isx_add_repo with this repo before trying to ${action}.`)
          }
          return { remote, index }
        }

        const confirmDestructive = async (context: { ask: Function }, target: string): Promise<void> => {
          await context.ask({
            permission: "edit",
            patterns: [target],
            always: [],
            metadata: {
              title: "Confirm isx index removal",
              target,
            },
          })
        }

        const withTitle = async (context: { metadata: Function }, title: string, fn: () => Promise<string>): Promise<string> => {
          context.metadata({ title })
          return fn()
        }

        const resolveRepoArg = async (repo: string | undefined, cwd: string): Promise<string> => repo || await requireRepoRemote(cwd)

        const resolveIndexedTarget = async (target: string | undefined, cwd: string, action: string): Promise<string> => {
          if (target) return target
          const resolved = await requireIndexedCurrentRepo(cwd, action)
          return resolved.index.name || resolved.remote
        }

        const resolveSearchGuard = async (cwd: string): Promise<void> => {
          const remote = await maybeCurrentRepoRemote(cwd)
          if (!remote) return
          const index = await findIndexForRepo(remote)
          if (!index) {
            throw new Error(`Current repo is not indexed in isx yet (${remote}). Run isx_add_repo first so semantic search does not silently hit some other repo.`)
          }
        }

        export const IsxToolsPlugin: Plugin = async () => ({
          tool: {
            isx_doctor: tool({
              description: "Check whether the local isx semantic-search runtime is configured and reachable.",
              args: {},
              execute: async (_args, context) => withTitle(context, "isx doctor", () => runIsx(["doctor"])),
            }),
            isx_list_indexes: tool({
              description: "List locally known islands indexes managed through isx.",
              args: {},
              execute: async (_args, context) => withTitle(context, "isx list", () => runIsx(["list"])),
            }),
            isx_models: tool({
              description: "List embedding models/routes available to isx.",
              args: {
                all: z.boolean().optional().describe("Show all models instead of only embedding-ish ones."),
              },
              execute: async ({ all }, context) => withTitle(context, "isx models", () => runIsx(all ? ["models", "--all"] : ["models"])),
            }),
            isx_use_model: tool({
              description: "Switch isx to a different embedding model.",
              args: {
                model: z.string().min(1).describe("Model or routed model name."),
                force: z.boolean().optional().describe("Skip remote model validation."),
              },
              execute: async ({ model, force }, context) => withTitle(context, `isx use ${model}`, () => runIsx(force ? ["use", model, "--force"] : ["use", model])),
            }),
            isx_add_repo: tool({
              description: "Clone and index a repository with isx. If repo is omitted, uses the current git origin remote.",
              args: {
                repo: z.string().min(1).optional().describe("Git repository URL. Optional when run inside a git repo with origin set."),
              },
              execute: async ({ repo }, context) => {
                const resolved = await resolveRepoArg(repo, context.directory)
                return withTitle(context, `isx add ${resolved}`, () => runIsx(["add", resolved]))
              },
            }),
            isx_search: tool({
              description: "Run semantic search across indexed repositories. Inside a git repo, this first checks that the current repo has actually been indexed.",
              args: {
                query: z.string().min(1).describe("Semantic search query."),
              },
              execute: async ({ query }, context) => {
                await resolveSearchGuard(context.directory)
                return withTitle(context, `isx search ${query}`, () => runIsx(["search", query]))
              },
            }),
            isx_reindex: tool({
              description: "Remove and rebuild an index from its saved clone URL. If target is omitted, uses the current indexed repo.",
              args: {
                target: z.string().min(1).optional().describe("Index name, repo URL, or known repo identifier. Optional when run inside an indexed repo."),
              },
              execute: async ({ target }, context) => {
                const resolved = await resolveIndexedTarget(target, context.directory, "reindex it")
                return withTitle(context, `isx reindex ${resolved}`, () => runIsx(["reindex", resolved]))
              },
            }),
            isx_sync: tool({
              description: "Sync indexed repositories. If target is omitted, syncs the current indexed repo when possible, otherwise all indexes.",
              args: {
                target: z.string().min(1).optional().describe("Optional index name to sync."),
              },
              execute: async ({ target }, context) => {
                const remote = await maybeCurrentRepoRemote(context.directory)
                if (target) {
                  return withTitle(context, `isx sync ${target}`, () => runIsx(["sync", target]))
                }
                if (remote) {
                  const index = await findIndexForRepo(remote)
                  if (!index) {
                    throw new Error(`Current repo is not indexed in isx yet (${remote}). Run isx_add_repo first before syncing it.`)
                  }
                  return withTitle(context, `isx sync ${index.name}`, () => runIsx(["sync", index.name]))
                }
                return withTitle(context, "isx sync", () => runIsx(["sync"]))
              },
            }),
            isx_remove: tool({
              description: "Remove an isx index. If target is omitted, removes the current indexed repo after confirmation.",
              args: {
                target: z.string().min(1).optional().describe("Index name, repo URL, or known repo identifier."),
                force: z.boolean().optional().describe("Skip confirmation prompt."),
              },
              execute: async ({ target, force }, context) => {
                const resolved = await resolveIndexedTarget(target, context.directory, "remove it")
                if (!force) {
                  await confirmDestructive(context, resolved)
                }
                return withTitle(context, `isx remove ${resolved}`, () => runIsx(["remove", resolved, "--force"]))
              },
            }),
          },
        })
        """
    )


def scaffold_skill(skill_name: str, skill_target: str, force: bool) -> list[Path]:
    """Write the isx SKILL.md to one or more skill directories."""
    destinations: list[Path] = []
    if skill_target in {"claude", "both"}:
        destinations.append(DEFAULT_CLAUDE_SKILLS_DIR / skill_name / "SKILL.md")
    if skill_target in {"opencode", "both"}:
        destinations.append(DEFAULT_OPENCODE_SKILLS_DIR / skill_name / "SKILL.md")

    content = render_isx_skill(skill_name)
    for path in destinations:
        write_text_file(path, content, force=force)
    return destinations


def scaffold_opencode_plugin(plugin_path: Path, opencode_config: Path, force: bool) -> Path:
    """Write the OpenCode plugin and register it in opencode.json."""
    write_text_file(plugin_path, render_opencode_plugin(), force=force)
    append_unique_json_list(opencode_config, "plugin", str(plugin_path))
    return plugin_path
