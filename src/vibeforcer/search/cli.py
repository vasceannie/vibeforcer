"""CLI subcommands for vibeforcer search (isx integration)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from vibeforcer.search.completions import print_completion
from vibeforcer.search.config import (
    APP_CONFIG,
    APP_NAME,
    DEFAULT_ISLANDS_CONFIG,
    DEFAULT_OPENCODE_CONFIG,
    DEFAULT_OPENCODE_PLUGIN_PATH,
    DEFAULT_SKILL_NAME,
    IsxError,
    detect_provider,
    expand,
    load_config,
    save_config,
)
from vibeforcer.search.git_utils import resolve_add_repo
from vibeforcer.search.index_ops import (
    find_local_index,
    local_indexes,
    resolve_reindex_target,
)
from vibeforcer.search.runtime import (
    choose_litellm_model,
    current_islands_config_path,
    embedding_like,
    fetch_runtime_models,
    islands_binary,
    run_islands,
    runtime_env,
    save_runtime_model,
    write_islands_config,
)
from vibeforcer.search.scaffolds import (
    scaffold_opencode_plugin,
    scaffold_skill,
)


# ---------------------------------------------------------------------------
# Token resolution
# ---------------------------------------------------------------------------


def _token_from_cli(
    args: argparse.Namespace,
) -> tuple[str | None, dict[str, str]]:
    """Check ``--token`` and ``--token-env`` flags."""
    extra: dict[str, str] = {}
    if getattr(args, "token", None):
        extra["ISLANDS_GIT_TOKEN"] = args.token
        return "--token", extra

    token_env = getattr(args, "token_env", None)
    if not token_env:
        return None, extra

    value = os.environ.get(token_env)
    if not value:
        raise IsxError(
            f"environment variable {token_env} is not set. "
            "Set it or use --token <value> instead."
        )
    extra["ISLANDS_GIT_TOKEN"] = value
    return token_env, extra


def _token_from_config(repo_url: str | None) -> str | None:
    """Check isx config for a saved token matching the repo host."""
    if not repo_url or not repo_url.startswith("https://"):
        return None
    try:
        cfg = load_config()
    except IsxError:
        return None
    git_tokens = cfg.get("git_tokens", {})
    if not isinstance(git_tokens, dict):
        return None
    host = urlparse(repo_url).hostname or ""
    token = git_tokens.get(host)
    return token if isinstance(token, str) and token else None


def _resolve_token(
    args: argparse.Namespace,
    repo_url: str | None = None,
) -> tuple[str | None, dict[str, str]]:
    """Resolve a git token from CLI flags, config, or env."""
    source, extra = _token_from_cli(args)
    if source:
        return source, extra

    config_token = _token_from_config(repo_url)
    if config_token:
        host = urlparse(repo_url or "").hostname or ""
        extra["ISLANDS_GIT_TOKEN"] = config_token
        return f"config:{host}", extra

    env_val = os.environ.get("ISLANDS_GIT_TOKEN")
    if env_val:
        extra["ISLANDS_GIT_TOKEN"] = env_val
        return "ISLANDS_GIT_TOKEN", extra

    return None, extra


def _embed_token_in_url(url: str, token: str) -> str:
    """Rewrite an HTTPS clone URL to embed *token* for auth."""
    if not url.startswith("https://"):
        return url
    parsed = urlparse(url)
    authed = parsed._replace(
        netloc=f"oauth2:{token}@{parsed.hostname}",
    )
    return urlunparse(authed)


def _build_add_args(
    repo: str,
    extra: dict[str, str],
) -> tuple[list[str], str]:
    """Build islands ``add`` args, optionally rewriting the URL."""
    add_args = ["add"]
    token_val = extra.get("ISLANDS_GIT_TOKEN")
    if token_val:
        add_args.extend(["--token", token_val])
        repo = _embed_token_in_url(repo, token_val)
    add_args.append(repo)
    return add_args, repo


# ---------------------------------------------------------------------------
# cmd_init helpers
# ---------------------------------------------------------------------------


def _resolve_init_provider(args: argparse.Namespace) -> tuple[str, str]:
    """Return ``(provider, base_url)`` for init."""
    provider = args.provider or detect_provider()
    if args.base_url:
        return provider, args.base_url
    if provider == "litellm":
        return provider, os.environ.get(
            "LITELLM_BASE_URL",
            "http://llm.toy",
        )
    return provider, "http://localhost:11434"


def _resolve_init_model(
    args: argparse.Namespace,
    provider: str,
    base_url: str,
) -> dict[str, str | list[str] | None]:
    """Resolve model and API key settings for init."""
    if provider == "litellm":
        api_key_env = args.api_key_env or "LITELLM_API_KEY"
        model, discovered, warning = choose_litellm_model(
            base_url,
            api_key_env,
            args.model,
        )
        return {
            "model": model,
            "api_key_env": api_key_env,
            "api_key_value": None,
            "discovered": discovered,
            "warning": warning,
        }
    return {
        "model": args.model or "nomic-embed-text",
        "api_key_env": args.api_key_env,
        "api_key_value": args.api_key_value or "ollama",
        "discovered": None,
        "warning": None,
    }


def _guard_overwrite(islands_cfg: Path, force: bool) -> None:
    """Raise if config files exist and *force* is False."""
    if APP_CONFIG.exists() and not force:
        raise IsxError(
            f"{APP_CONFIG} already exists. Re-run with --force to overwrite it."
        )
    if islands_cfg.exists() and not force:
        raise IsxError(
            f"{islands_cfg} already exists. Re-run with --force to overwrite it."
        )


def _scaffold_integration(
    integration: str,
    args: argparse.Namespace,
) -> tuple[list[Path], Path | None]:
    """Run the selected integration scaffold."""
    if integration == "skill":
        paths = scaffold_skill(
            args.skill_name,
            args.skill_target,
            force=args.force,
        )
        return paths, None
    if integration == "opencode-tool":
        plugin = scaffold_opencode_plugin(
            expand(
                args.opencode_plugin_path,
                DEFAULT_OPENCODE_PLUGIN_PATH,
            ),
            expand(args.opencode_config, DEFAULT_OPENCODE_CONFIG),
            force=args.force,
        )
        return [], plugin
    return [], None


def _print_init_summary(
    cli_cfg: dict,
    info: dict[str, str | list[str] | None],
) -> None:
    """Print the post-init summary block."""
    print(f"Initialized {APP_NAME}.")
    print(f"  CLI config:     {APP_CONFIG}")
    print(f"  Islands config: {cli_cfg['islands_config']}")
    print(f"  Provider:       {cli_cfg['provider']}")
    print(f"  Base URL:       {cli_cfg['base_url']}")
    print(f"  Model:          {cli_cfg['model']}")
    print(f"  Integration:    {cli_cfg['integration']}")
    if info.get("api_key_env"):
        print(f"  API key env:    {info['api_key_env']}")
    elif info.get("api_key_value"):
        print("  API key:        stored as fixed runtime value")
    if info.get("warning"):
        print(f"  Note:           {info['warning']}")
    _print_discovered(info.get("discovered"))


def _print_discovered(discovered: str | list[str] | None) -> None:
    """Print embedding-ish models found during init probe."""
    if not isinstance(discovered, list):
        return
    hits = [m for m in discovered if embedding_like(m)][:10]
    if not hits:
        return
    print("  Embedding routes seen:")
    for item in hits:
        print(f"    - {item}")


def _print_scaffold_results(
    skill_paths: list[Path],
    plugin_path: Path | None,
    args: argparse.Namespace,
) -> None:
    """Print paths written by integration scaffolding."""
    if skill_paths:
        print("  Skills written:")
        for path in skill_paths:
            print(f"    - {path}")
    if plugin_path:
        print(f"  OpenCode tool:  {plugin_path}")
        oc = expand(args.opencode_config, DEFAULT_OPENCODE_CONFIG)
        print(f"  OpenCode config:{oc}")


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    """Write wrapper and islands configs."""
    integration = args.integration or _prompt_integration_choice()
    provider, base_url = _resolve_init_provider(args)
    info = _resolve_init_model(args, provider, base_url)

    model = str(info["model"])
    islands_cfg = expand(args.islands_config, DEFAULT_ISLANDS_CONFIG)
    _guard_overwrite(islands_cfg, args.force)

    cli_cfg = {
        "provider": provider,
        "binary": args.binary,
        "base_url": base_url,
        "api_key_env": info["api_key_env"],
        "api_key_value": info["api_key_value"],
        "model": model,
        "islands_config": str(islands_cfg),
        "integration": integration,
    }
    save_config(cli_cfg)
    write_islands_config(islands_cfg, model)

    skill_paths, plugin_path = _scaffold_integration(integration, args)
    _print_init_summary(cli_cfg, info)
    _print_scaffold_results(skill_paths, plugin_path, args)
    print(f"\nTry:\n  {APP_NAME} doctor")
    print(f"  {APP_NAME} models")
    print(f"  {APP_NAME} add https://github.com/panbanda/islands")
    print(f'  {APP_NAME} search "embedding model configuration"')
    return 0


def cmd_doctor(_args: argparse.Namespace) -> int:
    """Check runtime config and endpoint reachability."""
    cfg = load_config()
    _print_doctor_config(cfg)
    return _probe_doctor_endpoint(cfg)


def cmd_models(args: argparse.Namespace) -> int:
    """List available models from the configured endpoint."""
    cfg = load_config()
    models = fetch_runtime_models(cfg)
    current = cfg.get("model")
    shown = models if args.all else [m for m in models if embedding_like(m)]

    if args.json:
        print(
            json.dumps(
                {"current": current, "models": shown},
                indent=2,
            )
        )
        return 0

    if not shown:
        raise IsxError("no models matched the current filter")

    print(f"Current model: {current}")
    for model in shown:
        marker = "*" if model == current else " "
        print(f"{marker} {model}")
    return 0


def cmd_use(args: argparse.Namespace) -> int:
    """Switch to a different embedding model."""
    cfg = load_config()
    model = args.model.strip()
    if not model:
        raise IsxError("model name is required")

    if not args.force:
        models = fetch_runtime_models(cfg)
        if model not in models:
            raise IsxError(
                f"model not found in /v1/models: {model}. "
                "Run `isx models --all` to inspect available routes."
            )

    save_runtime_model(cfg, model)
    print(f"Updated model to {model}")
    print(f"Wrote {current_islands_config_path(cfg)}")
    print(
        "Note: if your existing indexes were built with a different "
        "embedding dimension, re-add or rebuild them before searching.",
    )
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """List locally known indexes."""
    cfg = load_config()
    items = local_indexes(cfg)

    if args.json:
        print(json.dumps(items, indent=2))
        return 0

    if not items:
        print("No local indexes found.")
        print(f"Try: {APP_NAME} add https://github.com/panbanda/islands")
        return 0

    print(f"Local indexes ({len(items)}):")
    for item in items:
        repo = item.get("repository", {})
        print(f"- {item.get('name')}")
        print(f"  clone:   {repo.get('clone_url', 'unknown')}")
        print(f"  files:   {item.get('file_count', 0)}")
        print(f"  updated: {item.get('updated_at', 'unknown')}")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    """Index a repository URL."""
    cfg = load_config()
    repo = resolve_add_repo(args.repo, cwd=Path.cwd())
    token_source, extra = _resolve_token(args, repo_url=repo)
    if token_source:
        print(
            f"Using token from {token_source} for repository access",
            flush=True,
        )
    add_args, repo = _build_add_args(repo, extra)
    return run_islands(cfg, add_args, extra_env=extra)


def cmd_search(args: argparse.Namespace) -> int:
    """Search indexed repositories."""
    cfg = load_config()
    query = " ".join(args.query).strip()
    if not query:
        raise IsxError("search query is required")
    return run_islands(cfg, ["search", query])


def cmd_remove(args: argparse.Namespace) -> int:
    """Remove an index by name or repo identity."""
    cfg = load_config()
    item = find_local_index(cfg, args.target)
    if not item:
        raise IsxError(
            f"could not resolve local index: {args.target}",
        )
    index_name = item.get("name")
    if not index_name:
        raise IsxError("matched index metadata is missing its name")

    print(f"Removing index: {index_name}", flush=True)
    remove_args = ["remove"]
    if args.force:
        remove_args.append("--force")
    remove_args.append(str(index_name))
    return run_islands(cfg, remove_args)


def cmd_sync(args: argparse.Namespace) -> int:
    """Sync one or more indexes with upstream."""
    cfg = load_config()
    return run_islands(cfg, ["sync", *args.targets])


def cmd_reindex(args: argparse.Namespace) -> int:
    """Remove and rebuild an index from its clone URL."""
    cfg = load_config()
    index_name, repo_url = resolve_reindex_target(
        cfg,
        args.target,
        cwd=Path.cwd(),
    )

    if index_name:
        print(f"Removing existing index: {index_name}", flush=True)
        code = run_islands(cfg, ["remove", "--force", index_name])
        if code != 0:
            return code
    else:
        print(
            f"No existing local index matched {args.target}, adding fresh from URL",
            flush=True,
        )

    print(f"Adding repository: {repo_url}", flush=True)
    token_source, extra = _resolve_token(args, repo_url=repo_url)
    if token_source:
        print(
            f"Using token from {token_source} for repository access",
            flush=True,
        )
    add_args, repo_url = _build_add_args(repo_url, extra)
    return run_islands(cfg, add_args, extra_env=extra)


def cmd_completions(args: argparse.Namespace) -> int:
    """Print shell completion script."""
    return print_completion(args.shell)


def _prompt_integration_choice() -> str:
    """Interactively ask which integration to scaffold."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return "none"
    print("Integration setup:")
    print("  1) none")
    print("  2) skill (Claude Code / OpenCode)")
    print("  3) opencode-tool (native OpenCode plugin)")
    choice = input("Select integration [1]: ").strip() or "1"
    return {
        "1": "none",
        "2": "skill",
        "3": "opencode-tool",
    }.get(choice, "none")


# ---------------------------------------------------------------------------
# cmd_doctor helpers
# ---------------------------------------------------------------------------


def _print_doctor_config(cfg: dict) -> None:
    """Print the static config section of ``doctor``."""
    print(f"CLI config:     {APP_CONFIG}")
    print(f"Islands config: {cfg.get('islands_config')}")
    print(f"Binary:         {cfg.get('binary')}")
    print(f"Provider:       {cfg.get('provider')}")
    print(f"Base URL:       {cfg.get('base_url')}")
    print(f"Model:          {cfg.get('model')}")
    print(f"Integration:    {cfg.get('integration', 'none')}")

    try:
        print(f"Binary path:    {islands_binary(cfg)}")
    except IsxError as exc:
        print(f"Binary path:    ERROR: {exc}")

    api_key_env = cfg.get("api_key_env")
    if api_key_env:
        status = "set" if os.environ.get(api_key_env) else "missing"
        print(f"API key env:    {api_key_env}={status}")
    else:
        print("API key env:    n/a")


def _probe_doctor_endpoint(cfg: dict) -> int:
    """Probe the runtime endpoint and print results."""
    try:
        env = runtime_env(cfg)
        base = "set" if env.get("OPENAI_BASE_URL") else "missing"
        key = "set" if env.get("OPENAI_API_KEY") else "missing"
        print(f"OPENAI_BASE_URL={base}")
        print(f"OPENAI_API_KEY={key}")
        models = fetch_runtime_models(cfg)
        print(f"/v1/models:     ok ({len(models)} models)")
        sample = [m for m in models if embedding_like(m)][:8]
        if sample:
            print("Embedding-ish routes:")
            for item in sample:
                print(f"  - {item}")
    except urllib.error.HTTPError as exc:
        print(f"/v1/models:     HTTP {exc.code}")
        return 1
    except (OSError, ValueError, IsxError) as exc:
        print(f"Runtime check:  ERROR: {exc}")
        return 1
    return 0


# ---------------------------------------------------------------------------
# Parser construction — split into per-command helpers
# ---------------------------------------------------------------------------


def build_search_parser(
    subparsers: argparse._SubParsersAction | None = None,
) -> argparse.ArgumentParser:
    """Build the ``search`` subcommand parser.

    If *subparsers* is given, ``search`` is added as a child.
    Otherwise a standalone top-level parser is returned (for ``isx``).
    """
    parser = _create_search_root(subparsers)
    sub = parser.add_subparsers(dest="search_command")
    _register_all_subcommands(sub)
    parser.add_argument(
        "query_args",
        nargs="*",
        help="Search query (default action)",
    )
    return parser


def _create_search_root(
    subparsers: argparse._SubParsersAction | None,
) -> argparse.ArgumentParser:
    """Create the root parser for search commands."""
    if subparsers is not None:
        return subparsers.add_parser(
            "search",
            help="Semantic code search via islands",
            description="Semantic code search via islands-ollama.",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
    return argparse.ArgumentParser(
        prog="isx",
        description="Semantic code search via islands-ollama.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def _register_all_subcommands(
    sub: argparse._SubParsersAction,
) -> None:
    """Register every search subcommand on *sub*."""
    _add_init_parser(sub)
    _add_doctor_parser(sub)
    _add_models_parser(sub)
    _add_use_parser(sub)
    _add_list_parser(sub)
    _add_add_parser(sub)
    _add_query_parser(sub)
    _add_remove_parser(sub)
    _add_sync_parser(sub)
    _add_reindex_parser(sub)
    _add_completions_parser(sub)


def _add_init_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("init", help="write wrapper and islands configs")
    p.add_argument("--provider", choices=["litellm", "ollama"])
    p.add_argument("--base-url")
    p.add_argument("--model")
    p.add_argument("--api-key-env")
    p.add_argument("--api-key-value")
    p.add_argument("--binary", default="islands-ollama")
    p.add_argument("--islands-config")
    p.add_argument(
        "--integration",
        choices=["none", "skill", "opencode-tool"],
    )
    p.add_argument(
        "--skill-target",
        choices=["claude", "opencode", "both"],
        default="both",
    )
    p.add_argument("--skill-name", default=DEFAULT_SKILL_NAME)
    p.add_argument("--opencode-plugin-path")
    p.add_argument("--opencode-config")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)


def _add_doctor_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("doctor", help="check runtime config and endpoint")
    p.set_defaults(func=cmd_doctor)


def _add_models_parser(
    sub: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    p = sub.add_parser("models", help="list available embedding models")
    p.set_defaults(func=cmd_models)
    for option in ("--all", "--json"):
        p.add_argument(option, action="store_true")


def _add_use_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("use", help="set default model for this repo")
    p.add_argument("model")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_use)


def _add_list_json_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true")


def _add_list_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("list", help="list locally known indexes")
    p.set_defaults(func=cmd_list)
    _add_list_json_argument(p)


def _add_add_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("add", help="index a repository URL")
    p.add_argument("repo")
    p.add_argument("--token")
    p.add_argument("--token-env")
    p.set_defaults(func=cmd_add)


def _add_query_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("query", help="search indexed repositories")
    p.add_argument("query", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_search)


def _add_remove_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("remove", help="remove an index")
    p.set_defaults(func=cmd_remove)
    p.add_argument("target")
    p.add_argument("--force", action="store_true")


def _add_sync_targets_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("targets", nargs="*")


def _add_sync_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("sync", help="sync indexes with upstream")
    p.set_defaults(func=cmd_sync)
    _add_sync_targets_argument(p)


def _add_reindex_target_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target")


def _add_reindex_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("reindex", help="remove and rebuild an index")
    p.set_defaults(func=cmd_reindex)
    _add_reindex_target_argument(p)


def _add_completions_shell_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("shell", choices=["bash", "zsh"])


def _add_completions_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("completions", help="print shell completions")
    p.set_defaults(func=cmd_completions)
    _add_completions_shell_argument(p)
