"""Local index discovery and resolution."""
from __future__ import annotations

import json
from pathlib import Path

from vibeforcer.search.config import DEFAULT_INDEXES_PATH, IsxError, expand
from vibeforcer.search.git_utils import get_git_remote_url, get_git_repo_root, urls_match


def local_indexes(cfg: dict) -> list[dict]:
    """Scan ``~/.local/share/islands/indexes/`` for metadata.json files."""
    indexes_root = expand(None, DEFAULT_INDEXES_PATH)
    if not indexes_root.exists():
        return []

    items: list[dict] = []
    for path in indexes_root.glob("*/*/*/metadata.json"):
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        items.append(data)
    items.sort(key=lambda item: item.get("name", ""))
    return items


def find_local_index(cfg: dict, target: str) -> dict | None:
    """Find a local index by name, full_name, or clone URL."""
    normalized = target.strip()
    for item in local_indexes(cfg):
        repo = item.get("repository", {})
        exact_candidates = {
            item.get("name", ""),
            repo.get("full_name", ""),
            repo.get("name", ""),
        }
        if normalized in exact_candidates:
            return item
        url_candidates = [
            repo.get("clone_url"),
            repo.get("ssh_url"),
        ]
        for candidate in url_candidates:
            if urls_match(normalized, candidate):
                return item
    return None


def resolve_reindex_target(
    cfg: dict, target: str, cwd: Path | None = None
) -> tuple[str | None, str]:
    """Resolve a reindex target to ``(index_name_or_None, clone_url)``."""
    normalized = target.strip()
    if not normalized:
        raise IsxError("index or repo target is required")

    if normalized == ".":
        repo_root = get_git_repo_root(cwd)
        if not repo_root:
            raise IsxError(
                "could not resolve '.': not inside a git working tree. "
                "Pass a repo URL or index name instead."
            )
        clone_url = get_git_remote_url(repo_root)
        if not clone_url:
            raise IsxError(
                f"git repo at {repo_root} has no 'origin' remote. "
                "Pass the clone URL explicitly."
            )
        for item in local_indexes(cfg):
            repo = item.get("repository", {})
            if urls_match(repo.get("clone_url"), clone_url):
                return item.get("name"), clone_url
        return None, clone_url

    item = find_local_index(cfg, normalized)
    if item:
        repo = item.get("repository", {})
        clone_url = repo.get("clone_url")
        if not clone_url:
            raise IsxError(f"index {item.get('name')} is missing repository.clone_url")
        return item.get("name"), clone_url

    if "://" in normalized or normalized.startswith("git@"):
        return None, normalized

    known = ", ".join(item.get("name", "") for item in local_indexes(cfg)[:8])
    if known:
        raise IsxError(f"could not resolve target: {normalized}. Known indexes: {known}")
    raise IsxError(f"could not resolve target: {normalized}")
