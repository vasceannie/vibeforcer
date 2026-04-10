"""Git helpers for the search subsystem."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from vibeforcer.search.config import IsxError


def normalize_clone_url(url: str) -> str:
    """Normalize a clone URL for comparison.

    Strips .git suffix, lowercases the host, and converts SSH URLs to
    a canonical ``host/owner/repo`` form.
    """
    raw = url.strip()
    if not raw:
        return raw

    if raw.endswith(".git"):
        raw = raw[:-4]
    raw = raw.rstrip("/")

    ssh_match = re.match(r"^git@([^:]+):(.+)$", raw)
    if ssh_match:
        host = ssh_match.group(1).lower()
        path = ssh_match.group(2).strip("/")
        return f"{host}/{path}"

    proto_match = re.match(r"^[a-z]+://([^/]+)/(.+)$", raw, re.IGNORECASE)
    if proto_match:
        host = proto_match.group(1).lower()
        path = proto_match.group(2).strip("/")
        return f"{host}/{path}"

    return raw.lower()


def urls_match(a: str | None, b: str | None) -> bool:
    """Return True if two clone URLs refer to the same repository."""
    if not a or not b:
        return False
    return normalize_clone_url(a) == normalize_clone_url(b)


def get_git_remote_url(cwd: Path | None = None) -> str | None:
    """Return the origin URL for the git repo at *cwd*."""
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip() or None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def get_git_repo_root(cwd: Path | None = None) -> Path | None:
    """Return the root of the git repo containing *cwd*."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            path = result.stdout.strip()
            if path:
                return Path(path)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def resolve_add_repo(raw: str, cwd: Path | None = None) -> str:
    """Resolve a repo argument for ``add``.

    Handles ``"."`` or a local directory path by resolving to the git
    remote origin URL.  Normal URLs pass through unchanged.
    """
    stripped = raw.strip()
    target = Path(stripped).expanduser()

    if stripped == "." or target.is_dir():
        effective_cwd = (
            target if target.is_absolute() else (Path(cwd) / target if cwd else target)
        )
        effective_cwd = effective_cwd.resolve()
        repo_root = get_git_repo_root(effective_cwd)
        if not repo_root:
            raise IsxError(
                (
                    f"could not resolve '{stripped}': not inside a git working "
                    "tree. Pass a repository URL instead."
                )
            )
        clone_url = get_git_remote_url(repo_root)
        if not clone_url:
            raise IsxError(
                (
                    f"git repo at {repo_root} has no 'origin' remote. "
                    "Pass the clone URL explicitly."
                )
            )
        return clone_url

    return stripped
