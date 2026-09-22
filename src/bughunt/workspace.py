"""Bounded local clone of a program's own declared source-code asset.

This runs exactly one `git clone` of a URL you explicitly supply, into a
destination directory you explicitly supply. It never reads a dossier or acts
on one automatically -- you pick the reference from a dossier's
`source_code_assets` yourself, the same way clicking a link is your decision,
not code's. HTTPS only; no embedded credentials, no other Git transport
(`ssh://`, `git://`, `ext::`, `file://`), no shell interpretation of the URL.

This is for analyzing a program's own declared source locally -- open-source
projects and SDKs a program has made available for review -- never a live
target's production assets. Cloning a repository is not authorization to test
anything; scope and permission review stay a separate, human step.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

MIN_DEPTH, MAX_DEPTH = 1, 1000
_CLONE_TIMEOUT_SECONDS = 300
_GIT_TIMEOUT_SECONDS = 30


def _validate_https_git_url(value: object) -> str:
    if (not isinstance(value, str) or not value
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or "\\" in value):
        raise ValueError("Source URL is invalid")
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.netloc:
        raise ValueError("Source URL must use https:// (no ssh://, git://, ext::, or file://)")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise ValueError("Source URL must not embed credentials")
    if not parts.path or parts.path == "/":
        raise ValueError("Source URL must include a repository path")
    return value


def clone_source(url: str, destination, *, depth: int = 1) -> dict:
    """Clone ``url`` into ``destination``, which must not already exist."""
    url = _validate_https_git_url(url)
    if type(depth) is not int or not MIN_DEPTH <= depth <= MAX_DEPTH:
        raise ValueError(f"depth must be an integer between {MIN_DEPTH} and {MAX_DEPTH}")
    target = Path(destination)
    if target.exists():
        raise ValueError("Destination already exists; choose an empty path so nothing already there is touched")
    target.parent.mkdir(parents=True, exist_ok=True)
    # GIT_TERMINAL_PROMPT=0 turns a stuck credential prompt into a clean failure
    # instead of hanging; "--" stops the URL/path from ever being read as a flag.
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        completed = subprocess.run(
            ["git", "clone", "--depth", str(depth), "--single-branch", "--", url, str(target)],
            capture_output=True, timeout=_CLONE_TIMEOUT_SECONDS, env=env,
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError(f"Clone timed out after {_CLONE_TIMEOUT_SECONDS}s") from error
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()[:2000] or "unknown error"
        raise ValueError(f"git clone failed: {message}")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=target, capture_output=True, timeout=_GIT_TIMEOUT_SECONDS)
    branch = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=target, capture_output=True, timeout=_GIT_TIMEOUT_SECONDS)
    return {
        "url": url, "path": str(target.resolve()), "depth": depth,
        "head": head.stdout.decode("utf-8", errors="replace").strip() or None,
        "branch": branch.stdout.decode("utf-8", errors="replace").strip() or None,
        "notice": ("Cloned for local analysis only. This is not authorization to test anything, and "
                    "it does not contact the program's live/production assets. Use `finding evidence` "
                    "against this same workspace once a fix is ready."),
    }
