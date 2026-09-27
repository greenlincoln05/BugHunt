"""Bounded npm advisory check of an explicitly selected local source clone.

Only tracked root package manifests are copied to an isolated temporary
directory. No package installation, lifecycle scripts, project npm config, or
model call is involved. Results are dependency leads, never findings.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from .analysis import _tracked_files

MAX_MANIFEST_BYTES = 10 * 1024 * 1024
MAX_AUDIT_BYTES = 12 * 1024 * 1024
MIN_TIMEOUT, MAX_TIMEOUT = 30, 600
REGISTRY = "https://registry.npmjs.org/"


def _manifest(root: Path, name: str, tracked: set[str]) -> Path:
    if name not in tracked:
        raise ValueError(f"Workspace must track a root {name}; no dependencies were audited")
    path = root / name
    if path.is_symlink() or not path.is_file() or path.resolve() != path:
        raise ValueError(f"Root {name} must be a regular file, not a symlink")
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError(f"Root {name} exceeds the {MAX_MANIFEST_BYTES}-byte audit limit")
    return path


def _safe_environment() -> dict[str, str]:
    # npm can otherwise inherit credentials or arbitrary Node options from the
    # user's shell. A small allowlist is enough to launch Node on Windows/Unix.
    allowed = {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP",
               "TMPDIR", "HOME", "HOMEDRIVE", "HOMEPATH", "USERPROFILE", "OS"}
    return {key: value for key, value in os.environ.items()
            if key.upper() in allowed}


def _summarize(document: dict, *, root: Path) -> dict:
    if not isinstance(document, dict) or not isinstance(document.get("vulnerabilities"), dict):
        raise ValueError("npm did not return a usable advisory report")
    leads = []
    for name, entry in document["vulnerabilities"].items():
        if not isinstance(entry, dict):
            continue
        advisories = [
            {"title": item.get("title"), "url": item.get("url")}
            for item in entry.get("via", []) if isinstance(item, dict)
        ]
        leads.append({
            "package": name,
            "severity": entry.get("severity"),
            "direct_dependency": entry.get("isDirect") is True,
            "affected_range": entry.get("range"),
            "advisories": advisories,
        })
    order = {"critical": 0, "high": 1, "moderate": 2, "low": 3, "info": 4}
    leads.sort(key=lambda row: (order.get(row["severity"], 5), row["package"]))
    return {
        "workspace": str(root),
        "ecosystem": "npm",
        "registry": REGISTRY,
        "production_only": True,
        "counts": (document.get("metadata") or {}).get("vulnerabilities"),
        "leads": leads,
        "notice": ("Unverified dependency leads only. A version match is not a security finding or payout claim. "
                   "Review program exclusions and prove exploitability in the scoped product before drafting a report."),
    }


def audit_npm_dependencies(workspace, output, *, timeout_seconds=120) -> dict:
    """Query npm's free advisory API for tracked root production dependencies."""
    if type(timeout_seconds) is not int or not MIN_TIMEOUT <= timeout_seconds <= MAX_TIMEOUT:
        raise ValueError(f"timeout_seconds must be an integer between {MIN_TIMEOUT} and {MAX_TIMEOUT}")
    root = Path(workspace).resolve()
    if not root.is_dir():
        raise ValueError("Workspace must be an existing Git checkout")
    tracked = _tracked_files(root)
    package = _manifest(root, "package.json", tracked)
    lock = _manifest(root, "package-lock.json", tracked)
    destination = Path(output).resolve()
    if destination == root or root in destination.parents:
        raise ValueError("Audit output must be outside the source workspace")
    if destination.exists():
        raise ValueError("Audit output already exists; choose a new path")
    npm = shutil.which("npm")
    if not npm:
        raise ValueError("npm is unavailable; install Node.js/npm before auditing this clone")

    destination.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with destination.open("x", encoding="utf-8") as handle:
            created = True
            with tempfile.TemporaryDirectory(prefix="bughunt-npm-audit-") as scratch:
                isolated = Path(scratch)
                shutil.copyfile(package, isolated / "package.json")
                shutil.copyfile(lock, isolated / "package-lock.json")
                user_config = isolated / "user.npmrc"
                global_config = isolated / "global.npmrc"
                user_config.touch()
                global_config.touch()
                command = [npm, "audit", "--omit=dev", "--package-lock-only", "--ignore-scripts",
                           "--json", "--registry", REGISTRY, "--userconfig", str(user_config),
                           "--globalconfig", str(global_config), "--cache", str(isolated / "cache")]
                try:
                    run = subprocess.run(command, cwd=isolated, env=_safe_environment(),
                                         capture_output=True, timeout=timeout_seconds)
                except subprocess.TimeoutExpired:
                    raise ValueError(f"npm audit timed out after {timeout_seconds}s") from None
                if len(run.stdout) > MAX_AUDIT_BYTES:
                    raise ValueError("npm audit output exceeded the bounded result size")
                try:
                    document = json.loads(run.stdout)
                except (ValueError, UnicodeDecodeError):
                    raise ValueError("npm audit did not return JSON; check registry access") from None
                if run.returncode not in (0, 1) or "error" in document:
                    raise ValueError("npm audit could not retrieve advisories; check registry access")
                result = _summarize(document, root=root)
                handle.write(json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False) + "\n")
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise
    return {"output": str(destination), "lead_count": len(result["leads"]),
            "counts": result["counts"], "finding_confirmed": False, "testing_authorized": False}
