"""Local patch-workspace evidence capture. Runs no unattended automation, is not
part of the discovery worker, and contacts no target asset.

This executes exactly one command you choose, inside one workspace directory you
choose, and records what actually happened: real stdout/stderr, exit code, and
the uncommitted Git diff. It replaces a freehand "tests pass" attestation with
captured evidence, but it does not judge correctness and it never changes a
finding's ``patch_status`` itself. A human still reviews the evidence and
decides whether to run ``finding patch --status verified``.

Only point a workspace at source the program has actually made available to
you (a public repository, an SDK, code you were given for the engagement) --
never at a live target's production assets. This module does not restrict the
command's own network access; treat it exactly as you would a command you
typed into your own terminal, because that is what it does.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import subprocess
import time

MAX_OUTPUT_BYTES = 32 * 1024
MAX_DIFF_BYTES = 200 * 1024
MIN_TIMEOUT_SECONDS = 5
MAX_TIMEOUT_SECONDS = 1800
_GIT_TIMEOUT_SECONDS = 30


def _truncate(data: bytes, limit: int) -> tuple[str, bool]:
    text = data.decode("utf-8", errors="replace")
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def _run(args, cwd, timeout, *, shell=False):
    try:
        completed = subprocess.run(args, cwd=cwd, shell=shell, capture_output=True, timeout=timeout)
        return completed.returncode, completed.stdout, completed.stderr, False
    except subprocess.TimeoutExpired as error:
        return None, error.stdout or b"", error.stderr or b"", True
    except OSError as error:
        return None, b"", str(error).encode("utf-8", errors="replace"), False


def capture_regression(workspace, command, *, timeout_seconds=300, clock=None):
    """Run ``command`` inside ``workspace`` and capture real evidence.

    ``workspace`` must be an existing directory that is a Git checkout (a
    ``.git`` entry present) -- a basic sanity check, not a sandbox. ``command``
    is the exact shell command to run, exactly as you would type it yourself;
    it is executed with the workspace as the working directory. Nothing here
    verifies the patch; ``passed`` only reflects the command's own exit code.
    """
    directory = Path(workspace)
    if not directory.is_dir():
        raise ValueError("Workspace must be an existing directory")
    if not (directory / ".git").exists():
        raise ValueError("Workspace must be a Git checkout (no .git found); "
                          "clone or init the program's own source there first")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("Command must be a nonempty string")
    if type(timeout_seconds) is not int or not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout_seconds must be an integer between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}")
    now = clock() if clock is not None else datetime.now(timezone.utc)

    # "HEAD" catches staged and unstaged changes alike; an unborn HEAD (a brand new
    # `git init` with no commit yet) fails harmlessly and just yields an empty diff.
    _, diff_raw, _, _ = _run(["git", "diff", "HEAD", "--", "."], directory, _GIT_TIMEOUT_SECONDS)
    diff_text, diff_truncated = _truncate(diff_raw, MAX_DIFF_BYTES)
    _, stat_raw, _, _ = _run(["git", "diff", "HEAD", "--stat", "--", "."], directory, _GIT_TIMEOUT_SECONDS)
    stat_text, _ = _truncate(stat_raw, 4096)

    started = time.monotonic()
    exit_code, out, err, timed_out = _run(command, directory, timeout_seconds, shell=True)
    duration = time.monotonic() - started
    stdout_text, stdout_truncated = _truncate(out, MAX_OUTPUT_BYTES)
    stderr_text, stderr_truncated = _truncate(err, MAX_OUTPUT_BYTES)

    return {
        "schema_version": 1,
        "captured_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "workspace": str(directory.resolve()),
        "command": command,
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "exit_code": exit_code,
        "passed": exit_code == 0 and not timed_out,
        "duration_seconds": round(duration, 3),
        "stdout": stdout_text, "stdout_truncated": stdout_truncated,
        "stderr": stderr_text, "stderr_truncated": stderr_truncated,
        "diff_stat": stat_text,
        "diff": diff_text, "diff_truncated": diff_truncated,
        "diff_present": bool(diff_text.strip()),
        "notice": ("Real captured command output from your local workspace, not an automatic "
                   "correctness judgment or a submission. A human still reviews the diff and "
                   "output and records the outcome with `finding patch --status verified`."),
    }
