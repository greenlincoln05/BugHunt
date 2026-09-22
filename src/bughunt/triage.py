"""Bounded batch triage over already-discovered candidates: which ones declare
a source-code asset (see `dossier.source_code_assets`). This makes only small,
bounded requests to the same official structured_scopes endpoint
`opportunity dossier` already uses, and never contacts any candidate's assets.

State is a local, human-readable JSON file so a batch can be interrupted (or
deliberately run again later) and resume without re-checking a candidate it
already has an answer for. Results are a shortlist of *candidates*, not
verified or authorized targets -- read the actual program policy and dossier
reference yourself before cloning or testing anything.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

from .dossier import fetch_program_dossier
from .hackerone import AdapterError

MIN_CANDIDATES, MAX_CANDIDATES = 1, 200
MIN_PAGES, MAX_PAGES = 1, 20


def _load_state(path: Path) -> dict:
    if not path.exists():
        return {"schema_version": 1, "checked": {}}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"Could not read existing triage state at {path}: {error}") from error
    if not isinstance(state, dict) or not isinstance(state.get("checked"), dict):
        raise ValueError(f"{path} does not look like a triage state file")
    return state


def _save_json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def triage_candidates(client, opportunities, state_dir, *, max_candidates=25, max_pages=1, recheck=False, clock=None):
    """Peek at up to ``max_candidates`` opportunities for a declared source-code asset.

    Already-checked candidates are skipped unless ``recheck`` is set. A single
    candidate's error (bad handle, unexpected response) is recorded against
    that candidate and the batch continues; an authentication or rate-limit
    failure stops the whole batch early instead of burning through requests
    that will fail the same way, and nothing past that point is marked checked.
    """
    if type(max_candidates) is not int or not MIN_CANDIDATES <= max_candidates <= MAX_CANDIDATES:
        raise ValueError(f"max_candidates must be an integer between {MIN_CANDIDATES} and {MAX_CANDIDATES}")
    if type(max_pages) is not int or not MIN_PAGES <= max_pages <= MAX_PAGES:
        raise ValueError(f"max_pages must be an integer between {MIN_PAGES} and {MAX_PAGES}")
    now = clock() if clock is not None else datetime.now(timezone.utc)
    directory = Path(state_dir)
    state_path = directory / "status.json"
    state = _load_state(state_path)
    checked = state["checked"]
    pending = [row for row in opportunities if recheck or row["id"] not in checked]

    attempted, stopped_early, stop_reason = [], False, None
    for candidate in pending[:max_candidates]:
        try:
            dossier = fetch_program_dossier(client, candidate["handle"], max_pages=max_pages)
        except (AdapterError, ValueError) as error:
            if getattr(error, "kind", None) in {"authentication", "rate_limit"}:
                stopped_early, stop_reason = True, str(error)
                break
            checked[candidate["id"]] = {"checked_at": now.isoformat(), "name": candidate.get("name"),
                                         "handle": candidate.get("handle"), "error": str(error),
                                         "source_code_assets": None, "references": [], "complete": False}
            attempted.append(candidate["id"])
            continue
        checked[candidate["id"]] = {
            "checked_at": now.isoformat(), "name": candidate.get("name"), "handle": candidate["handle"],
            "error": None, "source_code_assets": len(dossier["source_code_assets"]),
            "references": [asset.get("reference") or asset.get("asset_identifier")
                            for asset in dossier["source_code_assets"]],
            "complete": dossier["completeness"]["complete"],
        }
        attempted.append(candidate["id"])

    _save_json(state_path, state)
    shortlist = sorted(
        ({"id": key, **value} for key, value in checked.items() if (value.get("source_code_assets") or 0) > 0),
        key=lambda row: (row.get("name") or "").casefold())
    shortlist_path = directory / "source_candidates.json"
    _save_json(shortlist_path, {
        "schema_version": 1, "generated_at": now.isoformat(),
        "notice": ("Candidates only -- not verified or authorized targets. Read the actual program "
                    "policy and each dossier reference yourself before running `workspace clone`."),
        "candidates": shortlist,
    })
    return {"attempted": len(attempted), "remaining": max(0, len(pending) - len(attempted)),
            "total_known": len(opportunities), "already_checked": len(checked) - len(attempted),
            "source_eligible": len(shortlist), "stopped_early": stopped_early, "stop_reason": stop_reason,
            "state_file": str(state_path.resolve()), "shortlist_file": str(shortlist_path.resolve())}
