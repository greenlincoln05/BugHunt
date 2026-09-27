"""Promote a saved HackerOne source dossier into an unverified program record.

This is offline bookkeeping. Neither the dossier nor promotion authorizes
testing; the source URL must be explicitly chosen from a bounty-eligible scope
entry and program verification remains a separate human action.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from .catalog import validate_program
from .scope import _parse_rule
from .workspace import _validate_https_git_url


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate dossier field: {key}")
        result[key] = value
    return result


def _source_url(value):
    value = _validate_https_git_url(value)
    parts = urlsplit(value)
    if (parts.query or parts.fragment
            or any(part in {"", ".", ".."} for part in parts.path.split("/")[1:])):
        raise ValueError("Source URL must be a clean HTTPS repository URL without query or fragment")
    _parse_rule(value)  # The catalog scope engine must be able to match it.
    return value


def _eligible_source(dossier, source_url):
    records = dossier.get("structured_scopes")
    if not isinstance(records, list):
        raise ValueError("Dossier has no structured scope list")
    for record in records:
        if (isinstance(record, dict) and record.get("asset_type") == "SOURCE_CODE"
                and record.get("eligible_for_bounty") is True
                and record.get("eligible_for_submission") is True
                and source_url in (record.get("asset_identifier"), record.get("reference"))):
            return True
    raise ValueError("Source URL is not a bounty-eligible SOURCE_CODE asset in this dossier")


def promote(store, opportunity_id, dossier_path: Path, source_url: str,
            payout_min: str, payout_max: str, *, clock):
    candidate = store.get("opportunities", opportunity_id)
    if (candidate.get("platform") != "hackerone" or candidate.get("offers_bounties") is not True
            or candidate.get("submission_state") != "open"):
        raise ValueError("Opportunity is not an open HackerOne bounty candidate")
    try:
        with Path(dossier_path).open("r", encoding="utf-8") as handle:
            dossier = json.load(handle, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ValueError("Dossier file is not valid UTF-8 JSON") from error
    if (not isinstance(dossier, dict) or dossier.get("schema_version") != 1
            or dossier.get("source") != "hackerone"
            or dossier.get("handle") != candidate.get("handle")
            or dossier.get("program_url") != candidate.get("program_url")
            or not isinstance(dossier.get("completeness"), dict)
            or dossier["completeness"].get("complete") is not True):
        raise ValueError("Dossier does not match this opportunity or is incomplete")
    source_url = _source_url(source_url)
    _eligible_source(dossier, source_url)
    program = validate_program({
        "id": candidate["id"], "name": candidate["name"],
        "platform": "hackerone", "program_url": candidate["program_url"],
        "status": "active", "scope": [source_url],
        "automation_allowed": False,
        "payout_min": payout_min, "payout_max": payout_max,
        "currency": candidate.get("currency") or "USD",
    })
    from .workflow import stamp
    with store.transaction():
        try:
            store.get("programs", program["id"])
        except ValueError:
            pass
        else:
            raise ValueError("Program already exists; promotion will not replace it")
        store.save("programs", program)
        store.audit("opportunity.promoted", "programs", program["id"], stamp(clock()), {
            "opportunity_id": opportunity_id, "source_url": source_url,
            "dossier": str(Path(dossier_path).resolve()), "verification_required": True,
        })
    return {"program": program, "verification_required": True,
            "testing_authorized": False}
