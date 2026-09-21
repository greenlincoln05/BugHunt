"""Validate a manually supplied, normalized catalog of bounty programs.

This module is an adapter boundary for local JSON imports. It neither implements
platform APIs nor accepts platform credentials. Importing a record does not
verify the program's current status, scope, or permission to automate testing;
verification fields are declarations supplied by the catalog author.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlsplit


_PLATFORMS = {"hackerone", "bugcrowd", "intigriti", "manual"}
_STATUSES = {"active", "paused", "closed"}
_REQUIRED = {"id", "name", "platform", "program_url", "status", "scope"}
_OPTIONAL = {
    "automation_allowed",
    "excluded_scope",
    "verified_at",
    "verification_expires_at",
    "blocked_reason",
    "payout_min",
    "payout_max",
    "currency",
}
_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_AMOUNT = re.compile(r"[0-9]+(?:\.[0-9]+)?\Z")


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")
    return value.strip()


def _strings(value: object, field: str, *, required: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list of strings")
    if required and not value:
        raise ValueError(f"{field} must contain at least one entry")
    return [_text(item, f"{field}[{index}]") for index, item in enumerate(value)]


def _url(value: object) -> str:
    value = _text(value, "program_url")
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127
           for character in value):
        raise ValueError("program_url must not contain whitespace or control characters")
    try:
        parts = urlsplit(value)
        # Accessing port also validates malformed and out-of-range port values.
        port = parts.port
        if (parts.scheme not in {"http", "https"} or not parts.hostname
                or parts.username is not None or parts.password is not None
                or "\\" in parts.netloc or port == 0):
            raise ValueError
    except ValueError as error:
        raise ValueError("program_url must be an HTTP(S) URL without user information") from error
    return value


def _timestamp(value: object, field: str) -> tuple[str | None, datetime | None]:
    if value is None:
        return None, None
    if not isinstance(value, str) or "T" not in value:
        raise ValueError(f"{field} must be a timezone-aware ISO 8601 timestamp or null")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        parsed = parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError) as error:
        raise ValueError(f"{field} must be a timezone-aware ISO 8601 timestamp or null") from error
    return parsed.isoformat().replace("+00:00", "Z"), parsed


def validate_program(data: dict) -> dict:
    """Return an independent normalized record, or raise ``ValueError``.

    Missing permission and verification fields have conservative defaults. The
    returned timestamps are UTC strings; this validates their syntax and order,
    not the truth or freshness of an author's verification claim.
    """
    if not isinstance(data, dict):
        raise ValueError("each program must be an object")
    if any(not isinstance(key, str) for key in data):
        raise ValueError("program field names must be strings")
    unknown = set(data) - _REQUIRED - _OPTIONAL
    if unknown:
        raise ValueError(f"unknown program field(s): {', '.join(sorted(unknown))}")
    missing = _REQUIRED - set(data)
    if missing:
        raise ValueError(f"missing program field(s): {', '.join(sorted(missing))}")

    program_id = _text(data["id"], "id")
    if not _SLUG.fullmatch(program_id):
        raise ValueError("id must be a lowercase slug containing letters, digits, and single hyphens")
    platform = _text(data["platform"], "platform")
    if platform not in _PLATFORMS:
        raise ValueError(f"platform must be one of: {', '.join(sorted(_PLATFORMS))}")
    status = _text(data["status"], "status")
    if status not in _STATUSES:
        raise ValueError(f"status must be one of: {', '.join(sorted(_STATUSES))}")
    automation = data.get("automation_allowed", False)
    if type(automation) is not bool:
        raise ValueError("automation_allowed must be a boolean")
    verified_at, verified = _timestamp(data.get("verified_at"), "verified_at")
    expires_at, expires = _timestamp(data.get("verification_expires_at"), "verification_expires_at")
    if verified is not None and expires is not None and expires <= verified:
        raise ValueError("verification_expires_at must be after verified_at")
    blocked_reason = data.get("blocked_reason")
    if blocked_reason is not None:
        blocked_reason = _text(blocked_reason, "blocked_reason")

    result = {
        "id": program_id,
        "name": _text(data["name"], "name"),
        "platform": platform,
        "program_url": _url(data["program_url"]),
        "status": status,
        "automation_allowed": automation,
        "scope": _strings(data["scope"], "scope", required=True),
        "excluded_scope": _strings(data.get("excluded_scope", []), "excluded_scope"),
        "verified_at": verified_at,
        "verification_expires_at": expires_at,
        "blocked_reason": blocked_reason,
    }
    for field in ("payout_min", "payout_max"):
        if field in data:
            value = data[field]
            if not isinstance(value, str) or not _AMOUNT.fullmatch(value):
                raise ValueError(f"{field} must be a nonnegative decimal string")
            result[field] = value
    if ("payout_min" in result and "payout_max" in result
            and Decimal(result["payout_min"]) > Decimal(result["payout_max"])):
        raise ValueError("payout_max must not be less than payout_min")
    if "currency" in data:
        currency = data["currency"]
        if not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency):
            raise ValueError("currency must be a three-letter uppercase currency code")
        result["currency"] = currency
    return result


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def load_catalog(path: str | Path) -> list[dict]:
    """Read a JSON array or ``{"programs": [...]}`` from a local file.

    An empty catalog is valid. Duplicate IDs, unknown envelope fields, and
    malformed records raise ``ValueError``. Filesystem errors propagate so a
    caller can distinguish inaccessible files from invalid catalog contents.
    """
    with Path(path).open(encoding="utf-8") as catalog_file:
        document = json.load(catalog_file, object_pairs_hook=_unique_object)
    if isinstance(document, dict):
        if set(document) != {"programs"}:
            raise ValueError("catalog object must contain only the programs field")
        document = document["programs"]
    if not isinstance(document, list):
        raise ValueError("catalog must be a program array or an object containing a programs array")
    programs = []
    seen = set()
    for index, data in enumerate(document):
        try:
            program = validate_program(data)
        except ValueError as error:
            raise ValueError(f"programs[{index}]: {error}") from error
        if program["id"] in seen:
            raise ValueError(f"duplicate program id: {program['id']}")
        seen.add(program["id"])
        programs.append(program)
    return programs


def rank_programs(
    programs: list[dict],
    min_payout: str = "50",
    max_payout: str = "200",
    currency: str = "USD",
    limit: int = 10,
) -> list[dict]:
    """Shortlist local records by closeness to a desired advertised payout range.

    Both advertised bounds and a matching currency are required. Closeness is
    the sum of the absolute differences between the desired and advertised
    endpoints; name and ID break ties deterministically. This does not verify
    permission to test, promise an award, or infer a company's size.
    """
    bounds = []
    for field, value in (("min_payout", min_payout), ("max_payout", max_payout)):
        if not isinstance(value, str) or not _AMOUNT.fullmatch(value):
            raise ValueError(f"{field} must be a positive finite decimal string")
        bound = Decimal(value)
        if not bound.is_finite() or bound <= 0:
            raise ValueError(f"{field} must be a positive finite decimal string")
        bounds.append(bound)
    minimum, maximum = bounds
    if minimum > maximum:
        raise ValueError("max_payout must not be less than min_payout")
    if not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency):
        raise ValueError("currency must be a three-letter uppercase currency code")
    if type(limit) is not int or limit < 1:
        raise ValueError("limit must be a positive integer")
    if not isinstance(programs, list):
        raise ValueError("programs must be a list")

    ranked = []
    seen = set()
    for source in programs:
        if isinstance(source, dict) and "verification_note" in source:
            fields = dict(source)
            note = fields.pop("verification_note")
            if note is not None and not isinstance(note, str):
                raise ValueError("verification_note must be a string or null")
            program = validate_program(fields)
            program["verification_note"] = note
        else:
            program = validate_program(source)
        if program["id"] in seen:
            raise ValueError(f"duplicate program id: {program['id']}")
        seen.add(program["id"])
        if (program["status"] != "active" or program["blocked_reason"] is not None
                or program.get("currency") != currency
                or "payout_min" not in program or "payout_max" not in program):
            continue
        low, high = Decimal(program["payout_min"]), Decimal(program["payout_max"])
        if low > maximum or high < minimum:
            continue
        distance = abs(low - minimum) + abs(high - maximum)
        program["shortlist_reason"] = (
            f"Imported {currency} {program['payout_min']}-{program['payout_max']} range "
            f"overlaps requested {currency} {min_payout}-{max_payout}; "
            "active record with no recorded block. Award and testing permission are unverified."
        )
        ranked.append((distance, program["name"].casefold(), program["id"], program))
    ranked.sort(key=lambda item: item[:3])
    return [item[3] for item in ranked[:limit]]
