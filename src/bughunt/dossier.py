"""Read bounded HackerOne scope metadata without granting testing permission.

Only the documented Hacker API structured_scopes and scope_exclusions GET
endpoints are used: https://api.hackerone.com/hacker-resources/ . Asset strings
and instructions are untrusted data; they are never visited or executed here.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlsplit
from urllib.request import Request

from .hackerone import (
    AdapterError, HackerOneClient, MAX_RESPONSE_BYTES, _encodable, _http_error,
    _invalid, _reject_constant, _truncated, _unique_object,
)


_ORIGIN = "https://api.hackerone.com"
_RESOURCES = {"structured_scopes", "scope_exclusions"}
_RATINGS = {"none", "low", "medium", "high", "critical"}
# The documented Hacker API asset_type enum value for a declared source-code asset.
_SOURCE_ASSET_TYPES = {"SOURCE_CODE"}


def source_code_assets(dossier: dict) -> list[dict]:
    """Filter an already-fetched dossier's structured scopes to declared source-code assets.

    Reads only local, already-validated data -- no request is made here. A
    returned ``reference``/``asset_identifier`` is still the program's own
    unverified claim, not a URL BugHunt has visited; read it yourself before
    passing it to `workspace clone`.
    """
    return [record for record in dossier.get("structured_scopes", [])
            if record.get("asset_type") in _SOURCE_ASSET_TYPES]


def _handle(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", value):
        raise ValueError("Program handle must contain only letters, numbers, underscores, or hyphens")
    return value


def _endpoint(handle: str, resource: str) -> str:
    if resource not in _RESOURCES:
        raise _invalid("HackerOne dossier endpoint is not approved")
    return f"{_ORIGIN}/v1/hackers/programs/{_handle(handle)}/{resource}"


def _validate_url(value: object, handle: str, resource: str) -> tuple[str, int, int]:
    """Canonicalize the two exact endpoints before credentials reach a Request."""
    endpoint = _endpoint(handle, resource)
    if (not isinstance(value, str) or not value or "\\" in value or "#" in value
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)):
        raise _invalid("HackerOne dossier pagination URL is invalid")
    try:
        parts = urlsplit(value)
        if (parts.scheme != "https"
                or parts.netloc not in {"api.hackerone.com", "api.hackerone.com:443"}
                or parts.path != urlsplit(endpoint).path):
            raise ValueError
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
        fields = {}
        for key, item in pairs:
            if (resource != "structured_scopes" or key not in {"page[number]", "page[size]"}
                    or key in fields or not re.fullmatch(r"[1-9][0-9]{0,2}", item)
                    or int(item) > 100):
                raise ValueError
            fields[key] = int(item)
    except ValueError:
        raise _invalid("HackerOne dossier pagination URL is not an approved endpoint") from None
    number, size = fields.get("page[number]", 1), fields.get("page[size]", 25)
    if resource == "scope_exclusions":
        return endpoint, number, size
    return f"{endpoint}?page[number]={number}&page[size]={size}", number, size


def _text(value: object, *, nullable=False, nonempty=False) -> str | None:
    if value is None and nullable:
        return None
    if (not isinstance(value, str) or not _encodable(value)
            or (nonempty and not value.strip())):
        raise _invalid("HackerOne dossier record has an invalid text field")
    return value


def _date(value: object) -> str:
    value = _text(value, nonempty=True)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
    except ValueError:
        raise _invalid("HackerOne dossier record has an invalid date") from None
    return value


def _record(record: object, resource: str) -> dict:
    expected_type = "structured-scope" if resource == "structured_scopes" else "scope-exclusion"
    if (not isinstance(record, dict) or record.get("type") != expected_type
            or not isinstance(record.get("attributes"), dict)
            or not isinstance(record.get("id"), str)
            or not re.fullmatch(r"[0-9]{1,30}", record["id"])):
        raise _invalid("HackerOne dossier record has an invalid structure")
    attributes = record["attributes"]
    result = {"id": record["id"]}
    if resource == "scope_exclusions":
        for field in ("category", "details"):
            result[field] = _text(attributes.get(field), nullable=True)
        for field in ("created_at", "updated_at"):
            result[field] = _date(attributes[field]) if field in attributes else None
        return result
    for field in ("asset_identifier", "asset_type"):
        result[field] = _text(attributes.get(field), nonempty=True)
    for field in ("eligible_for_bounty", "eligible_for_submission"):
        if type(attributes.get(field)) is not bool:
            raise _invalid("HackerOne dossier record has an invalid eligibility field")
        result[field] = attributes[field]
    for field in ("instruction", "reference"):
        result[field] = _text(attributes.get(field), nullable=True)
    for field in ("created_at", "updated_at"):
        result[field] = _date(attributes.get(field))
    severity = _text(attributes.get("max_severity"))
    if severity not in _RATINGS:
        raise _invalid("HackerOne dossier record has an invalid severity")
    result["max_severity"] = severity
    for field in ("confidentiality_requirement", "integrity_requirement", "availability_requirement"):
        if field in attributes:
            value = _text(attributes[field])
            if value not in _RATINGS - {"critical"}:
                raise _invalid("HackerOne dossier record has an invalid impact requirement")
            result[field] = value
    return result


def _page(client: HackerOneClient, url: str, handle: str, resource: str) -> dict:
    url, number, size = _validate_url(url, handle, resource)
    # Reuse the existing client's credentials and transport: the default opener
    # disables environment proxies and redirects. No second credential store.
    request = Request(url, method="GET", headers={
        "Authorization": client._authorization,
        "Accept": "application/json",
        "User-Agent": "BugHunt/0.2 read-only-program-dossier",
    })
    try:
        with client._opener.open(request, timeout=20) as response:
            if response.getcode() != 200:
                raise _http_error(response.getcode(), response.headers)
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            truncated = len(raw) <= MAX_RESPONSE_BYTES and _truncated(response, raw)
    except HTTPError as error:
        failure = _http_error(error.code, error.headers)
        error.close()
        raise failure from None
    except (URLError, OSError, HTTPException):
        raise AdapterError("transient", "HackerOne API request failed temporarily",
                           retry_after_seconds=60) from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise _invalid("HackerOne API response exceeds the size limit")
    if truncated:
        raise AdapterError("transient", "HackerOne API response was cut off", retry_after_seconds=60)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                              parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise _invalid("HackerOne API returned invalid JSON") from None
    if not isinstance(document, dict) or not isinstance(document.get("data"), list):
        raise _invalid("HackerOne dossier response must contain a list")
    if resource == "structured_scopes" and len(document["data"]) > size:
        raise _invalid("HackerOne dossier response exceeds the requested page size")
    links = document.get("links", {})
    if not isinstance(links, dict):
        raise _invalid("HackerOne dossier response has invalid pagination links")
    next_url = links.get("next")
    if next_url is not None:
        if resource == "scope_exclusions":
            raise _invalid("HackerOne scope exclusions unexpectedly contain pagination")
        next_url, next_number, next_size = _validate_url(next_url, handle, resource)
        if next_number <= number:
            raise _invalid("HackerOne dossier returned a pagination loop")
        if next_number != number + 1 or next_size != size:
            raise _invalid("HackerOne dossier pagination would skip or change pages")
    # A full page with no explicit terminal marker may have omitted its cursor.
    # Preserve that uncertainty instead of calling the scope collection complete.
    ambiguous = (resource == "structured_scopes" and len(document["data"]) == size
                 and "next" not in links)
    return {"records": [_record(item, resource) for item in document["data"]],
            "next_url": next_url, "ambiguous": ambiguous}


def _extend_unique(records: list, seen: dict, incoming: list) -> None:
    for record in incoming:
        previous = seen.get(record["id"])
        if previous is not None and previous != record:
            raise _invalid("HackerOne dossier contains conflicting duplicate records")
        if previous is None:
            records.append(record)
            seen[record["id"]] = record


def fetch_program_dossier(client: HackerOneClient, handle: str, max_pages=3) -> dict:
    """Collect a local review dossier; never visit assets or authorize testing.

    ``max_pages`` bounds structured-scope requests (1..20); exclusions require
    one additional, unpaginated request. An error raises ``AdapterError`` and
    returns no partial dossier. Completeness refers only to API collection;
    policy and actual authorization always need separate review.
    """
    handle = _handle(handle)
    if type(max_pages) is not int or not 1 <= max_pages <= 20:
        raise ValueError("max_pages must be an integer from 1 to 20")
    url = _endpoint(handle, "structured_scopes") + "?page[number]=1&page[size]=100"
    records, seen = [], {}
    pages_fetched, ambiguous = 0, False
    while url is not None and pages_fetched < max_pages:
        page = _page(client, url, handle, "structured_scopes")
        _extend_unique(records, seen, page["records"])
        pages_fetched += 1
        url, ambiguous = page["next_url"], page["ambiguous"]
    exclusions_page = _page(client, _endpoint(handle, "scope_exclusions"), handle, "scope_exclusions")
    exclusions = []
    _extend_unique(exclusions, {}, exclusions_page["records"])
    complete = url is None and not ambiguous
    scope_status = {"complete": complete, "pages_fetched": pages_fetched, "next_url": url,
                    "incomplete_reason": ("page_limit" if url is not None else
                                          "missing_pagination" if ambiguous else None)}
    return {
        "schema_version": 1,
        "source": "hackerone",
        "handle": handle,
        "program_url": "https://hackerone.com/" + handle,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "structured_scopes": records,
        "scope_exclusions": exclusions,
        "source_code_assets": source_code_assets({"structured_scopes": records}),
        "completeness": {"complete": complete, "structured_scopes": scope_status,
                         "scope_exclusions": {"complete": True, "pages_fetched": 1}},
        "review_needed": True,
        "testing_authorized": False,
        "automation_allowed": False,
        "review_note": ("Review the current program policy, asset instructions, exclusions, "
                        "and automation rules before any testing. Scope exclusions describe "
                        "report categories excluded from rewards, not an asset allowlist."),
    }
