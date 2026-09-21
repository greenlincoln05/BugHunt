"""Read public bounty-program metadata from the official HackerOne Hacker API.

Documentation: https://api.hackerone.com/hacker-resources/ and
https://api.hackerone.com/getting-started-hacker-api/ . Listing a program does
not establish its testing scope, automation permission, or likely payout.
"""

from __future__ import annotations

import base64
import json
import math
import os
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


PROGRAMS_URL = "https://api.hackerone.com/v1/hackers/programs?page[number]=1&page[size]=100"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class AdapterError(ValueError):
    """Sanitized failure suitable for local status reports and retry decisions."""

    def __init__(self, kind: str, message: str, retry_after_seconds: int | None = None):
        super().__init__(message)
        self.kind = kind
        self.retry_after_seconds = retry_after_seconds


def _invalid(message: str) -> AdapterError:
    return AdapterError("invalid_response", message)


def _validate_url(value: object) -> str:
    # Validate the original bytes before urlsplit can discard control characters.
    if (not isinstance(value, str) or not value or "\\" in value or "#" in value
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)):
        raise _invalid("HackerOne pagination URL is invalid")
    try:
        parts = urlsplit(value)
        if (parts.scheme != "https"
                or parts.netloc not in {"api.hackerone.com", "api.hackerone.com:443"}
                or parts.path != "/v1/hackers/programs"):
            raise ValueError
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
        seen = set()
        for key, item in pairs:
            if (key not in {"page[number]", "page[size]"} or key in seen
                    or not re.fullmatch(r"[1-9][0-9]{0,9}", item)
                    or (key == "page[size]" and int(item) > 100)):
                raise ValueError
            seen.add(key)
    except ValueError:
        raise _invalid("HackerOne pagination URL is not an approved programs endpoint") from None
    return value


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


MAX_RETRY_AFTER_SECONDS = 86400


def _truncated(response, raw: bytes) -> bool:
    """True when a Content-Length body ended early (http.client does not raise for read(amt))."""
    remaining = getattr(response, "length", None)
    if type(remaining) is int and remaining > 0:
        return True
    headers = getattr(response, "headers", None)
    declared = headers.get("Content-Length") if headers is not None else None
    return isinstance(declared, str) and declared.strip().isdigit() and len(raw) < int(declared.strip())


def _retry_after(value: object, minimum: int) -> int:
    if not isinstance(value, str):
        return minimum
    try:
        if re.fullmatch(r"[0-9]{1,10}", value.strip()):
            delay = int(value.strip())
        else:
            when = parsedate_to_datetime(value)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            delay = math.ceil((when - datetime.now(timezone.utc)).total_seconds())
        return min(max(minimum, delay), MAX_RETRY_AFTER_SECONDS)
    except (ValueError, TypeError, OverflowError):
        return minimum


def _http_error(status: int, headers) -> AdapterError:
    if status in {401, 403}:
        return AdapterError("authentication", "HackerOne credentials were rejected; check the API token")
    retry = headers.get("Retry-After") if headers is not None else None
    if status == 429:
        return AdapterError("rate_limit", "HackerOne API rate limit reached",
                            retry_after_seconds=_retry_after(retry, 3600))
    if 500 <= status <= 599:
        return AdapterError("transient", "HackerOne API is temporarily unavailable",
                            retry_after_seconds=_retry_after(retry, 60))
    return _invalid("HackerOne API returned an unexpected HTTP status")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("invalid JSON constant")


def _encodable(value: object) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _normalize(record: object) -> dict:
    if not isinstance(record, dict) or not isinstance(record.get("attributes"), dict):
        raise _invalid("HackerOne program record has an invalid structure")
    identifier = record.get("id")
    if (type(identifier) not in {str, int}
            or not re.fullmatch(r"[0-9]{1,30}", str(identifier))):
        raise _invalid("HackerOne program record has an invalid identifier")
    attributes = record["attributes"]
    handle = attributes.get("handle")
    if not isinstance(handle, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", handle):
        raise _invalid("HackerOne program record has an invalid handle")
    for field in ("name", "submission_state"):
        if not isinstance(attributes.get(field), str) or not attributes[field].strip():
            raise _invalid("HackerOne program record has invalid text fields")
    state = attributes.get("state")
    if state is not None and (not isinstance(state, str) or not state.strip()):
        raise _invalid("HackerOne program record has an invalid visibility")
    for field in ("offers_bounties", "fast_payments", "triage_active"):
        value = attributes.get(field)
        if value is not None and type(value) is not bool:
            raise _invalid("HackerOne program record has invalid boolean fields")
    currency = attributes.get("currency")
    if currency is not None:
        if not isinstance(currency, str) or not re.fullmatch(r"[A-Za-z]{3}", currency):
            raise _invalid("HackerOne program record has an invalid currency")
        currency = currency.upper()
    policy = attributes.get("policy")
    if policy is not None and not isinstance(policy, str):
        raise _invalid("HackerOne program record has an invalid policy")
    for value in (attributes["name"], attributes["submission_state"], state, policy):
        if isinstance(value, str) and not _encodable(value):
            raise _invalid("HackerOne program record has invalid text")
    return {
        "id": "h1-" + str(identifier),
        "handle": handle,
        "name": attributes["name"].strip(),
        "platform": "hackerone",
        "program_url": "https://hackerone.com/" + handle,
        "currency": currency,
        "policy": policy or "",
        "submission_state": attributes["submission_state"],
        "visibility": state,
        "offers_bounties": attributes.get("offers_bounties") is True,
        "fast_payments": attributes.get("fast_payments") is True,
        "triage_active": attributes.get("triage_active") is True,
        "automation_allowed": False,
        "verified_at": None,
        "payout_min": None,
        "payout_max": None,
    }


class HackerOneClient:
    """Read-only metadata client. An injected opener must expose ``open``.

    ``username`` is the API token identifier, not necessarily a profile handle.
    The default transport bypasses environment proxies and refuses redirects.
    """

    def __init__(self, username: str, api_token: str, *, opener=None):
        for value in (username, api_token):
            if (not isinstance(value, str) or not value or value != value.strip()
                    or any(ord(char) < 32 or ord(char) == 127 for char in value)):
                raise AdapterError("authentication", "Set HACKERONE_USERNAME and HACKERONE_API_TOKEN locally")
        if ":" in username:
            raise AdapterError("authentication", "HackerOne API token identifier must not contain a colon")
        encoded = base64.b64encode((username + ":" + api_token).encode("utf-8")).decode("ascii")
        self._authorization = "Basic " + encoded
        self._opener = opener if opener is not None else build_opener(ProxyHandler({}), _NoRedirect())

    @classmethod
    def from_environment(cls, *, environ=None, opener=None):
        environment = os.environ if environ is None else environ
        return cls(environment.get("HACKERONE_USERNAME", ""),
                   environment.get("HACKERONE_API_TOKEN", ""), opener=opener)

    def _page(self, url: str) -> dict:
        request = Request(_validate_url(url), method="GET", headers={
            "Authorization": self._authorization,
            "Accept": "application/json",
            "User-Agent": "BugHunt/0.2 read-only-program-discovery",
        })
        try:
            with self._opener.open(request, timeout=20) as response:
                status = response.getcode()
                if status != 200:
                    raise _http_error(status, response.headers)
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
            raise _invalid("HackerOne API response must contain a program list")
        links = document.get("links", {})
        if not isinstance(links, dict):
            raise _invalid("HackerOne API response has invalid pagination links")
        next_url = links.get("next")
        if next_url is not None:
            _validate_url(next_url)
        return {"programs": [_normalize(record) for record in document["data"]], "next_url": next_url}

    def list_programs(self, max_pages=3, start_url=None) -> dict:
        """Return eligible candidates and a continuation cursor when capped."""
        if type(max_pages) is not int or not 1 <= max_pages <= 20:
            raise ValueError("max_pages must be an integer from 1 to 20")
        url = _validate_url(PROGRAMS_URL if start_url is None else start_url)
        programs, seen_urls, seen_ids = [], set(), set()
        pages_fetched = 0
        while url is not None and pages_fetched < max_pages:
            seen_urls.add(url)
            page = self._page(url)
            pages_fetched += 1
            for program in page["programs"]:
                if (program["visibility"] == "public_mode"
                        and program["submission_state"] == "open"
                        and program["offers_bounties"] is True
                        and program["id"] not in seen_ids):
                    programs.append(program)
                    seen_ids.add(program["id"])
            url = page["next_url"]
            if url in seen_urls:
                raise _invalid("HackerOne API returned a pagination loop")
        return {"programs": programs, "next_url": url, "pages_fetched": pages_fetched}
