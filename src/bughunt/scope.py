"""Offline, fail-closed scope decisions for explicitly authorized HTTP targets.

``check_scope`` never resolves names or makes network requests. A program must be
active, explicitly allow automation (the boolean ``True``), and have UTC,
timezone-aware verification timestamps bracketing the current time. Every scope
entry is validated, including exclusions; invalid policy data denies all targets.

Matching semantics:
* ``example.com`` matches that exact host over HTTP or HTTPS, on any port.
* ``*.example.com`` matches one or more subdomain labels, never the bare host.
* ``https://example.com/api`` matches only that scheme and effective port, and
  either ``/api`` or descendants under ``/api/``. Default ports are equivalent;
  trailing slashes on a scope prefix do not change its meaning. A URL origin
  without a path covers every path on that origin. Queries never affect scope.
* Explicit IP addresses are exact host matches; IP wildcards are invalid.
* Any matching exclusion overrides any inclusion.

Hosts are lowercased and IDNA-encoded; IPv6 addresses are compressed. Paths are
UTF-8 decoded and requoted for canonical comparison. To avoid disagreements
between URL parsers and servers, credentials, fragments, whitespace/control
characters, backslashes, trailing-dot hosts, ambiguous numeric hosts, malformed
percent escapes, encoded path separators, encoded percent signs, repeated path
slashes, semicolons, and dot path segments are rejected, not repaired. This is
deliberately conservative. Queries are preserved, with escape hex uppercased.
This is a URL policy check, not proof of server-side routing or DNS ownership;
an executor must check redirects separately and enforce its own network policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import re
from urllib.parse import quote, unquote, urlsplit, urlunsplit


_ESCAPE = re.compile(r"%([0-9a-fA-F]{2})")
_BAD_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


@dataclass(frozen=True)
class _Target:
    url: str
    scheme: str
    host: str
    port: int
    path: str


@dataclass(frozen=True)
class _Rule:
    host: str
    wildcard: bool = False
    scheme: str | None = None
    port: int | None = None
    path: str = "/"

    def matches(self, target: _Target) -> bool:
        if self.wildcard:
            host_matches = target.host.endswith("." + self.host)
        else:
            host_matches = target.host == self.host
        if not host_matches:
            return False
        if self.scheme is None:
            return True
        if (target.scheme, target.port) != (self.scheme, self.port):
            return False
        prefix = self.path.rstrip("/")
        return not prefix or target.path == prefix or target.path.startswith(prefix + "/")


def _reject_unsafe_text(value: str) -> None:
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("Whitespace and control characters are not allowed")
    if "\\" in value:
        raise ValueError("Backslashes are not allowed")


def _canonical_host(raw_host: str) -> str:
    if not raw_host or raw_host.endswith(".") or "%" in raw_host:
        raise ValueError("Host is missing or ambiguous")
    try:
        return str(ipaddress.ip_address(raw_host))
    except ValueError:
        pass
    try:
        host = raw_host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as error:
        raise ValueError("Host is invalid") from error
    labels = host.split(".")
    if len(host) > 253 or any(not _DNS_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Host is invalid")
    # Browsers and HTTP stacks disagree about shortened, octal, hexadecimal,
    # and integer IPv4 literals. Only ipaddress-approved literals are accepted.
    if all(re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", label) for label in labels):
        raise ValueError("Ambiguous numeric host is not allowed")
    if labels[-1].isdigit():
        raise ValueError("Numeric final DNS label is not allowed")
    return host


def _canonical_path(raw_path: str) -> str:
    path = raw_path or "/"
    if _BAD_ESCAPE.search(path):
        raise ValueError("Path has malformed percent escapes")
    if re.search(r"%(?:2f|5c|25)", path, re.IGNORECASE):
        raise ValueError("Encoded separators or percent signs are not allowed in paths")
    try:
        decoded = unquote(path, encoding="utf-8", errors="strict")
    except UnicodeError as error:
        raise ValueError("Path is not valid UTF-8") from error
    _reject_unsafe_text(decoded)
    if "//" in decoded or ";" in decoded:
        raise ValueError("Ambiguous path separators are not allowed")
    if any(segment in (".", "..") for segment in decoded.split("/")):
        raise ValueError("Dot path segments are not allowed")
    try:
        return quote(decoded, safe="/:@!$&'()*+,=-._~", encoding="utf-8", errors="strict")
    except UnicodeError as error:
        raise ValueError("Path is not valid UTF-8") from error


def _parse_target(value: str) -> _Target:
    if not isinstance(value, str) or not value:
        raise ValueError("Target must be a nonempty URL")
    _reject_unsafe_text(value)
    if "#" in value:
        raise ValueError("URL fragments are not allowed")
    try:
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("Only absolute HTTP and HTTPS URLs are allowed")
        if "@" in parts.netloc or parts.username is not None or parts.password is not None:
            raise ValueError("URL credentials are not allowed")
        if parts.netloc.endswith(":"):
            raise ValueError("Empty URL port is not allowed")
        host = _canonical_host(parts.hostname or "")
        default_port = 443 if parts.scheme == "https" else 80
        port = parts.port if parts.port is not None else default_port
        if not 1 <= port <= 65535:
            raise ValueError("URL port is out of range")
        # urlsplit accepts text after a closing IPv6 bracket on some runtimes.
        if parts.netloc.startswith("["):
            close = parts.netloc.find("]")
            suffix = parts.netloc[close + 1 :]
            if close < 0 or (suffix and not re.fullmatch(r":[0-9]+", suffix)):
                raise ValueError("IPv6 authority is invalid")
        elif "[" in parts.netloc or "]" in parts.netloc:
            raise ValueError("URL authority is invalid")
        path = _canonical_path(parts.path)
        if _BAD_ESCAPE.search(parts.query):
            raise ValueError("Query has malformed percent escapes")
        if re.search(r"%(?:0[0-9a-f]|1[0-9a-f]|7f)", parts.query, re.IGNORECASE):
            raise ValueError("Encoded control characters are not allowed in queries")
        query = _ESCAPE.sub(lambda match: "%" + match.group(1).upper(), parts.query)
        query = quote(query, safe="%!$&'()*+,-./:;=?@_~", encoding="utf-8", errors="strict")
        authority = "[" + host + "]" if ":" in host else host
        if port != default_port:
            authority += ":" + str(port)
        url = urlunsplit((parts.scheme, authority, path, query, ""))
        return _Target(url, parts.scheme, host, port, path)
    except (UnicodeError, ValueError) as error:
        raise ValueError(str(error)) from error


def _parse_rule(value: str) -> _Rule:
    if not isinstance(value, str) or not value:
        raise ValueError("Scope entries must be nonempty strings")
    _reject_unsafe_text(value)
    if "://" in value:
        if "?" in value:
            raise ValueError("Scope URL entries cannot have queries")
        target = _parse_target(value)
        return _Rule(target.host, scheme=target.scheme, port=target.port, path=target.path)
    wildcard = value.startswith("*.")
    raw_host = value[2:] if wildcard else value
    if raw_host.startswith("[") and raw_host.endswith("]"):
        raw_host = raw_host[1:-1]
    host = _canonical_host(raw_host)
    if wildcard:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("IP wildcard entries are not allowed")
    return _Rule(host, wildcard=wildcard)


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str) or "T" not in value:
        raise ValueError("Verification timestamps must be ISO 8601 UTC strings")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("Verification timestamp is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("Verification timestamps must explicitly use UTC")
    return parsed


def check_scope(program: dict, target_url: str, now: datetime | None = None) -> dict:
    """Return ``allowed``, a human-readable ``reason``, and ``normalized_url``.

    Invalid target URLs have ``normalized_url=None``. Other denials return the
    normalized URL for inspection. The result grants no authorization beyond
    the supplied policy; verification of the source policy is a separate step.
    """
    try:
        target = _parse_target(target_url)
    except ValueError as error:
        return {"allowed": False, "reason": f"Invalid target URL: {error}.", "normalized_url": None}

    def result(allowed: bool, reason: str) -> dict:
        return {"allowed": allowed, "reason": reason, "normalized_url": target.url}

    if not isinstance(program, dict):
        return result(False, "Program policy must be an object.")
    if program.get("status") != "active":
        return result(False, "Program is not active.")
    if program.get("automation_allowed") is not True:
        return result(False, "Automated testing is not explicitly allowed.")
    if program.get("blocked_reason") not in (None, ""):
        return result(False, "Program has an unresolved policy block.")
    current = now if now is not None else datetime.now(timezone.utc)
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        return result(False, "Current time must be timezone-aware.")
    try:
        verified = _parse_time(program.get("verified_at"))
        expires = _parse_time(program.get("verification_expires_at"))
    except ValueError as error:
        return result(False, f"Policy verification is invalid: {error}.")
    if verified > current:
        return result(False, "Policy verification is dated in the future.")
    if expires <= verified or current >= expires:
        return result(False, "Policy verification has expired or has an invalid validity period.")
    scope = program.get("scope")
    excluded_scope = program.get("excluded_scope")
    if not isinstance(scope, list) or not scope or not isinstance(excluded_scope, list):
        return result(False, "Scope must be a nonempty list and excluded_scope must be a list.")
    try:
        inclusions = [_parse_rule(entry) for entry in scope]
        exclusions = [_parse_rule(entry) for entry in excluded_scope]
    except ValueError as error:
        return result(False, f"Program scope is invalid: {error}.")
    if any(rule.matches(target) for rule in exclusions):
        return result(False, "Target matches an explicit scope exclusion.")
    if not any(rule.matches(target) for rule in inclusions):
        return result(False, "Target is outside the verified program scope.")
    return result(True, "Target is within the program's verified scope.")
