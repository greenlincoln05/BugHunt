"""Local hard spend cap for paid model calls.

The API account is the real source of truth for credits, but it can only fail
*after* money is spent. This ledger is a circuit breaker that runs before the
call: once the configured request cap is used up, BugHunt refuses to make
another paid call. Accounting is deliberately pessimistic -- a request is
reserved and persisted *before* it is sent, so a crash mid-request still counts
as spent and the cap can only trip early, never late. Reads and writes happen
under an OS file lock, so concurrent runs cannot both spend the last request.

This is a speed bump against mistakes and runaway agents, not a security
boundary against someone with your file access: the real backstop is a spend
limit on the provider-side project. State lives under ``gate_state_dir()``
(never the current directory) and stores no credentials.

Requests are the enforced unit because they are known before the call. Token
counts reported by the API are recorded afterward and can carry an optional cap.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .fsutil import file_lock, gate_state_dir, write_json_atomic

MAX_CAP = 1_000_000
MAX_TOKEN_CAP = 1_000_000_000
KEEP = object()  # sentinel: leave the existing token cap unchanged
_HISTORY_LIMIT = 50


class BudgetExhausted(ValueError):
    """Raised instead of making a paid call the local cap does not allow."""


def default_ledger_path() -> Path:
    return gate_state_dir() / "model_budget.json"


def _resolve(path) -> Path:
    return Path(path) if path is not None else default_ledger_path()


def _now(clock):
    return (clock() if clock is not None else datetime.now(timezone.utc)).isoformat()


def _int(value, limit=MAX_CAP, allow_none=False):
    if value is None:
        return allow_none
    return type(value) is int and 0 <= value <= limit


def _load(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        import json
        ledger = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"Budget ledger at {path} is unreadable; fix or remove it deliberately: {error}") from error
    if (not isinstance(ledger, dict) or "max_tokens" not in ledger
            or not _int(ledger.get("max_requests")) or not _int(ledger.get("requests_used"))
            or not _int(ledger.get("tokens_used"), MAX_TOKEN_CAP)
            or not _int(ledger["max_tokens"], MAX_TOKEN_CAP, allow_none=True)
            or not isinstance(ledger.get("history", []), list)):
        raise ValueError(f"Budget ledger at {path} has an invalid shape; fix or remove it deliberately")
    ledger.setdefault("history", [])
    return ledger


def _cap(value, label, limit=MAX_CAP):
    if type(value) is not int or not 0 <= value <= limit:
        raise ValueError(f"{label} must be an integer between 0 and {limit}")
    return value


def _event(ledger, clock, **fields):
    ledger["history"] = ledger["history"][-(_HISTORY_LIMIT - 1):] + [{"at": _now(clock), **fields}]


def _status(ledger) -> dict:
    if ledger is None:
        return {"configured": False, "max_requests": 0, "requests_used": 0, "requests_remaining": 0,
                "tokens_used": 0, "max_tokens": None, "tokens_remaining": None,
                "message": "No budget set; paid calls are refused. Run `model budget set --max-requests N`."}
    token_room = None if ledger["max_tokens"] is None else max(0, ledger["max_tokens"] - ledger["tokens_used"])
    return {"configured": True, "max_requests": ledger["max_requests"], "requests_used": ledger["requests_used"],
            "requests_remaining": max(0, ledger["max_requests"] - ledger["requests_used"]),
            "tokens_used": ledger["tokens_used"], "max_tokens": ledger["max_tokens"], "tokens_remaining": token_room}


def status(*, path=None) -> dict:
    return _status(_load(_resolve(path)))


def set_budget(max_requests, *, max_tokens=KEEP, path=None, clock=None) -> dict:
    """Set the absolute caps, keeping what has already been used.

    Usage is never reset here, so lowering a cap below usage simply exhausts it.
    Omitting ``max_tokens`` keeps the existing token cap; pass ``None`` to clear it.
    """
    path = _resolve(path)
    max_requests = _cap(max_requests, "max_requests")
    if max_tokens is not KEEP and max_tokens is not None:
        max_tokens = _cap(max_tokens, "max_tokens", MAX_TOKEN_CAP)
    with file_lock(path):
        ledger = _load(path) or {"schema_version": 1, "requests_used": 0, "tokens_used": 0,
                                 "max_tokens": None, "history": []}
        previous = {"max_requests": ledger.get("max_requests"), "max_tokens": ledger["max_tokens"]}
        ledger["max_requests"] = max_requests
        if max_tokens is not KEEP:
            ledger["max_tokens"] = max_tokens
        _event(ledger, clock, event="cap_set", previous=previous,
               max_requests=max_requests, max_tokens=ledger["max_tokens"])
        write_json_atomic(path, ledger)
        return _status(ledger)


def reserve_request(*, path=None, clock=None) -> dict:
    """Spend one request from the cap *before* the call, or raise ``BudgetExhausted``."""
    path = _resolve(path)
    with file_lock(path):
        ledger = _load(path)
        if ledger is None:
            raise BudgetExhausted("No spend budget is set, so paid calls are refused. "
                                  "Run `model budget set --max-requests N`.")
        if ledger["requests_used"] >= ledger["max_requests"]:
            raise BudgetExhausted(f"Request budget exhausted ({ledger['requests_used']}/{ledger['max_requests']} used). "
                                  "Raise it deliberately with `model budget set` once more credits are loaded.")
        if ledger["max_tokens"] is not None and ledger["tokens_used"] >= ledger["max_tokens"]:
            raise BudgetExhausted(f"Token budget exhausted ({ledger['tokens_used']}/{ledger['max_tokens']} used).")
        ledger["requests_used"] += 1
        _event(ledger, clock, event="request_reserved")
        write_json_atomic(path, ledger)
        return _status(ledger)


def record_tokens(tokens, *, path=None) -> dict:
    """Add API-reported token usage after a call; ignores nonsense values."""
    path = _resolve(path)
    with file_lock(path):
        ledger = _load(path)
        if ledger is None or type(tokens) is not int or tokens < 0:
            return _status(ledger)
        ledger["tokens_used"] = min(MAX_TOKEN_CAP, ledger["tokens_used"] + tokens)
        write_json_atomic(path, ledger)
        return _status(ledger)
