"""Local hard spend cap for paid model calls.

The API account is the real source of truth for credits, but it can only fail
*after* money is spent. This ledger is a circuit breaker that runs before the
call: once the configured request cap is used up, BugHunt refuses to make
another paid call, no matter who or what asks. Accounting is deliberately
pessimistic -- a request is reserved and persisted *before* it is sent, so a
crash mid-request still counts as spent and the cap can only trip early, never
late.

Requests are the enforced unit because they are known before the call. Token
counts reported by the API are recorded afterward for visibility and can also
carry an optional cap. Stores no credentials.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

DEFAULT_LEDGER_PATH = Path(".bughunt/model_budget.json")
MAX_CAP = 1_000_000


class BudgetExhausted(ValueError):
    """Raised instead of making a paid call the local cap does not allow."""


def _now(clock):
    return (clock() if clock is not None else datetime.now(timezone.utc)).isoformat()


def _write_atomic(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def _load(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        ledger = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"Budget ledger at {path} is unreadable; fix or remove it deliberately: {error}") from error
    counters = ("max_requests", "requests_used", "tokens_used")
    if (not isinstance(ledger, dict) or any(type(ledger.get(key)) is not int or ledger[key] < 0 for key in counters)
            or ledger.get("max_tokens") is not None and (type(ledger["max_tokens"]) is not int or ledger["max_tokens"] < 0)):
        raise ValueError(f"Budget ledger at {path} has an invalid shape; fix or remove it deliberately")
    return ledger


def _cap(value, label):
    if type(value) is not int or not 0 <= value <= MAX_CAP:
        raise ValueError(f"{label} must be an integer between 0 and {MAX_CAP}")
    return value


def set_budget(max_requests, *, max_tokens=None, path=DEFAULT_LEDGER_PATH, clock=None) -> dict:
    """Set the absolute caps, keeping what has already been used.

    Raising a cap is a deliberate act (you decided to load more credits); usage
    is never reset here, so lowering the cap below usage simply exhausts it.
    """
    path = Path(path)
    max_requests = _cap(max_requests, "max_requests")
    if max_tokens is not None:
        max_tokens = _cap(max_tokens, "max_tokens")
    ledger = _load(path) or {"schema_version": 1, "requests_used": 0, "tokens_used": 0, "history": []}
    ledger.update(max_requests=max_requests, max_tokens=max_tokens)
    ledger["history"] = (ledger.get("history") or [])[-49:] + [
        {"at": _now(clock), "event": "cap_set", "max_requests": max_requests, "max_tokens": max_tokens}]
    _write_atomic(path, ledger)
    return status(path=path)


def status(*, path=DEFAULT_LEDGER_PATH) -> dict:
    path = Path(path)
    ledger = _load(path)
    if ledger is None:
        return {"configured": False, "max_requests": 0, "requests_used": 0, "requests_remaining": 0,
                "tokens_used": 0, "max_tokens": None,
                "message": "No budget set; paid calls are refused. Run `model budget set --max-requests N`."}
    remaining = max(0, ledger["max_requests"] - ledger["requests_used"])
    token_room = None if ledger["max_tokens"] is None else max(0, ledger["max_tokens"] - ledger["tokens_used"])
    return {"configured": True, "max_requests": ledger["max_requests"], "requests_used": ledger["requests_used"],
            "requests_remaining": remaining, "tokens_used": ledger["tokens_used"],
            "max_tokens": ledger["max_tokens"], "tokens_remaining": token_room}


def reserve_request(*, path=DEFAULT_LEDGER_PATH, clock=None) -> dict:
    """Spend one request from the cap *before* the call, or raise ``BudgetExhausted``."""
    path = Path(path)
    ledger = _load(path)
    if ledger is None:
        raise BudgetExhausted("No spend budget is set, so paid calls are refused. Run `model budget set --max-requests N`.")
    if ledger["requests_used"] >= ledger["max_requests"]:
        raise BudgetExhausted(f"Request budget exhausted ({ledger['requests_used']}/{ledger['max_requests']} used). "
                              "Raise it deliberately with `model budget set` once more credits are loaded.")
    if ledger["max_tokens"] is not None and ledger["tokens_used"] >= ledger["max_tokens"]:
        raise BudgetExhausted(f"Token budget exhausted ({ledger['tokens_used']}/{ledger['max_tokens']} used).")
    ledger["requests_used"] += 1
    ledger["history"] = (ledger.get("history") or [])[-49:] + [{"at": _now(clock), "event": "request_reserved"}]
    _write_atomic(path, ledger)
    return status(path=path)


def record_tokens(tokens, *, path=DEFAULT_LEDGER_PATH) -> dict:
    """Add API-reported token usage after a call; ignores nonsense values."""
    path = Path(path)
    ledger = _load(path)
    if ledger is None or type(tokens) is not int or tokens < 0:
        return status(path=path)
    ledger["tokens_used"] += tokens
    _write_atomic(path, ledger)
    return status(path=path)
