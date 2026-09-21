"""Credential-safe, opt-in OpenAI model metadata preflight; no inference calls.

Official endpoint and authentication documentation:
https://developers.openai.com/api/reference/resources/models/methods/retrieve
https://developers.openai.com/api/reference/overview#authentication
Access caveat: https://developers.openai.com/api/docs/guides/safety-checks/cybersecurity
"""

import json
import os
import re
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


MODELS_URL = "https://api.openai.com/v1/models/"
MAX_RESPONSE_BYTES = 64 * 1024
REQUEST_TIMEOUT_SECONDS = 20
_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,511}\Z")
_NOTICE = (
    "A listed or retrievable model is not proof of Trusted Access approval or inference permissions. "
    "Confirm the approved identity, organization/project, model, and API surface separately. "
    "This check sends no inference or generation requests and never selects a fallback model."
)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _present(value):
    return isinstance(value, str) and bool(value.strip())


def _header_value(value, maximum):
    # Header and exception output must never become a path for leaking a key.
    return (isinstance(value, str) and 0 < len(value) <= maximum
            and all(33 <= ord(character) <= 126 for character in value))


def _failure(result, status, message, http_status=None):
    result.update(status=status, message=message, http_status=http_status)
    if result["network_checked"]:
        result["model_retrievable"] = False
    return result


def _http_failure(result, status):
    # Never return error bodies, response headers, exception text, or account IDs.
    if status == 401:
        return _failure(result, "authentication_failed", "OpenAI returned HTTP 401; authentication was rejected.", status)
    if status == 403:
        return _failure(result, "forbidden", "OpenAI returned HTTP 403; this request was forbidden.", status)
    if status == 404:
        return _failure(result, "not_found_or_inaccessible", "OpenAI returned HTTP 404; the configured model was not found or is inaccessible to this credential context.", status)
    if status == 429:
        return _failure(result, "rate_limited", "OpenAI returned HTTP 429; a rate or quota limit prevented the check. No retry was made.", status)
    if isinstance(status, int) and 300 <= status <= 399:
        return _failure(result, "redirect_blocked", "OpenAI returned a redirect; it was not followed.", status)
    if isinstance(status, int) and 500 <= status <= 599:
        return _failure(result, "service_unavailable", "OpenAI returned a server error; retry the check later.", status)
    code = status if type(status) is int and 100 <= status <= 599 else None
    return _failure(result, "http_error", "The model endpoint returned an unexpected HTTP status.", code)


def _unique_object(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON field")
        document[key] = value
    return document


def _reject_constant(value):
    raise ValueError("invalid JSON constant")


def model_readiness(environ=None, check_access=False, opener=None):
    """Return redacted configuration flags and an optional model-metadata check.

    ``environ`` defaults to the current process environment. ``check_access=True``
    permits exactly one GET for the explicit ``BUGHUNT_OPENAI_MODEL``; no model
    is chosen automatically. An injected trusted test ``opener`` exposes
    ``open(request, timeout=...)``. The default transport blocks redirects and
    environment proxies. No keys, model values, or account IDs are returned,
    printed, persisted, or included in exception messages.
    """
    environment = os.environ if environ is None else environ
    key = environment.get("OPENAI_API_KEY")
    model = environment.get("BUGHUNT_OPENAI_MODEL")
    organization = environment.get("OPENAI_ORG_ID")
    project = environment.get("OPENAI_PROJECT_ID")
    result = {
        "api_key_present": _present(key), "model_configured": _present(model),
        "organization_id_present": _present(organization), "project_id_present": _present(project),
        "check_requested": check_access is True, "network_checked": False,
        "model_retrievable": None, "http_status": None, "status": "not_checked",
        "message": "Configuration presence only; no live model check was requested.",
        "trusted_access_approval": "not_verified", "inference_permissions": "not_verified",
        "inference_requests": 0, "fallback_selected": False, "notice": _NOTICE,
    }
    if check_access is not True:
        return result
    if not result["api_key_present"] or not result["model_configured"]:
        return _failure(result, "configuration_missing",
                        "Set OPENAI_API_KEY and an explicit BUGHUNT_OPENAI_MODEL locally before checking access.")
    if (not _header_value(key, 8192) or not _MODEL_ID.fullmatch(model)
            or (organization not in (None, "") and not _header_value(organization, 1024))
            or (project not in (None, "") and not _header_value(project, 1024))):
        return _failure(result, "configuration_invalid",
                        "The local key, model ID, or optional organization/project configuration is invalid; values are withheld.")
    url = MODELS_URL + quote(model, safe="")
    headers = {"Authorization": "Bearer " + key, "Accept": "application/json",
               "User-Agent": "BugHunt/0.2 read-only-model-preflight"}
    if organization:
        headers["OpenAI-Organization"] = organization
    if project:
        headers["OpenAI-Project"] = project
    request = Request(url, method="GET", headers=headers)
    result["network_checked"] = True
    try:
        transport = opener if opener is not None else build_opener(ProxyHandler({}), _NoRedirect())
        with transport.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            status = response.getcode()
            if status != 200:
                return _http_failure(result, status)
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE_BYTES:
                return _failure(result, "invalid_response", "The model endpoint response exceeded the size limit or had an invalid format.", 200)
            remaining = getattr(response, "length", None)
            declared = response.headers.get("Content-Length") if getattr(response, "headers", None) is not None else None
            if ((type(remaining) is int and remaining > 0)
                    or (declared is not None and (not isinstance(declared, str)
                        or not re.fullmatch(r"[0-9]{1,12}", declared.strip())
                        or len(raw) != int(declared.strip())))):
                return _failure(result, "invalid_response", "The model endpoint response was incomplete.", 200)
    except HTTPError as error:
        failure = _http_failure(result, error.code)
        error.close()
        return failure
    except (URLError, OSError, HTTPException):
        return _failure(result, "network_error", "The model metadata request failed; no response details or credentials are exposed.")
    except Exception:
        # Transport failures can contain the complete request, including headers.
        return _failure(result, "network_error", "The model metadata check could not complete; error details are withheld.")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                              parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError):
        return _failure(result, "invalid_response", "The model endpoint returned invalid JSON metadata.", 200)
    if not isinstance(document, dict) or document.get("object") != "model" or document.get("id") != model:
        return _failure(result, "invalid_response", "The model endpoint did not return metadata matching the configured model ID.", 200)
    result.update(status="retrievable", http_status=200, model_retrievable=True,
                  message="Metadata for the explicitly configured model was retrieved. No inference access or Trusted Access approval was verified.")
    return result
