"""All model-access checks use fake responses; no live API or inference calls."""

import io
import json
import os
import unittest
from http.client import IncompleteRead
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request

from bughunt.model_access import MAX_RESPONSE_BYTES, MODELS_URL, _NoRedirect, model_readiness


KEY = "local-fixture-key"
MODEL = "explicit-fixture-model"
ORG = "org-fixture-private"
PROJECT = "proj-fixture-private"


class Response(io.BytesIO):
    def __init__(self, document=None, *, status=200, headers=None):
        if document is None:
            document = {"id": MODEL, "object": "model", "created": 1, "owned_by": "fixture"}
        super().__init__(document if isinstance(document, bytes) else json.dumps(document).encode("utf-8"))
        self.status = status
        self.headers = headers or {}
        self.read_limits = []

    def getcode(self):
        return self.status

    def read(self, size=-1):
        self.read_limits.append(size)
        return super().read(size)


class Opener:
    def __init__(self, response=None):
        self.response = response
        self.requests = []

    def open(self, request, *, timeout):
        self.requests.append((request, timeout))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class ModelAccessTests(unittest.TestCase):
    def environment(self, **extra):
        return {"OPENAI_API_KEY": KEY, "BUGHUNT_OPENAI_MODEL": MODEL, **extra}

    def assert_redacted(self, result):
        serialized = json.dumps(result)
        for value in (KEY, MODEL, ORG, PROJECT):
            self.assertNotIn(value, serialized)
        self.assertEqual(result["trusted_access_approval"], "not_verified")
        self.assertEqual(result["inference_permissions"], "not_verified")
        self.assertEqual(result["inference_requests"], 0)
        self.assertFalse(result["fallback_selected"])

    def test_default_only_reports_presence_and_never_opens_network(self):
        opener = Opener()
        result = model_readiness(self.environment(OPENAI_ORG_ID=ORG, OPENAI_PROJECT_ID=PROJECT), opener=opener)
        for flag in ("api_key_present", "model_configured", "organization_id_present", "project_id_present"):
            self.assertIs(result[flag], True)
        self.assertEqual(result["status"], "not_checked")
        self.assertIsNone(result["model_retrievable"])
        self.assertFalse(result["network_checked"])
        self.assertEqual(opener.requests, [])
        self.assert_redacted(result)

    def test_default_environment_is_read_without_exposing_values(self):
        with patch.dict(os.environ, self.environment(), clear=True):
            result = model_readiness()
        self.assertTrue(result["api_key_present"])
        self.assertTrue(result["model_configured"])
        self.assert_redacted(result)

    def test_missing_key_or_explicit_model_never_opens_network(self):
        for environment in ({}, {"OPENAI_API_KEY": KEY}, {"BUGHUNT_OPENAI_MODEL": MODEL},
                            self.environment(OPENAI_API_KEY="   "), self.environment(BUGHUNT_OPENAI_MODEL="")):
            with self.subTest(environment_keys=list(environment)):
                opener = Opener()
                result = model_readiness(environment, check_access=True, opener=opener)
                self.assertEqual(result["status"], "configuration_missing")
                self.assertIsNone(result["model_retrievable"])
                self.assertFalse(result["network_checked"])
                self.assertEqual(opener.requests, [])
                self.assert_redacted(result)

    def test_success_makes_one_exact_get_with_optional_account_headers(self):
        response = Response()
        opener = Opener(response)
        result = model_readiness(self.environment(OPENAI_ORG_ID=ORG, OPENAI_PROJECT_ID=PROJECT), True, opener)
        self.assertEqual(result["status"], "retrievable")
        self.assertEqual(result["http_status"], 200)
        self.assertTrue(result["model_retrievable"])
        self.assertTrue(result["network_checked"])
        self.assertEqual(len(opener.requests), 1)
        request, timeout = opener.requests[0]
        self.assertEqual(request.full_url, MODELS_URL + MODEL)
        self.assertEqual(request.get_method(), "GET")
        self.assertIsNone(request.data)
        self.assertEqual(timeout, 20)
        self.assertEqual(request.get_header("Authorization"), "Bearer " + KEY)
        self.assertEqual(request.get_header("Openai-organization"), ORG)
        self.assertEqual(request.get_header("Openai-project"), PROJECT)
        self.assertEqual(response.read_limits, [MAX_RESPONSE_BYTES + 1])
        self.assertTrue(response.closed)
        self.assert_redacted(result)

    def test_no_optional_headers_or_model_fallback_are_added(self):
        opener = Opener(Response())
        model_readiness(self.environment(), check_access=True, opener=opener)
        request = opener.requests[0][0]
        self.assertIsNone(request.get_header("Openai-organization"))
        self.assertIsNone(request.get_header("Openai-project"))
        self.assertEqual(len(opener.requests), 1)

    def test_explicit_fine_tuned_identifier_is_encoded_without_changing_model(self):
        model = "ft:fixture-model:organization::abc"
        opener = Opener(Response({"id": model, "object": "model"}))
        result = model_readiness(self.environment(BUGHUNT_OPENAI_MODEL=model), True, opener)
        self.assertTrue(result["model_retrievable"])
        self.assertEqual(opener.requests[0][0].full_url, MODELS_URL + "ft%3Afixture-model%3Aorganization%3A%3Aabc")

    def test_invalid_configuration_never_sends_credentials(self):
        invalid = [("OPENAI_API_KEY", KEY + "\r\nInjected: yes"), ("OPENAI_API_KEY", "key value"),
                   ("OPENAI_API_KEY", "key\ud800"), ("OPENAI_ORG_ID", ORG + "\n"),
                   ("OPENAI_PROJECT_ID", " leading-space"), ("BUGHUNT_OPENAI_MODEL", "../responses"),
                   ("BUGHUNT_OPENAI_MODEL", "https://elsewhere.test/model"), ("BUGHUNT_OPENAI_MODEL", "model?token=x"),
                   ("BUGHUNT_OPENAI_MODEL", "model%2F.."), ("BUGHUNT_OPENAI_MODEL", "."),
                   ("BUGHUNT_OPENAI_MODEL", "model\n"), ("BUGHUNT_OPENAI_MODEL", "m" * 513)]
        for name, value in invalid:
            with self.subTest(name=name):
                opener = Opener()
                result = model_readiness(self.environment(**{name: value}), True, opener)
                self.assertEqual(result["status"], "configuration_invalid")
                self.assertFalse(result["network_checked"])
                self.assertEqual(opener.requests, [])
                self.assert_redacted(result)

    def test_http_failures_are_distinct_sanitized_and_never_retried(self):
        statuses = {401: "authentication_failed", 403: "forbidden", 404: "not_found_or_inaccessible",
                    429: "rate_limited", 503: "service_unavailable", 302: "redirect_blocked", 400: "http_error"}
        for status, expected in statuses.items():
            for raised in (False, True):
                with self.subTest(status=status, raised=raised):
                    body = (KEY + ORG + PROJECT).encode()
                    response = (HTTPError("https://elsewhere.test/" + KEY, status, KEY, {"x-account": ORG}, io.BytesIO(body))
                                if raised else Response(body, status=status, headers={"x-account": ORG}))
                    opener = Opener(response)
                    result = model_readiness(self.environment(), True, opener)
                    self.assertEqual(result["status"], expected)
                    self.assertEqual(result["http_status"], status)
                    self.assertFalse(result["model_retrievable"])
                    self.assertEqual(len(opener.requests), 1)
                    self.assertTrue(response.closed)
                    self.assert_redacted(result)

    def test_default_transport_disables_proxies_and_redirects(self):
        opener = Opener(Response())
        with patch("bughunt.model_access.build_opener", return_value=opener) as factory:
            model_readiness(self.environment(), check_access=True)
        proxy, redirect = factory.call_args.args
        self.assertIsInstance(proxy, ProxyHandler)
        self.assertEqual(proxy.proxies, {})
        self.assertIsInstance(redirect, _NoRedirect)
        self.assertIsNone(redirect.redirect_request(Request(MODELS_URL + MODEL), None, 302, "", {}, "https://elsewhere.test"))

    def test_transport_exceptions_never_expose_secrets(self):
        for error in (URLError(KEY), OSError(ORG), TimeoutError(PROJECT), IncompleteRead(KEY.encode()), RuntimeError(KEY)):
            with self.subTest(error_type=type(error).__name__):
                opener = Opener(error)
                result = model_readiness(self.environment(), True, opener)
                self.assertEqual(result["status"], "network_error")
                self.assertEqual(len(opener.requests), 1)
                self.assert_redacted(result)

    def test_invalid_metadata_is_not_access_proof(self):
        documents = [b"bad-json", b"\xff", [], {}, {"object": "list", "id": MODEL},
                     {"object": "model", "id": "different-model"},
                     b'{"object":"model","id":"explicit-fixture-model","id":"explicit-fixture-model"}',
                     b'{"object":"model","id":"explicit-fixture-model","created":NaN}']
        for document in documents:
            with self.subTest(document_type=type(document).__name__):
                result = model_readiness(self.environment(), True, Opener(Response(document)))
                self.assertEqual(result["status"], "invalid_response")
                self.assertFalse(result["model_retrievable"])
                self.assert_redacted(result)

    def test_oversized_and_truncated_responses_are_rejected(self):
        for response in (Response(b"x" * (MAX_RESPONSE_BYTES + 10)),
                         Response(headers={"Content-Length": "99999"}),
                         Response(headers={"Content-Length": "9" * 20}),
                         Response(headers={"Content-Length": "bad"})):
            with self.subTest(headers=response.headers):
                result = model_readiness(self.environment(), True, Opener(response))
                self.assertEqual(result["status"], "invalid_response")
                self.assertEqual(response.read_limits, [MAX_RESPONSE_BYTES + 1])
                self.assert_redacted(result)


if __name__ == "__main__":
    unittest.main()
