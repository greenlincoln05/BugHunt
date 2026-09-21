"""Mocked API tests: credentials stay at the metadata endpoint, with no target traffic."""

import base64
import io
import json
import unittest
from datetime import datetime, timedelta, timezone
from email.message import Message
from email.utils import format_datetime
from http.client import IncompleteRead
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request

from bughunt.hackerone import AdapterError, HackerOneClient, MAX_RESPONSE_BYTES, PROGRAMS_URL, _NoRedirect


def record(identifier="123", **attributes):
    fields = {
        "handle": "example_program", "name": "Example program", "currency": "usd",
        "policy": "Rules must be reviewed before testing", "submission_state": "open",
        "state": "public_mode", "offers_bounties": True,
        "fast_payments": True, "triage_active": True,
    }
    fields.update(attributes)
    return {"id": identifier, "type": "program", "attributes": fields}


def page(records=None, next_url=None):
    return {"data": [record()] if records is None else records, "links": {"next": next_url}}


class Response(io.BytesIO):
    def __init__(self, document, *, status=200, headers=None):
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
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, *, timeout):
        self.requests.append((request, timeout))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class HackerOneTests(unittest.TestCase):
    def client(self, *responses):
        opener = Opener(*responses)
        return HackerOneClient("api-identifier", "local-test-token", opener=opener), opener

    def test_normalizes_candidates_without_inventing_permission_or_payouts(self):
        client, opener = self.client(Response(page()))
        result = client.list_programs()
        candidate = result["programs"][0]
        self.assertEqual(candidate["id"], "h1-123")
        self.assertEqual(candidate["program_url"], "https://hackerone.com/example_program")
        self.assertEqual(candidate["currency"], "USD")
        self.assertEqual(candidate["platform"], "hackerone")
        self.assertIs(candidate["automation_allowed"], False)
        for key in ("verified_at", "payout_min", "payout_max"):
            self.assertIsNone(candidate[key])
        self.assertTrue(candidate["fast_payments"])
        self.assertTrue(candidate["triage_active"])
        self.assertEqual(result["pages_fetched"], 1)
        self.assertIsNone(result["next_url"])
        request, timeout = opener.requests[0]
        self.assertEqual(request.full_url, PROGRAMS_URL)
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(timeout, 20)
        self.assertEqual(request.get_header("Authorization"), "Basic " +
                         base64.b64encode(b"api-identifier:local-test-token").decode("ascii"))
        self.assertEqual(request.get_header("Accept"), "application/json")

    def test_only_public_open_bounty_programs_are_candidates(self):
        client, _ = self.client(Response(page([
            record("1"), record("2", state="soft_launched"),
            record("3", submission_state="closed"), record("4", offers_bounties=False),
        ])))
        self.assertEqual([item["id"] for item in client.list_programs()["programs"]], ["h1-1"])

    def test_legal_null_metadata_does_not_pause_discovery_or_imply_eligibility(self):
        client, _ = self.client(Response(page([
            record("1", state=None, offers_bounties=None, fast_payments=None, triage_active=None),
            record("2", offers_bounties=None),
            record("3", state=None),
            record("4", fast_payments=None, triage_active=None),
        ])))
        result = client.list_programs()
        self.assertEqual([item["id"] for item in result["programs"]], ["h1-4"])
        self.assertIs(result["programs"][0]["fast_payments"], False)
        self.assertIs(result["programs"][0]["triage_active"], False)
        self.assertIsNone(result["next_url"])

    def test_pagination_preserves_cursor_at_cap_and_resumes(self):
        next_url = "https://api.hackerone.com/v1/hackers/programs?page%5Bnumber%5D=2&page%5Bsize%5D=100"
        first, first_opener = self.client(Response(page(next_url=next_url)))
        batch = first.list_programs(max_pages=1)
        self.assertEqual(batch["next_url"], next_url)
        self.assertEqual(len(first_opener.requests), 1)
        second, second_opener = self.client(Response(page([record("124")])))
        final = second.list_programs(start_url=batch["next_url"])
        self.assertEqual(second_opener.requests[0][0].full_url, next_url)
        self.assertEqual(final["programs"][0]["id"], "h1-124")
        self.assertIsNone(final["next_url"])

    def test_collects_multiple_pages_and_deduplicates_ids(self):
        next_url = "https://api.hackerone.com/v1/hackers/programs?page[number]=2"
        client, _ = self.client(Response(page(next_url=next_url)), Response(page([record(), record("124")])))
        result = client.list_programs()
        self.assertEqual(result["pages_fetched"], 2)
        self.assertEqual([p["id"] for p in result["programs"]], ["h1-123", "h1-124"])

    def test_rejects_invalid_limits_without_network(self):
        client, opener = self.client()
        for limit in (0, 21, -1, True, "2", 1.5):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                client.list_programs(max_pages=limit)
        self.assertEqual(opener.requests, [])

    def test_untrusted_pagination_cannot_move_credentials(self):
        invalid_urls = [
            "http://api.hackerone.com/v1/hackers/programs",
            "https://evil.example/v1/hackers/programs",
            "https://api.hackerone.com.evil.example/v1/hackers/programs",
            "https://token@api.hackerone.com/v1/hackers/programs",
            "https://api.hackerone.com:444/v1/hackers/programs",
            "https://api.hackerone.com:bad/v1/hackers/programs",
            "https://api.hackerone.com/v1/hackers/programs#fragment",
            "https://api.hackerone.com/v1/hackers/programs#",
            "https://api.hackerone.com/v1/hackers/programs/../reports",
            "https://api.hackerone.com/v1/hackers/%70rograms",
            "https://api.hackerone.com/v1/hackers/programs/",
            "https://api.hackerone.com\\evil.example/v1/hackers/programs",
            "\nhttps://api.hackerone.com/v1/hackers/programs",
            "https://api.hackerone.com/v1/hackers/programs?page[number]=0",
            "https://api.hackerone.com/v1/hackers/programs?page[size]=101",
            "https://api.hackerone.com/v1/hackers/programs?page[number]=1&page[number]=2",
            "https://api.hackerone.com/v1/hackers/programs?redirect=https://evil.example",
            {"href": PROGRAMS_URL}, "", False,
        ]
        for value in invalid_urls:
            with self.subTest(value=value):
                client, opener = self.client()
                with self.assertRaises(AdapterError) as caught:
                    client.list_programs(start_url=value)
                self.assertEqual(caught.exception.kind, "invalid_response")
                self.assertEqual(opener.requests, [])
                client, opener = self.client(Response(page(next_url=value)))
                with self.assertRaises(AdapterError):
                    client.list_programs()
                self.assertEqual(len(opener.requests), 1)

    def test_omitted_pagination_metadata_means_terminal_page(self):
        for document in ({"data": [record()]}, {"data": [record()], "links": {}}):
            with self.subTest(document=document):
                client, _ = self.client(Response(document))
                result = client.list_programs()
                self.assertEqual(result["programs"][0]["id"], "h1-123")
                self.assertEqual(result["pages_fetched"], 1)
                self.assertIsNone(result["next_url"])

    def test_repeated_pagination_cursor_is_rejected(self):
        client, _ = self.client(Response(page(next_url=PROGRAMS_URL)))
        with self.assertRaisesRegex(AdapterError, "pagination loop"):
            client.list_programs()

    def test_default_transport_disables_proxies_and_redirects(self):
        with patch("bughunt.hackerone.build_opener") as factory:
            HackerOneClient("identifier", "token")
        handlers = factory.call_args.args
        self.assertIsInstance(handlers[0], ProxyHandler)
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], _NoRedirect)
        self.assertIsNone(handlers[1].redirect_request(Request(PROGRAMS_URL), None, 302,
                                                    "redirect", {}, "https://evil.example"))

    def test_environment_credentials_and_invalid_values_are_sanitized(self):
        opener = Opener(Response(page()))
        HackerOneClient.from_environment(environ={
            "HACKERONE_USERNAME": "identifier", "HACKERONE_API_TOKEN": "secret-value",
        }, opener=opener).list_programs()
        self.assertIn("Authorization", opener.requests[0][0].headers)
        for username, token in (("", "secret-value"), ("identifier", ""),
                                ("bad:identifier", "secret-value"), ("identifier", "secret-value\n")):
            with self.subTest(username=username), self.assertRaises(AdapterError) as caught:
                HackerOneClient(username, token)
            self.assertEqual(caught.exception.kind, "authentication")
            self.assertNotIn("secret-value", str(caught.exception))
        with self.assertRaises(AdapterError):
            HackerOneClient.from_environment(environ={})

    def test_http_failure_types_retry_minimums_and_no_body_leaks(self):
        for status, kind, delay in ((401, "authentication", None), (403, "authentication", None),
                                    (429, "rate_limit", 3600), (500, "transient", 60),
                                    (503, "transient", 60), (302, "invalid_response", None),
                                    (404, "invalid_response", None)):
            with self.subTest(status=status):
                headers = Message()
                headers["Retry-After"] = "2"
                body = io.BytesIO(b"secret-value in upstream body")
                error = HTTPError(PROGRAMS_URL, status, "secret-value in status", headers, body)
                client, _ = self.client(error)
                with self.assertRaises(AdapterError) as caught:
                    client.list_programs()
                self.assertEqual(caught.exception.kind, kind)
                self.assertEqual(caught.exception.retry_after_seconds, delay)
                self.assertNotIn("secret-value", str(caught.exception))
                self.assertTrue(body.closed)

    def test_retry_after_accepts_longer_seconds_and_http_dates(self):
        future = format_datetime(datetime.now(timezone.utc) + timedelta(hours=3), usegmt=True)
        for retry, minimum in (("7200", 7200), (future, 10790), ("bad", 3600), ("-100", 3600)):
            with self.subTest(retry=retry):
                client, _ = self.client(Response(page(), status=429, headers={"Retry-After": retry}))
                with self.assertRaises(AdapterError) as caught:
                    client.list_programs()
                self.assertGreaterEqual(caught.exception.retry_after_seconds, minimum)

    def test_network_errors_are_retryable_and_sanitized(self):
        for failure in (URLError("secret-value"), TimeoutError("secret-value"),
                        IncompleteRead(b"secret-value")):
            with self.subTest(failure=type(failure).__name__):
                client, _ = self.client(failure)
                with self.assertRaises(AdapterError) as caught:
                    client.list_programs()
                self.assertEqual(caught.exception.kind, "transient")
                self.assertEqual(caught.exception.retry_after_seconds, 60)
                self.assertNotIn("secret-value", str(caught.exception))

    def test_response_size_is_bounded(self):
        response = Response(b" " * (MAX_RESPONSE_BYTES + 1))
        client, _ = self.client(response)
        with self.assertRaisesRegex(AdapterError, "size limit"):
            client.list_programs()
        self.assertEqual(response.read_limits, [MAX_RESPONSE_BYTES + 1])
        self.assertTrue(response.closed)

    def test_invalid_json_and_shapes_are_rejected_without_echo(self):
        documents = [b"secret-value", b"\xff", b'{"data":[], "data":[], "links":{"next":null}}',
                     b'{"data":[], "links":{"next":null}, "secret-value":NaN}',
                     [], None, {"data": {}}, {"data": [False], "links": {"next": None}},
                     {"data": [], "links": []}, {"data": [], "links": None}]
        for document in documents:
            with self.subTest(document=document):
                client, _ = self.client(Response(document))
                with self.assertRaises(AdapterError) as caught:
                    client.list_programs()
                self.assertEqual(caught.exception.kind, "invalid_response")
                self.assertNotIn("secret-value", str(caught.exception))

    def test_malformed_program_fields_fail_closed(self):
        invalid_records = [record("../bad"), record(True), record(name=""), record(handle="../bad"),
                           record(currency="dollars"), record(policy=[]), record(state=1),
                           record(submission_state=False), {"id": "1", "attributes": []}]
        for field in ("offers_bounties", "fast_payments", "triage_active"):
            for value in ("true", 1, []):
                invalid_records.append(record(**{field: value}))
        for invalid in invalid_records:
            with self.subTest(record=invalid):
                client, _ = self.client(Response(page([invalid])))
                with self.assertRaises(AdapterError):
                    client.list_programs()

    def test_empty_page_and_optional_metadata(self):
        client, _ = self.client(Response(page([])))
        self.assertEqual(client.list_programs()["programs"], [])
        source = record(currency=None, policy=None)
        del source["attributes"]["fast_payments"]
        del source["attributes"]["triage_active"]
        client, _ = self.client(Response(page([source])))
        program = client.list_programs()["programs"][0]
        self.assertIsNone(program["currency"])
        self.assertEqual(program["policy"], "")
        self.assertIs(program["fast_payments"], False)
        self.assertIs(program["triage_active"], False)


if __name__ == "__main__":
    unittest.main()
