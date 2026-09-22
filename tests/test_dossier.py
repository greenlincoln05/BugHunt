"""Dossier collection uses mocked official API responses, never asset traffic."""

import io
import json
import unittest
from http.client import IncompleteRead
from urllib.error import HTTPError, URLError

from bughunt.dossier import fetch_program_dossier, source_code_assets
from bughunt.hackerone import AdapterError, HackerOneClient, MAX_RESPONSE_BYTES


BASE = "https://api.hackerone.com/v1/hackers/programs/example_program/"
SCOPES = BASE + "structured_scopes?page[number]=1&page[size]=100"
NEXT = BASE + "structured_scopes?page[number]=2&page[size]=100"
EXCLUSIONS = BASE + "scope_exclusions"
DATE = "2026-01-01T00:00:00.000Z"


def scope(identifier="10", **overrides):
    attributes = {"asset_identifier": "https://asset.example/", "asset_type": "URL",
                  "eligible_for_bounty": True, "eligible_for_submission": True,
                  "instruction": "Review policy first", "max_severity": "critical",
                  "created_at": DATE, "updated_at": DATE}
    attributes.update(overrides)
    return {"id": identifier, "type": "structured-scope", "attributes": attributes}


def exclusion(identifier="20", **overrides):
    attributes = {"category": "Missing security headers", "details": "No standalone rewards",
                  "created_at": DATE, "updated_at": DATE}
    attributes.update(overrides)
    return {"id": identifier, "type": "scope-exclusion", "attributes": attributes}


def page(records=None, next_url=None):
    return {"data": [scope()] if records is None else records, "links": {"next": next_url}}


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


class DossierTests(unittest.TestCase):
    def client(self, *responses):
        opener = Opener(*responses)
        return HackerOneClient("api-identifier", "local-test-token", opener=opener), opener

    def fetch(self, *responses, max_pages=3):
        client, opener = self.client(*responses)
        result = fetch_program_dossier(client, "example_program", max_pages=max_pages)
        return result, opener

    def test_collects_scope_and_exclusions_without_authorizing_or_visiting_assets(self):
        result, opener = self.fetch(Response(page()), Response({"data": [exclusion()]}))
        self.assertEqual([request.full_url for request, _ in opener.requests], [SCOPES, EXCLUSIONS])
        for request, timeout in opener.requests:
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(timeout, 20)
            self.assertEqual(request.get_header("Accept"), "application/json")
            self.assertTrue(request.get_header("Authorization").startswith("Basic "))
        self.assertEqual(result["structured_scopes"][0]["asset_identifier"], "https://asset.example/")
        self.assertEqual(result["scope_exclusions"][0]["category"], "Missing security headers")
        self.assertIs(result["completeness"]["complete"], True)
        self.assertIs(result["review_needed"], True)
        self.assertIs(result["testing_authorized"], False)
        self.assertIs(result["automation_allowed"], False)
        self.assertNotIn("Authorization", json.dumps(result))
        self.assertNotIn("local-test-token", json.dumps(result))

    def test_source_code_assets_are_filtered_out_for_oss_targeting(self):
        records = [scope("10", asset_type="URL"),
                   scope("11", asset_type="SOURCE_CODE", asset_identifier="bughunt-fixture/example",
                         reference="https://github.com/bughunt-fixture/example"),
                   scope("12", asset_type="MOBILE_APPLICATION_ANDROID")]
        result, _ = self.fetch(Response(page(records)), Response({"data": []}))
        self.assertEqual(len(result["source_code_assets"]), 1)
        self.assertEqual(result["source_code_assets"][0]["reference"], "https://github.com/bughunt-fixture/example")
        # The helper is also usable standalone against an already-saved dossier file.
        self.assertEqual(source_code_assets(result), result["source_code_assets"])
        self.assertEqual(source_code_assets({"structured_scopes": []}), [])
        self.assertEqual(source_code_assets({}), [])

    def test_preserves_both_eligible_and_ineligible_assets_for_review(self):
        result, _ = self.fetch(Response(page([scope(), scope("11", eligible_for_bounty=False,
                                                            eligible_for_submission=False)])),
                               Response({"data": []}))
        self.assertEqual(len(result["structured_scopes"]), 2)
        self.assertFalse(result["structured_scopes"][1]["eligible_for_submission"])

    def test_caps_requests_and_marks_dossier_incomplete(self):
        result, opener = self.fetch(Response(page(next_url=NEXT)), Response({"data": []}), max_pages=1)
        status = result["completeness"]
        self.assertIs(status["complete"], False)
        self.assertEqual(status["structured_scopes"], {
            "complete": False, "pages_fetched": 1, "next_url": NEXT, "incomplete_reason": "page_limit"})
        self.assertEqual(len(opener.requests), 2)

    def test_deduplicates_identical_ids_across_pages_and_exclusions(self):
        result, opener = self.fetch(Response(page(next_url=NEXT)),
                                   Response(page([scope(), scope("11")])),
                                   Response({"data": [exclusion(), exclusion()]}))
        self.assertEqual([item["id"] for item in result["structured_scopes"]], ["10", "11"])
        self.assertEqual(len(result["scope_exclusions"]), 1)
        self.assertEqual(result["completeness"]["structured_scopes"]["pages_fetched"], 2)
        self.assertTrue(result["completeness"]["complete"])
        self.assertEqual(len(opener.requests), 3)

    def test_conflicting_duplicate_ids_fail_instead_of_discarding_scope_changes(self):
        for responses in (
            (Response(page([scope(), scope(eligible_for_submission=False)])),),
            (Response(page(next_url=NEXT)), Response(page([scope(instruction="Changed rules")]))),
            (Response(page()), Response({"data": [exclusion(), exclusion(details="Changed exclusion")]})),
        ):
            with self.subTest():
                with self.assertRaisesRegex(AdapterError, "conflicting duplicate"):
                    self.fetch(*responses)

    def test_invalid_handle_or_limit_never_sends_request(self):
        client, opener = self.client()
        for handle in ("", "../reports", "a/b", "a?x", "a%2fb", "a\n", None, True):
            with self.subTest(handle=handle), self.assertRaises(ValueError):
                fetch_program_dossier(client, handle)
        for limit in (0, 21, -1, True, "2", 1.5):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                fetch_program_dossier(client, "example_program", max_pages=limit)
        self.assertEqual(opener.requests, [])

    def test_hostile_pagination_cannot_move_credentials_even_at_page_cap(self):
        invalid = [
            NEXT.replace("https:", "http:"), NEXT.replace("api.hackerone.com", "evil.example"),
            NEXT.replace("api.hackerone.com", "api.hackerone.com.evil.example"),
            NEXT.replace("api.hackerone.com", "user@api.hackerone.com"),
            NEXT.replace("api.hackerone.com", "api.hackerone.com:444"),
            NEXT.replace("api.hackerone.com", "api.hackerone.com:bad"),
            NEXT.replace("example_program", "different_program"),
            NEXT.replace("structured_scopes", "scope_exclusions"),
            NEXT.replace("structured_scopes", "structured_scopes/../reports"),
            NEXT.replace("structured_scopes", "%73tructured_scopes"),
            NEXT.replace("structured_scopes", "structured_scopes/"),
            NEXT + "#", NEXT + "#fragment", "\n" + NEXT, NEXT + "\n",
            NEXT.replace("api.hackerone.com", "api.hackerone.com\\evil.example"),
            NEXT + "&redirect=https://evil.example", NEXT + "&page[number]=3",
            NEXT + "&filter[id__gt]=10", NEXT.replace("number]=2", "number]=0"),
            NEXT.replace("size]=100", "size]=101"), NEXT.replace("size]=100", "size]=1"),
            NEXT.replace("number]=2", "number]=3"),
            NEXT.replace("number]=2", "number]=999999999999"),
            {"href": NEXT}, False, "", "/v1/hackers/programs/example_program/structured_scopes",
        ]
        for value in invalid:
            with self.subTest(value=value):
                client, opener = self.client(Response(page(next_url=value)))
                with self.assertRaises(AdapterError) as caught:
                    fetch_program_dossier(client, "example_program", max_pages=1)
                self.assertEqual(caught.exception.kind, "invalid_response")
                self.assertEqual(len(opener.requests), 1)

    def test_pagination_aliases_are_canonicalized_and_loops_rejected(self):
        alias = NEXT.replace("api.hackerone.com", "api.hackerone.com:443").replace("[", "%5B").replace("]", "%5D")
        result, opener = self.fetch(Response(page(next_url=alias)), Response(page([])), Response({"data": []}))
        self.assertEqual(opener.requests[1][0].full_url, NEXT)
        self.assertTrue(result["completeness"]["complete"])
        for next_url in (SCOPES, SCOPES.replace("[", "%5B").replace("]", "%5D")):
            with self.subTest(next_url=next_url), self.assertRaisesRegex(AdapterError, "pagination loop"):
                self.fetch(Response(page(next_url=next_url)))

    def test_scope_exclusions_do_not_follow_undocumented_pagination(self):
        with self.assertRaisesRegex(AdapterError, "unexpectedly contain pagination"):
            self.fetch(Response(page([])), Response(page([exclusion()], EXCLUSIONS + "?page[number]=2")))

    def test_full_page_without_terminal_marker_stays_incomplete(self):
        scopes = [scope(str(number)) for number in range(100)]
        for links in ({}, {"self": SCOPES}):
            with self.subTest(links=links):
                result, _ = self.fetch(Response({"data": scopes, "links": links}), Response({"data": []}))
                self.assertFalse(result["completeness"]["complete"])
                self.assertEqual(result["completeness"]["structured_scopes"]["incomplete_reason"],
                                 "missing_pagination")
        result, _ = self.fetch(Response(page(scopes)), Response({"data": []}))
        self.assertTrue(result["completeness"]["complete"])

    def test_short_page_without_links_and_empty_exclusions_are_supported(self):
        result, _ = self.fetch(Response({"data": []}), Response({"data": []}))
        self.assertEqual(result["structured_scopes"], [])
        self.assertEqual(result["scope_exclusions"], [])
        self.assertTrue(result["completeness"]["complete"])

    def test_optional_null_text_preserves_unknown_exclusion_information(self):
        result, _ = self.fetch(Response(page([scope(instruction=None, reference=None)])),
                               Response({"data": [{"id": "1", "type": "scope-exclusion", "attributes": {}}]}))
        self.assertIsNone(result["structured_scopes"][0]["instruction"])
        self.assertIsNone(result["scope_exclusions"][0]["category"])
        self.assertIsNone(result["scope_exclusions"][0]["details"])

    def test_record_types_and_required_fields_fail_closed(self):
        invalid = [scope(True), scope(1), scope("../bad"), scope(asset_identifier=""),
                   scope(asset_type=[]), scope(instruction=False), scope(reference=[]),
                   scope(max_severity="urgent"), scope(max_severity=[]),
                   scope(created_at="not a date"), scope(updated_at=DATE[:-1]),
                   scope(instruction="\ud800"), scope(confidentiality_requirement="critical"),
                   scope(integrity_requirement=None)]
        for field in ("eligible_for_bounty", "eligible_for_submission"):
            for value in (None, "true", 1, []):
                invalid.append(scope(**{field: value}))
        for field in ("asset_identifier", "asset_type", "max_severity", "created_at", "updated_at",
                      "eligible_for_bounty", "eligible_for_submission"):
            item = scope()
            del item["attributes"][field]
            invalid.append(item)
        wrong_type = scope()
        wrong_type["type"] = "program"
        invalid.extend([wrong_type, {"id": "1", "type": "structured-scope", "attributes": []}, False])
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(AdapterError):
                self.fetch(Response(page([item])))
        for item in (exclusion(category=[]), exclusion(details=True), exclusion(created_at=None),
                     exclusion(updated_at="invalid"), scope()):
            with self.subTest(item=item), self.assertRaises(AdapterError):
                self.fetch(Response(page([])), Response({"data": [item]}))

    def test_invalid_json_and_response_shapes_are_sanitized(self):
        invalid = [b"local-test-token", b"\xff", b'{"data":[],"data":[]}',
                   b'{"data":[],"extra":NaN}', [], None, {"data": {}},
                   {"data": [], "links": []}, {"data": [], "links": None},
                   page([scope(str(number)) for number in range(101)])]
        for document in invalid:
            with self.subTest(document=document):
                with self.assertRaises(AdapterError) as caught:
                    self.fetch(Response(document))
                self.assertEqual(caught.exception.kind, "invalid_response")
                self.assertNotIn("local-test-token", str(caught.exception))

    def test_response_limit_and_truncation_are_detected(self):
        response = Response(b" " * (MAX_RESPONSE_BYTES + 1))
        with self.assertRaisesRegex(AdapterError, "size limit"):
            self.fetch(response)
        self.assertEqual(response.read_limits, [MAX_RESPONSE_BYTES + 1])
        self.assertTrue(response.closed)
        response = Response(page(), headers={"Content-Length": "999999"})
        with self.assertRaises(AdapterError) as caught:
            self.fetch(response)
        self.assertEqual(caught.exception.kind, "transient")
        self.assertEqual(caught.exception.retry_after_seconds, 60)

    def test_http_and_network_errors_reuse_sanitized_retry_behavior(self):
        for status, kind, delay in ((401, "authentication", None), (403, "authentication", None),
                                    (429, "rate_limit", 7200), (503, "transient", 7200),
                                    (302, "invalid_response", None), (404, "invalid_response", None)):
            with self.subTest(status=status):
                body = io.BytesIO(b"local-test-token")
                error = HTTPError(SCOPES, status, "local-test-token", {"Retry-After": "7200"}, body)
                with self.assertRaises(AdapterError) as caught:
                    self.fetch(error)
                self.assertEqual(caught.exception.kind, kind)
                self.assertEqual(caught.exception.retry_after_seconds, delay)
                self.assertNotIn("local-test-token", str(caught.exception))
                self.assertTrue(body.closed)
        for error in (URLError("local-test-token"), TimeoutError("local-test-token"),
                      IncompleteRead(b"local-test-token")):
            with self.subTest(error=type(error).__name__), self.assertRaises(AdapterError) as caught:
                self.fetch(error)
            self.assertEqual(caught.exception.kind, "transient")
            self.assertNotIn("local-test-token", str(caught.exception))

    def test_exclusions_failure_does_not_return_partially_reviewed_dossier(self):
        with self.assertRaises(AdapterError) as caught:
            self.fetch(Response(page()), Response({"data": []}, status=503))
        self.assertEqual(caught.exception.kind, "transient")


if __name__ == "__main__":
    unittest.main()
