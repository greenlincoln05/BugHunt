"""Bounded batch triage uses mocked official API responses; never contacts
any candidate's live assets."""

import io
import json
import tempfile
import unittest
from pathlib import Path

from bughunt.hackerone import HackerOneClient
from bughunt.triage import MAX_CANDIDATES, MIN_CANDIDATES, triage_candidates


DATE = "2026-01-01T00:00:00.000Z"


def scope_record(identifier="10", asset_type="URL", **overrides):
    attributes = {"asset_identifier": "https://asset.example/", "asset_type": asset_type,
                  "eligible_for_bounty": True, "eligible_for_submission": True,
                  "instruction": None, "reference": None, "max_severity": "critical",
                  "created_at": DATE, "updated_at": DATE}
    attributes.update(overrides)
    return {"id": identifier, "type": "structured-scope", "attributes": attributes}


def scopes_page(records=None):
    return {"data": [scope_record()] if records is None else records, "links": {"next": None}}


class Response(io.BytesIO):
    def __init__(self, document, *, status=200, headers=None):
        super().__init__(document if isinstance(document, bytes) else json.dumps(document).encode("utf-8"))
        self.status = status
        self.headers = headers or {}

    def getcode(self):
        return self.status


class Opener:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, *, timeout):
        self.requests.append(request.full_url)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def opportunity(entity_id, handle, name="Example"):
    return {"id": entity_id, "handle": handle, "name": name}


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state_dir = Path(self.temp.name) / "triage"

    def client(self, *responses):
        return HackerOneClient("id", "token", opener=Opener(*responses))

    def test_shortlist_only_includes_source_code_eligible_candidates(self):
        candidates = [opportunity("h1-1", "alpha"), opportunity("h1-2", "beta")]
        client = self.client(
            Response(scopes_page([scope_record(asset_type="SOURCE_CODE", reference="https://github.com/a/a")])),
            Response({"data": []}),  # alpha exclusions
            Response(scopes_page([scope_record(asset_type="URL")])),
            Response({"data": []}),  # beta exclusions
        )
        result = triage_candidates(client, candidates, self.state_dir)
        self.assertEqual(result["attempted"], 2)
        self.assertEqual(result["source_eligible"], 1)
        self.assertEqual(result["remaining"], 0)
        shortlist = json.loads(Path(result["shortlist_file"]).read_text(encoding="utf-8"))
        self.assertEqual([row["id"] for row in shortlist["candidates"]], ["h1-1"])
        self.assertEqual(shortlist["candidates"][0]["references"], ["https://github.com/a/a"])

    def test_already_checked_candidates_are_skipped_unless_recheck(self):
        candidates = [opportunity("h1-1", "alpha")]
        first_client = self.client(Response(scopes_page([scope_record(asset_type="SOURCE_CODE")])), Response({"data": []}))
        triage_candidates(first_client, candidates, self.state_dir)

        second_client = self.client()  # no responses queued -- must not be called
        result = triage_candidates(second_client, candidates, self.state_dir)
        self.assertEqual(result["attempted"], 0)
        self.assertEqual(result["already_checked"], 1)

        third_client = self.client(Response(scopes_page([scope_record(asset_type="URL")])), Response({"data": []}))
        result = triage_candidates(third_client, candidates, self.state_dir, recheck=True)
        self.assertEqual(result["attempted"], 1)
        shortlist = json.loads(Path(result["shortlist_file"]).read_text(encoding="utf-8"))
        self.assertEqual(shortlist["candidates"], [])  # recheck flipped it to no longer eligible

    def test_max_candidates_bounds_one_batch_and_reports_remaining(self):
        candidates = [opportunity(f"h1-{n}", f"prog{n}") for n in range(3)]
        client = self.client(*(
            response for _ in range(2)
            for response in (Response(scopes_page([scope_record(asset_type="URL")])), Response({"data": []}))
        ))
        result = triage_candidates(client, candidates, self.state_dir, max_candidates=2)
        self.assertEqual(result["attempted"], 2)
        self.assertEqual(result["remaining"], 1)

    def test_per_candidate_error_is_recorded_and_batch_continues(self):
        candidates = [opportunity("h1-1", "broken"), opportunity("h1-2", "fine")]
        client = self.client(
            Response({"data": []}, status=500),  # broken program's scope request fails
            Response(scopes_page([scope_record(asset_type="SOURCE_CODE")])),
            Response({"data": []}),
        )
        result = triage_candidates(client, candidates, self.state_dir)
        self.assertEqual(result["attempted"], 2)
        self.assertEqual(result["source_eligible"], 1)
        state = json.loads(Path(result["state_file"]).read_text(encoding="utf-8"))
        self.assertIsNotNone(state["checked"]["h1-1"]["error"])
        self.assertIsNone(state["checked"]["h1-2"]["error"])

    def test_rate_limit_stops_batch_without_marking_that_candidate_checked(self):
        candidates = [opportunity("h1-1", "alpha"), opportunity("h1-2", "beta")]
        client = self.client(Response({"data": []}, status=429))
        result = triage_candidates(client, candidates, self.state_dir)
        self.assertTrue(result["stopped_early"])
        self.assertIsNotNone(result["stop_reason"])
        self.assertEqual(result["attempted"], 0)
        state = json.loads(Path(result["state_file"]).read_text(encoding="utf-8"))
        self.assertEqual(state["checked"], {})

    def test_rejects_out_of_range_bounds(self):
        for bad in (MIN_CANDIDATES - 1, MAX_CANDIDATES + 1, 0, -1):
            with self.assertRaises(ValueError):
                triage_candidates(self.client(), [], self.state_dir, max_candidates=bad)


if __name__ == "__main__":
    unittest.main()
