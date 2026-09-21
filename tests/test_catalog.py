"""Catalog boundary tests: untrusted imports cannot silently imply permission."""

import json
import tempfile
import unittest
from pathlib import Path

from bughunt.catalog import load_catalog, rank_programs, validate_program


class CatalogTests(unittest.TestCase):
    def program(self, **updates):
        data = {
            "id": "local-demo",
            "name": "Local demo",
            "platform": "manual",
            "program_url": "http://127.0.0.1:8000",
            "status": "active",
            "scope": ["http://127.0.0.1:8000"],
        }
        data.update(updates)
        return data

    def load(self, document):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "programs.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return load_catalog(path)

    def test_defaults_do_not_claim_authorization_or_verification(self):
        source = self.program()
        result = validate_program(source)
        self.assertIs(result["automation_allowed"], False)
        self.assertIsNone(result["verified_at"])
        self.assertIsNone(result["verification_expires_at"])
        self.assertEqual(result["excluded_scope"], [])
        result["scope"].append("http://127.0.0.1:9000")
        self.assertEqual(source["scope"], ["http://127.0.0.1:8000"])

    def test_accepts_both_catalog_shapes_and_empty_catalog(self):
        self.assertEqual(self.load([self.program()]), self.load({"programs": [self.program()]}))
        self.assertEqual(self.load([]), [])

    def test_rejects_truthy_values_for_automation(self):
        for invalid in ["false", "true", 0, 1, None, [], {}]:
            with self.subTest(value=invalid), self.assertRaisesRegex(ValueError, "boolean"):
                validate_program(self.program(automation_allowed=invalid))

    def test_requires_known_fields_and_valid_types(self):
        invalid_updates = [
            {"automaton_allowed": True},
            {"id": "../escape"},
            {"id": "Uppercase"},
            {"name": " "},
            {"platform": "unknown"},
            {"status": "enabled"},
            {"scope": []},
            {"scope": "http://127.0.0.1"},
            {"scope": [False]},
            {"excluded_scope": None},
            {"blocked_reason": 3},
        ]
        for updates in invalid_updates:
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                validate_program(self.program(**updates))
        source = self.program()
        del source["status"]
        with self.assertRaisesRegex(ValueError, "missing.*status"):
            validate_program(source)
        with self.assertRaises(ValueError):
            validate_program([])

    def test_rejects_non_http_urls_and_user_information(self):
        for url in [
            "file:///etc/passwd", "ftp://127.0.0.1", "https://", "//127.0.0.1",
            "http://user:password@127.0.0.1", "http://@127.0.0.1",
            "http://127.0.0.1:99999", "http://127.0.0.1:invalid",
            "http://127.0.0.1:0", "http://bad host", "http://127.0.0.1/\npath",
            "http://127.0.0.1\\other", "http://[invalid]",
        ]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_program(self.program(program_url=url))

    def test_normalizes_aware_timestamps_to_utc(self):
        result = validate_program(self.program(
            verified_at="2026-09-20T16:00:00-04:00",
            verification_expires_at="2026-09-21T20:00:00Z",
        ))
        self.assertEqual(result["verified_at"], "2026-09-20T20:00:00Z")
        self.assertEqual(result["verification_expires_at"], "2026-09-21T20:00:00Z")

    def test_rejects_naive_invalid_and_reversed_timestamps(self):
        for timestamp in ["2026-09-20", "2026-09-20T20:00:00", "yesterday", False]:
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                validate_program(self.program(verified_at=timestamp))
        for expiry in ["2026-09-19T20:00:00Z", "2026-09-20T20:00:00Z"]:
            with self.subTest(expiry=expiry), self.assertRaisesRegex(ValueError, "after"):
                validate_program(self.program(
                    verified_at="2026-09-20T20:00:00Z", verification_expires_at=expiry,
                ))

    def test_validates_and_preserves_optional_payouts(self):
        result = validate_program(self.program(payout_min="0.00", payout_max="1000.50", currency="USD"))
        self.assertEqual(result["payout_min"], "0.00")
        self.assertEqual(result["payout_max"], "1000.50")
        self.assertEqual(result["currency"], "USD")
        for updates in [
            {"payout_min": 100}, {"payout_min": "-1"}, {"payout_min": "NaN"},
            {"payout_max": "Infinity"}, {"payout_max": "1e10"},
            {"payout_min": "20.00", "payout_max": "19.99"}, {"currency": "usd"},
        ]:
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                validate_program(self.program(**updates))

    def test_rejects_duplicate_ids_and_unknown_envelope_fields(self):
        with self.assertRaisesRegex(ValueError, "duplicate program id"):
            self.load([self.program(), self.program()])
        for document in [None, 1, {}, {"programs": [] , "verified": True}, {"programs": {}}]:
            with self.subTest(document=document), self.assertRaises(ValueError):
                self.load(document)

    def test_error_identifies_invalid_record(self):
        with self.assertRaisesRegex(ValueError, r"programs\[1\].*automation_allowed"):
            self.load([self.program(), self.program(id="second", automation_allowed="false")])

    def test_rejects_duplicate_json_fields_and_malformed_json(self):
        for content in ['{"programs": [], "programs": []}', '{"programs": [']:
            with self.subTest(content=content), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "programs.json"
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_catalog(path)

    def test_demo_fixture_has_only_local_unverified_data(self):
        fixture = Path(__file__).resolve().parents[1] / "examples" / "programs.json"
        programs = load_catalog(fixture)
        self.assertEqual(len(programs), 1)
        self.assertEqual(programs[0]["scope"], ["http://127.0.0.1:8000"])
        self.assertIs(programs[0]["automation_allowed"], False)
        self.assertIsNone(programs[0]["verified_at"])
        self.assertIsNone(programs[0]["verification_expires_at"])

    def test_shortlist_prioritizes_range_fit_then_name_and_id(self):
        programs = [
            self.program(id="broad", name="A broad range", payout_min="10", payout_max="1000", currency="USD"),
            self.program(id="exact-z", name="Zulu", payout_min="50", payout_max="200", currency="USD"),
            self.program(id="exact-b", name="Alpha", payout_min="50", payout_max="200", currency="USD"),
            self.program(id="exact-a", name="Alpha", payout_min="50", payout_max="200", currency="USD"),
        ]
        ranked = rank_programs(programs, limit=3)
        self.assertEqual([program["id"] for program in ranked], ["exact-a", "exact-b", "exact-z"])
        self.assertEqual(ranked, rank_programs(list(reversed(programs)), limit=3))

    def test_shortlist_filters_status_blocks_currency_and_unknown_ranges(self):
        def candidate(program_id, **updates):
            fields = {"id": program_id, "payout_min": "50", "payout_max": "200", "currency": "USD"}
            fields.update(updates)
            return self.program(**fields)

        missing_minimum = candidate("missing-min")
        del missing_minimum["payout_min"]
        missing_maximum = candidate("missing-max")
        del missing_maximum["payout_max"]
        programs = [
            candidate("eligible"), candidate("paused", status="paused"),
            candidate("closed", status="closed"), candidate("blocked", blocked_reason="Owner restriction"),
            candidate("different-currency", currency="EUR"), candidate("above", payout_min="201", payout_max="300"),
            candidate("below", payout_min="1", payout_max="49"),
            missing_minimum, missing_maximum, self.program(id="unknown-range"),
        ]
        self.assertEqual([program["id"] for program in rank_programs(programs)], ["eligible"])

    def test_shortlist_includes_touching_ranges_and_copies_records(self):
        source = self.program(payout_min="200", payout_max="300", currency="USD")
        result = rank_programs([source])[0]
        self.assertIn("overlaps requested USD 50-200", result["shortlist_reason"])
        self.assertIn("unverified", result["shortlist_reason"])
        self.assertNotIn("shortlist_reason", source)
        result["scope"].append("http://127.0.0.1:9000")
        self.assertEqual(source["scope"], ["http://127.0.0.1:8000"])
        self.assertIs(result["automation_allowed"], False)

    def test_shortlist_rejects_invalid_bounds_currency_and_limit(self):
        for updates in [
            {"min_payout": "0"}, {"min_payout": "-1"}, {"min_payout": "NaN"},
            {"max_payout": "Infinity"}, {"max_payout": "49"}, {"min_payout": True},
            {"currency": "usd"}, {"limit": 0}, {"limit": -1}, {"limit": True}, {"limit": 1.5},
        ]:
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                rank_programs([], **updates)
        with self.assertRaisesRegex(ValueError, "duplicate program id"):
            rank_programs([self.program(), self.program()])

    def test_shortlist_preserves_internal_verification_note_but_import_rejects_it(self):
        for note in [None, "Scope and program status checked manually"]:
            source = self.program(payout_min="50", payout_max="200", currency="USD", verification_note=note)
            with self.subTest(note=note):
                result = rank_programs([source])[0]
                self.assertIn("verification_note", result)
                self.assertEqual(result["verification_note"], note)
                self.assertIsNot(result, source)
                with self.assertRaisesRegex(ValueError, "unknown program field.*verification_note"):
                    validate_program(source)
        with self.assertRaisesRegex(ValueError, "unknown program field.*other_metadata"):
            rank_programs([self.program(verification_note=None, other_metadata=True)])
        with self.assertRaisesRegex(ValueError, "verification_note must be"):
            rank_programs([self.program(verification_note=["unexpected mutable metadata"])])


if __name__ == "__main__":
    unittest.main()
