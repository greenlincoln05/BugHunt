"""Local spend cap: enforced before each paid call, persisted, pessimistic."""

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from bughunt import budget


class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "budget.json"
        self.now = datetime(2026, 9, 26, 12, tzinfo=timezone.utc)

    def reserve(self):
        return budget.reserve_request(path=self.path, clock=lambda: self.now)

    def test_unset_budget_refuses_paid_calls(self):
        self.assertFalse(budget.status(path=self.path)["configured"])
        with self.assertRaises(budget.BudgetExhausted):
            self.reserve()
        self.assertFalse(self.path.exists())

    def test_cap_is_enforced_and_usage_persists_between_calls(self):
        budget.set_budget(3, path=self.path, clock=lambda: self.now)
        for expected_remaining in (2, 1, 0):
            self.assertEqual(self.reserve()["requests_remaining"], expected_remaining)
        with self.assertRaises(budget.BudgetExhausted):
            self.reserve()
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8"))["requests_used"], 3)

    def test_reservation_is_written_before_the_call_could_happen(self):
        budget.set_budget(5, path=self.path)
        self.reserve()
        # A crash right after this point must still count the request as spent.
        self.assertEqual(json.loads(self.path.read_text(encoding="utf-8"))["requests_used"], 1)

    def test_raising_the_cap_keeps_usage_and_lowering_it_exhausts(self):
        budget.set_budget(2, path=self.path)
        self.reserve()
        self.reserve()
        self.assertEqual(budget.set_budget(5, path=self.path)["requests_remaining"], 3)
        self.assertEqual(budget.set_budget(1, path=self.path)["requests_remaining"], 0)
        with self.assertRaises(budget.BudgetExhausted):
            self.reserve()

    def test_token_cap_also_stops_further_calls(self):
        budget.set_budget(10, max_tokens=1000, path=self.path)
        self.reserve()
        self.assertEqual(budget.record_tokens(1200, path=self.path)["tokens_remaining"], 0)
        with self.assertRaises(budget.BudgetExhausted):
            self.reserve()

    def test_nonsense_token_values_are_ignored(self):
        budget.set_budget(3, path=self.path)
        for bad in (-5, "12", None, 1.5, True):
            budget.record_tokens(bad, path=self.path)
        self.assertEqual(budget.status(path=self.path)["tokens_used"], 0)

    def test_invalid_caps_are_rejected(self):
        for bad in (-1, 1.5, "10", True, budget.MAX_CAP + 1):
            with self.assertRaises(ValueError):
                budget.set_budget(bad, path=self.path)
        with self.assertRaises(ValueError):
            budget.set_budget(5, max_tokens=-1, path=self.path)

    def test_corrupt_ledger_is_an_error_not_a_silent_reset(self):
        self.path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.reserve()
        self.path.write_text(json.dumps({"max_requests": "lots", "requests_used": 0, "tokens_used": 0}), encoding="utf-8")
        with self.assertRaises(ValueError):
            budget.status(path=self.path)
        self.assertEqual(self.path.read_text(encoding="utf-8"), json.dumps(
            {"max_requests": "lots", "requests_used": 0, "tokens_used": 0}))


if __name__ == "__main__":
    unittest.main()
