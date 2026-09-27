"""Local spend cap: enforced before each paid call, persisted, pessimistic."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from bughunt import budget
from bughunt.fsutil import gate_state_dir


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


    def test_omitted_token_cap_is_kept_and_none_clears_it(self):
        budget.set_budget(5, max_tokens=1000, path=self.path)
        self.assertEqual(budget.set_budget(4, path=self.path)["max_tokens"], 1000)
        self.assertIsNone(budget.set_budget(4, max_tokens=None, path=self.path)["max_tokens"])

    def test_token_totals_above_the_request_bound_are_still_a_valid_ledger(self):
        budget.set_budget(5, path=self.path)
        budget.record_tokens(2_500_000, path=self.path)
        self.assertEqual(budget.status(path=self.path)["tokens_used"], 2_500_000)
        self.reserve()  # the ledger still loads and works

    def test_ledger_shape_is_validated_strictly(self):
        good = {"max_requests": 3, "requests_used": 0, "tokens_used": 0, "max_tokens": None, "history": []}
        for name, change in {"missing max_tokens": {"max_tokens": KEY_MISSING}, "huge cap": {"max_requests": budget.MAX_CAP + 1},
                             "negative use": {"requests_used": -1}, "bool": {"max_requests": True},
                             "history not a list": {"history": "x"}}.items():
            document = {k: v for k, v in {**good, **change}.items() if v is not KEY_MISSING}
            self.path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ValueError, msg=name):
                budget.status(path=self.path)

    def test_every_write_is_a_unique_temp_file_replaced_in_place(self):
        budget.set_budget(3, path=self.path)
        self.reserve()
        leftovers = [p.name for p in self.path.parent.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_concurrent_processes_cannot_both_spend_the_last_request(self):
        # Regression: without a cross-process lock, two runs both saw "1 left" and both paid.
        budget.set_budget(1, path=self.path)
        source = str(Path(__file__).resolve().parents[1] / "src")
        start = time.time() + 2.5
        script = (
            "import sys, time\n"
            f"sys.path.insert(0, {source!r})\n"
            "from bughunt import budget\n"
            f"time.sleep(max(0, {start!r} - time.time()))\n"
            "try:\n"
            f"    budget.reserve_request(path={str(self.path)!r})\n"
            "    print('OK')\n"
            "except budget.BudgetExhausted:\n"
            "    print('NO')\n"
            "except Exception as error:\n"
            "    print('ERR', type(error).__name__)\n")
        workers = [subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True) for _ in range(6)]
        results = [worker.communicate(timeout=90)[0].strip() for worker in workers]
        self.assertEqual(sorted(results), ["NO"] * 5 + ["OK"], results)
        self.assertEqual(budget.status(path=self.path)["requests_used"], 1)


class GateStateLocationTests(unittest.TestCase):
    def test_state_is_anchored_to_bughunt_home_or_the_user_directory_never_the_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"BUGHUNT_HOME": directory}):
                self.assertEqual(gate_state_dir(), Path(directory).resolve())
                self.assertEqual(budget.default_ledger_path().parent, Path(directory).resolve())
            environment = {k: v for k, v in os.environ.items() if k != "BUGHUNT_HOME"}
            with patch.dict(os.environ, environment, clear=True):
                self.assertEqual(gate_state_dir(), (Path.home() / ".bughunt").resolve())
                self.assertNotEqual(gate_state_dir(), (Path.cwd() / ".bughunt").resolve())


KEY_MISSING = object()


if __name__ == "__main__":
    unittest.main()
