"""CLI wiring for model verify / budget / workspace analyze. Runs inside a temp
working directory so the real .bughunt/ ledger and attestation are never touched."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from bughunt.cli import main
from bughunt.storage import Store
from test_analysis import KEY, MODEL, VULNERABLE, Opener, claim, metadata, model_reply


class ModelGateCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        previous = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        self.db = self.root / "test.db"
        env = patch.dict(os.environ, {"OPENAI_API_KEY": KEY, "BUGHUNT_OPENAI_MODEL": MODEL})
        env.start()
        self.addCleanup(env.stop)
        self.workspace = self.root / "checkout"
        (self.workspace / "app").mkdir(parents=True)
        subprocess.run(["git", "init", "-q"], cwd=self.workspace, capture_output=True, check=True)
        (self.workspace / "app" / "loader.py").write_text(VULNERABLE, encoding="utf-8")

    def run_cli(self, *arguments, opener=None):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors), \
                patch("bughunt.analysis.build_opener", return_value=opener), \
                patch("bughunt.model_access.build_opener", return_value=opener):
            code = main(["--db", str(self.db), *arguments])
        return code, output.getvalue(), errors.getvalue()

    def audit_actions(self):
        store = Store(self.db)
        try:
            return [row["action"] for row in store.snapshot()["audit"]]
        finally:
            store.close()

    def ready(self, requests=3):
        self.assertEqual(self.run_cli("model", "verify", "--note", "Checked approval email")[0], 0)
        self.assertEqual(self.run_cli("model", "budget", "set", "--max-requests", str(requests))[0], 0)

    def analyze(self, output, opener, *extra):
        return self.run_cli("workspace", "analyze", "--workspace", str(self.workspace), "--file", "app/loader.py",
                            "--output", str(output), *extra, opener=opener)

    def used(self):
        code, out, _ = self.run_cli("model", "budget", "status")
        return json.loads(out)["requests_used"]

    def test_verify_records_attestation_and_audits_it(self):
        code, output, errors = self.run_cli("model", "verify", "--note", "Checked approval email", "--valid-hours", "12")
        self.assertEqual(code, 0, errors)
        self.assertTrue(json.loads(output)["attested"])
        self.assertTrue((self.root / ".bughunt" / "model_access.json").exists())
        self.assertIn("model.access_attested", self.audit_actions())
        code, _, errors = self.run_cli("model", "verify", "--note", "   ")
        self.assertEqual(code, 2)
        self.assertIn("blank", errors)

    def test_status_shows_attestation_and_budget_without_secrets(self):
        self.ready(requests=7)
        code, output, _ = self.run_cli("model", "status")
        self.assertEqual(code, 0)
        status = json.loads(output)
        self.assertTrue(status["access_attestation"]["attested"])
        self.assertEqual(status["budget"]["requests_remaining"], 7)
        self.assertNotIn(KEY, output)
        self.assertNotIn(MODEL, output)

    def test_unattested_analyze_is_refused_and_writes_nothing(self):
        self.run_cli("model", "budget", "set", "--max-requests", "3")
        target = self.root / "out" / "result.json"
        opener = Opener()
        code, _, errors = self.analyze(target, opener)
        self.assertEqual(code, 2)
        self.assertIn("model verify", errors)
        self.assertEqual((opener.requests, target.exists(), self.used()), ([], False, 0))

    def test_happy_path_saves_result_audits_and_spends_one_request(self):
        self.ready()
        target = self.root / "out" / "result.json"
        opener = Opener(metadata(), model_reply([claim()]))
        code, output, errors = self.analyze(target, opener)
        self.assertEqual(code, 0, errors)
        summary = json.loads(output)
        self.assertEqual((summary["candidates"], summary["verified_in_source"]), (1, 1))
        self.assertIs(summary["testing_authorized"], False)
        saved = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(saved["candidates"][0]["file"], "app/loader.py")
        self.assertNotIn(KEY, target.read_text(encoding="utf-8"))
        self.assertIn("analysis.completed", self.audit_actions())
        self.assertEqual(self.used(), 1)

    def test_existing_output_is_refused_before_any_credit_is_spent(self):
        self.ready()
        target = self.root / "result.json"
        target.write_text("{}", encoding="utf-8")
        opener = Opener()
        code, _, errors = self.analyze(target, opener)
        self.assertEqual(code, 2)
        self.assertIn("before any credit", errors)
        self.assertEqual((opener.requests, self.used(), target.read_text(encoding="utf-8")), ([], 0, "{}"))

    def test_write_failure_after_paid_call_still_surfaces_the_result(self):
        self.ready()
        target = self.root / "result.json"
        opener = Opener(metadata(), model_reply([claim()]))
        with patch("bughunt.cli.json.dump", side_effect=OSError("disk full")):
            code, _, errors = self.analyze(target, opener)
        self.assertEqual(code, 2)
        self.assertIn("Unsafe deserialization", errors)  # paid output is never silently lost
        self.assertEqual(self.used(), 1)

    def test_budget_exhaustion_stops_the_cli(self):
        self.ready(requests=1)
        self.assertEqual(self.analyze(self.root / "one.json", Opener(metadata(), model_reply([claim()])))[0], 0)
        opener = Opener(metadata())
        code, _, errors = self.analyze(self.root / "two.json", opener)
        self.assertEqual(code, 2)
        self.assertIn("exhausted", errors)
        self.assertEqual([r.get_method() for r in opener.requests], ["GET"])
        self.assertFalse((self.root / "two.json").exists())


if __name__ == "__main__":
    unittest.main()
