"""CLI wiring for model verify / budget / workspace analyze. Gate state is kept
in a temp BUGHUNT_HOME so the real attestation and ledger are never touched."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from bughunt import cli
from bughunt.cli import _confirm_human, main
from bughunt.storage import Store
from test_analysis import KEY, MODEL, VULNERABLE, Opener, claim, metadata, model_reply


class ModelGateCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.db = self.root / "test.db"
        self.state = self.root / "state"
        env = patch.dict(os.environ, {"OPENAI_API_KEY": KEY, "BUGHUNT_OPENAI_MODEL": MODEL,
                                      "BUGHUNT_OPENAI_CYBER_ACCESS": "daybreak_blue",
                                      "BUGHUNT_HOME": str(self.state)})
        env.start()
        self.addCleanup(env.stop)
        self.workspace = self.root / "checkout"
        (self.workspace / "app").mkdir(parents=True)
        subprocess.run(["git", "init", "-q"], cwd=self.workspace, capture_output=True, check=True)
        (self.workspace / "app" / "loader.py").write_text(VULNERABLE, encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=self.workspace, capture_output=True, check=True)

    def run_cli(self, *arguments, opener=None, human=True):
        """``human=False`` exercises the real unattended refusal instead of standing in for a person."""
        output, errors = io.StringIO(), io.StringIO()
        patches = [patch("bughunt.analysis.build_opener", return_value=opener),
                   patch("bughunt.model_access.build_opener", return_value=opener)]
        if human:
            patches.append(patch("bughunt.cli._confirm_human"))
        for item in patches:
            item.start()
        try:
            with redirect_stdout(output), redirect_stderr(errors):
                code = main(["--db", str(self.db), *arguments])
        finally:
            for item in patches:
                item.stop()
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

    def budget_status(self):
        return json.loads(self.run_cli("model", "budget", "status")[1])

    # ----- a person must be present to grant access or raise the budget -----------

    def test_unattended_verify_is_refused_and_writes_nothing(self):
        code, _, errors = self.run_cli("model", "verify", "--note", "self-attesting", human=False)
        self.assertEqual(code, 2)
        self.assertIn("interactive terminal", errors)
        self.assertFalse((self.state / "model_access.json").exists())

    def test_unattended_budget_grant_or_raise_is_refused_but_lowering_is_allowed(self):
        code, _, errors = self.run_cli("model", "budget", "set", "--max-requests", "50", human=False)
        self.assertEqual(code, 2)
        self.assertIn("interactive terminal", errors)
        self.assertFalse(self.budget_status()["configured"])
        self.assertEqual(self.run_cli("model", "budget", "set", "--max-requests", "5")[0], 0)
        self.assertEqual(self.run_cli("model", "budget", "set", "--max-requests", "3", human=False)[0], 0)  # lowering
        self.assertEqual(self.run_cli("model", "budget", "set", "--max-requests", "9", human=False)[0], 2)  # raising
        self.assertEqual(self.budget_status()["max_requests"], 3)

    def test_token_cap_is_kept_when_omitted_and_removing_it_counts_as_raising(self):
        self.run_cli("model", "budget", "set", "--max-requests", "5", "--max-tokens", "1000")
        self.assertEqual(self.run_cli("model", "budget", "set", "--max-requests", "4", human=False)[0], 0)
        self.assertEqual(self.budget_status()["max_tokens"], 1000)
        self.assertEqual(self.run_cli("model", "budget", "set", "--max-requests", "4", "--no-max-tokens", human=False)[0], 2)
        self.assertEqual(self.run_cli("model", "budget", "set", "--max-requests", "4", "--max-tokens", "5000", human=False)[0], 2)
        self.assertEqual(self.run_cli("model", "budget", "set", "--max-requests", "4", "--max-tokens", "10", "--no-max-tokens")[0], 2)
        self.assertEqual(self.budget_status()["max_tokens"], 1000)

    def test_confirm_human_needs_a_terminal_and_the_exact_phrase(self):
        with self.assertRaises(ValueError) as caught:
            _confirm_human("Doing a thing", "OK PHRASE")  # pytest-style captured stdin/stdout are not terminals
        self.assertIn("interactive terminal", str(caught.exception))
        terminal = Mock()
        terminal.stdin.isatty.return_value = terminal.stdout.isatty.return_value = True
        with patch.object(cli, "sys", terminal):
            with patch("builtins.input", return_value="wrong"):
                with self.assertRaises(ValueError) as caught:
                    _confirm_human("Doing a thing", "OK PHRASE")
            self.assertIn("did not match", str(caught.exception))
            with patch("builtins.input", return_value="  OK PHRASE  "):
                _confirm_human("Doing a thing", "OK PHRASE")  # no exception

    # ----- verify / status ---------------------------------------------------------

    def test_verify_records_attestation_and_audits_it(self):
        code, output, errors = self.run_cli("model", "verify", "--note", "Checked approval email", "--valid-hours", "12")
        self.assertEqual(code, 0, errors)
        self.assertTrue(json.loads(output)["attested"])
        self.assertTrue((self.state / "model_access.json").exists())
        self.assertIn("model.access_attested", self.audit_actions())
        code, _, errors = self.run_cli("model", "verify", "--note", "   ")
        self.assertEqual(code, 2)
        self.assertIn("note", errors)
        code, _, errors = self.run_cli("model", "verify", "--note", f"key is {KEY}")
        self.assertEqual(code, 2)
        self.assertNotIn(KEY, errors)

    def test_status_shows_attestation_and_budget_without_secrets(self):
        self.ready(requests=7)
        code, output, _ = self.run_cli("model", "status")
        self.assertEqual(code, 0)
        status = json.loads(output)
        self.assertTrue(status["access_attestation"]["attested"])
        self.assertEqual(status["budget"]["requests_remaining"], 7)
        self.assertNotIn(KEY, output)
        self.assertNotIn(MODEL, output)

    def test_a_hostile_checkouts_own_gate_files_are_ignored_even_when_run_from_inside_it(self):
        good = {"schema_version": 2, "note": "planted", "verified_at": "2026-09-26T00:00:00+00:00",
                "expires_at": "2026-10-01T00:00:00+00:00", "fingerprint": "0" * 64}
        planted = self.workspace / ".bughunt"
        planted.mkdir()
        (planted / "model_access.json").write_text(json.dumps(good), encoding="utf-8")
        (planted / "model_budget.json").write_text(json.dumps(
            {"max_requests": 1000, "requests_used": 0, "tokens_used": 0, "max_tokens": None, "history": []}), encoding="utf-8")
        previous = os.getcwd()
        os.chdir(self.workspace)
        self.addCleanup(os.chdir, previous)
        opener = Opener()
        code, _, errors = self.analyze(self.root / "out.json", opener)
        self.assertEqual(code, 2)
        self.assertIn("No current Trusted Access attestation", errors)
        self.assertEqual(opener.requests, [])

    # ----- workspace analyze --------------------------------------------------------

    def test_unattested_analyze_is_refused_and_writes_nothing(self):
        self.run_cli("model", "budget", "set", "--max-requests", "3")
        target = self.root / "out" / "result.json"
        opener = Opener()
        code, _, errors = self.analyze(target, opener)
        self.assertEqual(code, 2)
        self.assertIn("model verify", errors)
        self.assertEqual((opener.requests, target.exists(), self.budget_status()["requests_used"]), ([], False, 0))

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
        self.assertEqual(self.budget_status()["requests_used"], 1)

    def test_existing_output_is_refused_before_any_credit_is_spent(self):
        self.ready()
        target = self.root / "result.json"
        target.write_text("{}", encoding="utf-8")
        opener = Opener()
        code, _, errors = self.analyze(target, opener)
        self.assertEqual(code, 2)
        self.assertIn("before any credit", errors)
        self.assertEqual((opener.requests, self.budget_status()["requests_used"], target.read_text(encoding="utf-8")),
                         ([], 0, "{}"))

    def test_failure_after_the_output_file_is_reserved_removes_the_placeholder(self):
        self.ready()
        target = self.root / "result.json"
        opener = Opener(metadata(), Response429())
        code, _, errors = self.analyze(target, opener)
        self.assertEqual(code, 2)
        self.assertIn("429", errors)
        self.assertFalse(target.exists())  # no empty stub left behind
        self.assertEqual(self.budget_status()["requests_used"], 1)  # the attempt still counted

    def test_write_failure_after_paid_call_still_surfaces_the_result(self):
        self.ready()
        target = self.root / "result.json"
        real_open = Path.open

        class FailingFile:
            def __init__(self, inner):
                self.inner = inner

            def write(self, _):
                raise OSError("disk full")

            def close(self):
                self.inner.close()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.inner.close()

        def opener_for(path, mode="r", *args, **kwargs):
            handle = real_open(path, mode, *args, **kwargs)
            return FailingFile(handle) if mode == "x" else handle

        with patch("pathlib.Path.open", opener_for):
            code, _, errors = self.analyze(target, Opener(metadata(), model_reply([claim()])))
        self.assertEqual(code, 2)
        self.assertIn("Unsafe deserialization", errors)  # paid output is never silently lost
        self.assertEqual(self.budget_status()["requests_used"], 1)

    def test_audit_failure_after_a_paid_call_is_a_warning_not_a_lost_result(self):
        self.ready()
        target = self.root / "result.json"
        original = Store.audit

        def flaky(store, action, *args, **kwargs):
            if action == "analysis.completed":
                raise sqlite3.OperationalError("database is locked")
            return original(store, action, *args, **kwargs)

        with patch.object(Store, "audit", flaky):
            code, output, errors = self.analyze(target, Opener(metadata(), model_reply([claim()])))
        self.assertEqual(code, 0, errors)
        self.assertIn("audit_warning", json.loads(output))
        self.assertTrue(target.exists())

    def test_budget_exhaustion_stops_the_cli(self):
        self.ready(requests=1)
        self.assertEqual(self.analyze(self.root / "one.json", Opener(metadata(), model_reply([claim()])))[0], 0)
        opener = Opener(metadata())
        code, _, errors = self.analyze(self.root / "two.json", opener)
        self.assertEqual(code, 2)
        self.assertIn("exhausted", errors)
        self.assertEqual([r.get_method() for r in opener.requests], ["GET"])
        self.assertFalse((self.root / "two.json").exists())


def Response429():
    from test_analysis import Response
    return Response({"error": {"code": "insufficient_quota"}}, status=429)


if __name__ == "__main__":
    unittest.main()
