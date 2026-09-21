from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest

from bughunt.cli import main
from bughunt.storage import Store


class CliTests(unittest.TestCase):
    def test_demo_reports_shortlist_and_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / "demo.db"
            out = root / "reports"
            with redirect_stdout(io.StringIO()) as output:
                code = main(["--db", str(db), "demo", "--out", str(out)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["network_requests"], 0)
            self.assertEqual(len(list(out.glob("*"))), 3)
            self.assertEqual(len(json.loads((out / "vulnerabilities_found.json").read_text(encoding="utf-8"))), 2)
            report = (out / "weekly_payout_report.md").read_text(encoding="utf-8")
            self.assertIn("DEMO ONLY", report)
            self.assertIn("| USD | 200.00 | 100.00 | 100.00 |", report)
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["--db", str(db), "program", "shortlist"]), 0)
            self.assertEqual(json.loads(output.getvalue())[0]["payout_min"], "50")
            with redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(main(["--db", str(db), "demo", "--out", str(out)]), 2)
            self.assertIn("empty database", errors.getvalue())

    def test_scope_denial_exit_code_and_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / "test.db"
            fixture = Path(__file__).resolve().parents[1] / "examples" / "programs.json"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--db", str(db), "program", "import", str(fixture)]), 0)
                self.assertEqual(main(["--db", str(db), "scope", "local-demo", "http://127.0.0.1:8000"]), 3)
            store = Store(db)
            try:
                self.assertFalse(store.snapshot()["audit"][-1]["details"]["allowed"])
            finally:
                store.close()

    def test_export_is_local_and_does_not_overwrite_existing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / "demo.db"
            with redirect_stdout(io.StringIO()):
                main(["--db", str(db), "demo", "--out", str(root / "reports")])
            store = Store(db)
            try:
                submission = store.list("submissions")[0]
            finally:
                store.close()
            target = root / "submission.json"
            arguments = ["--db", str(db), "submission", "export", submission["id"], "--output", str(target)]
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(arguments), 0)
            self.assertFalse(json.loads(output.getvalue())["submitted"])
            self.assertIn("Manual upload", json.loads(target.read_text(encoding="utf-8"))["delivery"])
            original = target.read_bytes()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(arguments), 2)
            self.assertEqual(original, target.read_bytes())


if __name__ == "__main__":
    unittest.main()
