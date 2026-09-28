from contextlib import redirect_stdout, redirect_stderr
import io
import json
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

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

    def test_markdown_export_is_reviewable_and_does_not_change_submission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / "demo.db"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--db", str(db), "demo", "--out", str(root / "reports")]), 0)
            store = Store(db)
            try:
                submission = store.list("submissions")[0]
                finding = store.get("findings", submission["finding_id"])
                original = store.get("submissions", submission["id"])
            finally:
                store.close()

            target = root / "submission.md"
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["--db", str(db), "submission", "export", submission["id"],
                                       "--output", str(target), "--format", "markdown"]), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["format"], "markdown")
            self.assertFalse(result["submitted"])
            report = target.read_text(encoding="utf-8")
            self.assertIn("# " + finding["title"], report)
            self.assertIn(finding["target"], report)
            self.assertIn(finding["reproduction"], report)
            self.assertIn(finding["impact"], report)
            self.assertIn(finding["confirmation_evidence"], report)
            self.assertIn(finding["verification"], report)
            self.assertIn("attach the actual proof-of-concept", report)
            store = Store(db)
            try:
                self.assertEqual(store.get("submissions", submission["id"]), original)
                self.assertEqual(store.snapshot()["audit"][-1]["details"]["format"], "markdown")
            finally:
                store.close()

    def test_review_zip_contains_only_selected_proof_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / "demo.db"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--db", str(db), "demo", "--out", str(root / "reports")]), 0)
            store = Store(db)
            try:
                submission = store.list("submissions")[0]
                original = store.get("submissions", submission["id"])
            finally:
                store.close()
            proof = root / "proof.txt"
            proof.write_bytes(b"owned-lab-regression-passed\n")
            unrelated = root / "do-not-include.txt"
            unrelated.write_text("private data", encoding="utf-8")
            target = root / "review.zip"
            command = ["--db", str(db), "submission", "export", submission["id"],
                       "--output", str(target), "--format", "zip", "--attachment", str(proof)]
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(command), 0)
            self.assertEqual(json.loads(output.getvalue())["attachments"], 1)
            with ZipFile(target) as archive:
                self.assertIsNone(archive.testzip())
                self.assertEqual(set(archive.namelist()), {"report.md", "submission.json", "manifest.json",
                                                       "attachments/proof.txt"})
                self.assertEqual(archive.read("attachments/proof.txt"), proof.read_bytes())
                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual(manifest["attachments"][0]["sha256"], sha256(proof.read_bytes()).hexdigest())
                self.assertNotIn(str(root), archive.read("manifest.json").decode("utf-8"))
            original_zip = target.read_bytes()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(command), 2)
            self.assertEqual(target.read_bytes(), original_zip)
            store = Store(db)
            try:
                self.assertEqual(store.get("submissions", submission["id"]), original)
                exports = [entry for entry in store.snapshot()["audit"] if entry["action"] == "submission.exported"]
                self.assertEqual(len(exports), 1)
                self.assertEqual(exports[0]["details"]["attachments"], 1)
            finally:
                store.close()

    def test_review_zip_rejects_duplicate_filenames_without_leaving_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / "demo.db"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--db", str(db), "demo", "--out", str(root / "reports")]), 0)
            store = Store(db)
            try:
                submission_id = store.list("submissions")[0]["id"]
            finally:
                store.close()
            first = root / "one" / "proof.txt"
            second = root / "two" / "PROOF.txt"
            first.parent.mkdir()
            second.parent.mkdir()
            first.write_text("first", encoding="utf-8")
            second.write_text("second", encoding="utf-8")
            target = root / "review.zip"
            with redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(main(["--db", str(db), "submission", "export", submission_id,
                                       "--output", str(target), "--format", "zip",
                                       "--attachment", str(first), "--attachment", str(second)]), 2)
            self.assertIn("Duplicate attachment", errors.getvalue())
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
