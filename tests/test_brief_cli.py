from contextlib import redirect_stderr, redirect_stdout
from datetime import timedelta
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from bughunt.cli import main
from bughunt.storage import Store
from bughunt.workflow import Workflow, utc_now


class BriefCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "test.db"
        self.store = Store(self.db)
        self.addCleanup(self.store.close)
        self.now = utc_now()
        self.app = Workflow(self.store, lambda: self.now)
        catalog = self.root / "programs.json"
        catalog.write_text(json.dumps([{
            "id": "test", "name": "Test", "platform": "manual",
            "program_url": "http://127.0.0.1:8000", "status": "active",
            "scope": ["http://127.0.0.1:8000"],
        }]), encoding="utf-8")
        self.app.import_programs(catalog)

    def finding(self, *, confirmed=True):
        self.app.verify_program("test", note="Synthetic policy", automation_allowed=True)
        finding = self.app.add_finding(
            "test", target="http://127.0.0.1:8000/api", title="Fixture \u2014 issue",
            vulnerability_type="validation", severity="low", reproduction="Fixture steps",
            impact="Fixture impact")
        if confirmed:
            self.app.confirm_finding(finding["id"], "Fixture evidence")
        return finding["id"]

    def command(self, finding_id, *arguments):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(["--db", str(self.db), "finding", "brief", finding_id, *arguments])
        return code, output.getvalue(), errors.getvalue()

    def test_stdout_is_complete_local_brief(self):
        finding_id = self.finding()
        code, output, errors = self.command(finding_id)
        self.assertEqual(code, 0, errors)
        brief = json.loads(output)
        self.assertEqual(brief["finding"]["id"], finding_id)
        self.assertEqual(brief["finding"]["title"], "Fixture \u2014 issue")
        self.assertFalse(brief["dispatched"])
        self.assertEqual(sum(row["action"] == "patch.briefed" for row in self.store.snapshot()["audit"]), 1)

    def test_stdout_delivery_failures_do_not_record_success(self):
        finding_id = self.finding()
        for method in ("write", "flush"):
            with self.subTest(method=method):
                stream = io.StringIO()
                errors = io.StringIO()
                with patch.object(stream, method, side_effect=OSError("Synthetic output failure")):
                    with redirect_stdout(stream), redirect_stderr(errors):
                        code = main(["--db", str(self.db), "finding", "brief", finding_id])
                self.assertEqual(code, 2)
                self.assertFalse(any(row["action"] == "patch.briefed" for row in self.store.snapshot()["audit"]))

    def test_file_is_json_with_newline_and_preserves_existing_evidence(self):
        finding_id = self.finding()
        target = self.root / "nested" / "brief.json"
        code, output, errors = self.command(finding_id, "--output", str(target))
        self.assertEqual(code, 0, errors)
        self.assertEqual(json.loads(output)["output"], str(target.resolve()))
        original = target.read_bytes()
        self.assertTrue(original.endswith(b"\n"))
        self.assertEqual(json.loads(original)["finding"]["id"], finding_id)
        code, output, errors = self.command(finding_id, "--output", str(target))
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertEqual(target.read_bytes(), original)
        self.assertEqual(sum(row["action"] == "patch.briefed" for row in self.store.snapshot()["audit"]), 1)

    def test_generated_command_updates_the_literal_custom_database_from_another_directory(self):
        shell = shutil.which("pwsh") or shutil.which("powershell") if os.name == "nt" else shutil.which("sh")
        if not shell:
            self.skipTest("No supported shell installed")
        finding_id = self.finding()
        db = self.root / "literal $budget 'quoted'" / "custom.db"
        custom = Store(db)
        try:
            with custom.transaction():
                custom.save("programs", self.store.get("programs", "test"))
                custom.save("findings", self.store.get("findings", finding_id))
            brief = Workflow(custom).patch_brief(finding_id)
            command = brief["requirements"][-1].split("`")[1]
            command = command.replace("PATH_OR_URL_TO_PATCH", "fixture.patch").replace("ACTUAL_TEST_COMMAND_AND_OUTPUT", "Synthetic test evidence")
            arguments = [shell, "-NoProfile", "-NonInteractive", "-Command", command] if os.name == "nt" else [shell, "-c", command]
            result = subprocess.run(arguments, cwd=self.root, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(custom.get("findings", finding_id)["patch_status"], "verified")
            self.assertEqual(self.store.get("findings", finding_id)["patch_status"], "not_started")
        finally:
            custom.close()

    def test_invalid_finding_does_not_create_output(self):
        unknown = "finding-unknown"
        unconfirmed = self.finding(confirmed=False)
        self.now -= timedelta(days=2)
        expired = self.finding()
        for finding_id, reason in ((unknown, "Unknown"), (unconfirmed, "confirmed"), (expired, "Scope denied")):
            with self.subTest(finding_id=finding_id):
                # Restore current program verification for the unconfirmed case.
                if finding_id == unconfirmed:
                    self.now += timedelta(days=2)
                    self.app.verify_program("test", note="Synthetic policy", automation_allowed=True)
                if finding_id == expired:
                    self.now -= timedelta(days=2)
                    self.app.verify_program("test", note="Old synthetic policy", automation_allowed=True)
                target = self.root / (finding_id + ".json")
                code, output, errors = self.command(finding_id, "--output", str(target))
                self.assertEqual(code, 2)
                self.assertEqual(output, "")
                self.assertIn(reason, errors)
                self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
