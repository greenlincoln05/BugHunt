"""CLI wiring for `finding evidence`: gating, audit timing, and no automatic
patch_status change. Adversarial focus: this must never let a model submit or
collect payment, and must never mark a patch verified on its own."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from bughunt.cli import main
from bughunt.storage import Store
from bughunt.workflow import Workflow, utc_now


def git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True)


class EvidenceCliTests(unittest.TestCase):
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
        self.app.verify_program("test", note="Synthetic policy", automation_allowed=True)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        git("init", "-q", cwd=self.workspace)
        git("-c", "user.email=a@b.c", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "init", cwd=self.workspace)

    def finding(self, *, confirmed=True):
        finding = self.app.add_finding(
            "test", target="http://127.0.0.1:8000/api", title="Fixture issue",
            vulnerability_type="validation", severity="low", reproduction="Fixture steps",
            impact="Fixture impact")
        if confirmed:
            self.app.confirm_finding(finding["id"], "Fixture evidence")
        return finding["id"]

    def command(self, *arguments):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(["--db", str(self.db), "finding", "evidence", *arguments])
        return code, output.getvalue(), errors.getvalue()

    def test_unconfirmed_finding_is_refused_before_running_anything(self):
        finding_id = self.finding(confirmed=False)
        code, output, errors = self.command(finding_id, "--workspace", str(self.workspace), "--command", "echo hi")
        self.assertEqual(code, 2)
        self.assertIn("must be confirmed", errors)
        self.assertEqual(self.store.list("findings")[0]["patch_status"], "not_started")

    def test_confirmed_finding_captures_real_output_to_stdout(self):
        finding_id = self.finding()
        code, output, errors = self.command(finding_id, "--workspace", str(self.workspace), "--command", "echo regression-ok")
        self.assertEqual(code, 0, errors)
        result = json.loads(output)
        self.assertTrue(result["passed"])
        self.assertIn("regression-ok", result["stdout"])

    def test_capture_never_changes_patch_status(self):
        """Capturing evidence -- even a passing one -- must never itself mark a patch ready/verified."""
        finding_id = self.finding()
        self.command(finding_id, "--workspace", str(self.workspace), "--command", "echo ok")
        self.assertEqual(self.store.list("findings")[0]["patch_status"], "not_started")

    def test_audit_recorded_only_after_stdout_flushes(self):
        finding_id = self.finding()
        self.command(finding_id, "--workspace", str(self.workspace), "--command", "echo ok")
        actions = [row["action"] for row in self.store.snapshot()["audit"]]
        self.assertIn("patch.evidence_captured", actions)

    def test_file_output_is_exclusive_create_and_audited_once(self):
        finding_id = self.finding()
        target = self.root / "nested" / "evidence.json"
        code, output, errors = self.command(finding_id, "--workspace", str(self.workspace),
                                             "--command", "echo ok", "--output", str(target))
        self.assertEqual(code, 0, errors)
        self.assertTrue(target.exists())
        recorded = json.loads(target.read_text(encoding="utf-8"))
        self.assertTrue(recorded["passed"])
        code, output, errors = self.command(finding_id, "--workspace", str(self.workspace),
                                             "--command", "echo ok", "--output", str(target))
        self.assertEqual(code, 2)  # exclusive create refuses to overwrite existing evidence
        actions = [row["action"] for row in self.store.snapshot()["audit"] if row["action"] == "patch.evidence_captured"]
        self.assertEqual(len(actions), 1)

    def test_failing_regression_is_reported_not_silently_passed(self):
        finding_id = self.finding()
        code, output, errors = self.command(finding_id, "--workspace", str(self.workspace),
                                             "--command", "python -c \"import sys; sys.exit(1)\"")
        self.assertEqual(code, 0, errors)  # capture itself succeeds; it just reports failure
        result = json.loads(output)
        self.assertFalse(result["passed"])
        self.assertEqual(result["exit_code"], 1)

    def test_missing_git_workspace_is_refused(self):
        finding_id = self.finding()
        plain = self.root / "not-git"
        plain.mkdir()
        code, output, errors = self.command(finding_id, "--workspace", str(plain), "--command", "echo hi")
        self.assertEqual(code, 2)
        self.assertIn("Git checkout", errors)


if __name__ == "__main__":
    unittest.main()
