"""Source findings need their own exact, time-limited policy gate."""

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bughunt.catalog import validate_program
from bughunt.cli import main
from bughunt.progress import build_progress
from bughunt.scope import check_scope, check_source_scope
from bughunt.storage import Store
from bughunt.submission_format import render_submission_markdown
from bughunt.workflow import Workflow


SOURCE = "https://github.com/example/library"
NOW = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)


def catalog_record(**changes):
    record = {"id": "example", "name": "Example", "platform": "hackerone",
              "program_url": "https://hackerone.com/example", "status": "active",
              "scope": [SOURCE], "excluded_scope": [], "source_code_assets": [{"url": SOURCE,
                       "eligible_for_bounty": True, "eligible_for_submission": True}],
              "automation_allowed": False}
    record.update(changes)
    return record


class SourceWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / "db.sqlite")
        self.addCleanup(self.store.close)
        self.now = NOW
        self.app = Workflow(self.store, lambda: self.now)
        self.catalog = self.root / "catalog.json"
        self.catalog.write_text(json.dumps([catalog_record()]), encoding="utf-8")
        self.app.import_programs(self.catalog)

    def finding(self, target=SOURCE):
        return self.app.add_finding("example", target=target, source_asset=True,
            title="Fixture", vulnerability_type="authorization", severity="low",
            reproduction="Local fixture steps", impact="Fixture impact")

    def test_import_and_promotion_metadata_do_not_grant_http_or_source_access(self):
        program = self.store.get("programs", "example")
        self.assertEqual(program["source_code_assets"][0]["url"], SOURCE)
        self.assertIsNone(program["source_review"])
        self.assertFalse(check_source_scope(program, SOURCE, self.now)["allowed"])
        self.assertFalse(check_scope(program, SOURCE, self.now)["allowed"])
        with self.assertRaises(ValueError):
            self.finding()

    def test_exact_source_review_allows_local_finding_chain_only(self):
        result = self.app.verify_source("example", SOURCE, note="Official policy checked today; source and submissions open")
        self.assertFalse(result["live_testing_authorized"])
        program = self.store.get("programs", "example")
        self.assertTrue(check_source_scope(program, SOURCE, self.now)["allowed"])
        self.assertFalse(check_scope(program, SOURCE, self.now)["allowed"])
        with self.assertRaises(ValueError):
            self.app.record_audit("example", SOURCE, "Would be a live HTTP audit")
        with self.assertRaises(ValueError):
            self.app.add_finding("example", target=SOURCE, title="HTTP fixture", vulnerability_type="test",
                                 severity="low", reproduction="steps", impact="impact")
        finding = self.finding()
        self.assertEqual(finding["target_kind"], "source_code")
        self.app.confirm_finding(finding["id"], "Actual local proof")
        self.assertEqual(self.app.patch_brief(finding["id"])["finding"]["target_kind"], "source_code")
        self.app.record_patch(finding["id"], patch_status="verified", reference="fix.patch",
                              verification="Regression test passed")
        submission = self.app.draft_submission(finding["id"])
        self.assertEqual(self.app.submission_bundle(submission["id"])["finding"]["id"], finding["id"])
        self.assertEqual(self.app.record_submission(submission["id"], "OFFICIAL-1")["status"], "submitted")
        self.now += timedelta(hours=25)
        archive = self.app.submission_bundle(submission["id"])
        self.assertFalse(archive["policy_review_current"])
        self.assertIn("Historical record only", archive["policy_warning"])
        self.assertIn("Policy status: Historical record only", render_submission_markdown(archive))

    def test_declared_source_never_becomes_live_http_scope(self):
        program = catalog_record(scope=[SOURCE, "https://example.test/live"], automation_allowed=True,
                                 verified_at="2026-09-21T11:00:00Z",
                                 verification_expires_at="2026-09-22T11:00:00Z")
        for target in (SOURCE, SOURCE + "/issues", SOURCE + "?tab=readme", "http://github.com/example/library"):
            with self.subTest(target=target):
                self.assertFalse(check_scope(program, target, self.now)["allowed"])
        self.assertTrue(check_scope(program, "https://example.test/live", self.now)["allowed"])
        program["scope"].append("github.com")
        self.assertFalse(check_scope(program, SOURCE + "/issues", self.now)["allowed"])

    def test_near_miss_urls_and_exclusions_fail_closed(self):
        self.app.verify_source("example", SOURCE, note="Current official policy reviewed")
        for target in (SOURCE + "/issues", SOURCE + "?view=1", SOURCE + "#readme",
                       SOURCE + "-evil", "https://github.com/example/other", SOURCE + "/"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.finding(target)
        program = self.store.get("programs", "example")
        program["excluded_scope"] = [SOURCE]
        self.store.save("programs", program)
        with self.assertRaises(ValueError):
            self.finding()
        self.assertEqual(self.store.list("findings"), [])

    def test_review_expiry_rechecks_confirm_brief_draft_record_and_export(self):
        self.app.verify_source("example", SOURCE, note="Current official policy reviewed", valid_hours=1)
        unconfirmed = self.finding()
        self.app.confirm_finding(unconfirmed["id"], "Proof")
        self.app.record_patch(unconfirmed["id"], patch_status="not_applicable", verification="Reason")
        draft = self.app.draft_submission(unconfirmed["id"])
        self.now += timedelta(hours=2)
        with self.assertRaises(ValueError):
            self.finding()
        for operation in (lambda: self.app.confirm_finding(unconfirmed["id"], "Proof again"),
                          lambda: self.app.patch_brief(unconfirmed["id"]),
                          lambda: self.app.draft_submission(unconfirmed["id"]),
                          lambda: self.app.submission_bundle(draft["id"]),
                          lambda: self.app.record_submission(draft["id"], "OFFICIAL-2")):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                operation()
        self.assertEqual(self.store.get("submissions", draft["id"])["attempts"], 0)
        self.app.verify_source("example", SOURCE, note="Official scope and submission status rechecked")
        self.assertEqual(self.app.record_submission(draft["id"], "OFFICIAL-2")["status"], "submitted")

    def test_import_block_and_policy_changes_clear_or_deny_review(self):
        self.app.verify_source("example", SOURCE, note="Current official policy reviewed")
        self.app.block_program("example", "Submissions closed")
        self.assertIsNone(self.store.get("programs", "example")["source_review"])
        with self.assertRaises(ValueError):
            self.app.verify_source("example", SOURCE, note="Still closed")
        self.app.unblock_program("example", "Open again")
        with self.assertRaises(ValueError):
            self.finding()
        self.app.verify_source("example", SOURCE, note="Official policy rechecked")
        self.app.import_programs(self.catalog)
        self.assertIsNone(self.store.get("programs", "example")["source_review"])
        with self.assertRaises(ValueError):
            self.finding()
        self.app.verify_source("example", SOURCE, note="Official policy reviewed after import")
        program = self.store.get("programs", "example")
        program["program_url"] = "https://hackerone.com/other"
        self.store.save("programs", program)
        with self.assertRaises(ValueError):
            self.finding()

    def test_catalog_source_metadata_validation(self):
        for assets in (None, "yes", [{"url": SOURCE}],
                       [{"url": SOURCE, "eligible_for_bounty": 1, "eligible_for_submission": True}],
                       [{"url": SOURCE + "?x=1", "eligible_for_bounty": True, "eligible_for_submission": True}],
                       [{"url": SOURCE, "eligible_for_bounty": True, "eligible_for_submission": True}] * 2):
            with self.subTest(assets=assets), self.assertRaises(ValueError):
                validate_program(catalog_record(source_code_assets=assets))
        with self.assertRaises(ValueError):
            validate_program(catalog_record(scope=["https://github.com/example"],
                                            source_code_assets=catalog_record()["source_code_assets"]))
        with self.assertRaises(ValueError):
            validate_program(catalog_record(source_review={"note": "Import must not attest"}))

    def test_progress_routes_source_finding_and_review_separately(self):
        initial = build_progress(self.store.snapshot(), now=self.now, credentials_present=True)
        self.assertIn("source_policy_review", [row["kind"] for row in initial["next_actions"]])
        self.assertNotIn("policy_review", [row["kind"] for row in initial["next_actions"]])
        self.app.verify_source("example", SOURCE, note="Current official policy reviewed")
        ready = build_progress(self.store.snapshot(), now=self.now, credentials_present=True)
        self.assertIn("local_research", [row["kind"] for row in ready["next_actions"]])
        finding = self.finding()
        queue = build_progress(self.store.snapshot(), now=self.now, credentials_present=True)
        self.assertIn("confirm_finding", [row["kind"] for row in queue["next_actions"]])
        self.now += timedelta(hours=25)
        stale = build_progress(self.store.snapshot(), now=self.now, credentials_present=True)
        self.assertIn("source_policy_review", [row["kind"] for row in stale["next_actions"]])
        self.assertIn("finding_scope_blocked", [row["kind"] for row in stale["next_actions"]])

    def test_cli_requires_terminal_attestation_then_accepts_explicit_source_flag(self):
        command = ["--db", str(self.store.path), "program", "verify-source", "example",
                   "--source-url", SOURCE, "--note", "Current official source policy checked"]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as error:
            self.assertEqual(main(command), 2)
        self.assertIn("interactive terminal", error.getvalue())
        with patch("bughunt.cli._confirm_human") as confirm, redirect_stdout(io.StringIO()):
            self.assertEqual(main(command), 0)
        confirm.assert_called_once()
        repro = self.root / "repro.txt"
        repro.write_text("Local fixture proof", encoding="utf-8")
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["--db", str(self.store.path), "finding", "add", "example",
                                   "--target", SOURCE, "--source-asset", "--title", "Fixture", "--type", "authorization",
                                   "--severity", "low", "--reproduction-file", str(repro), "--impact", "Fixture"]), 0)
        self.assertEqual(json.loads(output.getvalue())["target_kind"], "source_code")


if __name__ == "__main__":
    unittest.main()
