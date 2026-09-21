from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bughunt.storage import Store
from bughunt.workflow import Workflow


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / "test.db")
        self.addCleanup(self.store.close)
        self.now = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
        self.app = Workflow(self.store, lambda: self.now)
        self.catalog = self.root / "catalog.json"
        self.catalog.write_text(json.dumps([dict(id="test", name="Test", platform="manual",
            program_url="http://127.0.0.1:8000", status="active", automation_allowed=True,
            scope=["http://127.0.0.1:8000"], excluded_scope=["http://127.0.0.1:8000/admin"],
            payout_min="50", payout_max="200", currency="USD")]), encoding="utf-8")
        self.app.import_programs(self.catalog)
        self.app.verify_program("test", note="Synthetic test policy", automation_allowed=True)

    def finding(self):
        return self.app.add_finding("test", target="http://127.0.0.1:8000/api", title="Fixture",
            vulnerability_type="validation", severity="low", reproduction="Fixture steps", impact="Fixture impact")

    def test_patch_brief_requires_confirmation_and_assigns_astra(self):
        finding = self.finding()
        with self.assertRaises(ValueError):
            self.app.patch_brief(finding["id"])
        self.app.confirm_finding(finding["id"], "Fixture evidence")
        brief = self.app.patch_brief(finding["id"])
        self.assertEqual(brief["assignee"], "Astra")
        self.assertEqual(brief["finding"]["reproduction"], "Fixture steps")
        self.now += timedelta(hours=25)
        with self.assertRaises(ValueError):
            self.app.patch_brief(finding["id"])

    def draft(self):
        finding = self.finding()
        self.app.confirm_finding(finding["id"], "Fixture evidence")
        self.app.record_patch(finding["id"], patch_status="verified", reference="fix.patch", verification="Regression passed")
        return self.app.draft_submission(finding["id"])

    def submitted(self):
        return self.app.record_submission(self.draft()["id"], "PLATFORM-1")

    def test_import_clears_verification_and_preserves_blocks(self):
        self.app.block_program("test", "Automation withdrawn")
        imported = self.app.import_programs(self.catalog)[0]
        self.assertEqual(imported["blocked_reason"], "Automation withdrawn")
        self.assertIsNone(imported["verified_at"])
        with self.assertRaises(ValueError):
            self.app.verify_program("test", note="Still blocked", automation_allowed=True)
        self.app.unblock_program("test", "Reviewed new policy")
        self.assertFalse(self.app.scope_check("test", "http://127.0.0.1:8000")["allowed"])
        self.app.verify_program("test", note="Current policy permits this", automation_allowed=True)
        self.assertTrue(self.app.scope_check("test", "http://127.0.0.1:8000")["allowed"])

    def test_verification_requires_explicit_attestation_and_limited_lifetime(self):
        for values in ({"automation_allowed": False}, {"automation_allowed": True, "valid_hours": 169},
                       {"automation_allowed": True, "valid_hours": True}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.app.verify_program("test", note="Evidence", **values)

    def test_scope_denied_and_expired_findings_never_persist(self):
        with self.assertRaises(ValueError):
            self.app.add_finding("test", target="http://127.0.0.1:8000/admin", title="Fixture",
                vulnerability_type="test", severity="low", reproduction="steps", impact="test")
        self.now += timedelta(days=1)
        with self.assertRaises(ValueError):
            self.finding()
        self.assertEqual(self.store.list("findings"), [])

    def test_submission_requires_confirmation_and_verified_patch(self):
        finding = self.finding()
        with self.assertRaises(ValueError):
            self.app.draft_submission(finding["id"])
        self.app.confirm_finding(finding["id"], "Evidence")
        submission = self.app.draft_submission(finding["id"])
        with self.assertRaises(ValueError):
            self.app.record_submission(submission["id"], "ABC")
        with self.assertRaises(ValueError):
            self.app.record_patch(finding["id"], patch_status="verified", reference="fix.patch")
        self.app.record_patch(finding["id"], patch_status="not_applicable", verification="Configuration-only remediation")
        self.assertEqual(self.app.record_submission(submission["id"], "ABC")["status"], "submitted")

    def test_submission_rechecks_policy_before_recording(self):
        submission = self.draft()
        self.app.block_program("test", "Target requests stop")
        with self.assertRaises(ValueError):
            self.app.record_submission(submission["id"], "ABC")
        self.assertEqual(self.store.get("submissions", submission["id"])["attempts"], 0)

    def test_rejections_require_review_and_stop_after_two_resubmissions(self):
        submission = self.submitted()
        for attempt in range(1, 4):
            submission = self.app.reject_submission(submission["id"], f"Rejection {attempt}")
            self.assertEqual(submission["attempts"], attempt)
            with self.assertRaises(ValueError):
                self.app.record_submission(submission["id"], "ABC")
            if attempt < 3:
                self.app.review_rejection(submission["id"], "Updated reproduction and reviewed feedback")
                submission = self.app.record_submission(submission["id"], "ABC")
        self.assertEqual(submission["status"], "needs_review")
        with self.assertRaises(ValueError):
            self.app.review_rejection(submission["id"], "Try again")
        self.assertTrue(self.store.snapshot()["audit"][-1]["details"]["escalated"])

    def test_rate_limit_and_authentication_are_independent_gates(self):
        submission = self.draft()
        self.app.record_error(submission["id"], "rate_limit", "HTTP 429 recorded manually")
        self.app.record_error(submission["id"], "authentication", "Login expired")
        self.app.resume_submission(submission["id"], "Account recovered")
        with self.assertRaisesRegex(ValueError, "backoff"):
            self.app.record_submission(submission["id"], "ABC")
        self.now += timedelta(hours=1)
        self.assertEqual(self.app.record_submission(submission["id"], "ABC")["status"], "submitted")

    def test_authentication_and_unclear_status_pause_until_resolved(self):
        submission = self.draft()
        for kind in ("authentication", "unclear_status"):
            self.app.record_error(submission["id"], kind, "Needs human check")
            with self.assertRaisesRegex(ValueError, "paused"):
                self.app.record_submission(submission["id"], "ABC")
            self.app.resume_submission(submission["id"], "Resolved with evidence")
        self.app.record_submission(submission["id"], "ABC")

    def test_payments_require_acceptance_and_track_installments(self):
        submission = self.submitted()
        with self.assertRaises(ValueError):
            self.app.add_payment(submission["id"], "50", "USD")
        self.app.accept_submission(submission["id"], "Official acknowledgment")
        first = self.app.add_payment(submission["id"], "50.01", "USD")
        second = self.app.add_payment(submission["id"], "49.99", "USD")
        self.app.receive_payment(first["id"], "Received installment one")
        self.assertEqual(self.store.get("submissions", submission["id"])["status"], "accepted")
        self.app.receive_payment(second["id"], "Received installment two")
        self.assertEqual(self.store.get("submissions", submission["id"])["status"], "paid")
        with self.assertRaises(ValueError):
            self.app.receive_payment(second["id"], "Duplicate receipt")
        self.assertEqual(len(self.store.list("payments")), 2)

    def test_invalid_amounts_and_cvss_are_rejected(self):
        submission = self.submitted()
        self.app.accept_submission(submission["id"], "Acknowledgment")
        for amount in ("nan", "Infinity", "0", "-50", "0.001", "abc"):
            with self.subTest(amount=amount), self.assertRaises(ValueError):
                self.app.add_payment(submission["id"], amount, "USD")
        for score in ("NaN", "-1", "11", "abc"):
            with self.subTest(score=score), self.assertRaises(ValueError):
                self.app.add_finding("test", target="http://127.0.0.1:8000", title="Fixture", vulnerability_type="test",
                                     severity="low", reproduction="steps", impact="test", cvss_score=score)

    def test_failed_audit_rolls_back_entity_change(self):
        before = self.store.snapshot()
        with patch.object(self.store, "audit", side_effect=RuntimeError("Simulated write failure")):
            with self.assertRaises(RuntimeError):
                self.finding()
        self.assertEqual(self.store.snapshot(), before)

    def test_reopening_store_preserves_records_and_audit(self):
        finding = self.finding()
        other = Store(self.root / "test.db")
        try:
            self.assertEqual(other.get("findings", finding["id"]), finding)
            self.assertEqual(other.snapshot()["audit"][-1]["action"], "finding.created")
        finally:
            other.close()

    def test_duplicate_submission_does_not_reset_attempt_limit(self):
        submission = self.draft()
        with self.assertRaises(ValueError):
            self.app.draft_submission(submission["finding_id"])


if __name__ == "__main__":
    unittest.main()
