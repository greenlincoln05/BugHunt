"""Receipt identity and chronology protect locally recorded payout progress."""

from datetime import datetime, timedelta, timezone
import unittest

from bughunt.reports import _submission_report, _weekly_report
from bughunt.storage import Store
from bughunt.workflow import Workflow, stamp


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)
        self.now = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
        self.app = Workflow(self.store, lambda: self.now)
        self.submitted_at = self.now - timedelta(days=3)
        self.store.save("programs", {"id": "fixture"})

    def payment(self, platform="hackerone", amount="0.75"):
        number = len(self.store.list("submissions"))
        finding_id, submission_id = f"finding-{number}", f"submission-{number}"
        self.store.save("findings", {"id": finding_id, "program_id": "fixture"})
        self.store.save("submissions", {"id": submission_id, "finding_id": finding_id,
                        "platform": platform, "status": "accepted", "submitted_at": stamp(self.submitted_at)})
        return self.app.add_payment(submission_id, amount, "USD")

    def test_same_receipt_cannot_count_twice_on_a_platform(self):
        first, second = self.payment(), self.payment()
        self.app.receive_payment(first["id"], "Platform receipt", receipt_reference="receipt-1")
        before = self.store.snapshot()
        with self.assertRaisesRegex(ValueError, "already recorded"):
            self.app.receive_payment(second["id"], "Duplicate notice", receipt_reference="receipt-1")
        self.assertEqual(before, self.store.snapshot())
        report = _weekly_report([], [], self.store.list("payments"), [], self.now)
        self.assertIn("| USD | 0.75 | 0.75 | 0.75 |", report)

    def test_same_reference_on_different_platforms_is_independent(self):
        first, second = self.payment(), self.payment("bugcrowd")
        for payment in (first, second):
            self.app.receive_payment(payment["id"], "Receipt", receipt_reference="receipt-1")
        self.assertTrue(all(p["status"] == "received" for p in self.store.list("payments")))

    def test_referenced_retry_is_idempotent_and_keeps_original_time_and_audit(self):
        payment = self.payment()
        original = self.app.receive_payment(payment["id"], "Receipt", receipt_reference="receipt-1")
        before = self.store.snapshot()
        self.now += timedelta(hours=1)
        self.assertEqual(original, self.app.receive_payment(payment["id"], "Receipt", receipt_reference="receipt-1"))
        equivalent_time = "2026-09-21T08:00:00-04:00"
        self.assertEqual(original, self.app.receive_payment(payment["id"], "Receipt", receipt_reference="receipt-1",
                                                           received_at=equivalent_time))
        self.assertEqual(before, self.store.snapshot())

    def test_received_receipt_cannot_be_rewritten(self):
        payment = self.payment()
        self.app.receive_payment(payment["id"], "Receipt", receipt_reference="receipt-1")
        before = self.store.snapshot()
        for kwargs in ({"note": "Changed note", "receipt_reference": "receipt-1"},
                       {"note": "Receipt", "receipt_reference": "receipt-2"},
                       {"note": "Receipt", "receipt_reference": "receipt-1", "received_at": self.now - timedelta(hours=1)},
                       {"note": "Receipt"}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, "already been received"):
                self.app.receive_payment(payment["id"], **kwargs)
        self.assertEqual(before, self.store.snapshot())

    def test_actual_receipt_time_is_normalized_and_distinct_from_recorded_time(self):
        payment = self.payment()
        received = self.app.receive_payment(payment["id"], "User checked receipt", receipt_reference="receipt-1",
                                           received_at="2026-09-20T10:30:00-04:00")
        self.assertEqual(received["received_at"], "2026-09-20T14:30:00Z")
        self.assertEqual(received["recorded_at"], stamp(self.now))
        self.assertEqual(received["evidence_kind"], "user_attested_reference")
        event = self.store.snapshot()["audit"][-1]
        self.assertEqual(event["created_at"], stamp(self.now))
        self.assertEqual(event["details"]["received_at"], received["received_at"])

    def test_invalid_future_and_pre_submission_dates_leave_payment_pending(self):
        payment = self.payment()
        before = self.store.snapshot()
        for value in ("not a date", "2026-09-20", "2026-09-20T10:00:00", datetime(2026, 9, 20),
                      self.now + timedelta(microseconds=1), self.submitted_at - timedelta(microseconds=1)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.app.receive_payment(payment["id"], "Receipt", receipt_reference="receipt-1", received_at=value)
            self.assertEqual(before, self.store.snapshot())
        received = self.app.receive_payment(payment["id"], "Receipt", received_at=self.submitted_at)
        self.assertEqual(received["received_at"], stamp(self.submitted_at))

    def test_note_only_receipts_remain_manual_and_non_idempotent(self):
        payment = self.payment()
        received = self.app.receive_payment(payment["id"], "Legacy usage")
        self.assertEqual(received["evidence_kind"], "manual_note")
        self.assertIsNone(received["receipt_reference"])
        self.assertEqual(received["received_at"], stamp(self.now))
        with self.assertRaisesRegex(ValueError, "already been received"):
            self.app.receive_payment(payment["id"], "Legacy usage")

    def test_blank_references_are_rejected_without_receipt_mutation(self):
        payment = self.payment()
        for reference in ("", "   ", 123):
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                self.app.receive_payment(payment["id"], "Receipt", receipt_reference=reference)
        self.assertEqual(self.store.get("payments", payment["id"])["status"], "pending")

    def test_legacy_received_rows_cannot_be_relabelled_as_referenced(self):
        payment = self.payment()
        payment.update(status="received", receipt_note="Old note", received_at=stamp(self.now))
        self.store.save("payments", payment)
        before = self.store.snapshot()
        with self.assertRaises(ValueError):
            self.app.receive_payment(payment["id"], "Old note", receipt_reference="new-reference")
        self.assertEqual(before, self.store.snapshot())


class SubmissionReportTests(unittest.TestCase):
    def test_reports_expose_independent_pause_and_retry_deadline(self):
        now = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
        report = _submission_report([{"id": "submission-1", "status": "draft", "paused_reason": "authentication",
                                      "retry_after": "2026-09-21T13:00:00Z"}], {}, {}, now)
        self.assertIn("Paused reason", report)
        self.assertIn("Retry after (UTC)", report)
        self.assertIn("| authentication | 2026-09-21T13:00:00Z |", report)


if __name__ == "__main__":
    unittest.main()
