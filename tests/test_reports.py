import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from bughunt.reports import generate_reports


NOW = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)


class ReportTests(unittest.TestCase):
    def generate(self, snapshot):
        with tempfile.TemporaryDirectory() as directory:
            paths = generate_reports(snapshot, directory, now=NOW)
            self.assertEqual(len(paths), 3)
            self.assertTrue(all(isinstance(path, Path) for path in paths))
            self.assertEqual(sorted(path.name for path in Path(directory).iterdir()), sorted(path.name for path in paths))
            return {path.name: path.read_text(encoding="utf-8") for path in paths}

    def test_empty_snapshot(self):
        reports = self.generate({})
        self.assertEqual(json.loads(reports["vulnerabilities_found.json"]), [])
        self.assertIn("No submissions recorded.", reports["submissions_status.md"])
        self.assertIn("| Distinct targets audited | 0 | 0 |", reports["weekly_payout_report.md"])
        self.assertIn("No pending payments.", reports["weekly_payout_report.md"])

    def test_latest_submission_and_required_json_fields(self):
        snapshot = {
            "programs": [{"id": "p1", "name": "Program", "platform": "hackerone"}],
            "findings": [{"id": "f1", "program_id": "p1", "target": "example.test", "type": "xss", "title": "Reflected XSS", "severity": "high", "patch_status": "tested"}],
            "submissions": [
                {"id": "s1", "finding_id": "f1", "platform": "hackerone", "external_id": "old", "created_at": "2026-09-20T15:00:00Z", "updated_at": "2026-09-21T12:00:00Z"},
                {"id": "s2", "finding_id": "f1", "platform": "hackerone", "external_id": "new", "created_at": "2026-09-21T10:00:00Z"},
            ],
        }
        findings = json.loads(self.generate(snapshot)["vulnerabilities_found.json"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["submission_id"], "new")
        for field in ("target", "type", "severity", "patch_status", "submission_platform", "submission_id"):
            self.assertIn(field, findings[0])

    def test_payment_totals_are_exact_separate_and_deduplicated(self):
        snapshot = {"payments": [
            {"id": "p1", "submission_id": "s1", "amount": "0.10", "currency": "USD", "status": "pending", "created_at": "2026-09-01"},
            {"id": "p1", "submission_id": "s1", "amount": "0.10", "currency": "USD", "status": "received", "created_at": "2026-09-01", "received_at": "2026-09-20"},
            {"id": "p2", "submission_id": "s1", "amount": "0.20", "currency": "USD", "status": "received", "created_at": "2026-09-01", "received_at": "2026-09-20"},
            {"id": "p3", "submission_id": "s2", "amount": "5.00", "currency": "USD", "status": "pending", "created_at": "2026-09-19", "expected_date": "2026-10-01"},
            {"id": "p4", "submission_id": "s3", "amount": "7.25", "currency": "EUR", "status": "received", "created_at": "2026-09-01", "received_at": "2026-09-02"},
            {"id": "p5", "submission_id": "s4", "amount": "0.0001", "currency": "BTC", "status": "pending", "created_at": "2026-09-19"},
        ]}
        report = self.generate(snapshot)["weekly_payout_report.md"]
        self.assertIn("| USD | 5.00 | 0.30 | 0.30 |", report)
        self.assertIn("| EUR | 0.00 | 7.25 | 0.00 |", report)
        self.assertIn("| BTC | 0.0001 | 0.00 | 0.00 |", report)
        self.assertIn("| p3 | s2 | 5.00 | USD | 2026-10-01", report)

    def test_week_boundaries_audits_and_resolution(self):
        snapshot = {
            "findings": [
                {"id": "f1", "created_at": "2026-09-14T12:00:00Z"},
                {"id": "f2", "created_at": "2026-09-14T11:59:59Z"},
                {"id": "f3", "created_at": "2026-09-21T12:00:01Z"},
                {"id": "f4", "created_at": "2026-09-21T08:00:00-04:00"},
            ],
            "submissions": [
                {"id": "s1", "status": "paid", "submitted_at": "2026-09-17T12:00:00Z", "accepted_at": "2026-09-19T12:00:00Z"},
                {"id": "s2", "status": "accepted", "submitted_at": "2026-09-01T12:00:00Z", "accepted_at": "2026-09-05T12:00:00Z"},
                {"id": "s3", "status": "accepted", "submitted_at": "2026-09-20T12:00:00Z", "accepted_at": "2026-09-19T12:00:00Z"},
                {"id": "s4", "status": "accepted", "submitted_at": "bad", "accepted_at": None},
            ],
            "audit": [
                {"id": "a1", "action": "target.audited", "created_at": "2026-09-15", "details": {"target": "one.test"}},
                {"id": "a2", "action": "target.audited", "created_at": "2026-09-16", "details": {"target": "one.test"}},
                {"id": "a3", "action": "scope.checked", "created_at": "2026-09-16", "details": {"target": "two.test"}},
                {"id": "a4", "action": "target.audited", "created_at": "2026-09-01", "details": {"target": "three.test"}},
            ],
        }
        report = self.generate(snapshot)["weekly_payout_report.md"]
        self.assertIn("| Distinct targets audited | 1 | 2 |", report)
        self.assertIn("| Vulnerabilities recorded | 2 | 3 |", report)
        self.assertIn("| Submissions accepted | 2 | 3 |", report)
        self.assertIn("2.00 days \\(1 submissions\\)", report)
        self.assertIn("3.00 days \\(2 submissions\\)", report)

    def test_markdown_escapes_untrusted_content(self):
        snapshot = {
            "findings": [{"id": "f1", "title": "[click](javascript:alert(1)) | **bold**\n<script>x</script> `code`"}],
            "submissions": [{"id": "s1", "finding_id": "f1", "status": "rejected", "rejection_reason": "reason | next\n# Heading"}],
        }
        report = self.generate(snapshot)["submissions_status.md"]
        self.assertNotIn("<script>", report)
        self.assertNotIn("[click](", report)
        self.assertNotIn("\n# Heading", report)
        self.assertIn("&lt;script&gt;", report)
        self.assertIn("\\|", report)
        self.assertIn("\\*\\*bold\\*\\*", report)
        self.assertIn("\\`code\\`", report)

    def test_report_is_deterministic_and_does_not_mutate_snapshot(self):
        snapshot = {
            "findings": [{"id": "f2", "created_at": "2026-09-20"}, {"id": "f1", "created_at": "2026-09-19"}],
            "payments": [{"id": "p2", "amount": "10", "currency": "EUR", "status": "pending"}, {"id": "p1", "amount": "20", "currency": "USD", "status": "pending"}],
        }
        original = copy.deepcopy(snapshot)
        reports = self.generate(snapshot)
        self.assertEqual(snapshot, original)
        for rows in snapshot.values():
            rows.reverse()
        self.assertEqual(reports, self.generate(snapshot))

    def test_invalid_payments_do_not_break_or_pollute_totals(self):
        snapshot = {"payments": [
            {"id": "p1", "amount": "NaN", "currency": "USD", "status": "received"},
            {"id": "p2", "amount": "Infinity", "currency": "USD", "status": "received"},
            {"id": "p3", "amount": "-1", "currency": "USD", "status": "pending"},
        ]}
        report = self.generate(snapshot)["weekly_payout_report.md"]
        self.assertIn("Excluded 3 payment records", report)
        self.assertIn("No valid payments recorded.", report)

    def test_existing_files_are_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "vulnerabilities_found.json"
            destination.write_text("stale", encoding="utf-8")
            generate_reports({}, directory, NOW)
            self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), [])


if __name__ == "__main__":
    unittest.main()
