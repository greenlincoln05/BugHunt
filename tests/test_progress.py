from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bughunt.cli import main
from bughunt.progress import build_progress, export_progress
from bughunt.storage import Store


NOW = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)


def snapshot(amount="1.00", currency="USD"):
    return {
        "programs": [{"id": "p", "platform": "hackerone", "status": "active", "automation_allowed": True,
                      "scope": ["localhost"], "excluded_scope": [], "verified_at": "2026-09-21T00:00:00Z",
                      "verification_expires_at": "2026-09-22T00:00:00Z"}],
        "findings": [{"id": "f", "program_id": "p", "target": "http://localhost/", "status": "confirmed", "patch_status": "verified"}],
        "submissions": [{"id": "s", "finding_id": "f", "platform": "hackerone", "external_id": "123", "status": "paid",
                         "submitted_at": "2026-09-21T01:00:00Z", "accepted_at": "2026-09-21T02:00:00Z"}],
        "payments": [{"id": "r", "submission_id": "s", "amount": amount, "currency": currency,
                      "status": "received", "received_at": "2026-09-21T03:00:00Z", "receipt_reference": "receipt-1",
                      "evidence_kind": "user_attested_reference"}], "audit": [],
        "jobs": [{"id": "hackerone-discovery", "last_success_at": "2026-09-21T00:00:00Z", "status": "idle"}],
    }


class ProgressTests(unittest.TestCase):
    def progress(self, data):
        return build_progress(data, now=NOW, credentials_present=True)

    def test_empty_database_has_concrete_blockers_and_no_earnings(self):
        result = build_progress({}, now=NOW)
        self.assertFalse(result["milestone"]["receipt_recorded"])
        self.assertEqual(result["received_with_references"], {})
        self.assertEqual([row["kind"] for row in result["next_actions"]],
                         ["credentials", "discovery_stale", "select_program"])

    def test_threshold_uses_decimal_receipts_and_never_claims_platform_verification(self):
        data = snapshot("0.99")
        self.assertFalse(self.progress(data)["milestone"]["receipt_recorded"])
        second = dict(data["payments"][0], id="r2", amount="0.01", receipt_reference="receipt-2")
        data["payments"].append(second)
        result = self.progress(data)
        self.assertTrue(result["milestone"]["receipt_recorded"])
        self.assertFalse(result["milestone"]["platform_verified"])
        self.assertEqual(result["received_with_references"], {"USD": "1.00"})

    def test_pending_demo_legacy_and_non_usd_do_not_satisfy_dollar_goal(self):
        for variant in ("pending", "demo", "legacy", "currency"):
            with self.subTest(variant=variant):
                data = snapshot("100")
                if variant == "pending":
                    data["payments"][0]["status"] = "pending"
                elif variant == "demo":
                    data["audit"] = [{"action": "demo.created"}]
                elif variant == "legacy":
                    data["payments"][0].pop("evidence_kind")
                else:
                    data["payments"][0]["currency"] = "EUR"
                self.assertFalse(self.progress(data)["milestone"]["receipt_recorded"])

    def test_duplicate_receipts_across_rows_cannot_satisfy_threshold(self):
        data = snapshot("0.75")
        data["payments"].append(dict(data["payments"][0], id="r2"))
        result = self.progress(data)
        self.assertFalse(result["milestone"]["receipt_recorded"])
        self.assertEqual(result["received_with_references"]["USD"], "0.75")
        self.assertEqual(result["excluded_payments"], [{"payment_id": "r2", "reason": "duplicate_receipt_reference"}])

    def test_invalid_money_dates_or_missing_submission_evidence_excluded(self):
        for field, value in (("amount", "NaN"), ("amount", "-1"), ("amount", True), ("amount", "0.999"), ("currency", "12X"),
                             ("received_at", "2027-01-01T00:00:00Z"), ("received_at", "2026-09-20T00:00:00Z"),
                             ("received_at", "2026-09-21T04:00:00"), ("receipt_reference", " ")):
            with self.subTest(field=field, value=value):
                data = snapshot()
                data["payments"][0][field] = value
                self.assertFalse(self.progress(data)["milestone"]["receipt_recorded"])
        data = snapshot()
        data["submissions"][0]["external_id"] = None
        self.assertFalse(self.progress(data)["milestone"]["receipt_recorded"])
        for value in ("garbage", "2027-01-01T00:00:00Z", "2026-09-20T00:00:00Z"):
            data = snapshot()
            data["submissions"][0]["accepted_at"] = value
            self.assertFalse(self.progress(data)["milestone"]["receipt_recorded"])

    def test_pauses_backoff_retry_exhaustion_and_scope_expiry_surface(self):
        for changes, expected in (({"status": "draft", "paused_reason": "authentication"}, "submission_paused"),
                                  ({"status": "draft", "retry_after": "2026-09-22T00:00:00Z"}, "submission_backoff"),
                                  ({"status": "needs_review"}, "retry_exhausted"),
                                  ({"status": "rejected"}, "review_rejection")):
            data = snapshot()
            data["submissions"][0].update(changes)
            self.assertIn(expected, [row["kind"] for row in self.progress(data)["next_actions"]])
        data = snapshot()
        data["submissions"][0]["status"] = "draft"
        data["programs"][0]["verification_expires_at"] = "2026-09-21T05:00:00Z"
        kinds = [row["kind"] for row in self.progress(data)["next_actions"]]
        self.assertIn("submission_scope_blocked", kinds)
        self.assertNotIn("submit_report", kinds)

    def test_progress_has_no_mutation_and_exports_escaped_metadata(self):
        data = snapshot()
        data["payments"][0]["receipt_reference"] = None
        data["payments"][0]["id"] = "<script>|bad"
        original = deepcopy(data)
        result = self.progress(data)
        self.assertEqual(original, data)
        with tempfile.TemporaryDirectory() as directory:
            paths = export_progress(result, directory)
            self.assertEqual(len(paths), 2)
            markdown = Path(paths[1]).read_text(encoding="utf-8")
            self.assertNotIn("<script>", markdown)
            self.assertIn("&lt;script&gt;\\|bad", markdown)
            self.assertEqual(json.loads(Path(paths[0]).read_text(encoding="utf-8")), result)

    def test_progress_cli_exports_without_exposing_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with patch.dict("os.environ", {"HACKERONE_USERNAME": "secret-id", "HACKERONE_API_TOKEN": "secret-value"}):
                with redirect_stdout(output):
                    code = main(["--db", str(Path(directory) / "db.sqlite"), "progress", "--out", directory])
            self.assertEqual(code, 0)
            self.assertNotIn("secret-id", output.getvalue())
            self.assertNotIn("secret-value", output.getvalue())
            result = json.loads(output.getvalue())
            self.assertTrue(result["discovery"]["credentials_visible"])
            self.assertTrue((Path(directory) / "first_dollar.md").exists())


class DossierCliTests(unittest.TestCase):
    def test_saved_candidate_exports_without_importing_authorization_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "db.sqlite"
            store = Store(database)
            try:
                with store.transaction():
                    store.save("opportunities", {"id": "h1-1", "handle": "fixture", "name": "Fixture"})
            finally:
                store.close()
            output = Path(directory) / "dossier.json"
            argv = ["--db", str(database), "opportunity", "dossier", "h1-1", "--output", str(output)]
            with patch("bughunt.dossier.fetch_program_dossier", return_value={"completeness": {"complete": False}}) as fetch:
                with patch("bughunt.hackerone.HackerOneClient.from_environment", return_value=object()):
                    with redirect_stdout(io.StringIO()):
                        self.assertEqual(main(argv), 0)
                    self.assertEqual(fetch.call_count, 1)
            with patch("bughunt.dossier.fetch_program_dossier") as fetch:
                from contextlib import redirect_stderr
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(main(argv), 2)
                fetch.assert_not_called()
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["opportunity"]["handle"], "fixture")
            store = Store(database)
            try:
                self.assertEqual(store.list("programs"), [])
                self.assertEqual(store.snapshot()["audit"][0]["action"], "opportunity.dossier_exported")
            finally:
                store.close()
