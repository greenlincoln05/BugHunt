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
SOURCE = "https://github.com/example/library"


def source_snapshot():
    return {
        "opportunities": [{"id": "h1-source", "candidate_text": "Unverified model suggestion"}],
        "programs": [{"id": "source", "platform": "hackerone", "program_url": "https://hackerone.com/source",
                      "status": "active", "automation_allowed": False, "scope": [SOURCE], "excluded_scope": [],
                      "source_code_assets": [{"url": SOURCE, "eligible_for_bounty": True,
                                              "eligible_for_submission": True}], "source_review": None}],
        "findings": [], "submissions": [], "payments": [], "audit": [],
        "jobs": [{"id": "hackerone-discovery", "last_success_at": "2026-09-21T11:00:00Z", "status": "idle"}],
    }


def audit(action, entity_type, entity_id, details=None, when="2026-09-21T11:00:00Z"):
    return {"action": action, "entity_type": entity_type, "entity_id": entity_id,
            "created_at": when, "details": details or {}}


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

    def test_pipeline_requires_records_at_each_source_stage(self):
        data = source_snapshot()
        data["programs"] = []
        result = self.progress(data)
        self.assertEqual(result["pipeline"]["tracks"], [])
        self.assertEqual(result["pipeline"]["triage"]["opportunities_recorded"], 1)
        self.assertIn("triage", result["next_actions"][-1]["next_step"])
        data["programs"] = source_snapshot()["programs"]
        track = self.progress(data)["pipeline"]["tracks"][0]
        self.assertEqual(track["stages"]["triage"], "program_recorded")
        self.assertEqual(track["stages"]["finding"], "not_recorded")
        self.assertIsNone(track["next_stage"])
        self.assertFalse(track["source_policy_current"])

        data["programs"][0]["source_review"] = {
            "source_url": SOURCE, "program_url": "https://hackerone.com/source", "note": "Current policy checked",
            "reviewed_at": "2026-09-21T11:00:00Z", "expires_at": "2026-09-22T11:00:00Z"}
        track = self.progress(data)["pipeline"]["tracks"][0]
        self.assertEqual(track["next_stage"], "clone")
        self.assertEqual(track["stages"]["clone"], "not_recorded")
        data["audit"].append(audit("workspace.cloned", "workspace", "C:/old/clone", {"url": SOURCE}))
        track = self.progress(data)["pipeline"]["tracks"][0]
        self.assertEqual(track["stages"]["clone"], "historical_clone_recorded")
        self.assertEqual(track["recorded_clone_path"], "C:/old/clone")
        self.assertEqual(track["next_stage"], "finding")

        data["findings"].append({"id": "f-source", "program_id": "source", "target_kind": "source_code",
                                 "target": SOURCE, "status": "unconfirmed", "patch_status": "not_started"})
        track = self.progress(data)["pipeline"]["tracks"][0]
        self.assertEqual(track["stages"]["finding"], "unconfirmed_recorded")
        self.assertEqual(track["next_stage"], "finding")
        data["findings"][0].update(status="confirmed", confirmation_evidence="Actual local proof")
        self.assertEqual(self.progress(data)["pipeline"]["tracks"][0]["next_stage"], "patch")
        data["findings"][0].update(patch_status="verified", patch_reference="fix.patch",
                                   verification="Human-reviewed regression output")
        track = self.progress(data)["pipeline"]["tracks"][0]
        self.assertEqual(track["stages"]["patch"], "verified_recorded")
        self.assertEqual(track["stages"]["evidence"], "manual_verification_only")
        self.assertEqual(track["next_stage"], "evidence")
        self.assertIn("capture_evidence", [row["kind"] for row in self.progress(data)["next_actions"]])

        data["audit"].append(audit("patch.evidence_captured", "findings", "f-source",
                                   {"passed": False, "exit_code": 1, "timed_out": False}))
        self.assertEqual(self.progress(data)["pipeline"]["tracks"][0]["stages"]["evidence"],
                         "nonpassing_command_recorded")
        data["audit"].append(audit("patch.evidence_captured", "findings", "f-source",
                                   {"passed": True, "exit_code": 0, "timed_out": False}))
        track = self.progress(data)["pipeline"]["tracks"][0]
        self.assertEqual(track["stages"]["evidence"], "passing_command_recorded")
        self.assertEqual(track["next_stage"], "draft")
        data["submissions"].append({"id": "s-source", "finding_id": "f-source", "status": "draft"})
        self.assertEqual(self.progress(data)["pipeline"]["tracks"][0]["stages"]["draft"], "draft_recorded")
        data["audit"].append(audit("submission.exported", "submissions", "s-source",
                                   {"output": "C:/old/report.zip"}))
        track = self.progress(data)["pipeline"]["tracks"][0]
        self.assertEqual(track["stages"]["draft"], "historical_export_recorded")
        self.assertEqual(track["next_stage"], "draft")
        data["audit"].append(audit("patch.evidence_captured", "findings", "f-source",
                                   {"passed": False, "exit_code": 1, "timed_out": False}))
        result = self.progress(data)
        self.assertEqual(result["pipeline"]["tracks"][0]["next_stage"], "evidence")
        self.assertIn("capture_evidence", [row["kind"] for row in result["next_actions"]])
        self.assertNotIn("submit_report", [row["kind"] for row in result["next_actions"]])
        self.assertFalse(result["milestone"]["receipt_recorded"])

    def test_pipeline_does_not_mix_attachments_other_assets_or_future_events(self):
        data = source_snapshot()
        data["programs"][0]["source_review"] = {
            "source_url": SOURCE, "program_url": "https://hackerone.com/source", "note": "Current policy checked",
            "reviewed_at": "2026-09-21T11:00:00Z", "expires_at": "2026-09-22T11:00:00Z"}
        other = "https://github.com/example/other"
        data["programs"][0]["scope"].append(other)
        data["programs"][0]["source_code_assets"].append(
            {"url": other, "eligible_for_bounty": True, "eligible_for_submission": True})
        data["audit"] = [
            audit("workspace.cloned", "workspace", "C:/other", {"url": other}),
            audit("workspace.cloned", "workspace", "C:/future", {"url": SOURCE}, "2026-09-22T11:00:00Z"),
            audit("opportunity.triaged", "opportunities", "batch", {"attempted": 2, "source_eligible": 1}),
        ]
        data["findings"].append({"id": "other-finding", "program_id": "source", "target_kind": "source_code",
                                 "target": other, "status": "confirmed", "patch_status": "verified"})
        result = self.progress(data)
        tracks = {row["target"]: row for row in result["pipeline"]["tracks"]}
        self.assertEqual(tracks[SOURCE]["stages"]["clone"], "not_recorded")
        self.assertEqual(tracks[SOURCE]["next_stage"], "clone")
        self.assertEqual(tracks[other]["stages"]["clone"], "historical_clone_recorded")
        self.assertFalse(tracks[other]["source_policy_current"])
        self.assertIsNone(tracks[other]["next_stage"])
        self.assertEqual(result["pipeline"]["triage"]["batch_runs_recorded"], 1)
        self.assertEqual(result["pipeline"]["triage"]["last_batch_attempted"], 2)
        self.assertEqual(result["pipeline"]["triage"]["last_recorded_shortlist_size"], 1)
        self.assertIn("local_research", [row["kind"] for row in result["next_actions"]])

    def test_pipeline_uses_latest_submission_and_does_not_invent_missing_evidence(self):
        data = source_snapshot()
        data["programs"][0]["source_review"] = {
            "source_url": SOURCE, "program_url": "https://hackerone.com/source", "note": "Current policy checked",
            "reviewed_at": "2026-09-21T11:00:00Z", "expires_at": "2026-09-22T11:00:00Z"}
        finding = {"id": "f", "program_id": "source", "target_kind": "source_code", "target": SOURCE,
                   "status": "confirmed", "patch_status": "verified", "patch_reference": "fix.patch"}
        data["findings"] = [finding]
        track = self.progress(data)["pipeline"]["tracks"][0]
        self.assertEqual(track["stages"]["finding"], "confirmation_evidence_missing")
        self.assertEqual(track["stages"]["patch"], "verification_evidence_missing")
        self.assertEqual(track["next_stage"], "finding")
        self.assertIn("confirm_finding", [row["kind"] for row in self.progress(data)["next_actions"]])
        finding["confirmation_evidence"] = "Local proof"
        self.assertEqual(self.progress(data)["pipeline"]["tracks"][0]["next_stage"], "patch")
        finding["verification"] = "Human-reviewed regression"
        data["audit"].append(audit("patch.evidence_captured", "findings", "f",
                                   {"passed": True, "exit_code": 0, "timed_out": False}))
        data["submissions"] = [
            {"id": "old", "finding_id": "f", "status": "rejected", "created_at": "2026-09-20T10:00:00Z"},
            {"id": "new", "finding_id": "f", "status": "draft", "created_at": "2026-09-21T10:00:00Z"},
        ]
        data["audit"].append(audit("submission.exported", "submissions", "old", {"output": "C:/old.zip"}))
        track = self.progress(data)["pipeline"]["tracks"][0]
        self.assertEqual(track["submission_id"], "new")
        self.assertEqual(track["stages"]["draft"], "draft_recorded")
        self.assertIn("Export", track["next_step"])
        data["submissions"][1].update(status="submitted", external_id="OFFICIAL-1",
                                      submitted_at="2026-09-21T11:30:00Z")
        data["programs"][0]["source_review"]["expires_at"] = "2026-09-21T11:30:00Z"
        track = self.progress(data)["pipeline"]["tracks"][0]
        self.assertFalse(track["source_policy_current"])
        self.assertIsNone(track["next_stage"])
        self.assertIn("official triage", track["next_step"])

    def test_recent_worker_sync_does_not_require_token_in_reporter_process(self):
        result = build_progress(snapshot(), now=NOW, credentials_present=False)
        self.assertFalse(result["discovery"]["credentials_visible"])
        self.assertTrue(result["discovery"]["recent_successful_sync"])
        self.assertNotIn("credentials", [row["kind"] for row in result["next_actions"]])
        data = snapshot()
        data["jobs"][0]["paused_reason"] = "authentication"
        result = build_progress(data, now=NOW, credentials_present=False)
        self.assertIn("credentials", [row["kind"] for row in result["next_actions"]])

    def test_future_or_stale_sync_does_not_establish_current_discovery(self):
        for date in ("2026-09-22T00:00:00Z", "2026-09-19T00:00:00Z"):
            data = snapshot()
            data["jobs"][0]["last_success_at"] = date
            result = build_progress(data, now=NOW, credentials_present=False)
            self.assertFalse(result["discovery"]["recent_successful_sync"])
            self.assertIn("discovery_stale", [row["kind"] for row in result["next_actions"]])

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

    def test_progress_reads_external_database_without_initializing_a_store(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "live.sqlite"
            store = Store(source)
            try:
                with store.transaction():
                    store.save("opportunities", {"id": "h1-1", "name": "Live candidate"})
            finally:
                store.close()
            before = source.read_bytes()
            output = io.StringIO()
            with patch("bughunt.cli.Store", side_effect=AssertionError("Read-only progress must not open a writable Store")):
                with redirect_stdout(output):
                    self.assertEqual(main(["progress", "--source-db", str(source)]), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["counts"]["opportunities"], 1)
            self.assertEqual(result["source_database"], str(source.resolve()))
            self.assertEqual(source.read_bytes(), before)

    def test_progress_rejects_ambiguous_database_selection_without_creating_files(self):
        from contextlib import redirect_stderr
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / "source.sqlite", Path(directory) / "destination.sqlite"
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--db", str(destination), "progress", "--source-db", str(source)]), 2)
            self.assertFalse(source.exists())
            self.assertFalse(destination.exists())


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
