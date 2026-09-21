"""Regression tests for defects found in the pre-handoff bug sweep."""

from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from bughunt.hackerone import AdapterError, HackerOneClient, MAX_RETRY_AFTER_SECONDS, _retry_after
from bughunt.reports import _cell
from bughunt.scope import check_scope
from bughunt.storage import Store
from bughunt.worker import DiscoveryWorker, MAX_BACKOFF_SECONDS
from test_hackerone import Opener, Response, page, record
from test_worker import batch, candidate


class AdapterTests(unittest.TestCase):
    def client(self, *responses):
        return HackerOneClient("identifier", "token", opener=Opener(*responses))

    def test_short_content_length_body_is_transient_not_invalid(self):
        body = json.dumps(page()).encode("utf-8")
        response = Response(body[: len(body) // 2], headers={"Content-Length": str(len(body))})
        with self.assertRaises(AdapterError) as caught:
            self.client(response).list_programs(max_pages=1)
        self.assertEqual((caught.exception.kind, caught.exception.retry_after_seconds), ("transient", 60))

    def test_complete_content_length_body_parses(self):
        body = json.dumps(page()).encode("utf-8")
        response = Response(body, headers={"Content-Length": str(len(body))})
        self.assertEqual(len(self.client(response).list_programs(max_pages=1)["programs"]), 1)

    def test_retry_after_is_capped(self):
        self.assertEqual(_retry_after("9999999999", 60), MAX_RETRY_AFTER_SECONDS)
        far = "Fri, 01 Jan 2100 00:00:00 GMT"
        self.assertEqual(_retry_after(far, 60), MAX_RETRY_AFTER_SECONDS)

    def test_lone_surrogate_in_text_is_rejected(self):
        response = Response({"data": [record(name="bad\ud800name")], "links": {"next": None}})
        with self.assertRaises(AdapterError) as caught:
            self.client(response).list_programs(max_pages=1)
        self.assertEqual(caught.exception.kind, "invalid_response")


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / "worker.db")
        self.addCleanup(self.store.close)
        self.now = datetime(2026, 9, 21, 0, tzinfo=timezone.utc)
        self.client = Mock()
        self.client.list_programs.return_value = batch([candidate()])
        self.worker = DiscoveryWorker(self.store, client_factory=Mock(return_value=self.client), clock=lambda: self.now)

    def cycle(self):
        return self.worker.cycle(output_dir=self.root / "out")

    def test_processing_failure_releases_lease_and_pauses(self):
        with patch.object(DiscoveryWorker, "_publish", side_effect=RuntimeError("boom")):
            result = self.cycle()
        self.assertEqual(result["outcome"], "paused")
        job = self.store.get("jobs", "hackerone-discovery")
        self.assertIsNone(job["lease_owner"])
        self.assertEqual(job["paused_reason"], "invalid_response")

    def test_database_error_while_saving_backs_off_and_releases_lease(self):
        with patch.object(DiscoveryWorker, "_publish", side_effect=sqlite3.OperationalError("locked")):
            result = self.cycle()
        self.assertEqual(result["outcome"], "backoff")
        self.assertIsNotNone(self.store.get("jobs", "hackerone-discovery")["next_run_at"])

    def test_export_failure_does_not_kill_worker(self):
        with patch.object(DiscoveryWorker, "export", side_effect=PermissionError("locked")):
            result = self.cycle()
        self.assertEqual(result["outcome"], "complete")
        self.assertEqual(result["files"], [])
        actions = [row["action"] for row in self.store.snapshot()["audit"]]
        self.assertIn("discovery.export_failed", actions)

    def test_huge_retry_after_is_capped(self):
        self.client.list_programs.side_effect = AdapterError("rate_limit", "limited", retry_after_seconds=10**9)
        self.cycle()
        job = self.store.get("jobs", "hackerone-discovery")
        due = datetime.fromisoformat(job["next_run_at"].replace("Z", "+00:00"))
        self.assertEqual(due - self.now, timedelta(seconds=MAX_BACKOFF_SECONDS))

    def test_ctrl_c_releases_lease_without_backoff(self):
        self.client.list_programs.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.cycle()
        job = self.store.get("jobs", "hackerone-discovery")
        self.assertIsNone(job["lease_owner"])
        self.assertIsNone(job["next_run_at"])
        self.assertIsNone(job["last_error"])
        self.assertEqual(job["status"], "idle")


class ScopeTests(unittest.TestCase):
    def allowed(self, target, scope, excluded):
        program = dict(status="active", automation_allowed=True, blocked_reason=None,
                       verified_at="2026-09-21T00:00:00Z", verification_expires_at="2026-09-22T00:00:00Z",
                       scope=scope, excluded_scope=excluded)
        return check_scope(program, target, datetime(2026, 9, 21, 12, tzinfo=timezone.utc))["allowed"]

    def test_exclusion_applies_to_scheme_port_and_case_variants(self):
        scope, excluded = ["example.com"], ["https://example.com/api/billing"]
        for target in ("https://example.com/api/billing", "http://example.com/api/billing",
                       "https://example.com:8443/api/billing/x", "https://example.com/API/Billing"):
            self.assertFalse(self.allowed(target, scope, excluded), target)
        self.assertTrue(self.allowed("https://example.com/api/billings", scope, excluded))

    def test_wildcard_in_url_rule_is_invalid_and_denies_everything(self):
        for rule in ("https://example.com/api/*", "https://example.com/{id}/admin", "https://example.com/<x>"):
            self.assertFalse(self.allowed("https://example.com/api/x", ["example.com"], [rule]), rule)


class ReportTests(unittest.TestCase):
    def test_apostrophe_is_a_valid_entity_without_stray_backslash(self):
        self.assertEqual(_cell("Bob's program"), "Bob&#x27;s program")


if __name__ == "__main__":
    unittest.main()
