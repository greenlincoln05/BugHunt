from datetime import datetime, timedelta, timezone
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from bughunt.cli import main
from bughunt.hackerone import AdapterError
from bughunt.storage import Store
from bughunt.worker import DiscoveryWorker, JOB_ID


def candidate(entity_id="h1-1", name="Fictitious program"):
    return {"id": entity_id, "name": name, "platform": "hackerone", "automation_allowed": False}


def batch(programs=None, next_url=None):
    return {"programs": programs or [], "next_url": next_url, "pages_fetched": 1}


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
        self.factory = Mock(return_value=self.client)
        self.worker = DiscoveryWorker(self.store, client_factory=self.factory, clock=lambda: self.now)

    def cycle(self, **kwargs):
        return self.worker.cycle(output_dir=self.root / "out", **kwargs)

    def advance(self, seconds=900):
        self.now += timedelta(seconds=seconds)

    def test_complete_snapshot_persists_candidates_but_never_authorizes_targets(self):
        result = self.cycle()
        self.assertEqual(result["outcome"], "complete")
        self.assertEqual(self.store.list("programs"), [])
        self.assertFalse(self.store.list("opportunities")[0]["automation_allowed"])
        document = json.loads((self.root / "out/opportunities.json").read_text(encoding="utf-8"))
        self.assertEqual(document["last_complete_sync_at"], "2026-09-21T00:00:00Z")
        self.assertFalse(document["refresh_in_progress"])
        self.assertEqual(len(result["files"]), 4)

    def test_partial_refresh_is_not_published_or_mistaken_for_removals(self):
        self.cycle()
        self.advance()
        url = "https://api.hackerone.com/v1/hackers/programs?page%5Bnumber%5D=2"
        self.client.list_programs.return_value = batch([candidate("h1-2")], url)
        self.assertEqual(self.cycle()["outcome"], "continuing")
        self.assertEqual([x["id"] for x in self.store.list("opportunities")], ["h1-1"])
        reopened = Store(self.root / "worker.db")
        try:
            continued = DiscoveryWorker(reopened, client_factory=self.factory, clock=lambda: self.now)
            self.advance()
            self.client.list_programs.return_value = batch([candidate("h1-3")])
            self.assertEqual(continued.cycle(output_dir=self.root / "out")["outcome"], "complete")
            self.client.list_programs.assert_called_with(max_pages=3, start_url=url)
            self.assertEqual({x["id"] for x in reopened.list("opportunities")}, {"h1-2", "h1-3"})
        finally:
            reopened.close()

    def test_unchanged_refresh_does_not_duplicate_opportunity_events(self):
        self.cycle()
        self.advance()
        self.cycle()
        events = [x for x in self.store.snapshot()["audit"] if x["action"].startswith("opportunity.")]
        self.assertEqual(len(events), 1)

    def test_rate_limit_survives_restart_and_resume_cannot_bypass_it(self):
        self.client.list_programs.side_effect = AdapterError("rate_limit", "Rate limited", retry_after_seconds=7200)
        self.assertEqual(self.cycle()["outcome"], "backoff")
        self.assertEqual(self.worker.status()["next_run_at"], "2026-09-21T02:00:00Z")
        with self.assertRaises(ValueError):
            self.worker.resume("Try early")
        self.worker.start()
        self.advance(3600)
        self.assertEqual(self.cycle()["outcome"], "waiting")
        self.assertEqual(self.client.list_programs.call_count, 1)

    def test_missing_credentials_pause_without_retry_loop(self):
        self.factory.side_effect = AdapterError("authentication", "Configure credentials")
        result = self.worker.run(max_cycles=10, output_dir=self.root / "out", notify=lambda _: None,
                                 sleep=lambda _: self.fail("Paused worker must not sleep/retry"))
        self.assertEqual(result["outcome"], "paused")
        self.assertEqual(self.factory.call_count, 1)
        self.worker.start()
        self.assertEqual(self.cycle()["outcome"], "paused")
        self.worker.resume("Credentials configured locally")
        self.assertIsNone(self.worker.status()["paused_reason"])

    def test_single_active_lease_and_expired_lease_recovery(self):
        with self.store.transaction():
            job = self.worker._job()
            job.update(lease_owner="other", lease_until="2026-09-21T00:15:00Z", status="running")
            self.store.save("jobs", job)
        self.assertEqual(self.cycle()["outcome"], "busy")
        self.factory.assert_not_called()
        self.advance()
        self.assertEqual(self.cycle()["outcome"], "complete")

    def test_stop_during_fetch_discards_batch_and_releases_lease(self):
        def fetch(**kwargs):
            self.worker.stop()
            return batch([candidate()])
        self.client.list_programs.side_effect = fetch
        self.assertEqual(self.cycle()["outcome"], "stopped")
        self.assertEqual(self.store.list("opportunities"), [])
        self.assertIsNone(self.worker.status()["lease_until"])

    def test_run_waits_for_crashed_workers_lease_then_recovers(self):
        with self.store.transaction():
            job = self.worker._job()
            job.update(lease_owner="crashed", lease_until="2026-09-21T00:00:05Z", status="running")
            self.store.save("jobs", job)
        result = self.worker.run(max_cycles=2, output_dir=self.root / "out", sleep=self.advance, notify=lambda _: None)
        self.assertEqual(result["outcome"], "complete")
        self.assertEqual(self.client.list_programs.call_count, 1)

    def test_stop_is_observed_during_wait(self):
        def sleep(_):
            self.worker.stop()
        result = self.worker.run(output_dir=self.root / "out", sleep=sleep, notify=lambda _: None)
        self.assertEqual(result["outcome"], "stopped")
        self.assertEqual(self.client.list_programs.call_count, 1)

    def database_locker(self):
        self.store.connection.execute("PRAGMA busy_timeout = 0")
        locker = sqlite3.connect(self.store.path, isolation_level=None)
        self.addCleanup(locker.close)
        return locker

    def test_run_retries_start_after_a_competing_writer_releases(self):
        locker = self.database_locker()
        locker.execute("BEGIN IMMEDIATE")
        delays = []

        def sleep(seconds):
            delays.append(seconds)
            locker.rollback()
            self.advance(seconds)

        result = self.worker.run(max_cycles=1, output_dir=self.root / "out", sleep=sleep, notify=lambda _: None)
        self.assertEqual(result["outcome"], "complete")
        self.assertEqual(delays, [5])
        self.assertEqual(self.client.list_programs.call_count, 1)
        self.assertEqual(len(self.store.list("opportunities")), 1)

    def test_run_retries_cycle_before_fetching_when_database_is_locked(self):
        locker = self.database_locker()
        start = self.worker.start

        def start_then_lock():
            result = start()
            locker.execute("BEGIN IMMEDIATE")
            return result

        def sleep(seconds):
            self.client.list_programs.assert_not_called()
            locker.rollback()
            self.advance(seconds)

        with patch.object(self.worker, "start", side_effect=start_then_lock):
            result = self.worker.run(max_cycles=1, output_dir=self.root / "out", sleep=sleep, notify=lambda _: None)
        self.assertEqual(result["outcome"], "complete")
        self.assertEqual(self.client.list_programs.call_count, 1)

    def test_run_recovers_a_locked_idle_stop_check(self):
        locker = self.database_locker()
        delays = []

        def notify(_):
            locker.execute("BEGIN EXCLUSIVE")

        def sleep(seconds):
            delays.append(seconds)
            locker.rollback()
            self.worker.stop()
            self.advance(seconds)

        result = self.worker.run(output_dir=self.root / "out", sleep=sleep, notify=notify)
        self.assertEqual(result["outcome"], "stopped")
        self.assertEqual(delays, [5])
        self.assertEqual(self.client.list_programs.call_count, 1)

    def test_run_exits_with_unpersisted_attention_after_three_lock_failures(self):
        locker = self.database_locker()
        locker.execute("BEGIN IMMEDIATE")
        delays = []
        messages = []
        with patch.object(self.worker, "start", wraps=self.worker.start) as start:
            result = self.worker.run(output_dir=self.root / "out", sleep=delays.append, notify=messages.append)
        self.assertEqual(start.call_count, 3)
        self.assertEqual(delays, [5, 5])
        self.assertEqual(result["outcome"], "paused")
        self.assertEqual(result["state"]["paused_reason"], "database_contention")
        self.assertIs(result["persisted"], False)
        self.assertEqual(json.loads(messages[0]), result)
        self.factory.assert_not_called()
        locker.rollback()
        self.assertEqual(self.store.list("jobs"), [])

    def test_run_does_not_retry_other_sqlite_failures(self):
        failure = sqlite3.OperationalError("no such table: jobs")
        failure.sqlite_errorcode = sqlite3.SQLITE_ERROR
        with patch.object(self.worker, "start", side_effect=failure) as start:
            with self.assertRaises(sqlite3.OperationalError):
                self.worker.run(output_dir=self.root / "out", notify=lambda _: None,
                                sleep=lambda _: self.fail("A non-contention SQLite error must not retry"))
        self.assertEqual(start.call_count, 1)
        self.factory.assert_not_called()

    def test_cycle_does_not_turn_corrupt_database_into_retryable_backoff(self):
        failure = sqlite3.DatabaseError("database disk image is malformed")
        failure.sqlite_errorcode = sqlite3.SQLITE_CORRUPT
        with patch.object(self.worker, "_publish", side_effect=failure):
            with self.assertRaises(sqlite3.DatabaseError):
                self.cycle()

    def test_pagination_cycles_pause_instead_of_looping_across_restarts(self):
        url = "https://api.hackerone.com/v1/hackers/programs?page%5Bnumber%5D=2"
        self.client.list_programs.return_value = batch([candidate()], url)
        self.cycle()
        self.advance()
        self.assertEqual(self.cycle()["outcome"], "paused")
        self.assertEqual(self.worker.status()["paused_reason"], "invalid_response")
        self.assertEqual(self.store.list("opportunities"), [])

    def test_unexpected_transport_error_is_sanitized_and_lease_released(self):
        self.factory.side_effect = RuntimeError("sensitive-token-should-not-appear")
        result = self.cycle()
        self.assertEqual(result["outcome"], "paused")
        self.assertNotIn("sensitive-token", json.dumps(self.store.snapshot()))
        self.assertIsNone(self.worker.status()["lease_until"])

    def test_readiness_never_prints_credentials(self):
        with patch.dict("os.environ", {"HACKERONE_USERNAME": "secret-identifier", "HACKERONE_API_TOKEN": "secret-token"}):
            with redirect_stdout(io.StringIO()) as output:
                code = main(["--db", str(self.root / "setup.db"), "setup"])
        self.assertEqual(code, 0)
        value = output.getvalue()
        self.assertNotIn("secret-identifier", value)
        self.assertNotIn("secret-token", value)
        self.assertTrue(json.loads(value)["hackerone"]["api_token_present"])

    def test_cli_missing_credentials_returns_attention_code_and_persists_pause(self):
        path = self.root / "missing-credentials.db"
        with patch.dict("os.environ", {}, clear=True), redirect_stdout(io.StringIO()) as output:
            code = main(["--db", str(path), "worker", "once", "--out", str(self.root / "output")])
        self.assertEqual(code, 4)
        self.assertEqual(json.loads(output.getvalue())["outcome"], "paused")
        paused = Store(path)
        try:
            self.assertEqual(paused.get("jobs", JOB_ID)["paused_reason"], "authentication")
            self.assertEqual(paused.list("opportunities"), [])
        finally:
            paused.close()

    def test_schema_one_migrates_without_losing_data(self):
        path = self.root / "old.db"
        old = sqlite3.connect(path)
        old.executescript("CREATE TABLE programs (id TEXT PRIMARY KEY, data TEXT NOT NULL); PRAGMA user_version = 1;")
        old.execute("INSERT INTO programs VALUES (?, ?)", ("old", json.dumps({"id": "old", "name": "Keep me"})))
        old.commit()
        old.close()
        migrated = Store(path)
        try:
            self.assertEqual(migrated.get("programs", "old")["name"], "Keep me")
            self.assertEqual(migrated.connection.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(migrated.list("jobs"), [])
        finally:
            migrated.close()


if __name__ == "__main__":
    unittest.main()
