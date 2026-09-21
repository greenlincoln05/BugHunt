"""Durable, read-only opportunity discovery. Never contacts a program's assets."""

from datetime import datetime, timedelta
import json
from pathlib import Path
import sqlite3
import time
from uuid import uuid4

from .hackerone import AdapterError, HackerOneClient
from .reports import _atomic_write, generate_reports
from .workflow import stamp, utc_now, required

JOB_ID = "hackerone-discovery"
MAX_BACKOFF_SECONDS = 86400
DATABASE_RETRY_ATTEMPTS = 3
DATABASE_RETRY_SECONDS = 5


def parsed(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def _database_contention(error):
    # Extended SQLite result codes retain the primary code in their low byte.
    code = getattr(error, "sqlite_errorcode", None)
    return isinstance(code, int) and (code & 0xff) in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}


class _DatabaseContention(Exception):
    """The bounded local database retry budget was exhausted."""


class DiscoveryWorker:
    def __init__(self, store, *, client_factory=HackerOneClient.from_environment, clock=utc_now):
        self.store = store
        self.client_factory = client_factory
        self.clock = clock

    def _job(self):
        try:
            return self.store.get("jobs", JOB_ID)
        except ValueError:
            return dict(id=JOB_ID, status="idle", paused_reason=None, stop_requested=False,
                        next_run_at=None, last_success_at=None, last_attempt_at=None,
                        last_error=None, cursor=None, pending={}, lease_owner=None, lease_until=None,
                        completed_snapshots=0, seen_cursors=[])

    def status(self):
        job = self._job()
        result = {key: value for key, value in job.items() if key not in {"pending", "seen_cursors", "lease_owner"}}
        result["pending_programs"] = len(job["pending"])
        result["published_programs"] = len(self.store.list("opportunities"))
        return result

    def stop(self):
        with self.store.transaction():
            job = self._job()
            job["stop_requested"] = True
            self.store.save("jobs", job)
            self.store.audit("worker.stop_requested", "jobs", JOB_ID, stamp(self.clock()))
        return self.status()

    def start(self):
        # Starting never overrides an authentication pause or a rate limit.
        with self.store.transaction():
            job = self._job()
            job["stop_requested"] = False
            self.store.save("jobs", job)
        return self.status()

    def resume(self, note):
        note = required(note, "Resolution note")
        with self.store.transaction():
            job = self._job()
            if job["lease_until"] and parsed(job["lease_until"]) > self.clock():
                raise ValueError("Worker is currently fetching a page batch; wait for it to finish")
            if not job["paused_reason"]:
                raise ValueError("Worker has no pause to resolve; backoff cannot be bypassed")
            job.update(paused_reason=None, status="idle", cursor=None, pending={}, seen_cursors=[],
                       lease_owner=None, lease_until=None, last_error=None)
            self.store.save("jobs", job)
            self.store.audit("worker.resumed", "jobs", JOB_ID, stamp(self.clock()), {"note": note})
        return self.status()

    def _publish(self, job):
        old = {row["id"]: row for row in self.store.list("opportunities")}
        new = job["pending"]
        for entity_id, row in new.items():
            if old.get(entity_id) != row:
                self.store.save("opportunities", row)
                action = "opportunity.updated" if entity_id in old else "opportunity.discovered"
                self.store.audit(action, "opportunities", entity_id, stamp(self.clock()))
        for entity_id in old.keys() - new.keys():
            self.store.connection.execute("DELETE FROM opportunities WHERE id = ?", (entity_id,))
            self.store.audit("opportunity.removed", "opportunities", entity_id, stamp(self.clock()))
        job.update(pending={}, cursor=None, seen_cursors=[], last_success_at=stamp(self.clock()),
                   completed_snapshots=job["completed_snapshots"] + 1, status="idle")

    def cycle(self, *, max_pages=3, interval_seconds=900, output_dir=Path("reports/discovery")):
        if type(max_pages) is not int or not 1 <= max_pages <= 20:
            raise ValueError("max_pages must be between 1 and 20")
        if type(interval_seconds) is not int or not 60 <= interval_seconds <= 86400:
            raise ValueError("interval_seconds must be between 60 and 86400")
        now = self.clock()
        owner = uuid4().hex
        with self.store.transaction():
            job = self._job()
            if job["stop_requested"] or job["paused_reason"]:
                return {"outcome": "stopped" if job["stop_requested"] else "paused", "state": self._public(job)}
            if job["lease_until"] and parsed(job["lease_until"]) > now:
                return {"outcome": "busy", "state": self._public(job)}
            if job["next_run_at"] and parsed(job["next_run_at"]) > now:
                return {"outcome": "waiting", "state": self._public(job)}
            job.update(lease_owner=owner, lease_until=stamp(now + timedelta(minutes=15)),
                       status="running", last_attempt_at=stamp(now))
            self.store.save("jobs", job)
            self.store.audit("discovery.started", "jobs", JOB_ID, stamp(now), {"max_pages": max_pages})
        try:
            batch = self.client_factory().list_programs(max_pages=max_pages, start_url=job["cursor"])
        except AdapterError as error:
            return self._failure(owner, error, interval_seconds)
        except KeyboardInterrupt:
            self._release(owner)
            raise
        except Exception:
            # Do not expose arbitrary transport exceptions that may contain credentials.
            return self._failure(owner, AdapterError("invalid_response", "Unexpected connector failure; review and resume."), interval_seconds)
        try:
            outcome = self._apply(owner, batch, interval_seconds)
        except sqlite3.Error as error:
            if not _database_contention(error):
                raise
            return self._failure(owner, AdapterError("transient", "Could not save the fetched batch; will retry."), interval_seconds)
        except OSError:
            return self._failure(owner, AdapterError("transient", "Could not save the fetched batch; will retry."), interval_seconds)
        except Exception:
            return self._failure(owner, AdapterError("invalid_response", "Unexpected error processing a fetched batch; review and resume."), interval_seconds)
        if outcome["outcome"] in {"lease_lost", "stopped"}:
            return outcome
        job, next_url = outcome["job"], outcome["next_url"]
        try:
            paths = self.export(output_dir)
        except (OSError, sqlite3.Error) as error:
            if isinstance(error, sqlite3.Error) and not _database_contention(error):
                raise
            # Reports are best effort; a locked file must not kill the unattended worker.
            paths = []
            self._note_export_failure(error)
        return {"outcome": "paused" if job["paused_reason"] else "complete" if next_url is None else "continuing",
                "state": self.status(), "files": paths}

    def _apply(self, owner, batch, interval_seconds):
        """Merge one fetched batch atomically. Returns the outcome plus the saved job."""
        with self.store.transaction():
            job = self._job()
            if job["lease_owner"] != owner:
                return {"outcome": "lease_lost", "state": self._public(job)}
            if job["stop_requested"]:
                job.update(status="stopped", lease_owner=None, lease_until=None)
                self.store.save("jobs", job)
                return {"outcome": "stopped", "state": self._public(job)}
            next_url = batch["next_url"]
            if next_url and next_url in job["seen_cursors"]:
                job.update(status="paused", paused_reason="invalid_response", last_error="Pagination cycle detected.")
            else:
                for row in batch["programs"]:
                    job["pending"][row["id"]] = row
                if next_url:
                    job["seen_cursors"].append(next_url)
                    job.update(cursor=next_url, status="continuing")
                else:
                    self._publish(job)
                job["last_error"] = None
            job.update(lease_owner=None, lease_until=None, next_run_at=stamp(self.clock() + timedelta(seconds=interval_seconds)))
            self.store.save("jobs", job)
            self.store.audit("discovery.batch_completed", "jobs", JOB_ID, stamp(self.clock()),
                             {"pages": batch["pages_fetched"], "candidates": len(batch["programs"]), "complete": next_url is None})
        return {"outcome": "applied", "job": job, "next_url": next_url}

    def _release(self, owner):
        """Give the lease back after Ctrl-C without inventing a server backoff or error."""
        try:
            with self.store.transaction():
                job = self._job()
                if job["lease_owner"] == owner:
                    job.update(status="continuing" if job["cursor"] else "idle", lease_owner=None, lease_until=None)
                    self.store.save("jobs", job)
                    self.store.audit("discovery.interrupted", "jobs", JOB_ID, stamp(self.clock()))
        except sqlite3.Error:
            pass  # The lease expires on its own; still let the interrupt propagate.

    def _note_export_failure(self, error):
        try:
            with self.store.transaction():
                self.store.audit("discovery.export_failed", "jobs", JOB_ID, stamp(self.clock()),
                                 {"error": type(error).__name__})
        except sqlite3.Error as failure:
            if not _database_contention(failure):
                raise

    @staticmethod
    def _public(job):
        return {key: value for key, value in job.items() if key not in {"pending", "seen_cursors", "lease_owner"}}

    def _failure(self, owner, error, interval_seconds):
        with self.store.transaction():
            job = self._job()
            if job["lease_owner"] != owner:
                return {"outcome": "lease_lost", "state": self._public(job)}
            pause = error.kind in {"authentication", "invalid_response"}
            delay = min(max(interval_seconds, error.retry_after_seconds or 0, 3600 if error.kind == "rate_limit" else 60), MAX_BACKOFF_SECONDS)
            job.update(status="paused" if pause else "backoff", paused_reason=error.kind if pause else None,
                       last_error=str(error), next_run_at=None if pause else stamp(self.clock() + timedelta(seconds=delay)),
                       lease_owner=None, lease_until=None)
            self.store.save("jobs", job)
            self.store.audit("discovery.paused" if pause else "discovery.backoff", "jobs", JOB_ID, stamp(self.clock()),
                             {"kind": error.kind, "message": str(error), "next_run_at": job["next_run_at"]})
        return {"outcome": "paused" if pause else "backoff", "state": self.status()}

    def export(self, output_dir):
        directory = Path(output_dir)
        directory.mkdir(parents=True, exist_ok=True)
        # A single transaction keeps snapshot timestamps and opportunities consistent.
        snapshot = self.store.snapshot()
        job = next((row for row in snapshot["jobs"] if row["id"] == JOB_ID), self._job())
        document = {"generated_at": stamp(self.clock()), "last_complete_sync_at": job["last_success_at"],
                    "refresh_in_progress": bool(job["cursor"]), "source": "HackerOne official Hacker API",
                    "notice": "Candidates only. No testing authorization or guaranteed payout. Payout ranges require policy review.",
                    "programs": sorted(snapshot["opportunities"], key=lambda row: (row["name"].casefold(), row["id"]))}
        destination = directory / "opportunities.json"
        _atomic_write(destination, json.dumps(document, indent=2, ensure_ascii=False, allow_nan=False) + "\n")
        paths = [destination, *generate_reports(snapshot, directory)]
        return [str(path.resolve()) for path in paths]

    def run(self, *, max_cycles=0, interval_seconds=900, max_pages=3, output_dir=Path("reports/discovery"),
            sleep=time.sleep, notify=print):
        if type(max_cycles) is not int or max_cycles < 0:
            raise ValueError("max_cycles must be a nonnegative integer (0 means until stopped)")

        def retry_database(operation):
            for attempt in range(DATABASE_RETRY_ATTEMPTS):
                try:
                    return operation()
                except sqlite3.Error as error:
                    if not _database_contention(error):
                        raise
                    if attempt + 1 == DATABASE_RETRY_ATTEMPTS:
                        raise _DatabaseContention from None
                    sleep(DATABASE_RETRY_SECONDS)

        try:
            retry_database(self.start)
            cycles = 0
            while True:
                result = retry_database(lambda: self.cycle(
                    max_pages=max_pages, interval_seconds=interval_seconds, output_dir=output_dir))
                cycles += 1
                if result["outcome"] not in {"waiting", "busy"}:
                    notify(json.dumps(result, ensure_ascii=True))
                if result["outcome"] in {"paused", "stopped", "lease_lost"} or (max_cycles and cycles >= max_cycles):
                    return result
                state = result["state"]
                due = parsed(state.get("lease_until") if result["outcome"] == "busy" else state.get("next_run_at"))
                due = due or self.clock() + timedelta(seconds=interval_seconds)
                while self.clock() < due:
                    if retry_database(self._job)["stop_requested"]:
                        return {"outcome": "stopped", "state": retry_database(self.status)}
                    sleep(min(5, max(0, (due - self.clock()).total_seconds())))
        except _DatabaseContention:
            # The database may still be unavailable: do not claim this attention
            # state was persisted, or try another write while handling the failure.
            result = {"outcome": "paused", "persisted": False, "state": {
                "id": JOB_ID, "status": "paused", "paused_reason": "database_contention",
                "last_error": "Database remained busy or locked after three attempts. Close the competing database operation, check worker status, then restart.",
            }}
            notify(json.dumps(result, ensure_ascii=True))
            return result
