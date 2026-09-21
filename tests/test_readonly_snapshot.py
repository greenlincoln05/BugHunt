"""Reading a live database must neither migrate it nor mix transaction states."""

import json
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from bughunt.storage import Store, read_snapshot


class ReadSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "source #1.db"

    def seed_store(self):
        store = Store(self.path)
        self.addCleanup(store.close)
        with store.transaction():
            store.save("programs", {"id": "program", "name": "Before"})
            store.save("findings", {"id": "finding", "program_id": "program", "title": "Before"})
            store.save("submissions", {"id": "submission", "finding_id": "finding"})
            store.save("payments", {"id": "payment", "submission_id": "submission", "amount": 50})
            store.save("jobs", {"id": "job", "status": "idle"})
            store.save("opportunities", {"id": "opportunity", "program_id": "program"})
            store.audit("program.created", "programs", "program", "2026-09-21T00:00:00Z")
        return store

    def fingerprint(self):
        return {item.name: (item.read_bytes(), item.stat().st_mtime_ns)
                for item in self.path.parent.iterdir() if item.is_file()}

    def test_snapshot_matches_store_without_changing_database_or_files(self):
        store = self.seed_store()
        expected = store.snapshot()
        before = self.fingerprint()

        self.assertEqual(read_snapshot(self.path), expected)

        self.assertEqual(self.fingerprint(), before)
        self.assertEqual(store.snapshot(), expected)
        self.assertEqual(expected["audit"][0]["id"], 1)

    def test_missing_database_does_not_create_file_or_parent(self):
        missing = self.path.parent / "missing" / "source.db"
        with self.assertRaises(sqlite3.OperationalError):
            read_snapshot(missing)
        self.assertFalse(missing.parent.exists())
        with self.assertRaises(sqlite3.OperationalError):
            read_snapshot(self.path)
        self.assertFalse(self.path.exists())

    def test_version_one_is_read_without_schema_upgrade(self):
        store = self.seed_store()
        expected = store.snapshot()
        store.connection.executescript("""
            DROP TABLE jobs;
            DROP TABLE opportunities;
            PRAGMA user_version = 1;
        """)
        expected["jobs"] = []
        expected["opportunities"] = []
        before = self.fingerprint()

        self.assertEqual(read_snapshot(self.path), expected)

        self.assertEqual(self.fingerprint(), before)
        self.assertEqual(store.connection.execute("PRAGMA user_version").fetchone()[0], 1)
        tables = {row[0] for row in store.connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        self.assertNotIn("jobs", tables)
        self.assertNotIn("opportunities", tables)

    def test_wal_writer_does_not_mix_old_and_new_tables(self):
        store = self.seed_store()
        store.connection.execute("PRAGMA journal_mode = WAL")
        expected = store.snapshot()
        original_loads = json.loads
        writer_committed = False

        def load_and_commit(value):
            nonlocal writer_committed
            decoded = original_loads(value)
            if not writer_committed:
                writer_committed = True
                with store.transaction():
                    store.save("programs", {"id": "program", "name": "After"})
                    store.save("findings", {"id": "finding", "program_id": "program", "title": "After"})
                    store.audit("program.updated", "programs", "program", "2026-09-21T00:01:00Z")
            return decoded

        with patch("bughunt.storage.json.loads", side_effect=load_and_commit):
            actual = read_snapshot(self.path)

        self.assertTrue(writer_committed)
        self.assertEqual(actual, expected)
        self.assertEqual(store.get("programs", "program")["name"], "After")
        self.assertEqual(len(store.snapshot()["audit"]), 2)

    def track_connections(self):
        original_connect = sqlite3.connect
        connections = []

        class TrackedConnection(sqlite3.Connection):
            closed = False
            rolled_back = False

            def rollback(self):
                self.rolled_back = True
                return super().rollback()

            def close(self):
                self.closed = True
                return super().close()

        def connect(*args, **kwargs):
            connection = original_connect(*args, **kwargs, factory=TrackedConnection)
            connection.statements = []
            connection.set_trace_callback(connection.statements.append)
            connections.append(connection)
            return connection

        return connections, patch("bughunt.storage.sqlite3.connect", side_effect=connect)

    def test_unsupported_versions_fail_before_table_reads_and_close_connection(self):
        for version in (0, 99):
            with self.subTest(version=version):
                with closing(sqlite3.connect(self.path)) as connection:
                    connection.execute(f"PRAGMA user_version = {version}")
                before = self.fingerprint()
                connections, tracking = self.track_connections()
                with tracking, self.assertRaisesRegex(ValueError, f"schema version: {version}"):
                    read_snapshot(self.path)
                reader = connections[0]
                self.assertTrue(reader.rolled_back)
                self.assertTrue(reader.closed)
                self.assertFalse(any(sql.startswith("SELECT") for sql in reader.statements))
                self.assertEqual(self.fingerprint(), before)

    def test_malformed_schema_rolls_back_and_closes_connection(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA user_version = 2")
        before = self.fingerprint()
        connections, tracking = self.track_connections()
        with tracking, self.assertRaises(sqlite3.OperationalError):
            read_snapshot(self.path)
        self.assertTrue(connections[0].rolled_back)
        self.assertTrue(connections[0].closed)
        self.assertEqual(self.fingerprint(), before)

    def test_invalid_json_rolls_back_and_closes_connection(self):
        store = self.seed_store()
        store.connection.execute("PRAGMA ignore_check_constraints = ON")
        store.connection.execute("UPDATE findings SET data = 'invalid json'")
        before = self.fingerprint()
        connections, tracking = self.track_connections()
        with tracking, self.assertRaises(json.JSONDecodeError):
            read_snapshot(self.path)
        self.assertTrue(connections[0].rolled_back)
        self.assertTrue(connections[0].closed)
        self.assertEqual(self.fingerprint(), before)


if __name__ == "__main__":
    unittest.main()
