"""Persistence regressions exercised against real SQLite connections."""

from pathlib import Path
import sqlite3
import tempfile
import unittest

from bughunt.storage import Store


class StoreTransactionTests(unittest.TestCase):
    def test_failed_commit_rolls_back_and_allows_a_later_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "locked.db")
            reader = sqlite3.connect(store.path, isolation_level=None)
            try:
                store.connection.execute("PRAGMA busy_timeout = 0")
                # A reader permits BEGIN IMMEDIATE and writes, but prevents a
                # rollback-journal writer from acquiring its COMMIT lock.
                reader.execute("BEGIN")
                reader.execute("SELECT data FROM programs").fetchall()
                with self.assertRaises(sqlite3.OperationalError) as caught:
                    with store.transaction():
                        store.save("programs", {"id": "rolled-back"})
                        store.audit("program.created", "programs", "rolled-back", "2026-09-21T00:00:00Z")
                self.assertEqual(caught.exception.sqlite_errorcode, sqlite3.SQLITE_BUSY)
                self.assertFalse(store.connection.in_transaction)
                reader.rollback()

                # Both the entity and its audit entry must be absent, and the
                # same connection must remain usable for worker recovery.
                self.assertEqual(store.list("programs"), [])
                self.assertEqual(store.snapshot()["audit"], [])
                with store.transaction():
                    store.save("programs", {"id": "recovered"})
                self.assertEqual(store.get("programs", "recovered"), {"id": "recovered"})
            finally:
                reader.close()
                store.close()


if __name__ == "__main__":
    unittest.main()
