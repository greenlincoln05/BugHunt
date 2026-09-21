"""SQLite persistence. Entity changes and their audit entries share a transaction."""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path


TABLES = frozenset({"programs", "findings", "submissions", "payments"})


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.connection.execute("PRAGMA foreign_keys = ON")
        version = self.connection.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1):
            self.close()
            raise ValueError(f"Unsupported database schema version: {version}")
        self.connection.executescript("""
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS programs (
                id TEXT PRIMARY KEY, data TEXT NOT NULL CHECK(json_valid(data))
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                program_id TEXT NOT NULL REFERENCES programs(id),
                data TEXT NOT NULL CHECK(json_valid(data))
            );
            CREATE TABLE IF NOT EXISTS submissions (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL REFERENCES findings(id),
                data TEXT NOT NULL CHECK(json_valid(data))
            );
            CREATE TABLE IF NOT EXISTS payments (
                id TEXT PRIMARY KEY,
                submission_id TEXT NOT NULL REFERENCES submissions(id),
                data TEXT NOT NULL CHECK(json_valid(data))
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT NOT NULL CHECK(json_valid(data))
            );
            PRAGMA user_version = 1;
            COMMIT;
        """)

    def close(self):
        self.connection.close()

    @contextmanager
    def transaction(self):
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    @staticmethod
    def _table(table):
        if table not in TABLES:
            raise ValueError("Unknown entity table")
        return table

    def get(self, table, entity_id):
        table = self._table(table)
        row = self.connection.execute(f"SELECT data FROM {table} WHERE id = ?", (entity_id,)).fetchone()
        if row is None:
            raise ValueError(f"Unknown {table.rstrip('s')} ID: {entity_id}")
        return json.loads(row[0])

    def list(self, table):
        table = self._table(table)
        return [json.loads(row[0]) for row in self.connection.execute(f"SELECT data FROM {table} ORDER BY rowid")]

    def save(self, table, entity):
        table = self._table(table)
        columns = ["id", "data"]
        values = [entity["id"], json.dumps(entity, ensure_ascii=False, allow_nan=False)]
        relation = {"findings": "program_id", "submissions": "finding_id", "payments": "submission_id"}.get(table)
        if relation:
            columns.append(relation)
            values.append(entity[relation])
        assignments = ", ".join(f"{column}=excluded.{column}" for column in columns[1:])
        placeholders = ", ".join("?" for _ in columns)
        self.connection.execute(
            f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders}) "
            f"ON CONFLICT(id) DO UPDATE SET {assignments}", values,
        )

    def audit(self, action, entity_type, entity_id, created_at, details=None):
        record = dict(action=action, entity_type=entity_type, entity_id=entity_id,
                      created_at=created_at, details=details or {})
        self.connection.execute("INSERT INTO audit (data) VALUES (?)", (json.dumps(record, allow_nan=False),))

    def snapshot(self):
        with self.transaction():
            snapshot = {table: self.list(table) for table in sorted(TABLES)}
            snapshot["audit"] = [dict(json.loads(row[1]), id=row[0]) for row in self.connection.execute("SELECT id, data FROM audit ORDER BY id")]
        return snapshot
