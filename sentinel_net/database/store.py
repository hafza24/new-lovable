from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  topic TEXT NOT NULL,
  payload TEXT NOT NULL,
  created_at REAL NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  level TEXT NOT NULL,
  event TEXT NOT NULL,
  payload TEXT NOT NULL,
  created_at REAL NOT NULL
);
"""

class EndpointStore:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    def enqueue(self, topic: str, payload: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute("INSERT INTO queue(topic, payload, created_at) VALUES(?,?,?)", (topic, json.dumps(payload, default=str), time.time()))

    def fetch_queue(self, limit: int = 100) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute("SELECT * FROM queue ORDER BY id LIMIT ?", (limit,)).fetchall()

    def delete_queue(self, ids: Iterable[int]) -> None:
        ids = list(ids)
        if not ids:
            return
        with self.connect() as conn:
            conn.executemany("DELETE FROM queue WHERE id=?", [(i,) for i in ids])

    def mark_attempt(self, row_id: int) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE queue SET attempts=attempts+1 WHERE id=?", (row_id,))

    def set_state(self, key: str, value: Any) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO state(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (key, json.dumps(value, default=str), time.time()),
            )

    def get_state(self, key: str, default: Any = None) -> Any:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def audit(self, level: str, event: str, payload: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute("INSERT INTO audit_log(level,event,payload,created_at) VALUES(?,?,?,?)", (level, event, json.dumps(payload, default=str), time.time()))
