from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import ClassificationResult, InvestigationState


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.connection: sqlite3.Connection | None = None

    def __enter__(self) -> "Database":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS investigations (
            cve_id TEXT PRIMARY KEY, status TEXT NOT NULL, result_json TEXT,
            scratchpad_json TEXT NOT NULL, error TEXT, token_usage_json TEXT NOT NULL,
            updated_at TEXT NOT NULL)""")
        self.connection.commit()
        return self

    def __exit__(self, *_: object) -> None:
        if self.connection:
            self.connection.close()

    def save(self, cve_id: str, status: str, state: InvestigationState, result: ClassificationResult | None = None, error: str | None = None) -> None:
        assert self.connection is not None
        self.connection.execute("""INSERT INTO investigations(cve_id,status,result_json,scratchpad_json,error,token_usage_json,updated_at)
            VALUES(?,?,?,?,?,?,?) ON CONFLICT(cve_id) DO UPDATE SET status=excluded.status,result_json=excluded.result_json,
            scratchpad_json=excluded.scratchpad_json,error=excluded.error,token_usage_json=excluded.token_usage_json,updated_at=excluded.updated_at""",
            (cve_id, status, json.dumps(result.to_dict()) if result else None, json.dumps(state.to_dict()), error, json.dumps(state.token_usage), datetime.now(timezone.utc).isoformat()))
        self.connection.commit()

    def get(self, cve_id: str) -> sqlite3.Row | None:
        assert self.connection is not None
        self.connection.row_factory = sqlite3.Row
        return self.connection.execute("SELECT * FROM investigations WHERE cve_id=?", (cve_id,)).fetchone()
