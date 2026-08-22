from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cve_agent.models import ClassificationResult, InvestigationState


SCHEMA_VERSION = "2"


class IncompatibleDatabaseError(RuntimeError):
    pass


class PersistenceError(RuntimeError):
    pass


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.connection: sqlite3.Connection | None = None

    def __enter__(self) -> "Database":
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.connection = sqlite3.connect(self.path)
            self.connection.execute("PRAGMA foreign_keys = ON")
            tables = {row[0] for row in self.connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "investigations" in tables and "schema_meta" not in tables:
                raise IncompatibleDatabaseError(
                    f"database {self.path} uses the legacy schema; remove it explicitly and run the command again"
                )
            self.connection.execute("CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            version = self.connection.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
            if version and version[0] != SCHEMA_VERSION:
                raise IncompatibleDatabaseError(
                    f"database {self.path} has schema version {version[0]!r}, expected {SCHEMA_VERSION}; recreate it explicitly"
                )
            self.connection.execute("INSERT OR IGNORE INTO schema_meta(key,value) VALUES('schema_version',?)", (SCHEMA_VERSION,))
            self.connection.execute("""CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, completed_at TEXT,
                taxonomy_sha256 TEXT NOT NULL, model TEXT NOT NULL, settings_json TEXT NOT NULL,
                status TEXT NOT NULL)""")
            self.connection.execute("""CREATE TABLE IF NOT EXISTS investigations (
                run_id INTEGER NOT NULL REFERENCES runs(id), input_position INTEGER NOT NULL,
                cve_id TEXT NOT NULL, status TEXT NOT NULL, result_json TEXT,
                scratchpad_json TEXT NOT NULL, error TEXT, token_usage_json TEXT NOT NULL,
                coverage_json TEXT NOT NULL, updated_at TEXT NOT NULL,
                PRIMARY KEY(run_id,input_position))""")
            self.connection.commit()
            return self
        except IncompatibleDatabaseError:
            if self.connection:
                self.connection.close()
                self.connection = None
            raise
        except sqlite3.Error as exc:
            raise PersistenceError(f"failed to initialize database: {exc}") from exc

    def __exit__(self, *_: object) -> None:
        if self.connection:
            self.connection.close()
            self.connection = None

    def start_run(self, *, taxonomy_sha256: str, model: str, settings: dict[str, Any]) -> int:
        connection = self._connection()
        try:
            cursor = connection.execute(
                "INSERT INTO runs(started_at,taxonomy_sha256,model,settings_json,status) VALUES(?,?,?,?,?)",
                (_now(), taxonomy_sha256, model, json.dumps(settings, sort_keys=True), "running"),
            )
            connection.commit()
            return int(cursor.lastrowid)
        except sqlite3.Error as exc:
            raise PersistenceError(f"failed to create run: {exc}") from exc

    def finish_run(self, run_id: int, status: str) -> None:
        connection = self._connection()
        try:
            connection.execute("UPDATE runs SET status=?,completed_at=? WHERE id=?", (status, _now(), run_id))
            connection.commit()
        except sqlite3.Error as exc:
            raise PersistenceError(f"failed to finish run {run_id}: {exc}") from exc

    def save_investigation(
        self,
        run_id: int,
        input_position: int,
        cve_id: str,
        status: str,
        state: InvestigationState,
        result: ClassificationResult | None = None,
        error: str | None = None,
    ) -> None:
        connection = self._connection()
        coverage = result.operational.get("coverage", {}) if result else {}
        try:
            connection.execute(
                """INSERT INTO investigations(run_id,input_position,cve_id,status,result_json,scratchpad_json,error,token_usage_json,coverage_json,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(run_id,input_position) DO UPDATE SET
                cve_id=excluded.cve_id,status=excluded.status,result_json=excluded.result_json,
                scratchpad_json=excluded.scratchpad_json,error=excluded.error,
                token_usage_json=excluded.token_usage_json,coverage_json=excluded.coverage_json,
                updated_at=excluded.updated_at""",
                (
                    run_id, input_position, cve_id, str(status), json.dumps(result.to_dict()) if result else None,
                    json.dumps(state.to_dict()), error, json.dumps(state.token_usage), json.dumps(coverage), _now(),
                ),
            )
            connection.commit()
        except sqlite3.Error as exc:
            raise PersistenceError(f"failed to save investigation {cve_id}: {exc}") from exc

    def get(self, run_id: int, cve_id: str) -> sqlite3.Row | None:
        connection = self._connection()
        connection.row_factory = sqlite3.Row
        return connection.execute(
            "SELECT * FROM investigations WHERE run_id=? AND cve_id=? ORDER BY input_position LIMIT 1",
            (run_id, cve_id),
        ).fetchone()

    def get_run(self, run_id: int) -> sqlite3.Row | None:
        connection = self._connection()
        connection.row_factory = sqlite3.Row
        return connection.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()

    def _connection(self) -> sqlite3.Connection:
        if self.connection is None:
            raise PersistenceError("database is not open")
        return self.connection


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
