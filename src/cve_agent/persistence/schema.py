from __future__ import annotations

from pathlib import Path
import sqlite3

from cve_agent.core.errors import IncompatibleDatabaseError
from cve_agent.core.errors import PersistenceError


SCHEMA_VERSION = "3"


def _initialize_schema(connection: sqlite3.Connection, path: Path) -> None:
    try:
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            if not str(row[0]).startswith("sqlite_")
        }
        if tables and "schema_meta" not in tables:
            raise IncompatibleDatabaseError(
                f"database {path} uses an unsupported schema; move or remove it explicitly"
            )
        if "schema_meta" in tables:
            version = connection.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()
            if version is None or version[0] != SCHEMA_VERSION:
                found = version[0] if version else "unknown"
                raise IncompatibleDatabaseError(
                    f"database {path} has schema version {found!r}, expected {SCHEMA_VERSION}; "
                    "move or remove it explicitly"
                )
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT NOT NULL,
                model TEXT NOT NULL,
                settings_json TEXT NOT NULL,
                settings_sha256 TEXT NOT NULL,
                taxonomy_json TEXT NOT NULL,
                taxonomy_sha256 TEXT NOT NULL,
                taxonomy_name TEXT NOT NULL,
                taxonomy_source_path TEXT,
                taxonomy_labels INTEGER NOT NULL,
                hierarchy_policy TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS analyses (
                run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                input_position INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                status TEXT NOT NULL,
                error TEXT,
                label_ids_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT,
                PRIMARY KEY(run_id,input_position)
            );
            CREATE TABLE IF NOT EXISTS analysis_payloads (
                run_id INTEGER NOT NULL,
                input_position INTEGER NOT NULL,
                kind TEXT NOT NULL CHECK(kind IN ('checkpoint','result')),
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(run_id,input_position),
                FOREIGN KEY(run_id,input_position)
                    REFERENCES analyses(run_id,input_position) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS analysis_events (
                run_id INTEGER NOT NULL,
                input_position INTEGER NOT NULL,
                sequence INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY(run_id,input_position,sequence),
                FOREIGN KEY(run_id,input_position)
                    REFERENCES analyses(run_id,input_position) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS provenance_records (
                run_id INTEGER NOT NULL,
                input_position INTEGER NOT NULL,
                kind TEXT NOT NULL CHECK(kind IN ('internal','public')),
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(run_id,input_position,kind),
                FOREIGN KEY(run_id,input_position)
                    REFERENCES analyses(run_id,input_position) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS analyses_history_idx
                ON analyses(updated_at DESC);
            CREATE INDEX IF NOT EXISTS analyses_cache_idx
                ON analyses(cve_id,status,updated_at DESC);
            CREATE INDEX IF NOT EXISTS runs_fingerprints_idx
                ON runs(taxonomy_sha256,settings_sha256);
        """)
        connection.execute(
            "INSERT OR IGNORE INTO schema_meta(key,value) VALUES('schema_version',?)",
            (SCHEMA_VERSION,),
        )
        connection.commit()
    except IncompatibleDatabaseError:
        raise
    except sqlite3.Error as exc:
        raise PersistenceError(f"failed to initialize database: {exc}") from exc
