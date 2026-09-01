from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cve_agent.config import non_secret_settings, settings_fingerprint
from cve_agent.models import ClassificationResult, InvestigationState
from cve_agent.serialization import canonical_json
from cve_agent.taxonomy import Taxonomy, TaxonomyError, parse_taxonomy


SCHEMA_VERSION = "3"
STALE_RUN_AFTER = timedelta(hours=1)
TERMINAL_ANALYSIS_STATUSES = {
    "classified",
    "no_matching_label",
    "not_enough_information",
    "partial",
    "failed",
    "interrupted",
}


class IncompatibleDatabaseError(RuntimeError):
    pass


class PersistenceError(RuntimeError):
    pass


@dataclass(frozen=True)
class AnalysisSummary:
    run_id: int
    input_position: int
    cve_id: str
    status: str
    started_at: str
    completed_at: str | None
    updated_at: str
    taxonomy_fingerprint: str
    settings_fingerprint: str
    model: str
    run_status: str
    label_ids: tuple[str, ...]
    error: str | None
    taxonomy_path: str | None
    taxonomy_name: str
    taxonomy_labels: int
    hierarchy_policy: str

    @property
    def analysis_id(self) -> str:
        return f"{self.run_id}:{self.input_position}"


@dataclass(frozen=True)
class StoredAnalysis(AnalysisSummary):
    settings: dict[str, Any]
    taxonomy: Taxonomy
    scratchpad: dict[str, Any]
    result: dict[str, Any] | None
    internal_provenance: dict[str, Any]


class Database:
    """Transactional pipeline writer for the unified analysis repository."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.connection: sqlite3.Connection | None = None

    def __enter__(self) -> Database:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.connection = _open_connection(self.path)
            _initialize_schema(self.connection, self.path)
            return self
        except (IncompatibleDatabaseError, PersistenceError):
            if self.connection is not None:
                self.connection.close()
                self.connection = None
            raise
        except (OSError, sqlite3.Error) as exc:
            if self.connection is not None:
                self.connection.close()
                self.connection = None
            raise PersistenceError(f"failed to initialize database: {exc}") from exc

    def __exit__(self, *_: object) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def start_run(self, *, taxonomy: Taxonomy, model: str, settings: dict[str, Any]) -> int:
        connection = self._connection()
        settings_snapshot = non_secret_settings(settings)
        try:
            cursor = connection.execute(
                """INSERT INTO runs(
                    started_at,status,model,settings_json,settings_sha256,
                    taxonomy_json,taxonomy_sha256,taxonomy_name,taxonomy_source_path,
                    taxonomy_labels,hierarchy_policy
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    _now(),
                    "running",
                    model,
                    canonical_json(settings_snapshot),
                    settings_fingerprint(settings_snapshot),
                    canonical_json(taxonomy.to_dict()),
                    taxonomy.fingerprint,
                    taxonomy.display_name,
                    taxonomy.source_path,
                    len(taxonomy.labels),
                    taxonomy.hierarchy_policy.value,
                ),
            )
            connection.commit()
            return int(cursor.lastrowid)
        except sqlite3.Error as exc:
            raise PersistenceError(f"failed to create run: {exc}") from exc

    def finish_run(self, run_id: int, status: str) -> None:
        connection = self._connection()
        try:
            connection.execute(
                "UPDATE runs SET status=?,completed_at=? WHERE id=?",
                (status, _now(), run_id),
            )
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
        timestamp = _now()
        status_value = str(status)
        completed_at = timestamp if status_value in TERMINAL_ANALYSIS_STATUSES else None
        labels = [label.label for label in result.labels] if result else []
        state_payload = state.to_dict()
        internal_provenance = state_payload.pop("provenance", {})
        if result is None:
            payload_kind = "checkpoint"
            payload = state_payload
            public_provenance: dict[str, Any] | None = None
        else:
            classification = result.to_dict()
            public_provenance = classification.pop("provenance", {})
            payload_kind = "result"
            payload = {
                "classification": classification,
                "investigation": _final_investigation_payload(state_payload),
            }
        try:
            connection.execute(
                """INSERT INTO analyses(
                    run_id,input_position,cve_id,status,error,label_ids_json,
                    created_at,updated_at,completed_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(run_id,input_position) DO UPDATE SET
                    cve_id=excluded.cve_id,status=excluded.status,error=excluded.error,
                    label_ids_json=excluded.label_ids_json,updated_at=excluded.updated_at,
                    completed_at=COALESCE(excluded.completed_at,analyses.completed_at)""",
                (
                    run_id,
                    input_position,
                    cve_id,
                    status_value,
                    error,
                    canonical_json(labels),
                    timestamp,
                    timestamp,
                    completed_at,
                ),
            )
            connection.execute(
                """INSERT INTO analysis_payloads(
                    run_id,input_position,kind,payload_json,updated_at
                ) VALUES(?,?,?,?,?)
                ON CONFLICT(run_id,input_position) DO UPDATE SET
                    kind=excluded.kind,payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at""",
                (run_id, input_position, payload_kind, canonical_json(payload), timestamp),
            )
            _upsert_provenance(
                connection,
                run_id,
                input_position,
                "internal",
                internal_provenance,
                timestamp,
            )
            if public_provenance is not None:
                _upsert_provenance(
                    connection,
                    run_id,
                    input_position,
                    "public",
                    public_provenance,
                    timestamp,
                )
            connection.commit()
        except sqlite3.Error as exc:
            connection.rollback()
            raise PersistenceError(f"failed to save investigation {cve_id}: {exc}") from exc

    def get(self, run_id: int, cve_id: str) -> sqlite3.Row | None:
        return self._connection().execute(
            """SELECT a.*,p.kind AS payload_kind,p.payload_json
            FROM analyses a
            LEFT JOIN analysis_payloads p
              ON p.run_id=a.run_id AND p.input_position=a.input_position
            WHERE a.run_id=? AND a.cve_id=?
            ORDER BY a.input_position LIMIT 1""",
            (run_id, cve_id),
        ).fetchone()

    def get_run(self, run_id: int) -> sqlite3.Row | None:
        return self._connection().execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()

    def get_provenance(self, run_id: int, cve_id: str, *, kind: str = "internal") -> dict[str, Any]:
        row = self._connection().execute(
            """SELECT p.payload_json
            FROM provenance_records p
            JOIN analyses a
              ON a.run_id=p.run_id AND a.input_position=p.input_position
            WHERE a.run_id=? AND a.cve_id=? AND p.kind=?
            ORDER BY a.input_position LIMIT 1""",
            (run_id, cve_id, kind),
        ).fetchone()
        return _json_object(row["payload_json"]) if row else {}

    def _connection(self) -> sqlite3.Connection:
        if self.connection is None:
            raise PersistenceError("database is not open")
        return self.connection


class AnalysisRepository:
    """Read analyses and persist interface events using the pipeline schema."""

    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()

    def initialize(self) -> None:
        with Database(self.path):
            pass
        self.recover_stale()

    def list_analyses(self, *, limit: int = 200) -> list[AnalysisSummary]:
        if limit <= 0:
            return []
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    _SUMMARY_QUERY + " ORDER BY a.updated_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [_decode_summary(row) for row in rows]
        except (sqlite3.Error, json.JSONDecodeError) as exc:
            raise PersistenceError(f"failed to read analysis history: {exc}") from exc

    def get_analysis(self, analysis_id: str) -> StoredAnalysis | None:
        run_id, input_position = parse_analysis_id(analysis_id)
        try:
            with self._connect() as connection:
                row = connection.execute(
                    _FULL_QUERY + " WHERE a.run_id=? AND a.input_position=?",
                    (run_id, input_position),
                ).fetchone()
            return _decode_full(row) if row else None
        except (sqlite3.Error, json.JSONDecodeError, TaxonomyError) as exc:
            raise PersistenceError(f"failed to read analysis {analysis_id}: {exc}") from exc

    def find_cached(
        self,
        *,
        cve_id: str,
        taxonomy_fingerprint: str,
        settings_fingerprint_value: str,
    ) -> StoredAnalysis | None:
        accepted = ("classified", "no_matching_label", "not_enough_information")
        try:
            with self._connect() as connection:
                row = connection.execute(
                    _FULL_QUERY
                    + " WHERE a.cve_id=? AND r.taxonomy_sha256=? AND r.settings_sha256=?"
                    + " AND a.status IN (?,?,?) AND p.kind='result'"
                    + " ORDER BY a.updated_at DESC LIMIT 1",
                    (
                        cve_id,
                        taxonomy_fingerprint,
                        settings_fingerprint_value,
                        *accepted,
                    ),
                ).fetchone()
            return _decode_full(row) if row else None
        except (sqlite3.Error, json.JSONDecodeError, TaxonomyError) as exc:
            raise PersistenceError(f"failed to query cached analysis: {exc}") from exc

    def save_events(self, analysis_id: str, events: Iterable[dict[str, Any]]) -> None:
        run_id, input_position = parse_analysis_id(analysis_id)
        rows = []
        for sequence, event in enumerate(events):
            payload = dict(event)
            created_at = str(payload.pop("created_at", ""))
            event_type = str(payload.pop("type", "message"))
            rows.append((
                run_id,
                input_position,
                sequence,
                created_at,
                event_type,
                canonical_json(payload),
            ))
        try:
            with self._connect() as connection:
                connection.executemany(
                    """INSERT INTO analysis_events(
                        run_id,input_position,sequence,created_at,event_type,payload_json
                    ) VALUES(?,?,?,?,?,?)
                    ON CONFLICT(run_id,input_position,sequence) DO UPDATE SET
                        created_at=excluded.created_at,event_type=excluded.event_type,
                        payload_json=excluded.payload_json""",
                    rows,
                )
        except sqlite3.Error as exc:
            raise PersistenceError(f"failed to save analysis progress for {analysis_id}: {exc}") from exc

    def get_events(self, analysis_id: str, *, after_sequence: int = -1) -> list[dict[str, Any]]:
        run_id, input_position = parse_analysis_id(analysis_id)
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    """SELECT sequence,created_at,event_type,payload_json
                    FROM analysis_events
                    WHERE run_id=? AND input_position=? AND sequence>?
                    ORDER BY sequence""",
                    (run_id, input_position, after_sequence),
                ).fetchall()
            return [
                {
                    **_json_object(row["payload_json"]),
                    "sequence": int(row["sequence"]),
                    "created_at": str(row["created_at"]),
                    "type": str(row["event_type"]),
                }
                for row in rows
            ]
        except (sqlite3.Error, json.JSONDecodeError) as exc:
            raise PersistenceError(f"failed to read analysis progress for {analysis_id}: {exc}") from exc

    def recover_stale(self, *, before: str | None = None) -> int:
        cutoff = before or (datetime.now(timezone.utc) - STALE_RUN_AFTER).isoformat()
        timestamp = _now()
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """UPDATE analyses SET
                        status='interrupted',
                        error=COALESCE(error,'analysis process stopped before completion'),
                        updated_at=?,completed_at=?
                    WHERE status='investigating' AND updated_at<?""",
                    (timestamp, timestamp, cutoff),
                )
                connection.execute(
                    """UPDATE runs SET status='interrupted',completed_at=?
                    WHERE status='running' AND EXISTS(
                        SELECT 1 FROM analyses a
                        WHERE a.run_id=runs.id AND a.status='interrupted'
                    )""",
                    (timestamp,),
                )
                connection.execute(
                    """UPDATE runs SET
                        status=CASE
                            WHEN NOT EXISTS(
                                SELECT 1 FROM analyses a WHERE a.run_id=runs.id
                            ) THEN 'interrupted'
                            WHEN EXISTS(
                                SELECT 1 FROM analyses a
                                WHERE a.run_id=runs.id AND a.status='failed'
                            ) THEN 'completed_with_failures'
                            ELSE 'complete'
                        END,
                        completed_at=?
                    WHERE status='running'
                      AND COALESCE(
                          (SELECT MAX(a.updated_at) FROM analyses a WHERE a.run_id=runs.id),
                          runs.started_at
                      )<?
                      AND NOT EXISTS(
                          SELECT 1 FROM analyses a
                          WHERE a.run_id=runs.id AND a.status='investigating'
                      )""",
                    (timestamp, cutoff),
                )
                return int(cursor.rowcount)
        except sqlite3.Error as exc:
            raise PersistenceError(f"failed to recover interrupted analyses: {exc}") from exc

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = _open_connection(self.path)
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


_SUMMARY_QUERY = """SELECT
    a.run_id,a.input_position,a.cve_id,a.status,a.error,a.label_ids_json,
    a.updated_at,a.completed_at,r.started_at,r.taxonomy_sha256,r.settings_sha256,
    r.model,r.status AS run_status,r.taxonomy_source_path,r.taxonomy_name,
    r.taxonomy_labels,r.hierarchy_policy
FROM analyses a
JOIN runs r ON r.id=a.run_id"""

_FULL_QUERY = """SELECT
    a.run_id,a.input_position,a.cve_id,a.status,a.error,a.label_ids_json,
    a.updated_at,a.completed_at,r.started_at,r.taxonomy_sha256,r.settings_sha256,
    r.model,r.status AS run_status,r.taxonomy_source_path,r.taxonomy_name,
    r.taxonomy_labels,r.hierarchy_policy,r.settings_json,r.taxonomy_json,
    p.kind AS payload_kind,p.payload_json,
    internal.payload_json AS internal_provenance_json,
    public.payload_json AS public_provenance_json
FROM analyses a
JOIN runs r ON r.id=a.run_id
LEFT JOIN analysis_payloads p
  ON p.run_id=a.run_id AND p.input_position=a.input_position
LEFT JOIN provenance_records internal
  ON internal.run_id=a.run_id AND internal.input_position=a.input_position
  AND internal.kind='internal'
LEFT JOIN provenance_records public
  ON public.run_id=a.run_id AND public.input_position=a.input_position
  AND public.kind='public'"""


def parse_analysis_id(value: str) -> tuple[int, int]:
    try:
        run_id, input_position = value.split(":", 1)
        parsed = int(run_id), int(input_position)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid analysis ID: {value!r}") from exc
    if min(parsed) < 0 or max(parsed) > 2**63 - 1:
        raise ValueError(f"invalid analysis ID: {value!r}")
    return parsed


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


def _open_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _upsert_provenance(
    connection: sqlite3.Connection,
    run_id: int,
    input_position: int,
    kind: str,
    payload: dict[str, Any],
    updated_at: str,
) -> None:
    connection.execute(
        """INSERT INTO provenance_records(
            run_id,input_position,kind,payload_json,updated_at
        ) VALUES(?,?,?,?,?)
        ON CONFLICT(run_id,input_position,kind) DO UPDATE SET
            payload_json=excluded.payload_json,updated_at=excluded.updated_at""",
        (run_id, input_position, kind, canonical_json(payload), updated_at),
    )


def _final_investigation_payload(state: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in state.items()
        if key not in {"facts", "visited_urls", "token_usage"}
    }


def _decode_summary(row: sqlite3.Row) -> AnalysisSummary:
    return AnalysisSummary(
        run_id=int(row["run_id"]),
        input_position=int(row["input_position"]),
        cve_id=str(row["cve_id"]),
        status=str(row["status"]),
        started_at=str(row["started_at"]),
        completed_at=str(row["completed_at"]) if row["completed_at"] else None,
        updated_at=str(row["updated_at"]),
        taxonomy_fingerprint=str(row["taxonomy_sha256"]),
        settings_fingerprint=str(row["settings_sha256"]),
        model=str(row["model"]),
        run_status=str(row["run_status"]),
        label_ids=tuple(str(item) for item in _json_array(row["label_ids_json"])),
        error=str(row["error"]) if row["error"] else None,
        taxonomy_path=str(row["taxonomy_source_path"]) if row["taxonomy_source_path"] else None,
        taxonomy_name=str(row["taxonomy_name"]),
        taxonomy_labels=int(row["taxonomy_labels"]),
        hierarchy_policy=str(row["hierarchy_policy"]),
    )


def _decode_full(row: sqlite3.Row) -> StoredAnalysis:
    summary = _decode_summary(row)
    payload = _json_object(row["payload_json"]) if row["payload_json"] else {}
    internal_provenance = (
        _json_object(row["internal_provenance_json"])
        if row["internal_provenance_json"]
        else {}
    )
    result: dict[str, Any] | None = None
    if row["payload_kind"] == "result":
        result = _json_object_value(payload.get("classification"))
        result["provenance"] = (
            _json_object(row["public_provenance_json"])
            if row["public_provenance_json"]
            else {}
        )
        scratchpad = _json_object_value(payload.get("investigation"))
    else:
        scratchpad = payload
    scratchpad["provenance"] = internal_provenance
    return StoredAnalysis(
        run_id=summary.run_id,
        input_position=summary.input_position,
        cve_id=summary.cve_id,
        status=summary.status,
        started_at=summary.started_at,
        completed_at=summary.completed_at,
        updated_at=summary.updated_at,
        taxonomy_fingerprint=summary.taxonomy_fingerprint,
        settings_fingerprint=summary.settings_fingerprint,
        model=summary.model,
        run_status=summary.run_status,
        label_ids=summary.label_ids,
        error=summary.error,
        taxonomy_path=summary.taxonomy_path,
        taxonomy_name=summary.taxonomy_name,
        taxonomy_labels=summary.taxonomy_labels,
        hierarchy_policy=summary.hierarchy_policy,
        settings=_json_object(row["settings_json"]),
        taxonomy=_taxonomy_from_snapshot(row["taxonomy_json"], summary.taxonomy_path),
        scratchpad=scratchpad,
        result=result,
        internal_provenance=internal_provenance,
    )


def _json_object(value: str) -> dict[str, Any]:
    return _json_object_value(json.loads(value))


def _json_object_value(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _json_array(value: str) -> list[Any]:
    decoded = json.loads(value)
    return decoded if isinstance(decoded, list) else []


def _taxonomy_from_snapshot(value: str, source_path: str | None) -> Taxonomy:
    taxonomy = parse_taxonomy(json.loads(value))
    return Taxonomy(
        taxonomy.labels,
        taxonomy.hierarchy_policy,
        taxonomy.name,
        taxonomy.extra,
        source_path,
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
