from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
import json
import sqlite3

from cve_agent.core.errors import PersistenceError
from cve_agent.core.history import AnalysisSummary, HistorySearch
from cve_agent.core.history import StoredAnalysis
from cve_agent.core.history import parse_analysis_id
from cve_agent.core.serialization import canonical_json
from cve_agent.core.taxonomy import TaxonomyError
from cve_agent.persistence.codecs import _decode_full
from cve_agent.persistence.codecs import _decode_summary
from cve_agent.persistence.codecs import _json_object
from cve_agent.persistence.connection import _now
from cve_agent.persistence.connection import _open_connection
from cve_agent.persistence.writer import Database


STALE_RUN_AFTER = timedelta(hours=1)


class AnalysisRepository:
    """Read analyses and persist interface events using the pipeline schema."""

    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()

    def initialize(self) -> None:
        with Database(self.path):
            pass
        self.recover_stale()

    def list_analyses(self, *, limit: int = 200, offset: int = 0, search: HistorySearch | None = None) -> list[AnalysisSummary]:
        if limit <= 0:
            return []
        if offset < 0:
            raise ValueError("history offset must not be negative")
        query = (search.cve_query if search else "").strip().upper()
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    _SUMMARY_QUERY + " WHERE instr(upper(a.cve_id), ?) > 0"
                    " ORDER BY (upper(a.cve_id) = ?) DESC, a.updated_at DESC,"
                    " a.run_id DESC, a.input_position ASC LIMIT ? OFFSET ?",
                    (query, query, limit, offset),
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

    def find_result(
        self,
        *,
        cve_id: str,
        taxonomy_fingerprint: str,
        settings_fingerprint_value: str,
        accepted_statuses: tuple[str, ...],
    ) -> StoredAnalysis | None:
        placeholders = ",".join("?" for _ in accepted_statuses)
        try:
            with self._connect() as connection:
                row = connection.execute(
                    _FULL_QUERY
                    + " WHERE a.cve_id=? AND r.taxonomy_sha256=? AND r.settings_sha256=?"
                    + f" AND a.status IN ({placeholders}) AND p.kind='result'"
                    + " ORDER BY a.updated_at DESC LIMIT 1",
                    (
                        cve_id,
                        taxonomy_fingerprint,
                        settings_fingerprint_value,
                        *accepted_statuses,
                    ),
                ).fetchone()
            return _decode_full(row) if row else None
        except (sqlite3.Error, json.JSONDecodeError, TaxonomyError) as exc:
            raise PersistenceError(f"failed to query cached analysis: {exc}") from exc

    def save_events(
        self,
        analysis_id: str,
        events: Iterable[dict[str, Any]],
        *,
        start_sequence: int = 0,
    ) -> None:
        run_id, input_position = parse_analysis_id(analysis_id)
        if start_sequence < 0 or start_sequence > 2**63 - 1:
            raise ValueError("event start sequence must be a non-negative integer")
        rows = []
        for sequence, event in enumerate(events, start=start_sequence):
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
                    ON CONFLICT(run_id,input_position,sequence) DO NOTHING""",
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
