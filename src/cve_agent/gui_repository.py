from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from cve_agent.config import settings_fingerprint as canonical_settings_fingerprint
from cve_agent.persistence import Database, PersistenceError


@dataclass(frozen=True)
class StoredAnalysis:
    run_id: int
    input_position: int
    cve_id: str
    status: str
    started_at: str
    completed_at: str | None
    updated_at: str
    taxonomy_fingerprint: str
    model: str
    run_status: str
    settings: dict[str, Any]
    scratchpad: dict[str, Any]
    result: dict[str, Any] | None
    error: str | None
    taxonomy_path: str | None = None
    taxonomy_name: str | None = None
    config_path: str | None = None
    taxonomy_labels: int | None = None
    hierarchy_policy: str | None = None

    @property
    def analysis_id(self) -> str:
        return f"{self.run_id}:{self.input_position}"


class GuiAnalysisRepository:
    """Read core runs and persist GUI-only chat metadata/events in the same database."""

    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()

    def initialize(self) -> None:
        with Database(self.path):
            pass
        try:
            with self._connect() as connection:
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS gui_analysis_meta (
                        run_id INTEGER NOT NULL,
                        input_position INTEGER NOT NULL,
                        taxonomy_path TEXT,
                        taxonomy_name TEXT NOT NULL,
                        config_path TEXT,
                        settings_fingerprint TEXT NOT NULL,
                        taxonomy_labels INTEGER,
                        hierarchy_policy TEXT,
                        PRIMARY KEY(run_id,input_position),
                        FOREIGN KEY(run_id,input_position)
                            REFERENCES investigations(run_id,input_position) ON DELETE CASCADE
                    );
                    CREATE TABLE IF NOT EXISTS gui_analysis_events (
                        run_id INTEGER NOT NULL,
                        input_position INTEGER NOT NULL,
                        sequence INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        tone TEXT NOT NULL,
                        component TEXT NOT NULL,
                        message TEXT NOT NULL,
                        PRIMARY KEY(run_id,input_position,sequence),
                        FOREIGN KEY(run_id,input_position)
                            REFERENCES investigations(run_id,input_position) ON DELETE CASCADE
                    );
                """)
        except sqlite3.Error as exc:
            raise PersistenceError(f"failed to initialize GUI history: {exc}") from exc

    def list_analyses(self, *, limit: int = 200) -> list[StoredAnalysis]:
        if limit <= 0:
            return []
        try:
            with self._connect() as connection:
                rows = connection.execute(self._analysis_query() + " ORDER BY i.updated_at DESC LIMIT ?", (limit,)).fetchall()
            return [self._decode_analysis(row) for row in rows]
        except sqlite3.Error as exc:
            raise PersistenceError(f"failed to read analysis history: {exc}") from exc

    def get_analysis(self, analysis_id: str) -> StoredAnalysis | None:
        run_id, input_position = parse_analysis_id(analysis_id)
        try:
            with self._connect() as connection:
                row = connection.execute(
                    self._analysis_query() + " WHERE i.run_id=? AND i.input_position=?",
                    (run_id, input_position),
                ).fetchone()
            return self._decode_analysis(row) if row else None
        except sqlite3.Error as exc:
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
                rows = connection.execute(
                    self._analysis_query()
                    + " WHERE i.cve_id=? AND r.taxonomy_sha256=? AND i.status IN (?,?,?) AND i.result_json IS NOT NULL"
                    + " ORDER BY i.updated_at DESC",
                    (cve_id, taxonomy_fingerprint, *accepted),
                ).fetchall()
            for row in rows:
                analysis = self._decode_analysis(row)
                if settings_fingerprint(analysis.settings) == settings_fingerprint_value:
                    return analysis
            return None
        except sqlite3.Error as exc:
            raise PersistenceError(f"failed to query cached analysis: {exc}") from exc

    def save_snapshot(
        self,
        analysis_id: str,
        *,
        taxonomy_path: str | Path,
        taxonomy_name: str,
        config_path: str | Path,
        settings_fingerprint_value: str,
        taxonomy_labels: int,
        hierarchy_policy: str,
    ) -> None:
        run_id, input_position = parse_analysis_id(analysis_id)
        try:
            with self._connect() as connection:
                connection.execute(
                    """INSERT INTO gui_analysis_meta(
                        run_id,input_position,taxonomy_path,taxonomy_name,config_path,
                        settings_fingerprint,taxonomy_labels,hierarchy_policy
                    ) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(run_id,input_position) DO UPDATE SET
                        taxonomy_path=excluded.taxonomy_path,taxonomy_name=excluded.taxonomy_name,
                        config_path=excluded.config_path,settings_fingerprint=excluded.settings_fingerprint,
                        taxonomy_labels=excluded.taxonomy_labels,hierarchy_policy=excluded.hierarchy_policy""",
                    (
                        run_id,
                        input_position,
                        str(taxonomy_path),
                        taxonomy_name,
                        str(config_path),
                        settings_fingerprint_value,
                        taxonomy_labels,
                        hierarchy_policy,
                    ),
                )
        except sqlite3.Error as exc:
            raise PersistenceError(f"failed to save GUI configuration for {analysis_id}: {exc}") from exc

    def save_events(self, analysis_id: str, events: Iterable[dict[str, Any]]) -> None:
        run_id, input_position = parse_analysis_id(analysis_id)
        rows = [
            (
                run_id,
                input_position,
                sequence,
                str(event.get("created_at", "")),
                str(event.get("tone", "normal")),
                str(event.get("component", "AGENT")),
                str(event.get("message", "")),
            )
            for sequence, event in enumerate(events)
        ]
        try:
            with self._connect() as connection:
                connection.execute(
                    "DELETE FROM gui_analysis_events WHERE run_id=? AND input_position=?",
                    (run_id, input_position),
                )
                connection.executemany(
                    """INSERT INTO gui_analysis_events(
                        run_id,input_position,sequence,created_at,tone,component,message
                    ) VALUES(?,?,?,?,?,?,?)""",
                    rows,
                )
        except sqlite3.Error as exc:
            raise PersistenceError(f"failed to save GUI progress for {analysis_id}: {exc}") from exc

    def get_events(self, analysis_id: str) -> list[dict[str, Any]]:
        run_id, input_position = parse_analysis_id(analysis_id)
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    """SELECT created_at,tone,component,message FROM gui_analysis_events
                    WHERE run_id=? AND input_position=? ORDER BY sequence""",
                    (run_id, input_position),
                ).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            raise PersistenceError(f"failed to read GUI progress for {analysis_id}: {exc}") from exc

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _analysis_query() -> str:
        return """SELECT
            i.run_id,i.input_position,i.cve_id,i.status,i.result_json,i.scratchpad_json,
            i.error,i.updated_at,r.started_at,r.completed_at,r.taxonomy_sha256,r.model,
            r.settings_json,r.status AS run_status,m.taxonomy_path,m.taxonomy_name,m.config_path,
            m.taxonomy_labels,m.hierarchy_policy
        FROM investigations i
        JOIN runs r ON r.id=i.run_id
        LEFT JOIN gui_analysis_meta m
          ON m.run_id=i.run_id AND m.input_position=i.input_position"""

    @staticmethod
    def _decode_analysis(row: sqlite3.Row) -> StoredAnalysis:
        return StoredAnalysis(
            run_id=int(row["run_id"]),
            input_position=int(row["input_position"]),
            cve_id=str(row["cve_id"]),
            status=str(row["status"]),
            started_at=str(row["started_at"]),
            completed_at=str(row["completed_at"]) if row["completed_at"] else None,
            updated_at=str(row["updated_at"]),
            taxonomy_fingerprint=str(row["taxonomy_sha256"]),
            model=str(row["model"]),
            run_status=str(row["run_status"]),
            settings=_json_object(row["settings_json"]),
            scratchpad=_json_object(row["scratchpad_json"]),
            result=_json_object(row["result_json"]) if row["result_json"] else None,
            error=str(row["error"]) if row["error"] else None,
            taxonomy_path=str(row["taxonomy_path"]) if row["taxonomy_path"] else None,
            taxonomy_name=str(row["taxonomy_name"]) if row["taxonomy_name"] else None,
            config_path=str(row["config_path"]) if row["config_path"] else None,
            taxonomy_labels=int(row["taxonomy_labels"]) if row["taxonomy_labels"] is not None else None,
            hierarchy_policy=str(row["hierarchy_policy"]) if row["hierarchy_policy"] else None,
        )


def settings_fingerprint(settings: dict[str, Any]) -> str:
    """Compatibility alias for the canonical settings fingerprint."""
    return canonical_settings_fingerprint(settings)


def parse_analysis_id(value: str) -> tuple[int, int]:
    try:
        run_id, input_position = value.split(":", 1)
        parsed = int(run_id), int(input_position)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid analysis ID: {value!r}") from exc
    if min(parsed) < 0 or max(parsed) > 2**63 - 1:
        raise ValueError(f"invalid analysis ID: {value!r}")
    return parsed


def _json_object(value: str) -> dict[str, Any]:
    decoded = json.loads(value)
    return decoded if isinstance(decoded, dict) else {}
