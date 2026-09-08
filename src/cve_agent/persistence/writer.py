from __future__ import annotations

from pathlib import Path
from typing import Any
import sqlite3

from cve_agent.core.config import non_secret_settings, settings_fingerprint
from cve_agent.core.errors import IncompatibleDatabaseError
from cve_agent.core.errors import PersistenceError
from cve_agent.core.investigation import InvestigationState
from cve_agent.core.results import ClassificationResult
from cve_agent.core.serialization import canonical_json
from cve_agent.core.taxonomy import Taxonomy
from cve_agent.persistence.codecs import _final_investigation_payload
from cve_agent.persistence.codecs import _json_object
from cve_agent.persistence.connection import _now
from cve_agent.persistence.connection import _open_connection
from cve_agent.persistence.lifecycle import TERMINAL_ANALYSIS_STATUSES
from cve_agent.persistence.schema import _initialize_schema


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
