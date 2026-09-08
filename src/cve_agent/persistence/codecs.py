from __future__ import annotations

from typing import Any
import json
import sqlite3

from cve_agent.core.history import AnalysisSummary
from cve_agent.core.history import StoredAnalysis
from cve_agent.core.taxonomy import Taxonomy, parse_taxonomy


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
