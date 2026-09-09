from __future__ import annotations

from pathlib import Path
from typing import Any

from cve_agent.application.factory import create_history_repository
from cve_agent.classification.taxonomy import is_hierarchical
from cve_agent.core.history import AnalysisSummary, StoredAnalysis
from cve_agent.core.ports import AnalysisHistory
from cve_agent.gui.config import GlobalSettingsStore, public_configuration
from cve_agent.gui.progress import _result_tone
from cve_agent.runtime.diagnostics import safe_url


def _stored_lifecycle(analysis: StoredAnalysis) -> str:
    if analysis.status == "interrupted" or analysis.run_status == "interrupted":
        return "interrupted"
    if analysis.status == "failed":
        return "failed"
    if analysis.status == "investigating" or analysis.run_status == "running":
        return "running"
    return "completed"


def _events_from_scratchpad(analysis: StoredAnalysis) -> list[dict[str, Any]]:
    events = [
        {
            "created_at": analysis.started_at,
            "tone": "normal",
            "component": "HISTORY",
            "message": f"Loaded persisted analysis for {analysis.cve_id}.",
        }
    ]
    scratchpad = analysis.scratchpad or {}
    for item in scratchpad.get("tool_history", []):
        if not isinstance(item, dict):
            continue
        tool = str(item.get("tool", "agent"))
        status = str(item.get("status", "recorded"))
        detail = ""
        if item.get("query"):
            detail = f" — {str(item['query'])[:160]}"
        elif item.get("url"):
            detail = f" — {safe_url(str(item['url']))[:160]}"
        events.append({
            "created_at": analysis.updated_at,
            "tone": "warning" if status == "error" else "normal",
            "component": "RESEARCH",
            "message": f"{tool}: {status}{detail}",
        })
    events.append({
        "created_at": analysis.completed_at or analysis.updated_at,
        "tone": _result_tone(analysis.status),
        "component": "SYSTEM",
        "message": f"Persisted result status: {analysis.status}.",
    })
    return events


class RepositoryAccess:
    """Select the repository for the active GUI database under its shared lock."""

    def __init__(self, settings_store: GlobalSettingsStore, lock):
        self.settings_store = settings_store
        self._lock = lock
        self._repository_path: Path | None = None
        self._repository: AnalysisHistory | None = None

    def replace(self, repository: AnalysisHistory, path: Path) -> None:
        with self._lock:
            self._repository_path = path
            self._repository = repository

    def get(self, database_path: str | Path | None = None) -> AnalysisHistory:
        active_path = self.settings_store.get().database_path.resolve()
        path = Path(database_path).resolve() if database_path is not None else active_path
        with self._lock:
            if self._repository is None or self._repository_path != path:
                repository = create_history_repository(path)
                repository.initialize()
                if path == active_path:
                    self._repository = repository
                    self._repository_path = path
                return repository
            return self._repository

def stored_payload(repository: AnalysisHistory, analysis: StoredAnalysis) -> dict[str, Any]:
    events = repository.get_events(analysis.analysis_id)
    if not events:
        events = _events_from_scratchpad(analysis)
    return {
        "id": analysis.analysis_id,
        "cve_id": analysis.cve_id,
        "lifecycle": _stored_lifecycle(analysis),
        "stored_analysis_id": analysis.analysis_id,
        "events": events,
        "configuration": stored_configuration(analysis),
        "result": analysis.result,
        "error": analysis.error,
    }

def stored_configuration(analysis: StoredAnalysis) -> dict[str, Any]:
    name = analysis.taxonomy_name or f"Taxonomy {analysis.taxonomy_fingerprint[:12]}"
    taxonomy = analysis.taxonomy
    return public_configuration(
        settings=analysis.settings,
        taxonomy_path=analysis.taxonomy_path,
        taxonomy_name=name,
        taxonomy_fingerprint=analysis.taxonomy_fingerprint,
        taxonomy_labels=analysis.taxonomy_labels,
        taxonomy_hierarchical=is_hierarchical(taxonomy),
        hierarchy_policy=analysis.hierarchy_policy,
    )

def history_item(analysis: AnalysisSummary) -> dict[str, Any]:
    return {
        "id": analysis.analysis_id,
        "cve_id": analysis.cve_id,
        "status": analysis.status,
        "updated_at": analysis.updated_at,
        "taxonomy_name": analysis.taxonomy_name or f"Taxonomy {analysis.taxonomy_fingerprint[:8]}",
        "labels": list(analysis.label_ids),
    }
