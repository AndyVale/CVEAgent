from __future__ import annotations

import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from cve_agent.application import ApplicationRun, create_application
from cve_agent.classification import is_hierarchical
from cve_agent.config import Settings, load_settings, non_secret_settings
from cve_agent.gui_config import (
    GlobalSettingsStore,
    GuiConfigurationError,
    apply_chat_overrides,
    public_configuration,
    write_gui_settings,
)
from cve_agent.gui_paths import GuiPathError, GuiPathPolicy
from cve_agent.gui_repository import (
    AnalysisSummary,
    GuiAnalysisRepository,
    StoredAnalysis,
    settings_fingerprint,
)
from cve_agent.identifiers import CVEIdentifierError, normalize_cve_id as normalize_public_cve_id
from cve_agent.logging_config import LogTone, redact_secrets, safe_url
from cve_agent.pipeline import persisted_taxonomy_fingerprint
from cve_agent.taxonomy import Taxonomy, load_taxonomy


_COMPLETE_CACHE_STATUSES = {"classified", "no_matching_label", "not_enough_information"}


class Application(Protocol):
    def run(self, cve_ids: list[str], taxonomy: Taxonomy) -> ApplicationRun: ...


ApplicationFactory = Callable[[Settings], Application]


@dataclass(frozen=True)
class AnalysisConfiguration:
    settings: Settings
    taxonomy: Taxonomy
    taxonomy_path: Path
    taxonomy_name: str
    taxonomy_fingerprint: str
    settings_fingerprint: str

    def to_public_dict(self) -> dict[str, Any]:
        return public_configuration(
            settings=self.settings,
            taxonomy_path=self.taxonomy_path,
            taxonomy_name=self.taxonomy_name,
            taxonomy_fingerprint=self.taxonomy_fingerprint,
            taxonomy_labels=len(self.taxonomy.labels),
            taxonomy_hierarchical=is_hierarchical(self.taxonomy),
            hierarchy_policy=self.taxonomy.hierarchy_policy.value,
        )


@dataclass
class RunningAnalysis:
    analysis_id: str
    cve_id: str
    configuration: AnalysisConfiguration
    lifecycle: str = "queued"
    events: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    stored_analysis_id: str | None = None
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def add_event(self, *, tone: str, component: str, message: str) -> None:
        with self._lock:
            self.events.append(_event(tone=tone, component=component, message=message))

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "id": self.analysis_id,
                "cve_id": self.cve_id,
                "lifecycle": self.lifecycle,
                "stored_analysis_id": self.stored_analysis_id,
                "events": [dict(event) for event in self.events],
                "configuration": self.configuration.to_public_dict(),
                "result": None,
                "error": self.error,
            }


class GuiService:
    """GUI-facing orchestration without terminal or Flask concerns."""

    def __init__(
        self,
        settings_store: GlobalSettingsStore,
        *,
        application_factory: ApplicationFactory = create_application,
        executor: ThreadPoolExecutor | None = None,
    ):
        self.settings_store = settings_store
        self.path_policy = settings_store.path_policy
        self.application_factory = application_factory
        self._executor = executor or ThreadPoolExecutor(max_workers=1, thread_name_prefix="cve-gui")
        self._owns_executor = executor is None
        self._lock = threading.RLock()
        self._running: dict[str, RunningAnalysis] = {}
        self._completed_aliases: dict[str, str] = {}
        self._repository_path: Path | None = None
        self._repository: GuiAnalysisRepository | None = None
        self._get_repository()

    def close(self) -> None:
        if self._owns_executor:
            self._executor.shutdown(wait=False, cancel_futures=False)

    def global_settings(self) -> dict[str, str]:
        return self.settings_store.get().to_dict()

    def path_options(self) -> dict[str, Any]:
        return {
            "configuration": {
                "prefix": "./",
                "name": self.settings_store.get().default_config_path.name,
            },
            "taxonomies": _path_choices(
                self.path_policy.taxonomy_files(),
                self.path_policy.fixtures_root,
                "fixtures/",
            ),
            "databases": _path_choices(
                self.path_policy.database_files(),
                self.path_policy.data_root,
                ".data/",
            ),
        }

    def update_global_settings(self, raw: dict[str, Any]) -> dict[str, str]:
        if self._has_active_analysis():
            raise GuiConfigurationError("global settings cannot change while an analysis is running")
        if not isinstance(raw, dict):
            raise GuiConfigurationError("global settings must be an object")
        unknown = sorted(set(raw) - {"database_path", "default_taxonomy_path"})
        if unknown:
            raise GuiConfigurationError(f"unknown global setting fields: {unknown}")
        normalized = {
            **raw,
            "default_config_path": str(self.settings_store.get().default_config_path),
        }
        candidate = self.settings_store.validate(normalized)
        load_taxonomy(candidate.default_taxonomy_path)
        repository = GuiAnalysisRepository(candidate.database_path)
        repository.initialize()
        updated = self.settings_store.update(normalized)
        with self._lock:
            self._repository_path = updated.database_path
            self._repository = repository
        return updated.to_dict()

    def history(self, *, limit: int = 200) -> list[dict[str, Any]]:
        return [self._history_item(analysis) for analysis in self._get_repository().list_analyses(limit=limit)]

    def defaults(self, from_analysis_id: str | None = None) -> dict[str, Any]:
        global_settings = self.settings_store.get()
        if from_analysis_id:
            running, stored_alias = self._lookup_running(from_analysis_id)
            if running:
                return running.configuration.to_public_dict()
            stored = self._get_repository().get_analysis(stored_alias or from_analysis_id)
            if stored:
                return self._stored_configuration(stored)
        return self._resolve_configuration(
            taxonomy_path=global_settings.default_taxonomy_path,
            values={},
        ).to_public_dict()

    def update_analysis_options(self, raw: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise GuiConfigurationError("analysis options must be an object")
        unknown = sorted(set(raw) - {"taxonomy_path", "values"})
        if unknown:
            raise GuiConfigurationError(f"unknown analysis option fields: {unknown}")
        values = raw.get("values", {})
        global_settings = self.settings_store.get()
        taxonomy_path = raw.get("taxonomy_path") or global_settings.default_taxonomy_path
        with self._lock:
            configuration = self._resolve_configuration(
                taxonomy_path=taxonomy_path,
                values=values,
            )
            write_gui_settings(
                global_settings.default_config_path,
                configuration.settings,
                self.path_policy,
            )
            return self._resolve_configuration(
                taxonomy_path=taxonomy_path,
                values={},
            ).to_public_dict()

    def get_analysis(self, analysis_id: str) -> dict[str, Any] | None:
        running, stored_alias = self._lookup_running(analysis_id)
        if running:
            return running.snapshot()
        stored = self._get_repository().get_analysis(stored_alias or analysis_id)
        return self._stored_payload(stored) if stored else None

    def start_analysis(self, raw: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise GuiConfigurationError("analysis request must be an object")
        unknown_request = sorted(set(raw) - {"cve_id", "configuration"})
        if unknown_request:
            raise GuiConfigurationError(f"unknown analysis request fields: {unknown_request}")
        cve_id = normalize_cve_id(raw.get("cve_id"))
        configuration_raw = raw.get("configuration", {})
        if not isinstance(configuration_raw, dict):
            raise GuiConfigurationError("configuration must be an object")
        unknown = sorted(set(configuration_raw) - {"taxonomy_path", "values"})
        if unknown:
            raise GuiConfigurationError(f"unknown analysis configuration fields: {unknown}")
        global_settings = self.settings_store.get()
        configuration = self._resolve_configuration(
            taxonomy_path=(configuration_raw.get("taxonomy_path") or global_settings.default_taxonomy_path),
            values=configuration_raw.get("values", {}),
        )
        cached = self._get_repository().find_cached(
            cve_id=cve_id,
            taxonomy_fingerprint=configuration.taxonomy_fingerprint,
            settings_fingerprint_value=configuration.settings_fingerprint,
        )
        if cached and cached.status in _COMPLETE_CACHE_STATUSES:
            return {"id": cached.analysis_id, "cached": True, "lifecycle": "completed"}

        analysis_id = f"pending-{uuid.uuid4().hex}"
        running = RunningAnalysis(analysis_id, cve_id, configuration)
        running.add_event(tone="normal", component="YOU", message=f"Analyze {cve_id}")
        running.add_event(
            tone="normal",
            component="SYSTEM",
            message=f"Queued with taxonomy {configuration.taxonomy_name} ({len(configuration.taxonomy.labels)} labels).",
        )
        with self._lock:
            self._running[analysis_id] = running
        self._executor.submit(self._run_analysis, running)
        return {"id": analysis_id, "cached": False, "lifecycle": "queued"}

    def _run_analysis(self, running: RunningAnalysis) -> None:
        configuration = running.configuration
        with running._lock:
            running.lifecycle = "running"
        running.add_event(tone="normal", component="SYSTEM", message="Analysis started.")
        handler = _ProgressHandler(running, configuration.settings)
        package_logger = logging.getLogger("cve_agent")
        previous_level = package_logger.level
        previous_propagate = package_logger.propagate
        package_logger.addHandler(handler)
        package_logger.setLevel(logging.INFO)
        package_logger.propagate = False
        try:
            outcome = self.application_factory(configuration.settings).run(
                [running.cve_id], configuration.taxonomy
            )
            if not outcome.results:
                raise RuntimeError("classification pipeline returned no result")
            result = outcome.results[0]
            run_id = result.operational.get("run_id")
            if not isinstance(run_id, int):
                raise RuntimeError("classification result does not identify its persisted run")
            stored_id = f"{run_id}:0"
            running.add_event(
                tone=_result_tone(str(result.status)),
                component="SYSTEM",
                message=f"Analysis finished with status {result.status} and {len(result.labels)} label(s).",
            )
            self._get_repository().save_events(stored_id, running.events)
            with running._lock:
                running.stored_analysis_id = stored_id
                running.lifecycle = "completed"
            with self._lock:
                self._completed_aliases[running.analysis_id] = stored_id
                self._running.pop(running.analysis_id, None)
        except Exception as exc:
            detail = redact_secrets(exc, configuration.settings.api_key, configuration.settings.tavily_api_key)
            running.add_event(tone="error", component="SYSTEM", message=f"Analysis failed: {detail}")
            with running._lock:
                running.lifecycle = "failed"
                running.error = detail
        finally:
            package_logger.removeHandler(handler)
            handler.close()
            package_logger.setLevel(previous_level)
            package_logger.propagate = previous_propagate

    def _resolve_configuration(
        self,
        *,
        taxonomy_path: str | Path,
        values: Any,
    ) -> AnalysisConfiguration:
        global_settings = self.settings_store.get()
        try:
            resolved_config = self.path_policy.configuration_file(global_settings.default_config_path)
            resolved_taxonomy = self.path_policy.taxonomy_file(taxonomy_path)
            base = load_settings(resolved_config)
            taxonomy = load_taxonomy(resolved_taxonomy)
        except (OSError, ValueError, GuiPathError) as exc:
            raise GuiConfigurationError(str(exc)) from exc
        settings = apply_chat_overrides(
            base,
            values,
            database_path=global_settings.database_path,
            path_policy=self.path_policy,
        )
        fingerprint = persisted_taxonomy_fingerprint(taxonomy)
        return AnalysisConfiguration(
            settings=settings,
            taxonomy=taxonomy,
            taxonomy_path=resolved_taxonomy,
            taxonomy_name=taxonomy.display_name,
            taxonomy_fingerprint=fingerprint,
            settings_fingerprint=settings_fingerprint(non_secret_settings(settings)),
        )

    def _stored_payload(self, analysis: StoredAnalysis) -> dict[str, Any]:
        events = self._get_repository().get_events(analysis.analysis_id)
        if not events:
            events = _events_from_scratchpad(analysis)
        return {
            "id": analysis.analysis_id,
            "cve_id": analysis.cve_id,
            "lifecycle": _stored_lifecycle(analysis),
            "stored_analysis_id": analysis.analysis_id,
            "events": events,
            "configuration": self._stored_configuration(analysis),
            "result": analysis.result,
            "error": analysis.error,
        }

    def _stored_configuration(self, analysis: StoredAnalysis) -> dict[str, Any]:
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

    def _get_repository(self) -> GuiAnalysisRepository:
        path = self.settings_store.get().database_path.resolve()
        with self._lock:
            if self._repository is None or self._repository_path != path:
                repository = GuiAnalysisRepository(path)
                repository.initialize()
                self._repository = repository
                self._repository_path = path
            return self._repository

    def _lookup_running(self, analysis_id: str) -> tuple[RunningAnalysis | None, str | None]:
        with self._lock:
            return self._running.get(analysis_id), self._completed_aliases.get(analysis_id)

    def _has_active_analysis(self) -> bool:
        with self._lock:
            return any(item.lifecycle in {"queued", "running"} for item in self._running.values())

    @staticmethod
    def _history_item(analysis: AnalysisSummary) -> dict[str, Any]:
        return {
            "id": analysis.analysis_id,
            "cve_id": analysis.cve_id,
            "status": analysis.status,
            "updated_at": analysis.updated_at,
            "taxonomy_name": analysis.taxonomy_name or f"Taxonomy {analysis.taxonomy_fingerprint[:8]}",
            "labels": list(analysis.label_ids),
        }


class _ProgressHandler(logging.Handler):
    def __init__(self, running: RunningAnalysis, settings: Settings):
        super().__init__(logging.INFO)
        self.running = running
        self.settings = settings

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = redact_secrets(record.getMessage(), self.settings.api_key, self.settings.tavily_api_key)
            tone = getattr(record, "tone", None) or _level_tone(record.levelno)
            component = record.name.removeprefix("cve_agent.").upper()
            self.running.add_event(tone=str(tone), component=component, message=message)
        except Exception:
            self.handleError(record)


def normalize_cve_id(value: Any) -> str:
    try:
        return normalize_public_cve_id(value)
    except CVEIdentifierError as exc:
        raise GuiConfigurationError("enter a CVE ID such as CVE-2021-44228") from exc


def _path_choices(paths: tuple[Path, ...], root: Path, prefix: str) -> list[dict[str, str]]:
    return [
        {
            "path": str(path),
            "value": f"{prefix}{path.relative_to(root)}",
            "label": str(path.relative_to(root)),
        }
        for path in paths
    ]


def _event(*, tone: str, component: str, message: str) -> dict[str, Any]:
    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tone": tone,
        "component": component,
        "message": message,
    }


def _level_tone(level: int) -> str:
    if level >= logging.ERROR:
        return LogTone.ERROR.value
    if level >= logging.WARNING:
        return LogTone.WARNING.value
    return LogTone.NORMAL.value


def _result_tone(status: str) -> str:
    if status == "failed":
        return LogTone.ERROR.value
    if status in {"partial", "not_enough_information"}:
        return LogTone.INCOMPLETE.value
    return LogTone.SUCCESS.value


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
