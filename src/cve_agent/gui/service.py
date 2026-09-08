from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any
import threading

from cve_agent.application.factory import create_application
from cve_agent.cache.results import ResultCache
from cve_agent.gui.config import GlobalSettingsStore, GuiConfigurationError
from cve_agent.gui.configuration import ConfigurationService, normalize_cve_id
from cve_agent.gui.history import RepositoryAccess, history_item, stored_configuration, stored_payload
from cve_agent.gui.jobs import AnalysisJobs, ApplicationFactory


class GuiService:
    """Route-facing façade for configuration, jobs and stored analysis history."""

    def __init__(
        self, settings_store: GlobalSettingsStore, *,
        application_factory: ApplicationFactory = create_application,
        executor: ThreadPoolExecutor | None = None,
    ):
        lock = threading.RLock()
        self.settings_store = settings_store
        self.repositories = RepositoryAccess(settings_store, lock)
        self.jobs = AnalysisJobs(application_factory, self.repositories.get, lock, executor)
        self.configuration = ConfigurationService(settings_store, self.repositories, self.jobs.has_active, lock)
        self.repositories.get()

    def close(self) -> None:
        self.jobs.close()

    def global_settings(self) -> dict[str, str]:
        return self.configuration.global_settings()

    def path_options(self) -> dict[str, Any]:
        return self.configuration.path_options()

    def update_global_settings(self, raw: dict[str, Any]) -> dict[str, str]:
        return self.configuration.update_global_settings(raw)

    def update_analysis_options(self, raw: dict[str, Any]) -> dict[str, Any]:
        return self.configuration.update_analysis_options(raw)

    def history(self, *, limit: int = 200) -> list[dict[str, Any]]:
        return [history_item(analysis) for analysis in self.repositories.get().list_analyses(limit=limit)]

    def defaults(self, from_analysis_id: str | None = None) -> dict[str, Any]:
        global_settings = self.settings_store.get()
        if from_analysis_id:
            running, stored_alias = self.jobs.lookup(from_analysis_id)
            if running:
                return running.configuration.to_public_dict()
            stored = self.repositories.get().get_analysis(stored_alias or from_analysis_id)
            if stored:
                return stored_configuration(stored)
        return self.configuration.resolve(
            taxonomy_path=global_settings.default_taxonomy_path,
            values={},
        ).to_public_dict()

    def get_analysis(self, analysis_id: str) -> dict[str, Any] | None:
        running, stored_alias = self.jobs.lookup(analysis_id)
        if running:
            return running.snapshot()
        stored = self.repositories.get().get_analysis(stored_alias or analysis_id)
        return stored_payload(self.repositories.get(), stored) if stored else None

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
        configuration = self.configuration.resolve(
            taxonomy_path=(configuration_raw.get("taxonomy_path") or global_settings.default_taxonomy_path),
            values=configuration_raw.get("values", {}),
        )
        cached = ResultCache(self.repositories.get()).find_cached(
            cve_id=cve_id,
            taxonomy_fingerprint=configuration.taxonomy_fingerprint,
            settings_fingerprint_value=configuration.settings_fingerprint,
        )
        if cached:
            return {"id": cached.analysis_id, "cached": True, "lifecycle": "completed"}

        return self.jobs.submit(cve_id, configuration)
