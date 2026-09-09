from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any
import threading

from cve_agent.application.factory import create_application
from cve_agent.core.history import HistorySearch
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

    def history(self, *, limit: int = 200, offset: int = 0, query: str = "") -> list[dict[str, Any]]:
        return [history_item(analysis) for analysis in self.repositories.get().list_analyses(limit=limit, offset=offset, search=HistorySearch(cve_query=query))]

    def history_page(
        self,
        *,
        limit: int = 200,
        cursor: str | None = None,
        query: str = "",
    ) -> dict[str, Any]:
        page = self.repositories.get().list_analysis_page(
            limit=limit,
            cursor=cursor,
            search=HistorySearch(cve_query=query),
        )
        return {
            "analyses": [history_item(analysis) for analysis in page.analyses],
            "next_cursor": page.next_cursor,
            "has_more": page.next_cursor is not None,
        }

    def defaults(self, from_analysis_id: str | None = None) -> dict[str, Any]:
        global_settings = self.settings_store.get()
        if from_analysis_id:
            running, completed = self.jobs.lookup(from_analysis_id)
            if running:
                return running.configuration.to_public_dict()
            if completed:
                repository = self.repositories.get(completed.database_path)
                stored = repository.get_analysis(completed.analysis_id)
            elif from_analysis_id.startswith("pending-"):
                stored = None
            else:
                stored = self.repositories.get().get_analysis(from_analysis_id)
            if stored:
                return stored_configuration(stored)
        return self.configuration.resolve(
            taxonomy_path=global_settings.default_taxonomy_path,
            values={},
        ).to_public_dict()

    def get_analysis(self, analysis_id: str) -> dict[str, Any] | None:
        running, completed = self.jobs.lookup(analysis_id)
        if running:
            return running.snapshot()
        if completed:
            repository = self.repositories.get(completed.database_path)
            stored_id = completed.analysis_id
        elif analysis_id.startswith("pending-"):
            return None
        else:
            repository = self.repositories.get()
            stored_id = analysis_id
        stored = repository.get_analysis(stored_id)
        if stored is None:
            return None
        payload = stored_payload(repository, stored)
        warning = completed.warning if completed else self.jobs.progress_warning(analysis_id)
        if warning:
            payload["events"].append(dict(warning))
        return payload

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
        return self.jobs.submit(cve_id, configuration)
