from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import logging

import httpx

from cve_agent.application.coordinator import ClassificationCoordinator
from cve_agent.application.pipeline import Pipeline
from cve_agent.application.service import ClassificationApplication
from cve_agent.cache.disk import JsonDiskCache
from cve_agent.cache.web import CachedWebClient
from cve_agent.core.config import Settings, non_secret_settings
from cve_agent.core.ports import AnalysisHistory, AnalysisWriter, CVESource, Classifier, WebSource
from cve_agent.core.sources import SearchResult
from cve_agent.integrations.nvd import NVDClient
from cve_agent.integrations.tavily import TavilySearchProvider
from cve_agent.integrations.web import WebClient
from cve_agent.integrations.web_policy import PublicWebUrlPolicy
from cve_agent.persistence.repository import AnalysisRepository
from cve_agent.persistence.writer import Database


logger = logging.getLogger("cve_agent.application")


def create_application(
    settings: Settings,
    *,
    cve_source: CVESource | None = None,
    web_source: WebSource | None = None,
    classifier: Classifier | None = None,
    database: AnalysisWriter | None = None,
) -> ClassificationApplication:
    """Compose default adapters while retaining injectable boundaries for other UIs."""
    close_resources = None
    active_classifier = classifier
    if active_classifier is None:
        active_web_source = web_source or create_web_source(settings)
        if web_source is None:
            close_resources = active_web_source.close
        active_classifier = ClassificationCoordinator(settings, active_web_source)
    pipeline = Pipeline(
        cve_source or NVDClient(settings),
        active_classifier,
        database or Database(settings.database),
        run_metadata={"model": settings.model, "settings": non_secret_settings(settings)},
    )
    return ClassificationApplication(pipeline, close_resources=close_resources)


def create_web_source(
    settings: Settings, *, searcher: Callable[[str], list[SearchResult]] | None = None,
    http_client: httpx.Client | None = None, url_policy: PublicWebUrlPolicy | None = None,
) -> CachedWebClient:
    """Compose provider retrieval and caching; optional adapters support offline tests."""
    policy = url_policy or PublicWebUrlPolicy()
    provider = None
    active_searcher = searcher
    if active_searcher is None and settings.web_provider == "tavily":
        provider = TavilySearchProvider(settings)
        active_searcher = provider.search
    source = WebClient(settings, searcher=active_searcher, http_client=http_client, url_policy=policy)

    def close() -> None:
        first_failure: BaseException | None = None
        try:
            source.close()
        except BaseException as exc:
            first_failure = exc
        if provider is not None:
            try:
                provider.close()
            except BaseException as exc:
                if first_failure is None:
                    first_failure = exc
                else:
                    logger.error(
                        "secondary HTTP cleanup failure preserved separately "
                        "primary_type=%s cleanup_type=%s",
                        type(first_failure).__name__,
                        type(exc).__name__,
                    )
        if first_failure is not None:
            raise first_failure

    return CachedWebClient(source, JsonDiskCache(settings.cache_dir), policy, close=close)


def create_history_repository(path: Path) -> AnalysisHistory:
    """Construct the shared SQLite history adapter without opening it yet."""
    return AnalysisRepository(path)
