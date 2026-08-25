from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from cve_agent.adapters import CachedWebClient, NVDClient, TavilySearchProvider
from cve_agent.agent import InvestigationAgent
from cve_agent.config import Settings, non_secret_settings
from cve_agent.evaluation import Benchmark, EvaluationReport, evaluate_results
from cve_agent.models import ClassificationResult, ClassificationStatus
from cve_agent.persistence import Database
from cve_agent.pipeline import Pipeline
from cve_agent.ports import CVESource, Classifier, WebSource
from cve_agent.taxonomy import Taxonomy


class PipelineRunner(Protocol):
    def run(self, cve_ids: list[str], taxonomy: Taxonomy) -> list[ClassificationResult]: ...


@dataclass(frozen=True)
class ApplicationRun:
    """UI-independent output from one classification invocation."""

    results: tuple[ClassificationResult, ...]
    evaluation: EvaluationReport | None = None

    @property
    def failed_count(self) -> int:
        return sum(result.status == ClassificationStatus.FAILED for result in self.results)

    @property
    def partial_count(self) -> int:
        return sum(result.status == ClassificationStatus.PARTIAL for result in self.results)

    @property
    def successful_count(self) -> int:
        return len(self.results) - self.failed_count - self.partial_count

    @property
    def complete(self) -> bool:
        return self.failed_count == 0 and self.partial_count == 0


class ClassificationApplication:
    """Run the core pipeline and optional evaluation without terminal concerns."""

    def __init__(self, pipeline: PipelineRunner):
        self.pipeline = pipeline

    def run(
        self,
        cve_ids: list[str],
        taxonomy: Taxonomy,
        benchmark: Benchmark | None = None,
    ) -> ApplicationRun:
        results = tuple(self.pipeline.run(cve_ids, taxonomy))
        report = evaluate_results(list(results), benchmark, taxonomy) if benchmark else None
        return ApplicationRun(results, report)


def create_application(
    settings: Settings,
    *,
    cve_source: CVESource | None = None,
    web_source: WebSource | None = None,
    classifier: Classifier | None = None,
    database: Database | None = None,
) -> ClassificationApplication:
    """Compose default adapters while retaining injectable boundaries for other UIs."""
    active_classifier = classifier
    if active_classifier is None:
        active_web_source = web_source or CachedWebClient(
            settings,
            searcher=TavilySearchProvider(settings).search if settings.web_provider == "tavily" else None,
        )
        active_classifier = InvestigationAgent(settings, active_web_source)
    pipeline = Pipeline(
        cve_source or NVDClient(settings),
        active_classifier,
        database or Database(settings.database),
        run_metadata={"model": settings.model, "settings": non_secret_settings(settings)},
    )
    return ClassificationApplication(pipeline)
