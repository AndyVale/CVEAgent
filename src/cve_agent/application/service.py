from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from cve_agent.classification.evaluation import Benchmark, EvaluationReport, evaluate_results
from cve_agent.core.results import ClassificationResult, ClassificationStatus
from cve_agent.core.taxonomy import Taxonomy


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
