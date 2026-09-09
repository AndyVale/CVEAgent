from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Protocol
import logging

from cve_agent.classification.evaluation import Benchmark, EvaluationReport, evaluate_results
from cve_agent.core.ports import AnalysisProgress
from cve_agent.core.results import ClassificationResult, ClassificationStatus
from cve_agent.core.taxonomy import Taxonomy


logger = logging.getLogger("cve_agent.application")


class PipelineRunner(Protocol):
    def run(
        self,
        cve_ids: list[str],
        taxonomy: Taxonomy,
        *,
        progress: AnalysisProgress | None = None,
    ) -> list[ClassificationResult]: ...


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

    def __init__(
        self,
        pipeline: PipelineRunner,
        *,
        close_resources: Callable[[], None] | Iterable[Callable[[], None]] | None = None,
    ):
        self.pipeline = pipeline
        if close_resources is None:
            self._close_resources: tuple[Callable[[], None], ...] = ()
        elif callable(close_resources):
            self._close_resources = (close_resources,)
        else:
            self._close_resources = tuple(close_resources)

    def run(
        self,
        cve_ids: list[str],
        taxonomy: Taxonomy,
        benchmark: Benchmark | None = None,
        *,
        progress: AnalysisProgress | None = None,
    ) -> ApplicationRun:
        primary_failure: BaseException | None = None
        try:
            if progress is None:
                results = tuple(self.pipeline.run(cve_ids, taxonomy))
            else:
                results = tuple(self.pipeline.run(cve_ids, taxonomy, progress=progress))
        except BaseException as exc:
            primary_failure = exc
            raise
        finally:
            self._close_after_run(primary_failure)
        report = evaluate_results(list(results), benchmark, taxonomy) if benchmark else None
        return ApplicationRun(results, report)

    def _close_after_run(self, primary_failure: BaseException | None) -> None:
        first_cleanup_failure: BaseException | None = None
        for close_resource in self._close_resources:
            try:
                close_resource()
            except BaseException as exc:
                if primary_failure is None and first_cleanup_failure is None:
                    first_cleanup_failure = exc
                    continue
                logger.error(
                    "secondary resource cleanup failure preserved separately "
                    "primary_type=%s cleanup_type=%s",
                    type(primary_failure or first_cleanup_failure).__name__,
                    type(exc).__name__,
                )
        if primary_failure is None and first_cleanup_failure is not None:
            raise first_cleanup_failure
