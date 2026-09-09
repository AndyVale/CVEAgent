from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Callable, Protocol, Self

from cve_agent.core.history import HistorySearch
from cve_agent.core.history import AnalysisSummary, StoredAnalysis
from cve_agent.core.investigation import InvestigationState
from cve_agent.core.results import ClassificationResult
from cve_agent.core.sources import CVERecord, Document, SearchResult
from cve_agent.core.taxonomy import Taxonomy


class CVESource(Protocol):
    def get_cve(self, cve_id: str) -> CVERecord: ...


class WebSource(Protocol):
    def search(self, query: str) -> list[SearchResult]: ...
    def fetch(self, url: str) -> Document: ...


class Classifier(Protocol):
    def classify(self, cve: CVERecord, taxonomy: Taxonomy, state: InvestigationState, checkpoint: Callable[[], None] | None = None) -> ClassificationResult: ...


class AnalysisWriter(Protocol):
    """Transactional lifecycle operations used by the pipeline."""

    def __enter__(self) -> Self: ...
    def __exit__(self, *args: object) -> None: ...
    def start_run(self, *, taxonomy: Taxonomy, model: str, settings: dict[str, Any]) -> int: ...
    def finish_run(self, run_id: int, status: str) -> None: ...
    def save_investigation(
        self, run_id: int, input_position: int, cve_id: str, status: str,
        state: InvestigationState, result: ClassificationResult | None = None,
        error: str | None = None,
    ) -> None: ...


class ResultLookup(Protocol):
    """Query persisted results by immutable snapshots and explicit status eligibility."""

    def find_result(
        self, *, cve_id: str, taxonomy_fingerprint: str,
        settings_fingerprint_value: str, accepted_statuses: tuple[str, ...],
    ) -> StoredAnalysis | None: ...


class AnalysisHistory(ResultLookup, Protocol):
    """History and progress operations used by the graphical application."""

    def initialize(self) -> None: ...
    def list_analyses(self, *, limit: int = 200, offset: int = 0, search: HistorySearch | None = None) -> list[AnalysisSummary]: ...
    def get_analysis(self, analysis_id: str) -> StoredAnalysis | None: ...
    def save_events(self, analysis_id: str, events: Iterable[dict[str, Any]]) -> None: ...
    def get_events(self, analysis_id: str, *, after_sequence: int = -1) -> list[dict[str, Any]]: ...
