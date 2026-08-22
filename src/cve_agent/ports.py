from __future__ import annotations

from typing import Protocol

from cve_agent.models import CVERecord, ClassificationResult, Document, InvestigationState, SearchResult
from cve_agent.taxonomy import Taxonomy


class CVESource(Protocol):
    def get_cve(self, cve_id: str) -> CVERecord: ...


class WebSource(Protocol):
    def search(self, query: str) -> list[SearchResult]: ...
    def fetch(self, url: str) -> Document: ...


class Classifier(Protocol):
    def classify(self, cve: CVERecord, taxonomy: Taxonomy, state: InvestigationState) -> ClassificationResult: ...
