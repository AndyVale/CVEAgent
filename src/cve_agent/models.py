from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


@dataclass(frozen=True)
class Reference:
    url: str
    source: str | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class CVERecord:
    cve_id: str
    description: str
    references: tuple[Reference, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SearchResult:
    title: str
    url: str
    snippet: str = ""


@dataclass(frozen=True)
class Document:
    url: str
    title: str = ""
    content: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Evidence:
    url: str
    quote: str
    explanation: str


@dataclass(frozen=True)
class LabelClassification:
    label: str
    confidence: float
    evidence: tuple[Evidence, ...]


Status = Literal["classified", "not_enough_information", "failed"]


@dataclass
class ClassificationResult:
    cve_id: str
    status: Status
    labels: list[LabelClassification] = field(default_factory=list)
    error: str | None = None
    operational: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationState:
    facts: list[str] = field(default_factory=list)
    visited_urls: list[str] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    candidate_labels: list[str] = field(default_factory=list)
    unresolved_questions: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    token_usage: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
