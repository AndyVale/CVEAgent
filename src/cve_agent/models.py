from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


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
    document_id: str = ""
    requested_url: str = ""
    redirect_chain: tuple[str, ...] = ()


@dataclass(frozen=True)
class Passage:
    passage_id: str
    text: str


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    url: str
    quote: str
    source_type: str
    requested_url: str | None = None
    verification: str = "exact"


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


class ClassificationStatus(StrEnum):
    CLASSIFIED = "classified"
    NO_MATCHING_LABEL = "no_matching_label"
    NOT_ENOUGH_INFORMATION = "not_enough_information"
    PARTIAL = "partial"
    FAILED = "failed"


class InvestigationStopReason(StrEnum):
    INVESTIGATION_LIMIT = "investigation_limit"
    TOKEN_BUDGET = "token_budget"
    NO_FINISH_TOOL = "no_finish_tool"


@dataclass
class ClassificationResult:
    cve_id: str
    status: ClassificationStatus
    labels: list[LabelClassification] = field(default_factory=list)
    error: str | None = None
    operational: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.status = ClassificationStatus(self.status)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationState:
    facts: list[str] = field(default_factory=list)
    visited_urls: list[str] = field(default_factory=list)
    evidence: list[EvidenceRecord] = field(default_factory=list)
    tool_history: list[dict[str, Any]] = field(default_factory=list)
    token_usage: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
