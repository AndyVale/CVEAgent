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
    evidence_id: str = ""


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
    CLASSIFICATION_ERROR = "classification_error"


class InvestigationAspect(StrEnum):
    AFFECTED_SYSTEM = "affected_system"
    ROOT_CAUSE = "root_cause"
    EXPLOITATION_MECHANISM = "exploitation_mechanism"
    PRECONDITIONS = "preconditions"
    IMPACT = "impact"


MAX_INVESTIGATION_FINDINGS = 10


@dataclass(frozen=True)
class InvestigationFinding:
    aspect: InvestigationAspect
    statement: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class ProvenanceEvent:
    event_id: str
    action: str
    status: str
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass(frozen=True)
class ProvenanceSearch:
    search_id: str
    query: str
    status: str
    candidate_ids: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class SourceCandidate:
    candidate_id: str
    kind: str
    url: str
    title: str = ""
    snippet: str = ""
    query: str = ""
    search_id: str | None = None
    rank: int | None = None
    source: str | None = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class FetchTrace:
    fetch_id: str
    status: str
    requested_url: str
    candidate_ids: tuple[str, ...] = ()
    document_id: str | None = None
    source_id: str | None = None
    resolved_url: str | None = None
    redirect_chain: tuple[str, ...] = ()
    reused: bool = False
    error: str | None = None


@dataclass(frozen=True)
class SourceAssociation:
    status: str
    target_cve_id: str
    target_mentions: tuple[str, ...] = ()
    other_cve_ids: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class RetrievalTrace:
    extraction_method: str = "unknown"
    extraction_input_chars: int | None = None
    extraction_output_chars: int | None = None
    truncated: bool | None = None
    download_bytes: int | None = None
    content_type: str | None = None


@dataclass(frozen=True)
class SourceTrace:
    source_id: str
    document_id: str
    title: str
    requested_url: str
    resolved_url: str
    redirect_chain: tuple[str, ...]
    candidate_ids: tuple[str, ...]
    association: SourceAssociation
    passages: tuple[Passage, ...] = ()
    retrieval: RetrievalTrace | None = None


@dataclass(frozen=True)
class EvidenceTrace:
    evidence_id: str
    source_id: str
    passage_id: str
    selection_method: str
    selection_event_id: str | None = None
    previous_passage_id: str | None = None
    next_passage_id: str | None = None


@dataclass(frozen=True)
class LabelEvidenceTrace:
    label: str
    name: str
    description: str
    confidence: float
    evidence: tuple[dict[str, str], ...]
    ancestor_path: tuple[dict[str, str], ...] = ()


@dataclass
class ResearchProvenance:
    format_version: int = 2
    target_cve_id: str = ""
    nvd_metadata: dict[str, Any] = field(default_factory=dict)
    nvd_reference_count: int = 0
    omitted_nvd_references: int = 0
    events: list[ProvenanceEvent] = field(default_factory=list)
    searches: list[ProvenanceSearch] = field(default_factory=list)
    candidates: list[SourceCandidate] = field(default_factory=list)
    fetches: list[FetchTrace] = field(default_factory=list)
    sources: list[SourceTrace] = field(default_factory=list)
    evidence: list[EvidenceTrace] = field(default_factory=list)
    label_links: list[LabelEvidenceTrace] = field(default_factory=list)


@dataclass
class ClassificationResult:
    cve_id: str
    status: ClassificationStatus
    labels: list[LabelClassification] = field(default_factory=list)
    error: str | None = None
    operational: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.status = ClassificationStatus(self.status)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationState:
    facts: list[str] = field(default_factory=list)
    findings: list[InvestigationFinding] = field(default_factory=list)
    research_summary: str = ""
    research_information_status: str = ""
    visited_urls: list[str] = field(default_factory=list)
    evidence: list[EvidenceRecord] = field(default_factory=list)
    tool_history: list[dict[str, Any]] = field(default_factory=list)
    token_usage: dict[str, Any] = field(default_factory=dict)
    provenance: ResearchProvenance = field(default_factory=ResearchProvenance)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
