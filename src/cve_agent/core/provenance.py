from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cve_agent.core.sources import Passage


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
