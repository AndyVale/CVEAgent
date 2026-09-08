from __future__ import annotations

from dataclasses import dataclass, field
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
