from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cve_agent.core.sources import Document
from cve_agent.investigation.provenance import ResearchProvenanceRecorder


@dataclass
class ResearchSession:
    documents: dict[str, Document] = field(default_factory=dict)
    searches: int = 0
    fetches: int = 0
    turns: int = 0
    seen_calls: set[tuple[str, str]] = field(default_factory=set)
    redisplayed_documents: set[str] = field(default_factory=set)
    exchange: list[dict[str, Any]] = field(default_factory=list)
    provenance: ResearchProvenanceRecorder | None = None
    finish_corrections: int = 0
    pending_finish_arguments: dict[str, Any] | None = None
    pending_finish_documents: dict[str, Document] | None = None
