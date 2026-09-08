from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from cve_agent.core.provenance import ResearchProvenance
from cve_agent.core.sources import EvidenceRecord


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
