from __future__ import annotations

from dataclasses import dataclass

from cve_agent.core.investigation import InvestigationFinding, InvestigationStopReason


@dataclass(frozen=True)
class ResearchOutcome:
    information_status: str
    summary: str
    complete: bool
    turns: int
    duration_seconds: float
    stop_reason: InvestigationStopReason | None = None
    findings: tuple[InvestigationFinding, ...] = ()
    discarded_findings: int = 0
    promoted_evidence: int = 0
    discarded_reasons: tuple[str, ...] = ()
