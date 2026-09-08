from __future__ import annotations

from cve_agent.core.investigation import MAX_INVESTIGATION_FINDINGS, InvestigationState
from cve_agent.core.sources import EvidenceRecord


def profile_evidence(state: InvestigationState) -> list[EvidenceRecord]:
    evidence_ids = {evidence_id for finding in state.findings for evidence_id in finding.evidence_ids}
    selected = [item for item in state.evidence if item.evidence_id in evidence_ids]
    if selected:
        return selected
    return _fallback_evidence(state.evidence)


def _fallback_evidence(evidence: list[EvidenceRecord]) -> list[EvidenceRecord]:
    """Preserve bounded raw evidence when research stops before producing findings."""
    if len(evidence) <= MAX_INVESTIGATION_FINDINGS:
        return list(evidence)
    nvd = next((item for item in evidence if item.source_type == "nvd_description"), None)
    remaining = [item for item in evidence if item is not nvd]
    selected = remaining[-(MAX_INVESTIGATION_FINDINGS - int(nvd is not None)):]
    return ([nvd] if nvd else []) + selected
