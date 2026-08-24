from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cve_agent.evidence import build_passages, passage_id_candidates
from cve_agent.models import MAX_INVESTIGATION_FINDINGS, Document, EvidenceRecord, InvestigationAspect, InvestigationFinding, InvestigationState, Passage


_CORE_ASPECTS = {InvestigationAspect.ROOT_CAUSE, InvestigationAspect.EXPLOITATION_MECHANISM}
_ASPECT_ALIASES = {
    "affected_software": InvestigationAspect.AFFECTED_SYSTEM,
    "affected_component": InvestigationAspect.AFFECTED_SYSTEM,
    "attacker_input": InvestigationAspect.EXPLOITATION_MECHANISM,
    "security_primitive": InvestigationAspect.EXPLOITATION_MECHANISM,
    "attack_vector": InvestigationAspect.PRECONDITIONS,
    "privileges_required": InvestigationAspect.PRECONDITIONS,
    "user_interaction": InvestigationAspect.PRECONDITIONS,
    "scope": InvestigationAspect.IMPACT,
}


@dataclass(frozen=True)
class InvestigationProfile:
    information_status: str
    summary: str
    findings: tuple[InvestigationFinding, ...]
    discarded_findings: int = 0
    promoted_evidence: int = 0


def build_investigation_profile(
    arguments: dict[str, Any],
    state: InvestigationState,
    documents: dict[str, Document],
    *,
    max_preview_chars: int,
) -> InvestigationProfile:
    """Normalize a tolerant model finish call into an evidence-backed profile."""
    evidence_by_id = {item.evidence_id: item for item in state.evidence}
    passages, passage_documents = _available_passages(documents, max_preview_chars)
    raw_findings = arguments.get("findings")
    if not isinstance(raw_findings, list):
        raw_findings = []

    materialized: dict[tuple[InvestigationAspect, str], InvestigationFinding] = {}
    discarded = max(0, len(raw_findings) - MAX_INVESTIGATION_FINDINGS)
    promoted = 0
    for raw in raw_findings[:MAX_INVESTIGATION_FINDINGS]:
        if not isinstance(raw, dict):
            discarded += 1
            continue
        aspect = _normalize_aspect(raw.get("aspect"))
        statement = raw.get("statement")
        if aspect is None or not isinstance(statement, str) or not statement.strip():
            discarded += 1
            continue

        evidence_ids: list[str] = []
        references = raw.get("evidence_ids", [])
        if isinstance(references, str):
            references = [references]
        if not isinstance(references, list):
            references = []
        for reference in references:
            if not isinstance(reference, str) or not reference.strip():
                continue
            evidence_id, was_promoted = _materialize_reference(
                reference,
                passages,
                passage_documents,
                evidence_by_id,
                state,
            )
            if evidence_id and evidence_id not in evidence_ids:
                evidence_ids.append(evidence_id)
                promoted += int(was_promoted)
        if not evidence_ids:
            discarded += 1
            continue

        clean_statement = " ".join(statement.split())
        key = (aspect, clean_statement.casefold())
        previous = materialized.get(key)
        if previous:
            evidence_ids = list(dict.fromkeys((*previous.evidence_ids, *evidence_ids)))
        materialized[key] = InvestigationFinding(aspect, clean_statement, tuple(evidence_ids))

    findings = tuple(materialized.values())
    status = "sufficient" if any(item.aspect in _CORE_ASPECTS for item in findings) else "insufficient"
    summary = arguments.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        summary = " ".join(item.statement for item in findings) or "No evidence-backed vulnerability mechanism was established."
    return InvestigationProfile(status, " ".join(summary.split()), findings, discarded, promoted)


def _normalize_aspect(value: Any) -> InvestigationAspect | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().casefold().replace("-", "_").replace(" ", "_")
    try:
        return InvestigationAspect(normalized)
    except ValueError:
        return _ASPECT_ALIASES.get(normalized)


def _available_passages(
    documents: dict[str, Document],
    max_preview_chars: int,
) -> tuple[tuple[Passage, ...], dict[str, Document]]:
    passages: list[Passage] = []
    passage_documents: dict[str, Document] = {}
    for key, document in documents.items():
        document_id = document.document_id or key
        for passage in build_passages(document_id, document.content, max_chars=max_preview_chars):
            passages.append(passage)
            passage_documents[passage.passage_id] = document
    return tuple(passages), passage_documents


def _materialize_reference(
    reference: str,
    passages: tuple[Passage, ...],
    passage_documents: dict[str, Document],
    evidence_by_id: dict[str, EvidenceRecord],
    state: InvestigationState,
) -> tuple[str | None, bool]:
    normalized = reference.strip()
    if normalized in evidence_by_id:
        return normalized, False
    candidates = passage_id_candidates(passages, normalized)
    if len(candidates) != 1:
        return None, False

    passage = candidates[0]
    document = passage_documents[passage.passage_id]
    record = EvidenceRecord(
        passage.passage_id,
        document.url,
        passage.text,
        "web",
        document.requested_url or document.url,
        "finish_reference",
    )
    state.evidence.append(record)
    evidence_by_id[record.evidence_id] = record
    return record.evidence_id, True
