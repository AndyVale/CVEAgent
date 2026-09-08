from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cve_agent.core.investigation import (
    MAX_INVESTIGATION_FINDINGS,
    InvestigationAspect,
    InvestigationFinding,
    InvestigationState,
)
from cve_agent.core.sources import Document, EvidenceRecord, Passage
from cve_agent.investigation.evidence import (
    build_passages,
    passage_id_candidates,
    store_passage_evidence,
    unusable_evidence_reason,
)


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
    discarded_reasons: tuple[str, ...] = ()
    evidence_issues: tuple[EvidenceIssue, ...] = ()


@dataclass(frozen=True)
class EvidenceIssue:
    finding_index: int
    evidence_id: str
    reason: str


def build_investigation_profile(
    arguments: dict[str, Any],
    state: InvestigationState,
    documents: dict[str, Document],
    *,
    max_preview_chars: int,
    promote_evidence: bool = True,
) -> InvestigationProfile:
    """Normalize a tolerant model finish call into an evidence-backed profile."""
    evidence_by_id = {item.evidence_id: item for item in state.evidence}
    passages, passage_documents, complete_passage_ids = _available_passages(documents, max_preview_chars)
    raw_findings = arguments.get("findings")
    if not isinstance(raw_findings, list):
        raw_findings = []

    materialized: dict[tuple[InvestigationAspect, str], InvestigationFinding] = {}
    discarded = max(0, len(raw_findings) - MAX_INVESTIGATION_FINDINGS)
    discarded_reasons = ["finding_limit"] * discarded
    evidence_issues: list[EvidenceIssue] = []
    promoted_ids: set[str] = set()
    for finding_index, raw in enumerate(raw_findings[:MAX_INVESTIGATION_FINDINGS], start=1):
        if not isinstance(raw, dict):
            discarded += 1
            discarded_reasons.append("invalid_finding")
            continue
        aspect = _normalize_aspect(raw.get("aspect"))
        statement = raw.get("statement")
        if aspect is None or not isinstance(statement, str) or not statement.strip():
            discarded += 1
            discarded_reasons.append("invalid_finding")
            continue

        evidence_ids: list[str] = []
        references = raw.get("evidence_ids", [])
        if isinstance(references, str):
            references = [references]
        if not isinstance(references, list):
            references = []
        if not references:
            evidence_issues.append(EvidenceIssue(finding_index, "", "missing_evidence"))
        for reference in references:
            if not isinstance(reference, str) or not reference.strip():
                evidence_issues.append(EvidenceIssue(finding_index, "", "missing_evidence"))
                continue
            evidence_id, was_promoted, rejection = _resolve_reference(
                reference,
                passages,
                passage_documents,
                complete_passage_ids,
                evidence_by_id,
                state,
                promote_evidence=promote_evidence,
            )
            if rejection:
                evidence_issues.append(EvidenceIssue(finding_index, reference.strip(), rejection))
            if evidence_id and evidence_id not in evidence_ids:
                evidence_ids.append(evidence_id)
                if was_promoted:
                    promoted_ids.add(evidence_id)
        if not evidence_ids:
            discarded += 1
            discarded_reasons.append("no_usable_evidence")
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
    return InvestigationProfile(
        status,
        " ".join(summary.split()),
        findings,
        discarded,
        len(promoted_ids),
        tuple(discarded_reasons),
        tuple(evidence_issues),
    )


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
) -> tuple[tuple[Passage, ...], dict[str, Document], set[str]]:
    passages: list[Passage] = []
    passage_documents: dict[str, Document] = {}
    complete_passage_ids: set[str] = set()
    for key, document in documents.items():
        document_id = document.document_id or key
        document_passages = build_passages(document_id, document.content, max_chars=max_preview_chars)
        if len(document_passages) == 1:
            complete_passage_ids.add(document_passages[0].passage_id)
        for passage in document_passages:
            passages.append(passage)
            passage_documents[passage.passage_id] = document
    return tuple(passages), passage_documents, complete_passage_ids


def _resolve_reference(
    reference: str,
    passages: tuple[Passage, ...],
    passage_documents: dict[str, Document],
    complete_passage_ids: set[str],
    evidence_by_id: dict[str, EvidenceRecord],
    state: InvestigationState,
    *,
    promote_evidence: bool,
) -> tuple[str | None, bool, str | None]:
    normalized = reference.strip()
    if normalized in evidence_by_id:
        record = evidence_by_id[normalized]
        rejection = unusable_evidence_reason(
            record.quote,
            complete_source=record.source_type == "nvd_description" or normalized in complete_passage_ids,
        )
        return (None, False, rejection) if rejection else (normalized, False, None)
    candidates = passage_id_candidates(passages, normalized)
    if not candidates:
        return None, False, "unknown_evidence"
    if len(candidates) > 1:
        return None, False, "ambiguous_evidence"

    passage = candidates[0]
    rejection = unusable_evidence_reason(
        passage.text,
        complete_source=passage.passage_id in complete_passage_ids,
    )
    if rejection:
        return None, False, rejection
    if not promote_evidence:
        return passage.passage_id, True, None
    document = passage_documents[passage.passage_id]
    record, created = store_passage_evidence(
        state,
        document,
        passage,
        verification="finish_reference",
    )
    evidence_by_id[record.evidence_id] = record
    return record.evidence_id, created, None
