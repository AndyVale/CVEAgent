from __future__ import annotations

from dataclasses import asdict
from typing import Any

from cve_agent.models import (
    EvidenceRecord,
    EvidenceTrace,
    FetchTrace,
    InvestigationState,
    LabelClassification,
    LabelEvidenceTrace,
    Passage,
    SourceAssociation,
    SourceTrace,
)
from cve_agent.provenance import canonical_cve_id
from cve_agent.taxonomy import Taxonomy


def record_label_links(
    labels: list[LabelClassification],
    state: InvestigationState,
    taxonomy: Taxonomy,
) -> None:
    """Snapshot final label definitions and their canonical evidence associations."""
    links: list[LabelEvidenceTrace] = []
    for label in labels:
        definition = taxonomy.by_id[label.label]
        evidence = tuple(
            {"evidence_id": item.evidence_id, "explanation": item.explanation}
            for item in label.evidence
            if item.evidence_id
        )
        ancestors: list[dict[str, str]] = []
        parent_id = definition.parent
        while parent_id:
            parent = taxonomy.by_id[parent_id]
            ancestors.append({
                "id": parent.id,
                "name": parent.name,
                "description": parent.description,
            })
            parent_id = parent.parent
        links.append(LabelEvidenceTrace(
            label=label.label,
            name=definition.name,
            description=definition.description,
            confidence=label.confidence,
            evidence=evidence,
            ancestor_path=tuple(reversed(ancestors)),
        ))
    state.provenance.label_links = links


def build_public_provenance(
    labels: list[LabelClassification],
    state: InvestigationState,
) -> dict[str, Any]:
    """Materialize only trace paths reachable from returned label evidence."""
    evidence_records = {item.evidence_id: item for item in state.evidence}
    relevant_ids = {
        item.evidence_id
        for label in labels
        for item in label.evidence
        if item.evidence_id
    }
    if not relevant_ids:
        return {
            "format_version": 2,
            "labels": [asdict(item) for item in state.provenance.label_links],
            "sources": [],
            "evidence": [],
        }

    trace_by_evidence = {item.evidence_id: item for item in state.provenance.evidence}
    source_by_id = {item.source_id: item for item in state.provenance.sources}
    candidates = {item.candidate_id: item for item in state.provenance.candidates}
    fetches_by_source: dict[str, list[FetchTrace]] = {}
    for fetch in state.provenance.fetches:
        if fetch.source_id:
            fetches_by_source.setdefault(fetch.source_id, []).append(fetch)
    public_evidence: list[dict[str, Any]] = []
    relevant_source_ids: list[str] = []

    for evidence_id in sorted(relevant_ids):
        record = evidence_records.get(evidence_id)
        trace = trace_by_evidence.get(evidence_id)
        if record is None:
            continue
        if trace is None:
            source_id = f"source:untraced:{evidence_id}"
            trace = EvidenceTrace(evidence_id, source_id, evidence_id, record.verification)
            if source_id not in source_by_id:
                source_by_id[source_id] = _untraced_source(
                    record,
                    source_id,
                    state.provenance.target_cve_id,
                )
        if trace.source_id not in relevant_source_ids:
            relevant_source_ids.append(trace.source_id)
        source = source_by_id[trace.source_id]
        passage_by_id = {item.passage_id: item.text for item in source.passages}
        public_evidence.append({
            "evidence_id": evidence_id,
            "source_id": trace.source_id,
            "selection_method": trace.selection_method,
            "selection_event_id": trace.selection_event_id,
            "context": {
                "before": _context_passage(trace.previous_passage_id, passage_by_id),
                "after": _context_passage(trace.next_passage_id, passage_by_id),
            },
            "findings": [
                {
                    "finding_id": f"finding-{position}",
                    "aspect": finding.aspect.value,
                    "statement": finding.statement,
                }
                for position, finding in enumerate(state.findings, start=1)
                if evidence_id in finding.evidence_ids
            ],
        })

    public_sources: list[dict[str, Any]] = []
    for source_id in relevant_source_ids:
        source = source_by_id[source_id]
        public_sources.append({
            "source_id": source.source_id,
            "title": source.title,
            "requested_url": source.requested_url,
            "resolved_url": source.resolved_url,
            "redirect_chain": list(source.redirect_chain),
            "origins": [
                asdict(candidates[candidate_id])
                for candidate_id in source.candidate_ids
                if candidate_id in candidates
            ],
            "fetches": [asdict(item) for item in fetches_by_source.get(source.source_id, [])],
            "retrieval": asdict(source.retrieval) if source.retrieval else None,
            "cve_association": asdict(source.association),
        })
    return {
        "format_version": 2,
        "labels": [asdict(item) for item in state.provenance.label_links],
        "sources": public_sources,
        "evidence": public_evidence,
    }


def _untraced_source(record: EvidenceRecord, source_id: str, cve_id: str) -> SourceTrace:
    return SourceTrace(
        source_id=source_id,
        document_id=source_id.removeprefix("source:"),
        title="",
        requested_url=record.requested_url or record.url,
        resolved_url=record.url,
        redirect_chain=(),
        candidate_ids=(),
        association=SourceAssociation(
            "unverified",
            canonical_cve_id(cve_id),
            warnings=("provenance_trace_unavailable",),
        ),
        passages=(Passage(record.evidence_id, record.quote),),
    )


def _context_passage(
    passage_id: str | None,
    passage_by_id: dict[str, str],
) -> dict[str, str] | None:
    if not passage_id or passage_id not in passage_by_id:
        return None
    return {"passage_id": passage_id, "text": passage_by_id[passage_id]}
