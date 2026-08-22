from __future__ import annotations

from typing import Any

from cve_agent.models import ClassificationStatus, Evidence, EvidenceRecord, LabelClassification
from cve_agent.taxonomy import Taxonomy


def validate_classification(
    status_value: Any,
    raw_labels: Any,
    taxonomy: Taxonomy,
    evidence_records: list[EvidenceRecord],
) -> tuple[ClassificationStatus, list[LabelClassification]]:
    """Parse and validate the single canonical classification contract."""
    try:
        status = ClassificationStatus(status_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid classification status: {status_value!r}") from exc
    if status not in {
        ClassificationStatus.CLASSIFIED,
        ClassificationStatus.NO_MATCHING_LABEL,
        ClassificationStatus.NOT_ENOUGH_INFORMATION,
    }:
        raise ValueError(f"status {status.value!r} is not a complete classification outcome")
    if not isinstance(raw_labels, list):
        raise ValueError("labels must be an array")

    evidence_by_id = {record.evidence_id: record for record in evidence_records}
    labels: list[LabelClassification] = []
    seen_labels: set[str] = set()
    for raw_label in raw_labels:
        if not isinstance(raw_label, dict):
            raise ValueError("each label must be an object")
        label_id = raw_label.get("label")
        if label_id not in taxonomy.by_id:
            raise ValueError(f"classifier returned label outside taxonomy: {label_id!r}")
        if label_id in seen_labels:
            raise ValueError(f"classifier returned duplicate label: {label_id!r}")
        seen_labels.add(label_id)
        try:
            confidence = float(raw_label.get("confidence"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid confidence for {label_id!r}") from exc
        if not 0 <= confidence <= 1:
            raise ValueError(f"confidence for {label_id!r} must be in [0, 1]")
        raw_evidence = raw_label.get("evidence")
        if not isinstance(raw_evidence, list) or not raw_evidence:
            raise ValueError(f"label {label_id!r} requires supporting evidence")
        materialized: list[Evidence] = []
        seen_evidence: set[str] = set()
        for association in raw_evidence:
            if not isinstance(association, dict):
                raise ValueError("each evidence association must be an object")
            evidence_id = association.get("evidence_id")
            explanation = association.get("explanation")
            if evidence_id not in evidence_by_id:
                raise ValueError(f"unknown evidence_id: {evidence_id!r}")
            if evidence_id in seen_evidence:
                raise ValueError(f"duplicate evidence_id for {label_id!r}: {evidence_id!r}")
            if not isinstance(explanation, str) or not explanation.strip():
                raise ValueError("evidence explanation must be a non-empty string")
            seen_evidence.add(evidence_id)
            record = evidence_by_id[evidence_id]
            materialized.append(Evidence(record.url, record.quote, explanation.strip()))
        labels.append(LabelClassification(label_id, confidence, tuple(materialized)))

    if status == ClassificationStatus.CLASSIFIED and not labels:
        raise ValueError("classified results must contain at least one label")
    if status != ClassificationStatus.CLASSIFIED and labels:
        raise ValueError(f"{status.value} results cannot contain labels")
    return status, labels
