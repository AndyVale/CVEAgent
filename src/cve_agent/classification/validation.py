from __future__ import annotations

from typing import Any
import logging

from cve_agent.core.results import ClassificationStatus, Evidence, LabelClassification
from cve_agent.core.sources import EvidenceRecord
from cve_agent.core.taxonomy import Taxonomy


logger = logging.getLogger("cve_agent.validation")

_QUALITATIVE_CONFIDENCE = {
    "low": 0.35,
    "medium": 0.60,
    "high": 0.85,
}


def normalize_classification_labels(raw_labels: Any) -> list[dict[str, Any]]:
    """Normalize narrow, deterministic provider deviations in label payloads."""
    if not isinstance(raw_labels, list):
        raise ValueError("labels must be an array")

    normalized_labels: list[dict[str, Any]] = []
    for raw_label in raw_labels:
        if not isinstance(raw_label, dict):
            raise ValueError("each label must be an object")
        label_id = raw_label.get("label")
        confidence_value = raw_label.get("confidence")
        try:
            confidence = _normalize_confidence(confidence_value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid confidence for {label_id!r}") from exc
        if confidence != confidence_value:
            logger.warning(
                "normalized model confidence for label %r from %r to %.2f",
                label_id,
                confidence_value,
                confidence,
            )
        normalized_labels.append({**raw_label, "confidence": confidence})
    return normalized_labels


def _normalize_confidence(value: Any) -> float:
    if isinstance(value, bool):
        raise TypeError("boolean confidence is invalid")
    if isinstance(value, str):
        stripped = value.strip()
        qualitative = " ".join(stripped.casefold().replace("-", " ").replace("_", " ").split())
        if qualitative in _QUALITATIVE_CONFIDENCE:
            return _QUALITATIVE_CONFIDENCE[qualitative]
        if stripped.endswith("%"):
            return float(stripped[:-1].strip()) / 100
        value = stripped
    return float(value)


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
    normalized_labels = normalize_classification_labels(raw_labels)

    evidence_by_id = {record.evidence_id: record for record in evidence_records}
    labels: list[LabelClassification] = []
    seen_labels: set[str] = set()
    for raw_label in normalized_labels:
        label_id = raw_label.get("label")
        if label_id not in taxonomy.by_id:
            raise ValueError(f"classifier returned label outside taxonomy: {label_id!r}")
        if label_id in seen_labels:
            raise ValueError(f"classifier returned duplicate label: {label_id!r}")
        seen_labels.add(label_id)
        confidence = raw_label["confidence"]
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
            materialized.append(Evidence(
                record.url,
                record.quote,
                explanation.strip(),
                evidence_id=record.evidence_id,
            ))
        labels.append(LabelClassification(label_id, confidence, tuple(materialized)))

    if status == ClassificationStatus.CLASSIFIED and not labels:
        raise ValueError("classified results must contain at least one label")
    if status != ClassificationStatus.CLASSIFIED and labels:
        raise ValueError(f"{status.value} results cannot contain labels")
    return status, labels
