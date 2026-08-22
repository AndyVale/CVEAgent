import pytest

from cve_agent.models import EvidenceRecord
from cve_agent.taxonomy import Taxonomy, TaxonomyLabel
from cve_agent.validation import validate_classification


TAXONOMY = Taxonomy((TaxonomyLabel("GENERIC", "Generic", "Generic taxonomy definition."),))
EVIDENCE = [EvidenceRecord("e-1", "https://source.test", "Exact source passage.", "web")]


def valid_label():
    return {"label": "GENERIC", "confidence": 0.8, "evidence": [{"evidence_id": "e-1", "explanation": "Exact support."}]}


def test_validator_rejects_duplicate_labels():
    with pytest.raises(ValueError, match="duplicate label"):
        validate_classification("classified", [valid_label(), valid_label()], TAXONOMY, EVIDENCE)


def test_validator_rejects_confidence_outside_range():
    label = valid_label()
    label["confidence"] = 1.5
    with pytest.raises(ValueError, match="must be in"):
        validate_classification("classified", [label], TAXONOMY, EVIDENCE)


@pytest.mark.parametrize(("reported", "expected"), [("low", 0.35), ("medium", 0.60), ("high", 0.85), ("85%", 0.85)])
def test_validator_normalizes_common_confidence_variants(reported, expected, caplog):
    label = valid_label()
    label["confidence"] = reported
    _, materialized = validate_classification("classified", [label], TAXONOMY, EVIDENCE)
    assert materialized[0].confidence == expected
    assert "normalized model confidence" in caplog.text


def test_validator_rejects_unknown_qualitative_confidence():
    label = valid_label()
    label["confidence"] = "very certain"
    with pytest.raises(ValueError, match="invalid confidence"):
        validate_classification("classified", [label], TAXONOMY, EVIDENCE)


def test_validator_rejects_unrecorded_evidence():
    label = valid_label()
    label["evidence"][0]["evidence_id"] = "fabricated"
    with pytest.raises(ValueError, match="unknown evidence_id"):
        validate_classification("classified", [label], TAXONOMY, EVIDENCE)
