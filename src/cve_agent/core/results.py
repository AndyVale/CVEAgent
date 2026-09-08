from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


@dataclass(frozen=True)
class Evidence:
    url: str
    quote: str
    explanation: str
    evidence_id: str = ""


@dataclass(frozen=True)
class LabelClassification:
    label: str
    confidence: float
    evidence: tuple[Evidence, ...]


class ClassificationStatus(StrEnum):
    CLASSIFIED = "classified"
    NO_MATCHING_LABEL = "no_matching_label"
    NOT_ENOUGH_INFORMATION = "not_enough_information"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass
class ClassificationResult:
    cve_id: str
    status: ClassificationStatus
    labels: list[LabelClassification] = field(default_factory=list)
    error: str | None = None
    operational: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.status = ClassificationStatus(self.status)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
