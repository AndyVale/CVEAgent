from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cve_agent.core.config import settings_fingerprint
from cve_agent.core.taxonomy import Taxonomy


@dataclass(frozen=True)
class HistorySearch:
    """Explicit history criteria; add future metadata filters here independently of the UI."""

    cve_query: str = ""


@dataclass(frozen=True)
class AnalysisSummary:
    run_id: int
    input_position: int
    cve_id: str
    status: str
    started_at: str
    completed_at: str | None
    updated_at: str
    taxonomy_fingerprint: str
    settings_fingerprint: str
    model: str
    run_status: str
    label_ids: tuple[str, ...]
    error: str | None
    taxonomy_path: str | None
    taxonomy_name: str
    taxonomy_labels: int
    hierarchy_policy: str

    @property
    def analysis_id(self) -> str:
        return f"{self.run_id}:{self.input_position}"


@dataclass(frozen=True)
class StoredAnalysis(AnalysisSummary):
    settings: dict[str, Any]
    taxonomy: Taxonomy
    scratchpad: dict[str, Any]
    result: dict[str, Any] | None
    internal_provenance: dict[str, Any]


def parse_analysis_id(value: str) -> tuple[int, int]:
    try:
        run_id, input_position = value.split(":", 1)
        parsed = int(run_id), int(input_position)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid analysis ID: {value!r}") from exc
    if min(parsed) < 0 or max(parsed) > 2**63 - 1:
        raise ValueError(f"invalid analysis ID: {value!r}")
    return parsed
