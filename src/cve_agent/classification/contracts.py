from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from cve_agent.core.investigation import InvestigationState, InvestigationStopReason
from cve_agent.core.results import LabelClassification
from cve_agent.core.sources import CVERecord
from cve_agent.core.taxonomy import Taxonomy
from cve_agent.runtime.budget import TokenBudget


@dataclass(frozen=True)
class TaxonomyScanOutcome:
    candidates: tuple[LabelClassification, ...]
    evaluated_ids: tuple[str, ...]
    pruned_ids: tuple[str, ...] = ()
    unresolved_ids: tuple[str, ...] = ()
    classification_requests: int = 0
    routing_levels: int = 0
    pruned_branches: tuple[dict[str, Any], ...] = ()
    cost_switches: int = 0
    stop_reason: InvestigationStopReason | None = None
    error: str | None = None

    @property
    def complete(self) -> bool:
        return not self.unresolved_ids


class ClassificationScanner(Protocol):
    """Shared interface for exhaustive and adaptive taxonomy scanners."""

    def scan(
        self,
        cve: CVERecord,
        taxonomy: Taxonomy,
        state: InvestigationState,
        budget: TokenBudget,
        checkpoint: Callable[[], None],
    ) -> TaxonomyScanOutcome: ...
