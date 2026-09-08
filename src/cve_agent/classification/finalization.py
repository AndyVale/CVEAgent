from __future__ import annotations

from collections import Counter
from typing import Any, Callable
import logging
import time

from cve_agent.classification.contracts import TaxonomyScanOutcome
from cve_agent.classification.planning import ClassificationPlan
from cve_agent.classification.provenance import build_public_provenance, record_label_links
from cve_agent.classification.taxonomy import apply_hierarchy_policy
from cve_agent.core.config import Settings
from cve_agent.core.investigation import InvestigationState
from cve_agent.core.research import ResearchOutcome
from cve_agent.core.results import ClassificationResult, ClassificationStatus
from cve_agent.core.sources import CVERecord
from cve_agent.core.taxonomy import Taxonomy
from cve_agent.runtime.budget import TokenBudget
from cve_agent.runtime.diagnostics import LogTone, log_extra


logger = logging.getLogger("cve_agent.agent")


def finalize_result(
    settings: Settings, classification_plan: ClassificationPlan, cve: CVERecord,
    taxonomy: Taxonomy, state: InvestigationState, budget: TokenBudget,
    research: ResearchOutcome, scan: TaxonomyScanOutcome, started: float,
    checkpoint_fn: Callable[[], None],
) -> ClassificationResult:
    coverage_complete = scan.complete and len(scan.evaluated_ids) + len(scan.pruned_ids) == len(taxonomy.labels)
    candidates = list(scan.candidates)
    if candidates and coverage_complete:
        status = ClassificationStatus.CLASSIFIED
        labels = apply_hierarchy_policy(candidates, taxonomy)
    elif candidates:
        status = ClassificationStatus.PARTIAL
        labels = apply_hierarchy_policy(candidates, taxonomy)
    elif coverage_complete:
        status = (
            ClassificationStatus.NO_MATCHING_LABEL
            if research.information_status == "sufficient"
            else ClassificationStatus.NOT_ENOUGH_INFORMATION
        )
        labels = []
    else:
        status, labels = ClassificationStatus.PARTIAL, []

    coverage = {
        "effective_strategy": classification_plan.effective_strategy.value,
        "total_labels": len(taxonomy.labels),
        "evaluated_labels": len(scan.evaluated_ids),
        "pruned_labels": len(scan.pruned_ids),
        "unresolved_labels": len(scan.unresolved_ids),
        "classification_requests": scan.classification_requests,
        "routing_levels": scan.routing_levels,
        "complete": coverage_complete,
    }
    if not research.complete or not coverage_complete or scan.stop_reason or budget.exhausted:
        status = ClassificationStatus.PARTIAL
    state.token_usage = budget.to_dict()
    operational: dict[str, Any] = {
        "turns": research.turns,
        "duration_seconds": round(time.monotonic() - started, 3),
        "token_usage": budget.to_dict(),
        "coverage": coverage,
        "classification": {
            "configured_strategy": settings.classification_strategy.value,
            "effective_strategy": classification_plan.effective_strategy.value,
            "pruning_confidence_threshold": settings.pruning_confidence_threshold,
            "cost_switches": scan.cost_switches,
            "pruned_branches": list(scan.pruned_branches),
        },
        "research_information_status": research.information_status,
        "research_profile": {
            "findings": len(research.findings),
            "discarded_findings": research.discarded_findings,
            "discarded_by_reason": dict(sorted(Counter(research.discarded_reasons).items())),
            "promoted_evidence": research.promoted_evidence,
        },
    }
    stop_reason = scan.stop_reason or research.stop_reason
    if stop_reason:
        operational["stop_reason"] = stop_reason
    if scan.error:
        operational["stop_detail"] = scan.error

    record_label_links(labels, state, taxonomy)
    provenance = build_public_provenance(labels, state)
    checkpoint_fn()

    logger.info(
        "[%s] agent finished status=%s labels=%d evaluated=%d pruned=%d unresolved=%d tokens=%d stop_reason=%s duration_seconds=%.3f",
        cve.cve_id,
        status.value,
        len(labels),
        len(scan.evaluated_ids),
        len(scan.pruned_ids),
        len(scan.unresolved_ids),
        budget.total_tokens,
        stop_reason.value if stop_reason else "none",
        time.monotonic() - started,
        extra=log_extra(
            LogTone.INCOMPLETE
            if status in {ClassificationStatus.PARTIAL, ClassificationStatus.NOT_ENOUGH_INFORMATION}
            else LogTone.SUCCESS
        ),
    )
    return ClassificationResult(
        cve.cve_id,
        status,
        labels,
        operational=operational,
        provenance=provenance,
    )
