from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any, Callable

from cve_agent.budget import (
    BudgetExceeded,
    TokenBudget,
    estimate_exhaustive_tokens,
    estimate_routing_tokens,
    routing_input_tokens,
    taxonomy_input_tokens,
)
from cve_agent.classification import (
    TaxonomyTree,
    build_taxonomy_tree,
    chunk_labels,
    hierarchy_order,
    label_dict,
    normalize_label_references,
    routing_label_dict,
)
from cve_agent.config import Settings
from cve_agent.models import CVERecord, EvidenceRecord, InvestigationState, InvestigationStopReason, LabelClassification
from cve_agent.prompts import HIERARCHY_ROUTING_SYSTEM_PROMPT
from cve_agent.schemas import hierarchy_routing_response_format
from cve_agent.taxonomy import Taxonomy, TaxonomyLabel
from cve_agent.taxonomy_scan import ExhaustiveTaxonomyScanner, TaxonomyScanOutcome, decode_json_content, profile_evidence
from cve_agent.validation import validate_classification


logger = logging.getLogger(__name__)


class RoutingResponseError(ValueError):
    """A hierarchy-routing response remained invalid after correction."""


class RoutingDecisionState(StrEnum):
    SUPPORTED = "supported"
    UNCERTAIN = "uncertain"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class RoutingDecision:
    label: TaxonomyLabel
    state: RoutingDecisionState
    confidence: float
    explanation: str
    candidate: LabelClassification | None = None
    normalized_to_uncertain: bool = False


class HybridTaxonomyScanner:
    """Traverse a hierarchy conservatively and exhaustively resolve active subtrees when cheaper."""

    def __init__(self, settings: Settings, chat: Callable[..., Any]):
        self.settings = settings
        self.chat = chat
        self.request_count = 0

    def scan(
        self,
        cve: CVERecord,
        taxonomy: Taxonomy,
        state: InvestigationState,
        budget: TokenBudget,
        checkpoint: Callable[[], None],
    ) -> TaxonomyScanOutcome:
        tree = build_taxonomy_tree(taxonomy)
        ordered = hierarchy_order(taxonomy)
        evaluated: set[str] = set()
        pruned: set[str] = set()
        pending_uncertain: set[str] = set()
        candidates: dict[str, LabelClassification] = {}
        pruned_branches: list[dict[str, Any]] = []
        routing_levels = cost_switches = 0
        frontier = list(tree.roots)

        logger.info(
            "[%s] hierarchy scan started roots=%d labels=%d threshold=%.3f",
            cve.cve_id,
            len(frontier),
            len(taxonomy.labels),
            self.settings.pruning_confidence_threshold,
        )

        while frontier:
            level_id = routing_levels + 1
            level_decisions: list[RoutingDecision] = []
            render = lambda label: routing_label_dict(tree, label)
            chunks = chunk_labels(
                frontier,
                available_tokens=routing_input_tokens(self.settings),
                render=render,
            )
            logger.info(
                "[%s] hierarchy level started level=%d nodes=%d chunks=%d",
                cve.cve_id,
                level_id,
                len(frontier),
                len(chunks),
            )
            for chunk_position, chunk in enumerate(chunks, start=1):
                try:
                    decisions = self._route_chunk(cve, taxonomy, tree, level_id, chunk.labels, state, budget)
                except BudgetExceeded as exc:
                    self._checkpoint_error(
                        state,
                        budget,
                        checkpoint,
                        level_id,
                        tuple(label.id for label in chunk.labels),
                        str(exc),
                    )
                    return self._outcome(
                        taxonomy,
                        candidates,
                        evaluated,
                        pruned,
                        pending_uncertain,
                        pruned_branches,
                        routing_levels,
                        cost_switches,
                        InvestigationStopReason.TOKEN_BUDGET,
                        str(exc),
                    )
                except RoutingResponseError as exc:
                    self._checkpoint_error(
                        state,
                        budget,
                        checkpoint,
                        level_id,
                        tuple(label.id for label in chunk.labels),
                        str(exc),
                    )
                    return self._outcome(
                        taxonomy,
                        candidates,
                        evaluated,
                        pruned,
                        pending_uncertain,
                        pruned_branches,
                        routing_levels,
                        cost_switches,
                        InvestigationStopReason.CLASSIFICATION_ERROR,
                        str(exc),
                    )

                normalized_count = 0
                chunk_pruned = 0
                for decision in decisions:
                    evaluated.add(decision.label.id)
                    if decision.state == RoutingDecisionState.SUPPORTED:
                        if decision.candidate is None:
                            raise AssertionError("validated supported routing decision lacks a candidate")
                        candidates[decision.label.id] = decision.candidate
                        pending_uncertain.discard(decision.label.id)
                    elif decision.state == RoutingDecisionState.UNCERTAIN:
                        pending_uncertain.add(decision.label.id)
                    else:
                        descendants = {
                            item.id for item in tree.descendants(decision.label.id)
                            if item.id not in evaluated and item.id not in pruned
                        }
                        pruned.update(descendants)
                        pending_uncertain.difference_update(descendants)
                        chunk_pruned += len(descendants)
                        pruned_branches.append({
                            "label": decision.label.id,
                            "confidence": decision.confidence,
                            "pruned_descendants": len(descendants),
                            "explanation": decision.explanation[:500],
                        })
                    normalized_count += int(decision.normalized_to_uncertain)
                level_decisions.extend(decisions)
                state.tool_history.append({
                    "tool": "route_taxonomy_level",
                    "status": "success",
                    "level": level_id,
                    "chunk": chunk_position,
                    "label_count": len(chunk.labels),
                    "supported": sum(item.state == RoutingDecisionState.SUPPORTED for item in decisions),
                    "uncertain": sum(item.state == RoutingDecisionState.UNCERTAIN for item in decisions),
                    "unsupported": sum(item.state == RoutingDecisionState.UNSUPPORTED for item in decisions),
                    "normalized_to_uncertain": normalized_count,
                    "pruned_labels": chunk_pruned,
                    "decisions": [{
                        "label": item.label.id,
                        "decision": item.state.value,
                        "confidence": item.confidence,
                        "explanation": item.explanation[:500],
                        "normalized_to_uncertain": item.normalized_to_uncertain,
                    } for item in decisions],
                })
                state.token_usage = budget.to_dict()
                checkpoint()
                logger.info(
                    "[%s] hierarchy chunk accepted level=%d chunk=%d/%d supported=%s uncertain=%s unsupported=%s normalized=%d pruned=%d",
                    cve.cve_id,
                    level_id,
                    chunk_position,
                    len(chunks),
                    _decision_labels(decisions, RoutingDecisionState.SUPPORTED),
                    _decision_labels(decisions, RoutingDecisionState.UNCERTAIN),
                    _decision_labels(decisions, RoutingDecisionState.UNSUPPORTED),
                    normalized_count,
                    chunk_pruned,
                )

            routing_levels += 1
            next_frontier = [
                child
                for decision in level_decisions
                if decision.state in {RoutingDecisionState.SUPPORTED, RoutingDecisionState.UNCERTAIN}
                for child in tree.children[decision.label.id]
                if child.id not in pruned
            ]
            if not next_frontier:
                break

            active_labels = self._active_labels(ordered, tree, next_frontier, pending_uncertain, evaluated, pruned)
            exhaustive_cost = estimate_exhaustive_tokens(active_labels, self.settings)
            hybrid_cost = self._estimate_hybrid_continuation(next_frontier, pending_uncertain, tree)
            logger.info(
                "[%s] hierarchy continuation estimate level=%d active_labels=%d exhaustive_tokens=%d hybrid_tokens=%d",
                cve.cve_id,
                level_id,
                len(active_labels),
                exhaustive_cost,
                hybrid_cost,
            )
            if exhaustive_cost <= hybrid_cost:
                cost_switches += 1
                logger.info(
                    "[%s] hierarchy switching to exhaustive continuation level=%d active_labels=%d exhaustive_tokens=%d hybrid_tokens=%d",
                    cve.cve_id,
                    level_id,
                    len(active_labels),
                    exhaustive_cost,
                    hybrid_cost,
                )
                state.tool_history.append({
                    "tool": "switch_taxonomy_strategy",
                    "status": "success",
                    "from": "hybrid",
                    "to": "exhaustive",
                    "after_routing_level": level_id,
                    "active_labels": len(active_labels),
                    "estimated_exhaustive_tokens": exhaustive_cost,
                    "estimated_hybrid_tokens": hybrid_cost,
                })
                state.token_usage = budget.to_dict()
                checkpoint()
                fallback = self._exhaustive_subset(
                    cve,
                    taxonomy,
                    active_labels,
                    state,
                    budget,
                    checkpoint,
                    "hybrid_exhaustive_fallback",
                )
                evaluated.update(fallback.evaluated_ids)
                pending_uncertain.difference_update(fallback.evaluated_ids)
                candidates.update({item.label: item for item in fallback.candidates})
                if fallback.stop_reason:
                    return self._outcome(
                        taxonomy,
                        candidates,
                        evaluated,
                        pruned,
                        pending_uncertain,
                        pruned_branches,
                        routing_levels,
                        cost_switches,
                        fallback.stop_reason,
                        fallback.error,
                    )
                frontier = []
                break
            frontier = next_frontier

        supported_ids = set(candidates)
        pending_uncertain = {
            label_id for label_id in pending_uncertain
            if not self._has_supported_descendant(label_id, supported_ids, tree)
        }
        if pending_uncertain:
            adjudication_labels = [label for label in ordered if label.id in pending_uncertain]
            logger.info(
                "[%s] hierarchy adjudication started labels=%d",
                cve.cve_id,
                len(adjudication_labels),
            )
            adjudication = self._exhaustive_subset(
                cve,
                taxonomy,
                adjudication_labels,
                state,
                budget,
                checkpoint,
                "adjudicate_uncertain_taxonomy",
            )
            evaluated.update(adjudication.evaluated_ids)
            pending_uncertain.difference_update(adjudication.evaluated_ids)
            candidates.update({item.label: item for item in adjudication.candidates})
            if adjudication.stop_reason:
                return self._outcome(
                    taxonomy,
                    candidates,
                    evaluated,
                    pruned,
                    pending_uncertain,
                    pruned_branches,
                    routing_levels,
                    cost_switches,
                    adjudication.stop_reason,
                    adjudication.error,
                )

        outcome = self._outcome(
            taxonomy,
            candidates,
            evaluated,
            pruned,
            pending_uncertain,
            pruned_branches,
            routing_levels,
            cost_switches,
        )
        logger.info(
            "[%s] hierarchy scan finished evaluated=%d pruned=%d unresolved=%d candidates=%d requests=%d levels=%d switches=%d",
            cve.cve_id,
            len(outcome.evaluated_ids),
            len(outcome.pruned_ids),
            len(outcome.unresolved_ids),
            len(outcome.candidates),
            outcome.classification_requests,
            outcome.routing_levels,
            outcome.cost_switches,
        )
        return outcome

    def _route_chunk(
        self,
        cve: CVERecord,
        taxonomy: Taxonomy,
        tree: TaxonomyTree,
        level_id: int,
        labels: tuple[TaxonomyLabel, ...],
        state: InvestigationState,
        budget: TokenBudget,
    ) -> list[RoutingDecision]:
        selected_evidence = profile_evidence(state)
        payload = {
            "vulnerability_profile": {
                "cve_id": cve.cve_id,
                "information_status": state.research_information_status,
                "findings": [asdict(item) for item in state.findings],
            },
            "evidence": [asdict(item) for item in selected_evidence],
            "taxonomy_level": {
                "level_id": level_id,
                "labels": [routing_label_dict(tree, item) for item in labels],
            },
        }
        messages = [
            {"role": "system", "content": HIERARCHY_ROUTING_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ]
        for correction_attempt in range(2):
            self.request_count += 1
            response = self.chat(
                cve.cve_id,
                budget,
                "classification",
                messages=messages,
                response_format=hierarchy_routing_response_format(),
            )
            try:
                return self._validate_decisions(
                    decode_json_content(response),
                    cve.cve_id,
                    level_id,
                    labels,
                    taxonomy,
                    selected_evidence,
                )
            except ValueError as exc:
                if correction_attempt:
                    raise RoutingResponseError(str(exc)) from exc
                logger.warning(
                    "[%s] hierarchy routing invalid level=%d correction=1/1 detail=%s",
                    cve.cve_id,
                    level_id,
                    str(exc),
                )
                messages.extend([
                    {"role": "assistant", "content": response.choices[0].message.content or ""},
                    {"role": "user", "content": f"The routing response was invalid: {exc}. Return a corrected object for this same level chunk."},
                ])
        raise AssertionError("unreachable")

    def _validate_decisions(
        self,
        decoded: dict[str, Any] | list[Any],
        cve_id: str,
        level_id: int,
        labels: tuple[TaxonomyLabel, ...],
        taxonomy: Taxonomy,
        evidence: list[EvidenceRecord],
    ) -> list[RoutingDecision]:
        if not isinstance(decoded, dict):
            raise ValueError("hierarchy routing response must be a JSON object")
        if decoded.get("level_id") != level_id:
            raise ValueError(f"router returned level_id {decoded.get('level_id')!r}, expected {level_id}")
        raw_decisions = decoded.get("decisions")
        if not isinstance(raw_decisions, list):
            raise ValueError("hierarchy routing response requires a decisions array")
        raw_decisions, replacements = normalize_label_references(raw_decisions, labels)
        for reference, label_id in replacements:
            logger.warning(
                "[%s] normalized hierarchy label reference from name=%r to id=%r level=%d",
                cve_id,
                reference,
                label_id,
                level_id,
            )
        expected = {label.id: label for label in labels}
        raw_by_id: dict[str, dict[str, Any]] = {}
        for raw in raw_decisions:
            if not isinstance(raw, dict):
                raise ValueError("each routing decision must be an object")
            label_id = raw.get("label")
            if label_id not in expected:
                raise ValueError(f"routing decision uses label outside the level chunk: {label_id!r}")
            if label_id in raw_by_id:
                raise ValueError(f"duplicate routing decision for {label_id!r}")
            raw_by_id[label_id] = raw
        missing = [label.id for label in labels if label.id not in raw_by_id]
        if missing:
            raise ValueError(f"routing response omitted labels: {missing}")

        evidence_ids = {item.evidence_id for item in evidence}
        decisions: list[RoutingDecision] = []
        for label in labels:
            raw = raw_by_id[label.id]
            try:
                decision_state = RoutingDecisionState(raw.get("decision"))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid routing decision for {label.id!r}") from exc
            confidence_value = raw.get("confidence")
            if isinstance(confidence_value, bool) or not isinstance(confidence_value, (int, float)):
                raise ValueError(f"routing confidence for {label.id!r} must be numeric")
            confidence = float(confidence_value)
            if not 0 <= confidence <= 1:
                raise ValueError(f"routing confidence for {label.id!r} must be in [0, 1]")
            explanation = raw.get("explanation")
            if not isinstance(explanation, str) or not explanation.strip():
                raise ValueError(f"routing decision for {label.id!r} requires an explanation")
            raw_evidence = raw.get("evidence")
            if not isinstance(raw_evidence, list):
                raise ValueError(f"routing evidence for {label.id!r} must be an array")
            for association in raw_evidence:
                if not isinstance(association, dict):
                    raise ValueError("each routing evidence association must be an object")
                if association.get("evidence_id") not in evidence_ids:
                    raise ValueError(f"unknown routing evidence_id: {association.get('evidence_id')!r}")
                if not isinstance(association.get("explanation"), str) or not association["explanation"].strip():
                    raise ValueError("routing evidence explanation must be non-empty")

            candidate = None
            if decision_state == RoutingDecisionState.SUPPORTED:
                if not raw_evidence:
                    raise ValueError(f"supported routing decision for {label.id!r} requires evidence")
                _, materialized = validate_classification(
                    "classified",
                    [{"label": label.id, "confidence": confidence, "evidence": raw_evidence}],
                    taxonomy,
                    evidence,
                )
                candidate = materialized[0]

            normalized = False
            if (
                decision_state == RoutingDecisionState.UNSUPPORTED
                and confidence < self.settings.pruning_confidence_threshold
            ):
                logger.warning(
                    "[%s] normalized low-confidence unsupported routing decision label=%s confidence=%.3f threshold=%.3f",
                    cve_id,
                    label.id,
                    confidence,
                    self.settings.pruning_confidence_threshold,
                )
                decision_state = RoutingDecisionState.UNCERTAIN
                normalized = True
            decisions.append(RoutingDecision(
                label,
                decision_state,
                confidence,
                explanation.strip(),
                candidate,
                normalized,
            ))
        return decisions

    def _exhaustive_subset(
        self,
        cve: CVERecord,
        taxonomy: Taxonomy,
        labels: list[TaxonomyLabel],
        state: InvestigationState,
        budget: TokenBudget,
        checkpoint: Callable[[], None],
        tool_name: str,
    ) -> TaxonomyScanOutcome:
        if not labels:
            return TaxonomyScanOutcome(candidates=(), evaluated_ids=())
        chunks = chunk_labels(labels, available_tokens=taxonomy_input_tokens(self.settings), render=label_dict)
        scanner = ExhaustiveTaxonomyScanner(self.chat, chunks, tool_name=tool_name)
        outcome = scanner.scan(
            cve,
            Taxonomy(tuple(labels), taxonomy.hierarchy_policy),
            state,
            budget,
            checkpoint,
        )
        self.request_count += outcome.classification_requests
        return outcome

    def _estimate_hybrid_continuation(
        self,
        frontier: list[TaxonomyLabel],
        pending_uncertain: set[str],
        tree: TaxonomyTree,
    ) -> int:
        frontier_cost = estimate_routing_tokens(frontier, tree, self.settings)
        path_costs: list[int] = []
        for path in tree.paths_from(frontier):
            descendant_routing = sum(
                estimate_routing_tokens(tree.children[parent.id], tree, self.settings)
                for parent in path[:-1]
            )
            adjudication_ids = {*pending_uncertain, *(label.id for label in path)}
            adjudication = [label for label in tree.by_id.values() if label.id in adjudication_ids]
            path_costs.append(descendant_routing + estimate_exhaustive_tokens(adjudication, self.settings))
        return frontier_cost + (max(path_costs) if path_costs else 0)

    @staticmethod
    def _active_labels(
        ordered: list[TaxonomyLabel],
        tree: TaxonomyTree,
        frontier: list[TaxonomyLabel],
        pending_uncertain: set[str],
        evaluated: set[str],
        pruned: set[str],
    ) -> list[TaxonomyLabel]:
        active_ids = set(pending_uncertain)
        for label in frontier:
            active_ids.add(label.id)
            active_ids.update(item.id for item in tree.descendants(label.id))
        return [
            label for label in ordered
            if label.id in active_ids and (label.id not in evaluated or label.id in pending_uncertain) and label.id not in pruned
        ]

    @staticmethod
    def _has_supported_descendant(
        label_id: str,
        supported_ids: set[str],
        tree: TaxonomyTree,
    ) -> bool:
        return any(item.id in supported_ids for item in tree.descendants(label_id))

    def _outcome(
        self,
        taxonomy: Taxonomy,
        candidates: dict[str, LabelClassification],
        evaluated: set[str],
        pruned: set[str],
        pending_uncertain: set[str],
        pruned_branches: list[dict[str, Any]],
        routing_levels: int,
        cost_switches: int,
        stop_reason: InvestigationStopReason | None = None,
        error: str | None = None,
    ) -> TaxonomyScanOutcome:
        ordered_ids = [label.id for label in taxonomy.labels]
        unresolved = (set(ordered_ids) - evaluated - pruned) | pending_uncertain
        return TaxonomyScanOutcome(
            candidates=tuple(candidates[label_id] for label_id in ordered_ids if label_id in candidates),
            evaluated_ids=tuple(label_id for label_id in ordered_ids if label_id in evaluated),
            pruned_ids=tuple(label_id for label_id in ordered_ids if label_id in pruned),
            unresolved_ids=tuple(label_id for label_id in ordered_ids if label_id in unresolved),
            classification_requests=self.request_count,
            routing_levels=routing_levels,
            pruned_branches=tuple(pruned_branches),
            cost_switches=cost_switches,
            stop_reason=stop_reason,
            error=error,
        )

    def _checkpoint_error(
        self,
        state: InvestigationState,
        budget: TokenBudget,
        checkpoint: Callable[[], None],
        level_id: int,
        label_ids: tuple[str, ...],
        error: str,
    ) -> None:
        state.tool_history.append({
            "tool": "route_taxonomy_level",
            "status": "error",
            "level": level_id,
            "labels": list(label_ids),
            "error": error[:500],
        })
        state.token_usage = budget.to_dict()
        checkpoint()


def _decision_labels(
    decisions: list[RoutingDecision],
    state: RoutingDecisionState,
    limit: int = 8,
) -> str:
    labels = [item.label.id for item in decisions if item.state == state]
    if not labels:
        return "none"
    shown = ",".join(labels[:limit])
    return shown if len(labels) <= limit else f"{shown},…(+{len(labels) - limit})"
