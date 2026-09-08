from __future__ import annotations

from typing import Callable

from cve_agent.classification.prompts import CLASSIFICATION_SYSTEM_PROMPT, HIERARCHY_ROUTING_SYSTEM_PROMPT
from cve_agent.classification.schemas import classification_response_format, hierarchy_routing_response_format
from cve_agent.classification.taxonomy import (
    TaxonomyChunk,
    TaxonomyTree,
    build_taxonomy_tree,
    chunk_labels,
    label_dict,
    routing_label_dict,
)
from cve_agent.core.config import Settings
from cve_agent.core.investigation import MAX_INVESTIGATION_FINDINGS
from cve_agent.core.taxonomy import Taxonomy, TaxonomyLabel
from cve_agent.runtime.budget import BudgetPlan
from cve_agent.runtime.tokens import estimate_tokens


class BudgetPreflightError(ValueError):
    pass


def create_budget_plan(chunks: tuple[TaxonomyChunk, ...], settings: Settings) -> BudgetPlan:
    """Reserve an estimated exhaustive taxonomy scan before research."""
    per_call_output = min(settings.max_tokens, 600)
    repeated_context = classification_context_tokens()
    reserve = sum(
        estimate_tokens([[label.id, label.name, label.description, label.parent] for label in chunk.labels])
        + repeated_context
        + per_call_output
        for chunk in chunks
    )
    expanded = int(settings.token_budget * (1 + settings.finalization_overrun_percent / 100))
    if reserve > expanded:
        raise BudgetPreflightError(
            f"token budget cannot cover exhaustive taxonomy classification: estimated minimum {reserve}, expanded limit {expanded}"
        )
    return BudgetPlan(settings.token_budget, expanded, reserve, max(0, settings.token_budget - reserve))


def create_hybrid_budget_plan(taxonomy: Taxonomy, settings: Settings) -> BudgetPlan:
    """Reserve root routing, the costliest complete branch, and one adjudication pass."""
    tree = build_taxonomy_tree(taxonomy)
    root_cost = estimate_routing_tokens(tree.roots, tree, settings)
    branch_costs = [
        _branch_reserve(path, tree, settings)
        for path in tree.root_to_leaf_paths()
    ]
    reserve = root_cost + (max(branch_costs) if branch_costs else 0)
    expanded = int(settings.token_budget * (1 + settings.finalization_overrun_percent / 100))
    if reserve > expanded:
        raise BudgetPreflightError(
            f"token budget cannot cover minimum hybrid taxonomy traversal: estimated minimum {reserve}, expanded limit {expanded}"
        )
    return BudgetPlan(settings.token_budget, expanded, reserve, max(0, settings.token_budget - reserve))


def classification_context_tokens() -> int:
    """Estimate non-taxonomy input repeated for every classification request."""
    return (
        estimate_tokens(CLASSIFICATION_SYSTEM_PROMPT)
        + estimate_tokens(classification_response_format())
        + MAX_INVESTIGATION_FINDINGS * 350
    )


def routing_context_tokens() -> int:
    """Estimate non-taxonomy input repeated for every hierarchy-routing request."""
    return (
        estimate_tokens(HIERARCHY_ROUTING_SYSTEM_PROMPT)
        + estimate_tokens(hierarchy_routing_response_format())
        + MAX_INVESTIGATION_FINDINGS * 350
    )


def taxonomy_input_tokens(settings: Settings) -> int:
    """Return the input allowance available to taxonomy labels in one request."""
    available = settings.max_input_tokens_per_request - classification_context_tokens()
    if available <= 0:
        raise BudgetPreflightError(
            "max_input_tokens_per_request cannot fit the classification profile and response schema"
        )
    return available


def routing_input_tokens(settings: Settings) -> int:
    available = settings.max_input_tokens_per_request - routing_context_tokens()
    if available <= 0:
        raise BudgetPreflightError(
            "max_input_tokens_per_request cannot fit the hierarchy routing profile and response schema"
        )
    return available


def estimate_exhaustive_tokens(labels: tuple[TaxonomyLabel, ...] | list[TaxonomyLabel], settings: Settings) -> int:
    chunks = chunk_labels(tuple(labels), available_tokens=taxonomy_input_tokens(settings), render=label_dict)
    return _chunk_reserve(chunks, classification_context_tokens(), settings, label_dict)


def estimate_routing_tokens(
    labels: tuple[TaxonomyLabel, ...] | list[TaxonomyLabel],
    tree: TaxonomyTree,
    settings: Settings,
) -> int:
    render = lambda label: routing_label_dict(tree, label)
    chunks = chunk_labels(tuple(labels), available_tokens=routing_input_tokens(settings), render=render)
    return _chunk_reserve(chunks, routing_context_tokens(), settings, render)


def _chunk_reserve(
    chunks: tuple[TaxonomyChunk, ...],
    repeated_context: int,
    settings: Settings,
    render: Callable[[TaxonomyLabel], object],
) -> int:
    per_call_output = min(settings.max_tokens, 600)
    return sum(
        sum(estimate_tokens(render(label)) for label in chunk.labels)
        + repeated_context
        + per_call_output
        for chunk in chunks
    )


def _branch_reserve(path: tuple[TaxonomyLabel, ...], tree: TaxonomyTree, settings: Settings) -> int:
    route_cost = sum(
        estimate_routing_tokens(tree.children[parent.id], tree, settings)
        for parent in path[:-1]
    )
    return route_cost + estimate_exhaustive_tokens(path, settings)
