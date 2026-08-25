from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from cve_agent.classification import (
    TaxonomyChunk,
    TaxonomyTree,
    build_taxonomy_tree,
    chunk_labels,
    estimate_tokens,
    label_dict,
    routing_label_dict,
)
from cve_agent.config import Settings
from cve_agent.models import MAX_INVESTIGATION_FINDINGS
from cve_agent.prompts import CLASSIFICATION_SYSTEM_PROMPT, HIERARCHY_ROUTING_SYSTEM_PROMPT
from cve_agent.schemas import classification_response_format, hierarchy_routing_response_format
from cve_agent.taxonomy import Taxonomy, TaxonomyLabel


class BudgetPreflightError(ValueError):
    pass


class BudgetExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class BudgetPlan:
    base_budget: int
    expanded_budget: int
    classification_reserve: int
    investigation_limit: int


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


class TokenBudget:
    def __init__(self, plan: BudgetPlan, settings: Settings):
        self.plan = plan
        self.settings = settings
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.reported_interactions = 0
        self.estimated_interactions = 0
        self.exhausted = False

    def admit(self, stage: str, request: dict[str, Any]) -> int:
        estimated_prompt = estimate_tokens(request)
        if estimated_prompt > self.settings.max_input_tokens_per_request:
            raise BudgetExceeded(
                f"estimated prompt size {estimated_prompt} exceeds max_input_tokens_per_request={self.settings.max_input_tokens_per_request}"
            )
        limit = self.plan.investigation_limit if stage == "investigation" else self.plan.expanded_budget
        remaining = limit - self.total_tokens - estimated_prompt
        if remaining <= 0:
            self.exhausted = True
            raise BudgetExceeded(f"{stage} token allowance exhausted")
        return min(self.settings.max_tokens, remaining)

    def record(self, response: Any, request: dict[str, Any]) -> None:
        usage = response.usage.model_dump() if getattr(response, "usage", None) else {}
        prompt = int(usage.get("prompt_tokens", 0))
        completion = int(usage.get("completion_tokens", 0))
        total = int(usage.get("total_tokens", 0))
        if prompt or completion or total:
            if not total:
                total = prompt + completion
            self.reported_interactions += 1
        else:
            prompt = estimate_tokens(request)
            message = response.choices[0].message
            completion = estimate_tokens(message.model_dump(exclude_none=True) if hasattr(message, "model_dump") else getattr(message, "content", ""))
            total = prompt + completion
            self.estimated_interactions += 1
        self.prompt_tokens += prompt
        self.completion_tokens += completion
        self.total_tokens += total
        if self.total_tokens > self.plan.expanded_budget:
            self.exhausted = True

    def to_dict(self) -> dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "reported_interactions": self.reported_interactions,
            "estimated_interactions": self.estimated_interactions,
            "base_budget": self.plan.base_budget,
            "expanded_budget": self.plan.expanded_budget,
            "classification_reserve": self.plan.classification_reserve,
            "investigation_limit": self.plan.investigation_limit,
        }
