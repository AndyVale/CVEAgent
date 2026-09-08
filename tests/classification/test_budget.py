from types import SimpleNamespace

import pytest

from cve_agent.classification.budget import (
    BudgetPreflightError,
    classification_context_tokens,
    create_budget_plan,
    create_hybrid_budget_plan,
    estimate_exhaustive_tokens,
    estimate_routing_tokens,
    routing_context_tokens,
    routing_input_tokens,
    taxonomy_input_tokens,
)
from cve_agent.classification.taxonomy import TaxonomyChunk, build_taxonomy_tree
from cve_agent.core.taxonomy import Taxonomy, TaxonomyLabel
from cve_agent.runtime.budget import BudgetExceeded, TokenBudget
from tests.support.agent import settings


def test_preflight_rejects_budget_that_cannot_cover_exhaustive_scan(tmp_path):
    configured = settings(tmp_path).__class__(**{**settings(tmp_path).__dict__, "token_budget": 100, "finalization_overrun_percent": 0})
    chunks = (TaxonomyChunk(1, (TaxonomyLabel("GENERIC", "Generic", "A generic taxonomy label."),)),)
    with pytest.raises(BudgetPreflightError, match="estimated minimum"):
        create_budget_plan(chunks, configured)


def test_finalization_overrun_is_not_available_to_investigation(tmp_path):
    configured = settings(tmp_path).__class__(**{**settings(tmp_path).__dict__, "token_budget": 5000, "finalization_overrun_percent": 20})
    chunks = (TaxonomyChunk(1, (TaxonomyLabel("GENERIC", "Generic", "A generic taxonomy label."),)),)
    budget = TokenBudget(create_budget_plan(chunks, configured), configured)
    budget.total_tokens = budget.plan.investigation_limit
    with pytest.raises(BudgetExceeded, match="investigation"):
        budget.admit("investigation", {"messages": []})
    assert budget.admit("classification", {"messages": []}) > 0


def test_missing_provider_usage_is_estimated(tmp_path):
    configured = settings(tmp_path)
    chunks = (TaxonomyChunk(1, (TaxonomyLabel("GENERIC", "Generic", "A generic taxonomy label."),)),)
    budget = TokenBudget(create_budget_plan(chunks, configured), configured)
    message = SimpleNamespace(content="small response", model_dump=lambda exclude_none=True: {"content": "small response"})
    response = SimpleNamespace(usage=None, choices=[SimpleNamespace(message=message)])
    budget.record(response, {"messages": [{"role": "user", "content": "small prompt"}]})
    assert budget.total_tokens > 0
    assert budget.to_dict()["estimated_interactions"] == 1


def test_taxonomy_chunk_allowance_reserves_classification_context(tmp_path):
    configured = settings(tmp_path).__class__(**{
        **settings(tmp_path).__dict__,
        "max_input_tokens_per_request": classification_context_tokens() + 321,
    })
    assert taxonomy_input_tokens(configured) == 321


def test_preflight_rejects_input_limit_that_cannot_fit_classification_context(tmp_path):
    configured = settings(tmp_path).__class__(**{
        **settings(tmp_path).__dict__,
        "max_input_tokens_per_request": classification_context_tokens(),
    })
    with pytest.raises(BudgetPreflightError, match="classification profile"):
        taxonomy_input_tokens(configured)


def test_hybrid_preflight_reserves_roots_deepest_path_and_adjudication(tmp_path):
    configured = settings(tmp_path).__class__(**{
        **settings(tmp_path).__dict__,
        "token_budget": 100_000,
    })
    taxonomy = Taxonomy((
        TaxonomyLabel("ROOT-A", "Root A", "First broad family."),
        TaxonomyLabel("CHILD-A", "Child A", "Specific mechanism.", "ROOT-A"),
        TaxonomyLabel("LEAF-A", "Leaf A", "Most specific mechanism.", "CHILD-A"),
        TaxonomyLabel("ROOT-B", "Root B", "Second broad family."),
    ))
    tree = build_taxonomy_tree(taxonomy)
    plan = create_hybrid_budget_plan(taxonomy, configured)
    root_cost = estimate_routing_tokens(tree.roots, tree, configured)
    path_costs = [
        sum(
            estimate_routing_tokens(tree.children[parent.id], tree, configured)
            for parent in path[:-1]
        ) + estimate_exhaustive_tokens(path, configured)
        for path in tree.root_to_leaf_paths()
    ]

    assert plan.classification_reserve == root_cost + max(path_costs)
    assert plan.investigation_limit == configured.token_budget - plan.classification_reserve


def test_hybrid_preflight_and_routing_context_fail_before_research(tmp_path):
    taxonomy = Taxonomy((TaxonomyLabel("ROOT", "Root", "Broad family."),))
    too_small_budget = settings(tmp_path).__class__(**{
        **settings(tmp_path).__dict__,
        "token_budget": 100,
        "finalization_overrun_percent": 0,
    })
    with pytest.raises(BudgetPreflightError, match="minimum hybrid"):
        create_hybrid_budget_plan(taxonomy, too_small_budget)

    too_small_input = settings(tmp_path).__class__(**{
        **settings(tmp_path).__dict__,
        "max_input_tokens_per_request": routing_context_tokens(),
    })
    with pytest.raises(BudgetPreflightError, match="routing profile"):
        routing_input_tokens(too_small_input)
