from types import SimpleNamespace

import pytest

from cve_agent.budget import BudgetExceeded, BudgetPreflightError, TokenBudget, create_budget_plan
from cve_agent.classification import TaxonomyChunk
from cve_agent.taxonomy import TaxonomyLabel
from test_agent import settings


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
