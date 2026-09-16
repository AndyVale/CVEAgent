from pathlib import Path
import logging

from cve_agent.application.coordinator import ClassificationCoordinator
from cve_agent.core.strategy import ClassificationStrategy, EffectiveClassificationStrategy
from cve_agent.core.taxonomy import Taxonomy, TaxonomyLabel, load_taxonomy
from tests.support.agent import FixtureWeb, FullFlowClient, settings, taxonomy


def test_strategy_selection_is_taxonomy_aware_and_config_only(tmp_path):
    flat = taxonomy()
    hierarchy = Taxonomy((
        TaxonomyLabel("ROOT", "Root", "Broad family."),
        TaxonomyLabel("CHILD", "Child", "Specific mechanism.", "ROOT"),
    ))
    base = settings(tmp_path)

    forced_hybrid_flat = base.__class__(**{
        **base.__dict__,
        "classification_strategy": ClassificationStrategy.HYBRID,
        "token_budget": 100_000,
    })
    assert ClassificationCoordinator(forced_hybrid_flat, FixtureWeb(), FullFlowClient()).planner.plan(flat).effective_strategy == EffectiveClassificationStrategy.EXHAUSTIVE

    assert ClassificationCoordinator(base, FixtureWeb(), FullFlowClient()).planner.plan(hierarchy).effective_strategy == EffectiveClassificationStrategy.EXHAUSTIVE

    forced_hybrid = base.__class__(**{
        **base.__dict__,
        "classification_strategy": ClassificationStrategy.HYBRID,
        "token_budget": 100_000,
    })
    assert ClassificationCoordinator(forced_hybrid, FixtureWeb(), FullFlowClient()).planner.plan(hierarchy).effective_strategy == EffectiveClassificationStrategy.HYBRID

    long_definition = "Long hierarchy definition. " * 220
    large_hierarchy = Taxonomy((
        TaxonomyLabel("ROOT", "Root", long_definition),
        TaxonomyLabel("CHILD", "Child", long_definition, "ROOT"),
    ))
    auto_large = base.__class__(**{
        **base.__dict__,
        "max_input_tokens_per_request": 8000,
        "token_budget": 100_000,
    })
    assert ClassificationCoordinator(auto_large, FixtureWeb(), FullFlowClient()).planner.plan(large_hierarchy).effective_strategy == EffectiveClassificationStrategy.HYBRID

    forced_exhaustive = auto_large.__class__(**{
        **auto_large.__dict__,
        "classification_strategy": ClassificationStrategy.EXHAUSTIVE,
    })
    assert ClassificationCoordinator(forced_exhaustive, FixtureWeb(), FullFlowClient()).planner.plan(large_hierarchy).effective_strategy == EffectiveClassificationStrategy.EXHAUSTIVE


def test_demo_fixtures_use_the_documented_automatic_strategies(tmp_path):
    fixtures = Path(__file__).parents[2] / "fixtures"
    base = settings(tmp_path)
    configured = base.__class__(**{
        **base.__dict__,
        "token_budget": 50_000,
    })

    plans = {
        name: ClassificationCoordinator(configured, FixtureWeb(), FullFlowClient()).planner.plan(
            load_taxonomy(fixtures / name / "taxonomy.json")
        )
        for name in ("flat", "hierarchical", "hybrid")
    }

    assert plans["flat"].effective_strategy == EffectiveClassificationStrategy.EXHAUSTIVE
    assert len(plans["flat"].chunks) == 1
    assert plans["hierarchical"].effective_strategy == EffectiveClassificationStrategy.EXHAUSTIVE
    assert len(plans["hierarchical"].chunks) == 1
    assert plans["hybrid"].effective_strategy == EffectiveClassificationStrategy.HYBRID
    assert len(plans["hybrid"].chunks) == 2
    assert 0 < plans["hybrid"].budget.classification_reserve < configured.token_budget
    assert plans["hybrid"].budget.investigation_limit == (
        configured.token_budget - plans["hybrid"].budget.classification_reserve
    )


def test_flat_taxonomy_logs_that_configured_hybrid_strategy_is_ignored(tmp_path, caplog):
    configured = settings(tmp_path).__class__(**{
        **settings(tmp_path).__dict__,
        "classification_strategy": ClassificationStrategy.HYBRID,
    })
    caplog.set_level(logging.INFO, logger="cve_agent.agent")

    plan = ClassificationCoordinator(configured, FixtureWeb(), FullFlowClient()).planner.plan(taxonomy())

    assert plan.effective_strategy == EffectiveClassificationStrategy.EXHAUSTIVE
    assert "ignoring configured_strategy=hybrid" in caplog.text
