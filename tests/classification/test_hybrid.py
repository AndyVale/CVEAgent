from pathlib import Path

from cve_agent.classification.budget import create_hybrid_budget_plan
from cve_agent.classification.hybrid import HybridTaxonomyScanner
from cve_agent.classification.taxonomy import apply_hierarchy_policy
from cve_agent.core.sources import CVERecord
from cve_agent.core.taxonomy import HierarchyPolicy, Taxonomy, load_taxonomy
from cve_agent.runtime.budget import TokenBudget
from tests.support.routing import (
    hierarchy,
    state,
    RoutingChat,
    MissingSupportedEvidenceChat,
    FailingAfterRootChat,
    PureHybridScanner,
    configured,
    run_scan,
)


def test_hybrid_traversal_prunes_branches_and_keeps_supported_descendant(tmp_path):
    chat = RoutingChat({
        "ROOT": ("supported", 0.9),
        "OTHER": ("unsupported", 0.95),
        "CHILD": ("uncertain", 0.6),
        "LEAF": ("supported", 0.9),
    })
    outcome, selected_state, checkpoints = run_scan(tmp_path, PureHybridScanner, chat)

    assert outcome.complete
    assert outcome.evaluated_ids == ("ROOT", "CHILD", "LEAF", "OTHER")
    assert outcome.pruned_ids == ("OTHER-LEAF",)
    assert outcome.unresolved_ids == ()
    assert [item.label for item in outcome.candidates] == ["ROOT", "LEAF"]
    assert [item.label for item in apply_hierarchy_policy(list(outcome.candidates), hierarchy())] == ["LEAF"]
    assert outcome.routing_levels == 3
    assert outcome.classification_requests == 3
    assert len(checkpoints) == 3
    assert selected_state.tool_history[0]["tool"] == "route_taxonomy_level"


def test_low_confidence_pruning_expands_and_adjudicates_uncertain_nodes(tmp_path):
    chat = RoutingChat({
        "ROOT": ("unsupported", 0.7),
        "OTHER": ("unsupported", 0.95),
        "CHILD": ("uncertain", 0.5),
        "LEAF": ("uncertain", 0.5),
    }, binary_supported={"LEAF"})
    outcome, selected_state, _ = run_scan(tmp_path, PureHybridScanner, chat)

    assert outcome.complete
    assert [item.label for item in outcome.candidates] == ["LEAF"]
    assert outcome.classification_requests == 4
    assert any(item.get("normalized_to_uncertain") == 1 for item in selected_state.tool_history)
    assert selected_state.tool_history[-1]["tool"] == "adjudicate_uncertain_taxonomy"


def test_hybrid_switches_active_subtree_to_cheaper_exhaustive_scan(tmp_path):
    chat = RoutingChat({
        "ROOT": ("supported", 0.9),
        "OTHER": ("unsupported", 0.95),
    }, binary_supported={"LEAF"})
    outcome, selected_state, _ = run_scan(tmp_path, HybridTaxonomyScanner, chat)

    assert outcome.complete
    assert outcome.cost_switches == 1
    assert outcome.routing_levels == 1
    assert outcome.classification_requests == 2
    assert [item.label for item in outcome.candidates] == ["ROOT", "LEAF"]
    assert selected_state.tool_history[-2]["tool"] == "switch_taxonomy_strategy"
    assert selected_state.tool_history[-2]["estimated_exhaustive_tokens"] <= selected_state.tool_history[-2]["estimated_hybrid_tokens"]
    assert selected_state.tool_history[-1]["tool"] == "hybrid_exhaustive_fallback"


def test_persistently_malformed_routing_returns_exact_partial_coverage(tmp_path):
    outcome, selected_state, checkpoints = run_scan(
        tmp_path,
        PureHybridScanner,
        RoutingChat({}, malformed_routes=2),
    )

    assert not outcome.complete
    assert outcome.evaluated_ids == ()
    assert outcome.pruned_ids == ()
    assert set(outcome.unresolved_ids) == {"ROOT", "CHILD", "LEAF", "OTHER", "OTHER-LEAF"}
    assert outcome.classification_requests == 2
    assert outcome.stop_reason == "classification_error"
    assert selected_state.tool_history[-1]["status"] == "error"
    assert len(checkpoints) == 1


def test_supported_internal_node_remains_when_children_are_pruned(tmp_path):
    chat = RoutingChat({
        "ROOT": ("supported", 0.9),
        "OTHER": ("unsupported", 0.95),
        "CHILD": ("unsupported", 0.95),
    })
    outcome, _, _ = run_scan(tmp_path, PureHybridScanner, chat)

    assert outcome.complete
    assert [item.label for item in outcome.candidates] == ["ROOT"]
    assert set(outcome.pruned_ids) == {"LEAF", "OTHER-LEAF"}
    assert [item.label for item in apply_hierarchy_policy(list(outcome.candidates), hierarchy())] == ["ROOT"]


def test_hybrid_supports_multiple_independent_root_branches(tmp_path):
    chat = RoutingChat({
        "ROOT": ("supported", 0.9),
        "OTHER": ("supported", 0.9),
        "CHILD": ("supported", 0.9),
        "OTHER-LEAF": ("supported", 0.9),
        "LEAF": ("unsupported", 0.95),
    })
    outcome, _, _ = run_scan(tmp_path, PureHybridScanner, chat)
    final = apply_hierarchy_policy(list(outcome.candidates), hierarchy())

    assert outcome.complete
    assert outcome.pruned_ids == ()
    assert [item.label for item in final] == ["CHILD", "OTHER-LEAF"]


def test_include_ancestors_is_applied_after_hybrid_candidates_are_merged(tmp_path):
    chat = RoutingChat({
        "ROOT": ("uncertain", 0.6),
        "OTHER": ("unsupported", 0.95),
        "CHILD": ("uncertain", 0.6),
        "LEAF": ("supported", 0.9),
    })
    outcome, _, _ = run_scan(tmp_path, PureHybridScanner, chat)
    include_ancestors = Taxonomy(hierarchy().labels, HierarchyPolicy.INCLUDE_ANCESTORS)

    assert outcome.complete
    assert {item.label for item in apply_hierarchy_policy(list(outcome.candidates), include_ancestors)} == {
        "ROOT", "CHILD", "LEAF",
    }


def test_missing_supported_evidence_is_corrected_then_returns_partial(tmp_path):
    chat = MissingSupportedEvidenceChat({"ROOT": ("supported", 0.9)})
    outcome, _, _ = run_scan(tmp_path, PureHybridScanner, chat)

    assert not outcome.complete
    assert outcome.stop_reason == "classification_error"
    assert outcome.classification_requests == 2


def test_routing_requires_numeric_confidence_after_one_correction(tmp_path):
    outcome, _, _ = run_scan(
        tmp_path,
        PureHybridScanner,
        RoutingChat({"ROOT": ("unsupported", "high")}),
    )

    assert not outcome.complete
    assert outcome.stop_reason == "classification_error"
    assert "must be numeric" in outcome.error
    assert outcome.classification_requests == 2


def test_unexpected_hybrid_budget_exhaustion_preserves_candidates_and_exact_coverage(tmp_path):
    chat = FailingAfterRootChat({
        "ROOT": ("supported", 0.9),
        "OTHER": ("unsupported", 0.95),
    })
    outcome, _, _ = run_scan(tmp_path, HybridTaxonomyScanner, chat)

    assert not outcome.complete
    assert [item.label for item in outcome.candidates] == ["ROOT"]
    assert set(outcome.evaluated_ids) == {"ROOT", "OTHER"}
    assert outcome.pruned_ids == ("OTHER-LEAF",)
    assert set(outcome.unresolved_ids) == {"CHILD", "LEAF"}
    assert outcome.stop_reason == "token_budget"


def test_hierarchical_fixture_traversal_is_deterministic_without_live_services(tmp_path):
    fixture = Path(__file__).parents[2] / "fixtures" / "hierarchical" / "taxonomy.json"
    selected_taxonomy = load_taxonomy(fixture)
    selected_settings = configured(tmp_path, max_input_tokens_per_request=6000)
    budget = TokenBudget(create_hybrid_budget_plan(selected_taxonomy, selected_settings), selected_settings)
    selected_state = state()

    outcome = PureHybridScanner(selected_settings, RoutingChat({})).scan(
        CVERecord("VULN-1", "Fixture vulnerability."),
        selected_taxonomy,
        selected_state,
        budget,
        lambda: None,
    )

    assert outcome.complete
    assert len(outcome.evaluated_ids) == 5
    assert len(outcome.pruned_ids) == 22
    assert len(outcome.evaluated_ids) + len(outcome.pruned_ids) == len(selected_taxonomy.labels)
