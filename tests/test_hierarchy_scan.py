import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from cve_agent.budget import BudgetExceeded, TokenBudget, create_hybrid_budget_plan
from cve_agent.classification import apply_hierarchy_policy
from cve_agent.hierarchy_scan import HybridTaxonomyScanner
from cve_agent.models import CVERecord, EvidenceRecord, InvestigationAspect, InvestigationFinding, InvestigationState
from cve_agent.prompts import HIERARCHY_ROUTING_SYSTEM_PROMPT
from cve_agent.taxonomy import HierarchyPolicy, Taxonomy, TaxonomyLabel, load_taxonomy
from test_agent import settings


def hierarchy():
    return Taxonomy((
        TaxonomyLabel("ROOT", "Root", "Root vulnerability family."),
        TaxonomyLabel("CHILD", "Child", "Specific child family.", "ROOT"),
        TaxonomyLabel("LEAF", "Leaf", "Specific leaf mechanism.", "CHILD"),
        TaxonomyLabel("OTHER", "Other", "Unrelated family."),
        TaxonomyLabel("OTHER-LEAF", "Other leaf", "Unrelated leaf mechanism.", "OTHER"),
    ))


def state():
    return InvestigationState(
        findings=[InvestigationFinding(
            InvestigationAspect.ROOT_CAUSE,
            "The evidence establishes the mechanism.",
            ("e-1",),
        )],
        research_information_status="sufficient",
        evidence=[EvidenceRecord("e-1", "https://source.test", "Exact mechanism evidence.", "web")],
    )


def model_response(payload):
    message = SimpleNamespace(content=json.dumps(payload), tool_calls=[])
    return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=None)


class RoutingChat:
    def __init__(self, decisions, *, binary_supported=(), malformed_routes=0):
        self.decisions = decisions
        self.binary_supported = set(binary_supported)
        self.malformed_routes = malformed_routes
        self.requests = []

    def __call__(self, context, budget, stage, **request):
        self.requests.append(request)
        system = request["messages"][0]["content"]
        payload = json.loads(request["messages"][1]["content"])
        if system == HIERARCHY_ROUTING_SYSTEM_PROMPT:
            level = payload["taxonomy_level"]
            if self.malformed_routes:
                self.malformed_routes -= 1
                return model_response({"level_id": level["level_id"], "decisions": []})
            routed = []
            for label in level["labels"]:
                decision, confidence = self.decisions.get(label["id"], ("unsupported", 0.95))
                routed.append({
                    "label": label["id"],
                    "decision": decision,
                    "confidence": confidence,
                    "explanation": f"Fixture decision for {label['id']}.",
                    "evidence": [{
                        "evidence_id": "e-1",
                        "explanation": "The exact passage supports this node.",
                    }] if decision == "supported" else [],
                })
            return model_response({"level_id": level["level_id"], "decisions": routed})

        chunk = payload["taxonomy_chunk"]
        supported = [{
            "label": label["id"],
            "confidence": 0.9,
            "evidence": [{
                "evidence_id": "e-1",
                "explanation": "The exact passage supports the final label.",
            }],
        } for label in chunk["labels"] if label["id"] in self.binary_supported]
        return model_response({"chunk_id": chunk["chunk_id"], "supported": supported})


class MissingSupportedEvidenceChat(RoutingChat):
    def __call__(self, context, budget, stage, **request):
        response = super().__call__(context, budget, stage, **request)
        payload = json.loads(response.choices[0].message.content)
        if "decisions" in payload:
            for decision in payload["decisions"]:
                if decision["decision"] == "supported":
                    decision["evidence"] = []
            return model_response(payload)
        return response


class FailingAfterRootChat(RoutingChat):
    def __call__(self, context, budget, stage, **request):
        if self.requests:
            raise BudgetExceeded("classification token allowance exhausted")
        return super().__call__(context, budget, stage, **request)


class PureHybridScanner(HybridTaxonomyScanner):
    def _estimate_hybrid_continuation(self, frontier, pending_uncertain, tree):
        return 0


def configured(tmp_path, **changes):
    return replace(settings(tmp_path), token_budget=100_000, **changes)


def run_scan(tmp_path, scanner_class, chat):
    selected_taxonomy = hierarchy()
    selected_settings = configured(tmp_path)
    budget = TokenBudget(create_hybrid_budget_plan(selected_taxonomy, selected_settings), selected_settings)
    selected_state = state()
    checkpoints = []
    outcome = scanner_class(selected_settings, chat).scan(
        CVERecord("VULN-1", "Fixture vulnerability."),
        selected_taxonomy,
        selected_state,
        budget,
        lambda: checkpoints.append(len(selected_state.tool_history)),
    )
    return outcome, selected_state, checkpoints


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
    fixture = Path(__file__).parents[1] / "fixtures" / "hierarchical_taxonomy.json"
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
