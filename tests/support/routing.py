from dataclasses import replace
from types import SimpleNamespace
import json

from cve_agent.classification.budget import create_hybrid_budget_plan
from cve_agent.classification.hybrid import HybridTaxonomyScanner
from cve_agent.classification.prompts import HIERARCHY_ROUTING_SYSTEM_PROMPT
from cve_agent.core.investigation import InvestigationAspect, InvestigationFinding, InvestigationState
from cve_agent.core.sources import CVERecord, EvidenceRecord
from cve_agent.core.taxonomy import Taxonomy, TaxonomyLabel
from cve_agent.runtime.budget import BudgetExceeded, TokenBudget
from tests.support.agent import settings


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
