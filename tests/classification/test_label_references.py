from dataclasses import replace
from types import SimpleNamespace
import json
import logging

from cve_agent.classification.budget import (
    create_budget_plan,
    create_hybrid_budget_plan,
    taxonomy_input_tokens,
)
from cve_agent.classification.exhaustive import ExhaustiveTaxonomyScanner
from cve_agent.classification.hybrid import HybridTaxonomyScanner
from cve_agent.classification.taxonomy import chunk_taxonomy, normalize_label_references
from cve_agent.core.investigation import InvestigationAspect, InvestigationFinding, InvestigationState
from cve_agent.core.sources import CVERecord, EvidenceRecord
from cve_agent.core.taxonomy import Taxonomy, TaxonomyLabel
from cve_agent.runtime.budget import TokenBudget
from tests.support.agent import settings


def model_response(payload):
    message = SimpleNamespace(content=json.dumps(payload), tool_calls=[])
    return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=None)


def evidence_state():
    return InvestigationState(
        findings=[InvestigationFinding(
            InvestigationAspect.ROOT_CAUSE,
            "The evidence establishes query injection.",
            ("e-1",),
        )],
        research_information_status="sufficient",
        evidence=[EvidenceRecord("e-1", "https://source.test", "Query syntax is attacker controlled.", "web")],
    )


def test_normalizes_only_unique_names_or_whitespace_padded_ids():
    labels = (
        TaxonomyLabel("QUERY", "Query Injection", "Query definition."),
        TaxonomyLabel("OTHER", "Shared Name", "First shared definition."),
        TaxonomyLabel("ANOTHER", "Shared Name", "Second shared definition."),
    )
    entries, replacements = normalize_label_references([
        {"label": "Query Injection"},
        {"label": " QUERY "},
        {"label": "Shared Name"},
        {"label": "Unknown Name"},
    ], labels)

    assert [item["label"] for item in entries] == ["QUERY", "QUERY", "Shared Name", "Unknown Name"]
    assert replacements == (("Query Injection", "QUERY"), (" QUERY ", "QUERY"))


def test_exhaustive_scanner_accepts_unambiguous_display_names(tmp_path, caplog):
    taxonomy = Taxonomy((
        TaxonomyLabel("InputProcessing", "Input Processing Weaknesses", "Broad input-processing family."),
        TaxonomyLabel("InterpreterInjection", "Interpreter Injection", "Input changes interpreter syntax.", "InputProcessing"),
        TaxonomyLabel("QueryInjection", "Query-Language Injection", "Untrusted data changes query syntax.", "InterpreterInjection"),
    ))
    configured = replace(settings(tmp_path), token_budget=100_000)
    chunks = chunk_taxonomy(taxonomy, available_tokens=taxonomy_input_tokens(configured))
    budget = TokenBudget(create_budget_plan(chunks, configured), configured)

    def chat(*args, **kwargs):
        return model_response({
            "chunk_id": 1,
            "supported": [{
                "label": name,
                "confidence": 0.9,
                "evidence": [{
                    "evidence_id": "e-1",
                    "explanation": "The passage establishes attacker-controlled query syntax.",
                }],
            } for name in (
                "Query-Language Injection",
                "Interpreter Injection",
                "Input Processing Weaknesses",
            )],
        })

    caplog.set_level(logging.WARNING, logger="cve_agent.taxonomy_scan")
    outcome = ExhaustiveTaxonomyScanner(chat, chunks).scan(
        CVERecord("VULN-1", "Fixture vulnerability."),
        taxonomy,
        evidence_state(),
        budget,
        lambda: None,
    )

    assert outcome.complete
    assert [item.label for item in outcome.candidates] == [
        "QueryInjection",
        "InterpreterInjection",
        "InputProcessing",
    ]
    assert outcome.classification_requests == 1
    assert "normalized taxonomy label reference" in caplog.text


def test_hybrid_router_accepts_unambiguous_display_names(tmp_path, caplog):
    taxonomy = Taxonomy((
        TaxonomyLabel("InputProcessing", "Input Processing Weaknesses", "Broad input-processing family."),
        TaxonomyLabel("QueryInjection", "Query-Language Injection", "Untrusted data changes query syntax.", "InputProcessing"),
    ))
    configured = replace(settings(tmp_path), token_budget=100_000)
    budget = TokenBudget(create_hybrid_budget_plan(taxonomy, configured), configured)

    def chat(*args, **kwargs):
        return model_response({
            "level_id": 1,
            "decisions": [{
                "label": "Input Processing Weaknesses",
                "decision": "unsupported",
                "confidence": 0.95,
                "explanation": "The fixture rules out this branch.",
                "evidence": [],
            }],
        })

    caplog.set_level(logging.WARNING, logger="cve_agent.hierarchy_scan")
    outcome = HybridTaxonomyScanner(configured, chat).scan(
        CVERecord("VULN-1", "Fixture vulnerability."),
        taxonomy,
        evidence_state(),
        budget,
        lambda: None,
    )

    assert outcome.complete
    assert outcome.evaluated_ids == ("InputProcessing",)
    assert outcome.pruned_ids == ("QueryInjection",)
    assert outcome.classification_requests == 1
    assert "normalized hierarchy label reference" in caplog.text
