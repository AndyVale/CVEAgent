from dataclasses import replace
from types import SimpleNamespace
import json
import logging

import pytest

from cve_agent.application.coordinator import ClassificationCoordinator
from cve_agent.core.investigation import InvestigationAspect, InvestigationState
from cve_agent.core.results import ClassificationStatus
from cve_agent.core.sources import CVERecord, EvidenceRecord
from cve_agent.core.strategy import ClassificationStrategy
from cve_agent.core.taxonomy import Taxonomy, TaxonomyLabel
from tests.support.agent import (
    FinishCorrectionClient,
    FinishCorrectionResearchClient,
    FixtureWeb,
    FullFlowClient,
    HybridFlowClient,
    Message,
    MultiDocumentWeb,
    RecordEvidenceFlowClient,
    ToolCall,
    finish_arguments,
    response,
    settings,
    taxonomy,
)


def test_finish_investigation_gets_one_evidence_correction_before_materialization(tmp_path):
    client = FinishCorrectionClient()
    state = InvestigationState()
    snapshots = []

    def checkpoint():
        if state.tool_history:
            snapshots.append((state.tool_history[-1]["tool"], state.tool_history[-1]["status"], len(state.evidence)))

    result = ClassificationCoordinator(settings(tmp_path), FixtureWeb(), client).classify(
        CVERecord("VULN-1", "fixture"), taxonomy(), state, checkpoint=checkpoint,
    )

    finish_events = [event for event in state.tool_history if event["tool"] == "finish_investigation"]
    assert result.status == ClassificationStatus.CLASSIFIED
    assert [event["status"] for event in finish_events] == ["error", "success"]
    assert ("finish_investigation", "error", 0) in snapshots
    assert result.operational["research_profile"]["discarded_findings"] == 0
    assert [item.evidence_id for item in state.evidence] == ["doc-1:p1"]


def test_failed_finish_correction_retains_valid_findings_and_reason_counts(tmp_path):
    client = FinishCorrectionClient(repeat_invalid=True)
    state = InvestigationState()

    result = ClassificationCoordinator(settings(tmp_path), FixtureWeb(), client).classify(
        CVERecord("VULN-1", "fixture"), taxonomy(), state,
    )

    finish_events = [event for event in state.tool_history if event["tool"] == "finish_investigation"]
    assert result.status == ClassificationStatus.CLASSIFIED
    assert [event["status"] for event in finish_events] == ["error", "success"]
    assert result.operational["research_profile"]["discarded_by_reason"] == {"no_usable_evidence": 1}
    assert state.findings[0].aspect == InvestigationAspect.ROOT_CAUSE


def test_finish_correction_allows_auxiliary_research_until_corrected_submission(tmp_path):
    client = FinishCorrectionResearchClient()
    state = InvestigationState()

    result = ClassificationCoordinator(
        replace(settings(tmp_path), max_search_calls=2, max_fetch_calls=2),
        MultiDocumentWeb(),
        client,
    ).classify(CVERecord("VULN-1", "fixture"), taxonomy(), state)

    assert result.status == ClassificationStatus.CLASSIFIED
    research_events = [event for event in state.tool_history if event["tool"] != "classify_taxonomy_chunk"]
    assert [event["tool"] for event in research_events] == [
        "search",
        "fetch",
        "finish_investigation",
        "search",
        "fetch",
        "finish_investigation",
    ]
    finish_events = [event for event in state.tool_history if event["tool"] == "finish_investigation"]
    assert [event["status"] for event in finish_events] == ["error", "success"]
    assert result.operational["research_profile"]["discarded_findings"] == 0
    assert [item.evidence_id for item in state.evidence] == ["doc-1:p1", "doc-2:p1"]


def test_agent_collects_evidence_then_classifies_complete_taxonomy(tmp_path):
    client = FullFlowClient()
    state = InvestigationState(evidence=[EvidenceRecord("unused", "https://fixture.test/unused", "Unlinked passage.", "web")])
    result = ClassificationCoordinator(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "A vulnerability exists."), taxonomy(), state)
    assert result.status == ClassificationStatus.CLASSIFIED
    assert result.labels[0].label == "MEMORY"
    assert result.labels[0].evidence[0].quote == "The issue causes memory corruption in aggregate processing."
    assert result.operational["coverage"] == {
        "effective_strategy": "exhaustive",
        "total_labels": 1,
        "evaluated_labels": 1,
        "pruned_labels": 0,
        "unresolved_labels": 0,
        "classification_requests": 1,
        "routing_levels": 0,
        "complete": True,
    }
    research_contexts = [json.loads(item["messages"][1]["content"]) for item in client.requests if "tools" in item]
    research_requests = [item for item in client.requests if "tools" in item]
    assert len(research_contexts) == 3
    assert all("taxonomy" not in context for context in research_contexts)
    assert all("provenance" not in context for context in research_contexts)
    record_tools = [
        next(
            (tool["function"] for tool in request["tools"] if tool["function"]["name"] == "record_evidence"),
            None,
        )
        for request in research_requests
    ]
    assert record_tools[:2] == [None, None]
    assert record_tools[2]["parameters"]["properties"]["document_id"]["enum"] == ["doc-1"]
    classification_request = next(item for item in client.requests if "tools" not in item)
    classification_payload = json.loads(classification_request["messages"][1]["content"])
    assert classification_request["response_format"]["type"] == "json_schema"
    assert classification_request["response_format"]["json_schema"]["strict"] is True
    assert classification_payload["vulnerability_profile"]["findings"]
    assert "unknowns" not in classification_payload["vulnerability_profile"]
    assert "summary" not in classification_payload["vulnerability_profile"]
    assert [item["evidence_id"] for item in classification_payload["evidence"]] == ["doc-1:p1"]
    assert classification_payload["taxonomy_chunk"]["labels"][0]["id"] == "MEMORY"
    assert "provenance" not in classification_payload
    assert result.labels[0].evidence[0].evidence_id == "doc-1:p1"
    assert result.provenance["evidence"][0]["evidence_id"] == "doc-1:p1"


def test_record_evidence_response_uses_context_for_quote_and_history_moves_once(tmp_path):
    client = RecordEvidenceFlowClient()
    state = InvestigationState()

    result = ClassificationCoordinator(settings(tmp_path), FixtureWeb(), client).classify(
        CVERecord("VULN-1", "fixture"), taxonomy(), state,
    )

    research_requests = [item for item in client.requests if "tools" in item]
    contexts = [json.loads(item["messages"][1]["content"]) for item in research_requests]
    assert result.status == ClassificationStatus.CLASSIFIED
    assert [[event["tool"] for event in context["tool_history"]] for context in contexts] == [
        [],
        [],
        ["search"],
        ["search", "fetch"],
    ]
    assert contexts[-1]["recorded_evidence"][0]["quote"] == state.evidence[0].quote
    record_result = json.loads(research_requests[-1]["messages"][-1]["content"])
    assert record_result["evidence_id"] == "doc-1:p1"
    assert "quote" not in record_result


def test_agent_can_finish_from_sufficient_nvd_evidence_without_web_calls(tmp_path):
    class NoWebCalls(FixtureWeb):
        def search(self, query):
            raise AssertionError("search should not be called")

        def fetch(self, url):
            raise AssertionError("fetch should not be called")

    class NvdOnlyClient:
        def __init__(self):
            self.requests = []
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

        def create(self, **kwargs):
            self.requests.append(kwargs)
            if "tools" in kwargs:
                return response(Message([ToolCall(
                    "finish-nvd",
                    "finish_investigation",
                    finish_arguments("nvd-description"),
                )]))
            payload = json.loads(kwargs["messages"][1]["content"])
            return response(Message(content=json.dumps({
                "chunk_id": payload["taxonomy_chunk"]["chunk_id"],
                "supported": [{
                    "label": "MEMORY",
                    "confidence": 0.9,
                    "evidence": [{
                        "evidence_id": "nvd-description",
                        "explanation": "The NVD description directly establishes the mechanism.",
                    }],
                }],
            })))

    client = NvdOnlyClient()
    state = InvestigationState(evidence=[EvidenceRecord(
        "nvd-description",
        "https://nvd.test/VULN-1",
        "An unchecked length causes an out-of-bounds read of attacker-selected bytes.",
        "nvd_description",
    )])

    result = ClassificationCoordinator(settings(tmp_path), NoWebCalls(), client).classify(
        CVERecord("VULN-1", state.evidence[0].quote), taxonomy(), state,
    )

    assert result.status == ClassificationStatus.CLASSIFIED
    assert len([request for request in client.requests if "tools" in request]) == 1
    assert state.tool_history[0]["tool"] == "finish_investigation"
    assert state.visited_urls == []


def test_agent_emits_stage_and_tool_progress_without_logging_evidence_text(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="cve_agent")
    result = ClassificationCoordinator(settings(tmp_path), FixtureWeb(), FullFlowClient()).classify(
        CVERecord("VULN-1", "fixture"),
        taxonomy(),
        InvestigationState(),
    )

    assert result.status == ClassificationStatus.CLASSIFIED
    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert "LLM request started stage=investigation" in messages
    assert "query='generic vulnerability mechanism'" in messages
    assert "research tool=fetch status=success" in messages
    assert "classification chunk accepted chunk_id=1 supported=1 supported_labels=MEMORY" in messages
    assert "aspects=root_cause" in messages
    assert "agent finished status=classified" in messages
    assert "The issue causes memory corruption" not in messages


def test_malformed_tool_arguments_are_recoverable(tmp_path):
    client = FullFlowClient(malformed_first=True)
    state = InvestigationState()
    result = ClassificationCoordinator(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), taxonomy(), state)
    assert result.status == ClassificationStatus.CLASSIFIED
    assert state.tool_history[0]["status"] == "error"
    assert "invalid tool arguments" in state.tool_history[0]["error"]


def test_malformed_taxonomy_chunk_gets_one_correction_attempt(tmp_path):
    client = FullFlowClient(malformed_chunk=True)
    result = ClassificationCoordinator(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), taxonomy(), InvestigationState())
    assert result.status == ClassificationStatus.CLASSIFIED
    chunk_requests = [item for item in client.requests if item["messages"][0]["content"].startswith("You are a cybersecurity taxonomy classifier")]
    assert len(chunk_requests) == 2
    assert "response was invalid" in chunk_requests[1]["messages"][-1]["content"]


def test_invalid_chunk_confidence_is_corrected_before_chunk_is_accepted(tmp_path):
    client = FullFlowClient(invalid_chunk_confidence=True)
    result = ClassificationCoordinator(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), taxonomy(), InvestigationState())
    assert result.status == ClassificationStatus.CLASSIFIED
    chunk_requests = [item for item in client.requests if item["messages"][0]["content"].startswith("You are a cybersecurity taxonomy classifier")]
    assert len(chunk_requests) == 2
    assert "invalid confidence" in chunk_requests[1]["messages"][-1]["content"]


def test_qualitative_chunk_confidence_is_normalized_in_final_result(tmp_path):
    client = FullFlowClient(qualitative_chunk_confidence=True)
    result = ClassificationCoordinator(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), taxonomy(), InvestigationState())
    assert result.status == ClassificationStatus.CLASSIFIED
    assert result.labels[0].confidence == 0.85
    assert len([item for item in client.requests if "tools" not in item]) == 1


def test_top_level_chunk_array_is_accepted_as_provider_compatibility_fallback(tmp_path):
    client = FullFlowClient(array_chunk=True)
    result = ClassificationCoordinator(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), taxonomy(), InvestigationState())
    assert result.status == ClassificationStatus.CLASSIFIED
    chunk_requests = [item for item in client.requests if item["messages"][0]["content"].startswith("You are a cybersecurity taxonomy classifier")]
    assert len(chunk_requests) == 1


@pytest.mark.parametrize(
    ("mechanism_supported", "expected_status"),
    [(True, ClassificationStatus.NO_MATCHING_LABEL), (False, ClassificationStatus.NOT_ENOUGH_INFORMATION)],
)
def test_empty_exhaustive_scan_maps_research_status_without_adjudication(tmp_path, mechanism_supported, expected_status):
    client = FullFlowClient(empty_chunk=True, mechanism_supported=mechanism_supported)
    result = ClassificationCoordinator(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), taxonomy(), InvestigationState())
    assert result.status == expected_status
    assert result.labels == []
    assert len([item for item in client.requests if "tools" not in item]) == 1


def test_multiple_taxonomy_chunks_are_merged_without_final_model_call(tmp_path):
    configured = settings(tmp_path).__class__(**{
        **settings(tmp_path).__dict__,
        "max_input_tokens_per_request": 8000,
        "token_budget": 30000,
    })
    long_definition = "Mechanism-specific definition. " * 180
    custom_taxonomy = Taxonomy((
        TaxonomyLabel("LABEL-A", "First label", long_definition),
        TaxonomyLabel("LABEL-B", "Second label", long_definition),
    ))
    client = FullFlowClient()
    result = ClassificationCoordinator(configured, FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), custom_taxonomy, InvestigationState())
    assert result.status == ClassificationStatus.CLASSIFIED
    assert [item.label for item in result.labels] == ["LABEL-A", "LABEL-B"]
    assert result.operational["coverage"]["classification_requests"] == 2
    assert result.operational["coverage"]["evaluated_labels"] == 2
    assert len([item for item in client.requests if "tools" not in item]) == 2


def test_persistently_malformed_later_chunk_returns_partial_with_prior_labels(tmp_path):
    configured = settings(tmp_path).__class__(**{
        **settings(tmp_path).__dict__,
        "max_input_tokens_per_request": 8000,
        "token_budget": 30000,
    })
    long_definition = "Mechanism-specific definition. " * 180
    custom_taxonomy = Taxonomy((
        TaxonomyLabel("LABEL-A", "First label", long_definition),
        TaxonomyLabel("LABEL-B", "Second label", long_definition),
    ))
    state = InvestigationState()
    result = ClassificationCoordinator(configured, FixtureWeb(), FullFlowClient(malformed_chunk_id=2)).classify(
        CVERecord("VULN-1", "fixture"),
        custom_taxonomy,
        state,
    )

    assert result.status == ClassificationStatus.PARTIAL
    assert [item.label for item in result.labels] == ["LABEL-A"]
    assert result.operational["stop_reason"] == "classification_error"
    assert result.operational["coverage"]["evaluated_labels"] == 1
    assert result.operational["coverage"]["unresolved_labels"] == 1
    assert state.tool_history[-1]["status"] == "error"


def test_agent_runs_forced_hybrid_without_exposing_taxonomy_to_research(tmp_path):
    base = settings(tmp_path)
    configured = base.__class__(**{
        **base.__dict__,
        "classification_strategy": ClassificationStrategy.HYBRID,
        "token_budget": 100_000,
    })
    selected_taxonomy = Taxonomy((
        TaxonomyLabel("ROOT", "Root", "Broad memory family."),
        TaxonomyLabel("CHILD", "Child", "Specific memory mechanism.", "ROOT"),
    ))
    client = HybridFlowClient()
    state = InvestigationState()

    result = ClassificationCoordinator(configured, FixtureWeb(), client).classify(
        CVERecord("VULN-1", "fixture"),
        selected_taxonomy,
        state,
    )

    assert result.status == ClassificationStatus.CLASSIFIED
    assert [item.label for item in result.labels] == ["CHILD"]
    assert result.operational["classification"]["configured_strategy"] == "hybrid"
    assert result.operational["classification"]["effective_strategy"] == "hybrid"
    assert result.operational["classification"]["cost_switches"] == 1
    assert result.operational["coverage"] == {
        "effective_strategy": "hybrid",
        "total_labels": 2,
        "evaluated_labels": 2,
        "pruned_labels": 0,
        "unresolved_labels": 0,
        "classification_requests": 2,
        "routing_levels": 1,
        "complete": True,
    }
    research_contexts = [
        json.loads(item["messages"][1]["content"])
        for item in client.requests
        if "tools" in item
    ]
    assert all("taxonomy" not in context for context in research_contexts)
    classification_requests = [item for item in client.requests if "tools" not in item]
    assert len(classification_requests) == 2
    routing_payload = json.loads(classification_requests[0]["messages"][1]["content"])
    assert routing_payload["taxonomy_level"]["labels"] == [{
        "id": "ROOT",
        "name": "Root",
        "description": "Broad memory family.",
        "ancestor_path": [],
        "children": [{"id": "CHILD", "name": "Child"}],
    }]
    assert {item["tool"] for item in state.tool_history} >= {
        "route_taxonomy_level", "switch_taxonomy_strategy", "hybrid_exhaustive_fallback",
    }


def test_agent_reports_empty_provider_response(tmp_path):
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **kwargs: SimpleNamespace(id="empty", choices=None, error=None))))
    try:
        ClassificationCoordinator(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), taxonomy(), InvestigationState())
    except RuntimeError as exc:
        assert "no usable choices" in str(exc)
    else:
        raise AssertionError("expected empty completion failure")


def test_agent_marks_result_partial_when_research_limit_is_reached(tmp_path):
    configured = settings(tmp_path).__class__(**{**settings(tmp_path).__dict__, "max_agent_turns": 1})

    class LimitedClient(FullFlowClient):
        def create(self, **kwargs):
            if "tools" not in kwargs:
                system = kwargs["messages"][0]["content"]
                if system.startswith("You are a cybersecurity taxonomy classifier"):
                    payload = json.loads(kwargs["messages"][1]["content"])
                    return response(Message(content=json.dumps({"chunk_id": payload["taxonomy_chunk"]["chunk_id"], "supported": []})))
            return super().create(**kwargs)

    result = ClassificationCoordinator(configured, FixtureWeb(), LimitedClient()).classify(CVERecord("VULN-1", "fixture"), taxonomy(), InvestigationState())
    assert result.status == ClassificationStatus.PARTIAL
    assert result.operational["stop_reason"] == "investigation_limit"
    assert result.operational["coverage"]["complete"] is True


def test_incomplete_research_preserves_bounded_evidence_for_partial_classification(tmp_path):
    configured = settings(tmp_path).__class__(**{**settings(tmp_path).__dict__, "max_agent_turns": 1})

    class LimitedClient(FullFlowClient):
        def create(self, **kwargs):
            if "tools" not in kwargs:
                payload = json.loads(kwargs["messages"][1]["content"])
                assert payload["vulnerability_profile"]["findings"] == []
                assert [item["evidence_id"] for item in payload["evidence"]] == ["nvd-description"]
                return response(Message(content=json.dumps({
                    "chunk_id": payload["taxonomy_chunk"]["chunk_id"],
                    "supported": [{
                        "label": "MEMORY",
                        "confidence": 0.8,
                        "evidence": [{"evidence_id": "nvd-description", "explanation": "The NVD passage directly supports this label."}],
                    }],
                })))
            return super().create(**kwargs)

    state = InvestigationState(evidence=[EvidenceRecord(
        "nvd-description",
        "https://nvd.test/VULN-1",
        "The implementation performs an out-of-bounds read.",
        "nvd_description",
    )])
    result = ClassificationCoordinator(configured, FixtureWeb(), LimitedClient()).classify(CVERecord("VULN-1", "fixture"), taxonomy(), state)

    assert result.status == ClassificationStatus.PARTIAL
    assert [item.label for item in result.labels] == ["MEMORY"]
