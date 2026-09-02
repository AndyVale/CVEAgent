import json
import logging
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

import cve_agent.research_context as research_context_module
from cve_agent.adapters import CachedWebClient, TavilySearchProvider, UnusableDocumentError
from cve_agent.agent import InvestigationAgent
from cve_agent.config import Settings
from cve_agent.evidence import build_passages
from cve_agent.investigation import build_investigation_profile
from cve_agent.models import CVERecord, ClassificationStatus, Document, EvidenceRecord, InvestigationAspect, InvestigationState, Reference, SearchResult
from cve_agent.prompts import CLASSIFICATION_SYSTEM_PROMPT, HIERARCHY_ROUTING_SYSTEM_PROMPT, RESEARCH_SYSTEM_PROMPT
from cve_agent.provenance import ResearchProvenanceRecorder
from cve_agent.research import ResearchSession, ResearchToolExecutor
from cve_agent.research_context import MAX_NVD_REFERENCE_CANDIDATES, _ResearchContextSerializer, build_research_context, select_reference_candidates
from cve_agent.schemas import AGENT_TOOLS
from cve_agent.strategy import ClassificationStrategy, EffectiveClassificationStrategy
from cve_agent.taxonomy import Taxonomy, TaxonomyLabel, load_taxonomy
from cve_agent.web_policy import PublicWebUrlError, PublicWebUrlPolicy


def settings(tmp_path):
    return Settings(
        model="fixture-model", endpoint="https://fixture.test/v1", api_key=None,
        max_tokens=500, temperature=0.0, top_p=1.0, llm_timeout=5, llm_retry_count=0,
        llm_retry_wait=0.01, llm_retry_max_wait=0.02, llm_min_request_interval=0.0,
        nvd_base_url="https://nvd.test", nvd_timeout=5, nvd_retry_count=0, web_timeout=5, web_retry_count=0,
        web_provider="tavily", tavily_base_url="https://api.tavily.com", tavily_max_results=5,
        tavily_search_depth="basic", tavily_api_key=None, cache_dir=tmp_path / "cache",
        max_document_chars=10000, max_preview_chars=1000, max_download_bytes=100000, database=tmp_path / "db.sqlite",
        token_budget=12000, max_agent_turns=8, max_search_calls=1, max_fetch_calls=1,
        max_investigation_seconds=30,
    )


class FixtureWeb:
    def search(self, query):
        return [SearchResult("Advisory", "https://fixture.test/advisory", "memory corruption")]

    def fetch(self, url):
        return Document(url, "Advisory", "The issue causes memory corruption in aggregate processing.", document_id="doc-1")


class FailingFetchWeb(FixtureWeb):
    def fetch(self, url):
        request = httpx.Request("GET", url)
        raise httpx.HTTPStatusError("forbidden", request=request, response=httpx.Response(403, request=request))


class MultiDocumentWeb(FixtureWeb):
    def fetch(self, url):
        if url.endswith("/secondary"):
            return Document(
                url,
                "Technical analysis",
                "A crafted request bypasses authentication before reaching the vulnerable handler.",
                document_id="doc-2",
            )
        return super().fetch(url)


class ToolCall:
    def __init__(self, call_id, name, arguments):
        self.id = call_id
        self.function = SimpleNamespace(name=name, arguments=arguments if isinstance(arguments, str) else json.dumps(arguments))


class Message:
    def __init__(self, calls=None, content=None):
        self.tool_calls = calls or []
        self.content = content

    def model_dump(self, exclude_none=True):
        result = {"role": "assistant"}
        if self.tool_calls:
            result["tool_calls"] = [{"id": call.id, "type": "function", "function": {"name": call.function.name, "arguments": call.function.arguments}} for call in self.tool_calls]
        if self.content is not None:
            result["content"] = self.content
        return result


def response(message, total=15):
    usage = SimpleNamespace(model_dump=lambda: {"prompt_tokens": total - 5, "completion_tokens": 5, "total_tokens": total})
    return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage)


def finish_arguments(evidence_id="doc-1:p1", *, mechanism_supported=True):
    aspect = InvestigationAspect.ROOT_CAUSE if mechanism_supported else InvestigationAspect.IMPACT
    return {
        "findings": [
            {"aspect": aspect.value, "statement": f"Source-grounded {aspect.value} finding.", "evidence_ids": [evidence_id]},
        ],
        "summary": "The product corrupts memory while processing attacker-controlled aggregate input.",
    }


class FullFlowClient:
    def __init__(self, *, malformed_first=False, malformed_chunk=False, malformed_chunk_id=None, invalid_chunk_confidence=False, qualitative_chunk_confidence=False, array_chunk=False, empty_chunk=False, mechanism_supported=True):
        self.requests = []
        self.research_step = -1 if malformed_first else 0
        self.malformed_chunk = malformed_chunk
        self.malformed_chunk_id = malformed_chunk_id
        self.invalid_chunk_confidence = invalid_chunk_confidence
        self.qualitative_chunk_confidence = qualitative_chunk_confidence
        self.array_chunk = array_chunk
        self.empty_chunk = empty_chunk
        self.mechanism_supported = mechanism_supported
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.requests.append(kwargs)
        if "tools" in kwargs:
            if self.research_step == -1:
                self.research_step = 0
                return response(Message([ToolCall("bad", "search", "{")]))
            steps = [
                ("search", {"query": "generic vulnerability mechanism"}),
                ("fetch", {"url": "https://fixture.test/advisory"}),
                ("finish_investigation", finish_arguments(mechanism_supported=self.mechanism_supported)),
            ]
            name, arguments = steps[self.research_step]
            self.research_step += 1
            return response(Message([ToolCall(f"call-{self.research_step}", name, arguments)]))
        system = kwargs["messages"][0]["content"]
        if system.startswith("You are a cybersecurity taxonomy classifier"):
            payload = json.loads(kwargs["messages"][1]["content"])
            taxonomy_chunk = payload["taxonomy_chunk"]
            if taxonomy_chunk["chunk_id"] == self.malformed_chunk_id:
                return response(Message(content='{"wrong":"shape"}'))
            if self.malformed_chunk:
                self.malformed_chunk = False
                return response(Message(content='{"wrong":"shape"}'))
            confidence = 0.9
            if self.invalid_chunk_confidence:
                self.invalid_chunk_confidence = False
                confidence = "very certain"
            elif self.qualitative_chunk_confidence:
                confidence = "high"
            supported = [{
                "label": taxonomy_chunk["labels"][0]["id"], "confidence": confidence,
                "evidence": [{"evidence_id": "doc-1:p1", "explanation": "The exact passage supports the label."}],
            }] if not self.empty_chunk else []
            content = supported if self.array_chunk else {"chunk_id": taxonomy_chunk["chunk_id"], "supported": supported}
            return response(Message(content=json.dumps(content)))
        raise AssertionError("unexpected model request after taxonomy chunk classification")


class RecordEvidenceFlowClient(FullFlowClient):
    def create(self, **kwargs):
        if "tools" in kwargs:
            self.requests.append(kwargs)
            steps = [
                ("search", {"query": "generic vulnerability mechanism"}),
                ("fetch", {"url": "https://fixture.test/advisory"}),
                ("record_evidence", {"document_id": "doc-1", "passage_id": "p1", "quote_anchor": ""}),
                ("finish_investigation", finish_arguments()),
            ]
            name, arguments = steps[self.research_step]
            self.research_step += 1
            return response(Message([ToolCall(f"call-{self.research_step}", name, arguments)]))
        return super().create(**kwargs)


class FinishCorrectionClient(FullFlowClient):
    def __init__(self, *, repeat_invalid=False):
        super().__init__()
        invalid = finish_arguments()
        invalid["findings"].append({
            "aspect": "impact",
            "statement": "Unsupported impact claim.",
            "evidence_ids": ["doc-1:p99"],
        })
        self.research_steps = [
            ("search", {"query": "generic vulnerability mechanism"}),
            ("fetch", {"url": "https://fixture.test/advisory"}),
            ("finish_investigation", invalid),
            ("finish_investigation", invalid if repeat_invalid else finish_arguments()),
        ]

    def create(self, **kwargs):
        if "tools" in kwargs:
            self.requests.append(kwargs)
            name, arguments = self.research_steps[self.research_step]
            self.research_step += 1
            return response(Message([ToolCall(f"call-{self.research_step}", name, arguments)]))
        return super().create(**kwargs)


class FinishCorrectionResearchClient(FinishCorrectionClient):
    def __init__(self):
        super().__init__()
        corrected = finish_arguments()
        corrected["findings"].append({
            "aspect": "exploitation_mechanism",
            "statement": "A crafted request bypasses authentication before reaching the handler.",
            "evidence_ids": ["doc-2:p1"],
        })
        self.research_steps[3:3] = [
            (None, {}),
            ("search", {"query": "specific vendor vulnerability mechanism"}),
            ("fetch", {"url": "https://fixture.test/secondary"}),
        ]
        self.research_steps[-1] = ("finish_investigation", corrected)

    def create(self, **kwargs):
        if "tools" in kwargs and self.research_steps[self.research_step][0] is None:
            self.requests.append(kwargs)
            self.research_step += 1
            return response(Message(content="I need another source before correcting the citations."))
        return super().create(**kwargs)


class HybridFlowClient(FullFlowClient):
    def create(self, **kwargs):
        if "tools" not in kwargs and kwargs["messages"][0]["content"] == HIERARCHY_ROUTING_SYSTEM_PROMPT:
            self.requests.append(kwargs)
            payload = json.loads(kwargs["messages"][1]["content"])
            level = payload["taxonomy_level"]
            return response(Message(content=json.dumps({
                "level_id": level["level_id"],
                "decisions": [{
                    "label": label["id"],
                    "decision": "supported",
                    "confidence": 0.9,
                    "explanation": "The evidence supports this hierarchy branch.",
                    "evidence": [{
                        "evidence_id": "doc-1:p1",
                        "explanation": "The exact passage supports this hierarchy branch.",
                    }],
                } for label in level["labels"]],
            })))
        return super().create(**kwargs)


def taxonomy():
    return Taxonomy((TaxonomyLabel("MEMORY", "Memory Safety Error", "Invalid memory access or corruption."),))


def public_url_policy():
    return PublicWebUrlPolicy(lambda _hostname, _port: ("93.184.216.34",))


def test_prompts_require_mechanism_focused_evidence_without_exposing_taxonomy_to_research():
    prompt = RESEARCH_SYSTEM_PROMPT.casefold()
    assert "taxonomy" not in prompt
    assert "strongest starting evidence" in prompt
    assert "without performing web research" not in prompt
    assert "search the web only" not in prompt
    assert "never call fetch" not in prompt
    assert "same stored passages" in prompt
    assert "one repeat fetch per document is permitted" in prompt
    assert "further repeats return a no-new-information error" in prompt
    assert "search omits results" in prompt
    assert "immediately after each successful fetch" in prompt
    assert "before searching, fetching another source" in prompt
    assert "never a search result or its snippet" in prompt
    assert "must not be recorded again" in prompt
    assert "separate root_cause or exploitation_mechanism finding" in prompt
    assert "act as a trusted service" in prompt
    assert "could allow remote code execution" in prompt
    assert "do not finish on that phrase alone" in prompt
    assert "make a targeted search" in prompt
    assert "additional targeted research is appropriate" in prompt
    assert "information that could change classification" in prompt
    assert "expected only to restate recorded facts" in prompt
    assert "root cause" in RESEARCH_SYSTEM_PROMPT
    assert "record_evidence" in RESEARCH_SYSTEM_PROMPT
    assert "untrusted source data" in RESEARCH_SYSTEM_PROMPT
    assert "not a checklist" in RESEARCH_SYSTEM_PROMPT
    assert "consequence" in CLASSIFICATION_SYSTEM_PROMPT
    assert "does not by itself prove" in CLASSIFICATION_SYSTEM_PROMPT
    assert "regardless of their organizational aspect" in CLASSIFICATION_SYSTEM_PROMPT
    assert "acts as a trusted service through an alternate route" in CLASSIFICATION_SYSTEM_PROMPT
    assert "semantic specialization" in HIERARCHY_ROUTING_SYSTEM_PROMPT
    assert "exactly one routing decision" in HIERARCHY_ROUTING_SYSTEM_PROMPT


def test_finish_tool_uses_five_optional_topics_without_unknown_or_status_matrix():
    finish = next(item["function"] for item in AGENT_TOOLS if item["function"]["name"] == "finish_investigation")
    parameters = finish["parameters"]
    aspects = parameters["properties"]["findings"]["items"]["properties"]["aspect"]["enum"]

    assert parameters["required"] == ["findings", "summary"]
    assert set(aspects) == {item.value for item in InvestigationAspect}
    assert "unknowns" not in parameters["properties"]
    assert "information_status" not in parameters["properties"]
    fetch = next(item["function"] for item in AGENT_TOOLS if item["function"]["name"] == "fetch")
    assert "available_documents" in fetch["description"]
    assert "same stored passages" in fetch["description"]
    assert "Never fetch" not in fetch["description"]
    assert "permitted to redisplay" in fetch["description"]
    assert "immediately record" in fetch["description"].casefold()
    record = next(item["function"] for item in AGENT_TOOLS if item["function"]["name"] == "record_evidence")
    assert "every distinct, substantive passage" in record["description"]
    assert "nvd-description" in record["description"]
    assert "already in recorded_evidence" in record["description"]
    assert "separate root_cause or exploitation_mechanism findings" in finish["description"]


def test_finish_investigation_promotes_fetched_passages_and_discards_only_unsupported_findings(tmp_path):
    documents = {"doc-1": FixtureWeb().fetch("https://fixture.test/advisory")}
    arguments = finish_arguments()
    arguments["findings"].append({
        "aspect": "impact",
        "statement": "Unsupported impact claim.",
        "evidence_ids": ["doc-1:p99"],
    })
    arguments["unknowns"] = [{"aspect": "root_cause", "explanation": "Legacy field is ignored."}]
    state = InvestigationState()

    outcome = build_investigation_profile(arguments, state, documents, max_preview_chars=settings(tmp_path).max_preview_chars)

    assert outcome.information_status == "sufficient"
    assert [item.aspect for item in outcome.findings] == [InvestigationAspect.ROOT_CAUSE]
    assert outcome.discarded_findings == 1
    assert outcome.discarded_reasons == ("no_usable_evidence",)
    assert outcome.evidence_issues[0].reason == "unknown_evidence"
    assert outcome.promoted_evidence == 1
    assert state.evidence[0].evidence_id == "doc-1:p1"
    assert state.evidence[0].verification == "finish_reference"


def test_finish_investigation_derives_insufficient_without_core_mechanism_or_web_evidence(tmp_path):
    state = InvestigationState(evidence=[EvidenceRecord("nvd-description", "https://nvd.test/VULN-1", "Known impact.", "nvd_description")])
    outcome = build_investigation_profile(
        finish_arguments("nvd-description", mechanism_supported=False),
        state,
        {},
        max_preview_chars=settings(tmp_path).max_preview_chars,
    )

    assert outcome.information_status == "insufficient"
    assert outcome.findings[0].aspect == InvestigationAspect.IMPACT


def test_finish_investigation_auto_promotes_an_unrecorded_late_passage(tmp_path):
    content = "\n".join(f"Passage {index}: " + "technical detail " * 10 for index in range(1, 20))
    document = Document("https://fixture.test/long", "Long advisory", content, document_id="doc-late")
    late_passage = build_passages("doc-late", content, max_chars=settings(tmp_path).max_preview_chars)[-1]
    arguments = finish_arguments(late_passage.passage_id)

    outcome = build_investigation_profile(
        arguments,
        InvestigationState(),
        {"doc-late": document},
        max_preview_chars=settings(tmp_path).max_preview_chars,
    )

    assert outcome.findings[0].evidence_ids == (late_passage.passage_id,)
    assert outcome.promoted_evidence == 1


def test_finish_validation_does_not_promote_evidence_before_acceptance(tmp_path):
    documents = {"doc-1": FixtureWeb().fetch("https://fixture.test/advisory")}
    state = InvestigationState()

    outcome = build_investigation_profile(
        finish_arguments(),
        state,
        documents,
        max_preview_chars=settings(tmp_path).max_preview_chars,
        promote_evidence=False,
    )

    assert outcome.findings[0].evidence_ids == ("doc-1:p1",)
    assert outcome.promoted_evidence == 1
    assert state.evidence == []


def test_finish_investigation_gets_one_evidence_correction_before_materialization(tmp_path):
    client = FinishCorrectionClient()
    state = InvestigationState()
    snapshots = []

    def checkpoint():
        if state.tool_history:
            snapshots.append((state.tool_history[-1]["tool"], state.tool_history[-1]["status"], len(state.evidence)))

    result = InvestigationAgent(settings(tmp_path), FixtureWeb(), client).classify(
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

    result = InvestigationAgent(settings(tmp_path), FixtureWeb(), client).classify(
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

    result = InvestigationAgent(
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
    result = InvestigationAgent(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "A vulnerability exists."), taxonomy(), state)
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

    result = InvestigationAgent(settings(tmp_path), FixtureWeb(), client).classify(
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

    result = InvestigationAgent(settings(tmp_path), NoWebCalls(), client).classify(
        CVERecord("VULN-1", state.evidence[0].quote), taxonomy(), state,
    )

    assert result.status == ClassificationStatus.CLASSIFIED
    assert len([request for request in client.requests if "tools" in request]) == 1
    assert state.tool_history[0]["tool"] == "finish_investigation"
    assert state.visited_urls == []


def test_research_context_prioritizes_and_bounds_nvd_references():
    generic = tuple(Reference(f"https://generic.test/{index}", tags=("Third Party Advisory",)) for index in range(30))
    vendor = Reference("https://vendor.test/advisory", tags=("Vendor Advisory",))
    cve = CVERecord("VULN-1", "fixture", generic + (vendor,))

    selected = select_reference_candidates(cve.references)
    context = build_research_context(
        cve,
        InvestigationState(),
        {},
        turn=0,
        searches=0,
        fetches=0,
        max_turns=8,
        max_searches=2,
        max_fetches=3,
    )

    assert len(selected) == MAX_NVD_REFERENCE_CANDIDATES
    assert selected[0] == vendor
    assert context["cve"]["references"][0]["url"] == vendor.url
    assert context["cve"]["reference_count"] == 31
    assert context["cve"]["omitted_reference_count"] == 31 - MAX_NVD_REFERENCE_CANDIDATES
    assert "description" not in context["cve"]
    assert "facts" not in context


def test_research_context_serializer_reuses_static_fragments_and_defers_exchange_history(monkeypatch):
    description = "Unique NVD description serialized exactly once."
    cve = CVERecord(
        "CVE-2024-12345",
        description,
        (Reference("https://vendor.test/advisory", tags=("Vendor Advisory",)),),
        {"published": "2024-01-01"},
    )
    state = InvestigationState(
        evidence=[EvidenceRecord("nvd-description", "https://nvd.test/CVE-2024-12345", description, "nvd_description")],
        tool_history=[
            {"tool": "get_cve", "status": "success"},
            {"tool": "fetch", "status": "success", "document_id": "doc-1"},
        ],
    )
    documents = {"doc-1": Document(
        "https://vendor.test/advisory",
        "Vendor advisory",
        "Technical evidence.",
        document_id="doc-1",
    )}
    encoded = []
    original_dumps = research_context_module._json_dumps

    def counting_dumps(value):
        encoded.append(value)
        return original_dumps(value)

    monkeypatch.setattr(research_context_module, "_json_dumps", counting_dumps)
    serializer = _ResearchContextSerializer(cve)
    current = serializer.render(
        state,
        documents,
        [{"role": "tool", "content": "fetch result"}],
        turn=1,
        searches=0,
        fetches=1,
        max_turns=8,
        max_searches=2,
        max_fetches=3,
    )
    initial_encodings = len(encoded)
    following = serializer.render(
        state,
        documents,
        [],
        turn=2,
        searches=0,
        fetches=1,
        max_turns=8,
        max_searches=2,
        max_fetches=3,
    )

    current_context = json.loads(current)
    following_context = json.loads(following)
    assert "description" not in current_context["cve"]
    assert current.count(description) == 1
    assert [event["tool"] for event in current_context["tool_history"]] == ["get_cve"]
    assert [event["tool"] for event in following_context["tool_history"]] == ["get_cve", "fetch"]
    assert len(encoded) == initial_encodings + 1  # Only the changed budget counters were encoded.

    state.evidence.append(EvidenceRecord("doc-1:p1", documents["doc-1"].url, "Technical evidence.", "web"))
    state.tool_history.append({"tool": "record_evidence", "status": "success", "evidence_id": "doc-1:p1"})
    documents["doc-2"] = Document("https://vendor.test/second", "Second", "More evidence.", document_id="doc-2")
    before_changes = len(encoded)
    updated = serializer.render(
        state,
        documents,
        [],
        turn=3,
        searches=0,
        fetches=2,
        max_turns=8,
        max_searches=2,
        max_fetches=3,
    )

    assert len(encoded) == before_changes + 4  # New evidence, event, document catalog, and budget.
    assert len(json.loads(updated)["recorded_evidence"]) == 2

    state.evidence[:] = [state.evidence[-1]]
    state.tool_history.reverse()
    documents.pop("doc-1")
    rebuilt = json.loads(serializer.render(
        state,
        documents,
        [],
        turn=4,
        searches=0,
        fetches=2,
        max_turns=8,
        max_searches=2,
        max_fetches=3,
    ))

    assert [item["evidence_id"] for item in rebuilt["recorded_evidence"]] == ["doc-1:p1"]
    assert [item["tool"] for item in rebuilt["tool_history"]] == ["record_evidence", "fetch", "get_cve"]
    assert [item["document_id"] for item in rebuilt["available_documents"]] == ["doc-2"]


def test_research_context_identifies_both_urls_of_fetched_documents():
    document = Document(
        "https://vendor.test/final",
        "Vendor advisory",
        "Technical vulnerability evidence.",
        document_id="vendor-doc",
        requested_url="https://vendor.test/start",
    )

    context = build_research_context(
        CVERecord("VULN-1", "fixture"),
        InvestigationState(),
        {"vendor-doc": document},
        turn=1,
        searches=0,
        fetches=1,
        max_turns=8,
        max_searches=2,
        max_fetches=3,
    )

    assert context["available_documents"] == [{
        "document_id": "vendor-doc",
        "requested_url": "https://vendor.test/start",
        "resolved_url": "https://vendor.test/final",
        "title": "Vendor advisory",
    }]


def test_agent_emits_stage_and_tool_progress_without_logging_evidence_text(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="cve_agent")
    result = InvestigationAgent(settings(tmp_path), FixtureWeb(), FullFlowClient()).classify(
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
    result = InvestigationAgent(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), taxonomy(), state)
    assert result.status == ClassificationStatus.CLASSIFIED
    assert state.tool_history[0]["status"] == "error"
    assert "invalid tool arguments" in state.tool_history[0]["error"]


def test_malformed_taxonomy_chunk_gets_one_correction_attempt(tmp_path):
    client = FullFlowClient(malformed_chunk=True)
    result = InvestigationAgent(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), taxonomy(), InvestigationState())
    assert result.status == ClassificationStatus.CLASSIFIED
    chunk_requests = [item for item in client.requests if item["messages"][0]["content"].startswith("You are a cybersecurity taxonomy classifier")]
    assert len(chunk_requests) == 2
    assert "response was invalid" in chunk_requests[1]["messages"][-1]["content"]


def test_invalid_chunk_confidence_is_corrected_before_chunk_is_accepted(tmp_path):
    client = FullFlowClient(invalid_chunk_confidence=True)
    result = InvestigationAgent(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), taxonomy(), InvestigationState())
    assert result.status == ClassificationStatus.CLASSIFIED
    chunk_requests = [item for item in client.requests if item["messages"][0]["content"].startswith("You are a cybersecurity taxonomy classifier")]
    assert len(chunk_requests) == 2
    assert "invalid confidence" in chunk_requests[1]["messages"][-1]["content"]


def test_qualitative_chunk_confidence_is_normalized_in_final_result(tmp_path):
    client = FullFlowClient(qualitative_chunk_confidence=True)
    result = InvestigationAgent(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), taxonomy(), InvestigationState())
    assert result.status == ClassificationStatus.CLASSIFIED
    assert result.labels[0].confidence == 0.85
    assert len([item for item in client.requests if "tools" not in item]) == 1


def test_top_level_chunk_array_is_accepted_as_provider_compatibility_fallback(tmp_path):
    client = FullFlowClient(array_chunk=True)
    result = InvestigationAgent(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), taxonomy(), InvestigationState())
    assert result.status == ClassificationStatus.CLASSIFIED
    chunk_requests = [item for item in client.requests if item["messages"][0]["content"].startswith("You are a cybersecurity taxonomy classifier")]
    assert len(chunk_requests) == 1


@pytest.mark.parametrize(
    ("mechanism_supported", "expected_status"),
    [(True, ClassificationStatus.NO_MATCHING_LABEL), (False, ClassificationStatus.NOT_ENOUGH_INFORMATION)],
)
def test_empty_exhaustive_scan_maps_research_status_without_adjudication(tmp_path, mechanism_supported, expected_status):
    client = FullFlowClient(empty_chunk=True, mechanism_supported=mechanism_supported)
    result = InvestigationAgent(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), taxonomy(), InvestigationState())
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
    result = InvestigationAgent(configured, FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), custom_taxonomy, InvestigationState())
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
    result = InvestigationAgent(configured, FixtureWeb(), FullFlowClient(malformed_chunk_id=2)).classify(
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
    assert InvestigationAgent(forced_hybrid_flat, FixtureWeb(), FullFlowClient())._classification_plan(flat).effective_strategy == EffectiveClassificationStrategy.EXHAUSTIVE

    assert InvestigationAgent(base, FixtureWeb(), FullFlowClient())._classification_plan(hierarchy).effective_strategy == EffectiveClassificationStrategy.EXHAUSTIVE

    forced_hybrid = base.__class__(**{
        **base.__dict__,
        "classification_strategy": ClassificationStrategy.HYBRID,
        "token_budget": 100_000,
    })
    assert InvestigationAgent(forced_hybrid, FixtureWeb(), FullFlowClient())._classification_plan(hierarchy).effective_strategy == EffectiveClassificationStrategy.HYBRID

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
    assert InvestigationAgent(auto_large, FixtureWeb(), FullFlowClient())._classification_plan(large_hierarchy).effective_strategy == EffectiveClassificationStrategy.HYBRID

    forced_exhaustive = auto_large.__class__(**{
        **auto_large.__dict__,
        "classification_strategy": ClassificationStrategy.EXHAUSTIVE,
    })
    assert InvestigationAgent(forced_exhaustive, FixtureWeb(), FullFlowClient())._classification_plan(large_hierarchy).effective_strategy == EffectiveClassificationStrategy.EXHAUSTIVE


def test_auto_selects_hybrid_for_large_hybrid_fixture(tmp_path):
    fixture = Path(__file__).parents[1] / "fixtures" / "hybrid_taxonomy.json"
    selected_taxonomy = load_taxonomy(fixture)
    base = settings(tmp_path)
    configured = base.__class__(**{
        **base.__dict__,
        "token_budget": 50_000,
    })

    plan = InvestigationAgent(configured, FixtureWeb(), FullFlowClient())._classification_plan(selected_taxonomy)

    assert plan.effective_strategy == EffectiveClassificationStrategy.HYBRID
    assert len(plan.chunks) == 2
    assert 0 < plan.budget.classification_reserve < configured.token_budget
    assert plan.budget.investigation_limit == configured.token_budget - plan.budget.classification_reserve


def test_flat_taxonomy_logs_that_configured_hybrid_strategy_is_ignored(tmp_path, caplog):
    configured = settings(tmp_path).__class__(**{
        **settings(tmp_path).__dict__,
        "classification_strategy": ClassificationStrategy.HYBRID,
    })
    caplog.set_level(logging.INFO, logger="cve_agent.agent")

    plan = InvestigationAgent(configured, FixtureWeb(), FullFlowClient())._classification_plan(taxonomy())

    assert plan.effective_strategy == EffectiveClassificationStrategy.EXHAUSTIVE
    assert "ignoring configured_strategy=hybrid" in caplog.text


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

    result = InvestigationAgent(configured, FixtureWeb(), client).classify(
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
        InvestigationAgent(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "fixture"), taxonomy(), InvestigationState())
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

    result = InvestigationAgent(configured, FixtureWeb(), LimitedClient()).classify(CVERecord("VULN-1", "fixture"), taxonomy(), InvestigationState())
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
    result = InvestigationAgent(configured, FixtureWeb(), LimitedClient()).classify(CVERecord("VULN-1", "fixture"), taxonomy(), state)

    assert result.status == ClassificationStatus.PARTIAL
    assert [item.label for item in result.labels] == ["MEMORY"]


def test_record_evidence_resolves_anchor_and_reuses_fetch(tmp_path):
    class CountingWeb(FixtureWeb):
        def __init__(self):
            self.fetches = 0

        def fetch(self, url):
            self.fetches += 1
            return super().fetch(url)

    web = CountingWeb()
    executor = ResearchToolExecutor(settings(tmp_path), web)
    state = InvestigationState()
    session = ResearchSession(provenance=ResearchProvenanceRecorder(
        CVERecord("CVE-2024-12345", "Fixture vulnerability."),
        state,
        max_preview_chars=settings(tmp_path).max_preview_chars,
    ))
    first = executor.execute("fetch", {"url": "https://fixture.test/advisory"}, state, session)
    session.provenance.record_tool_call("fetch", {"url": "https://fixture.test/advisory"}, first, session.documents)
    second = executor.execute("fetch", {"url": "https://fixture.test/advisory"}, state, session)
    session.provenance.record_tool_call("fetch", {"url": "https://fixture.test/advisory"}, second, session.documents)
    third = executor.execute("fetch", {"url": "https://fixture.test/advisory"}, state, session)
    session.provenance.record_tool_call("fetch", {"url": "https://fixture.test/advisory"}, third, session.documents)
    recorded = executor.execute(
        "record_evidence",
        {"document_id": "doc-1", "passage_id": "", "quote_anchor": "issue causes memory corruption aggregate processing"},
        state,
        session,
    )
    assert web.fetches == 1
    assert session.fetches == 1
    assert first["reused"] is False
    assert second["reused"] is True
    assert third["reused"] is True
    assert "error" in third
    assert "passages" not in third
    assert [item.reused for item in state.provenance.fetches] == [False, True, True]
    assert second["document_id"] == first["document_id"]
    assert recorded["evidence_id"] == "doc-1:p1"
    assert "quote" not in recorded
    assert state.evidence[0].verification == "fuzzy_anchor"

    repeated = executor.execute(
        "record_evidence",
        {"document_id": "doc-1", "passage_id": "p1", "quote_anchor": ""},
        state,
        session,
    )
    assert repeated == {
        "recorded": False,
        "evidence_id": "doc-1:p1",
        "evidence_count": 1,
        "instruction": "This evidence is already recorded; continue without recording it again.",
    }


@pytest.mark.parametrize(
    "equivalent_url",
    [
        "HTTPS://FIXTURE.TEST:443/advisory#section",
        "https://fixture.test:443/advisory",
        "https://fixture.test/advisory#other",
    ],
)
def test_fetch_reuses_normalized_url_variants_without_consuming_quota(tmp_path, equivalent_url):
    class CountingWeb(FixtureWeb):
        def __init__(self):
            self.fetches = 0

        def fetch(self, url):
            self.fetches += 1
            return super().fetch(url)

    web = CountingWeb()
    executor = ResearchToolExecutor(settings(tmp_path), web)
    session, state = ResearchSession(), InvestigationState()

    executor.execute("fetch", {"url": "https://fixture.test/advisory"}, state, session)
    reused = executor.execute("fetch", {"url": equivalent_url}, state, session)

    assert reused["reused"] is True
    assert web.fetches == 1
    assert session.fetches == 1


def test_search_omits_results_for_available_requested_and_resolved_urls(tmp_path):
    class ExistingAndNovelWeb(FixtureWeb):
        def search(self, query):
            return [
                SearchResult("Requested", "https://fixture.test/start"),
                SearchResult("Resolved", "https://fixture.test/final#section"),
                SearchResult("Novel", "https://fixture.test/novel"),
            ]

        def fetch(self, url):
            return Document(
                "https://fixture.test/final",
                "Advisory",
                "Substantive redirected vulnerability evidence.",
                document_id="redirected",
                requested_url=url,
            )

    executor = ResearchToolExecutor(settings(tmp_path), ExistingAndNovelWeb())
    session, state = ResearchSession(), InvestigationState()

    executor.execute("fetch", {"url": "https://fixture.test/start"}, state, session)
    result = executor.execute("search", {"query": "new technical evidence"}, state, session)

    assert [item["url"] for item in result["results"]] == ["https://fixture.test/novel"]
    assert result["available_results_omitted"] == 2
    assert "available_documents" in result["instruction"]


def test_fetch_reuses_both_sides_of_a_redirect(tmp_path):
    class RedirectWeb(FixtureWeb):
        def __init__(self):
            self.fetches = 0

        def fetch(self, url):
            self.fetches += 1
            return Document(
                "https://fixture.test/final",
                "Advisory",
                "Substantive redirected vulnerability evidence.",
                document_id="redirected",
                requested_url=url,
                redirect_chain=(url, "https://fixture.test/final"),
            )

    web = RedirectWeb()
    executor = ResearchToolExecutor(settings(tmp_path), web)
    session, state = ResearchSession(), InvestigationState()

    first = executor.execute("fetch", {"url": "https://fixture.test/start"}, state, session)
    resolved = executor.execute("fetch", {"url": "https://fixture.test/final#details"}, state, session)

    assert first["reused"] is False
    assert resolved["reused"] is True
    assert web.fetches == 1


def test_fetch_normalizes_an_implicit_root_path(tmp_path):
    class CountingWeb(FixtureWeb):
        def __init__(self):
            self.fetches = 0

        def fetch(self, url):
            self.fetches += 1
            return Document(url, content="Substantive vulnerability evidence.", document_id="root-doc")

    web = CountingWeb()
    executor = ResearchToolExecutor(settings(tmp_path), web)
    session, state = ResearchSession(), InvestigationState()

    executor.execute("fetch", {"url": "https://fixture.test"}, state, session)
    reused = executor.execute("fetch", {"url": "https://fixture.test/#details"}, state, session)

    assert reused["reused"] is True
    assert web.fetches == 1


def test_fetch_keeps_distinct_query_strings_separate(tmp_path):
    class CountingWeb(FixtureWeb):
        def __init__(self):
            self.fetches = 0

        def fetch(self, url):
            self.fetches += 1
            return Document(url, content="Substantive vulnerability evidence.", document_id=f"doc-{self.fetches}")

    configured = settings(tmp_path).__class__(**{**settings(tmp_path).__dict__, "max_fetch_calls": 2})
    web = CountingWeb()
    executor = ResearchToolExecutor(configured, web)
    session, state = ResearchSession(), InvestigationState()

    first = executor.execute("fetch", {"url": "https://fixture.test/advisory?version=1"}, state, session)
    second = executor.execute("fetch", {"url": "https://fixture.test/advisory?version=2"}, state, session)

    assert first["reused"] is False
    assert second["reused"] is False
    assert web.fetches == 2
    assert session.fetches == 2


def test_unavailable_document_does_not_poison_later_evidence_retry(tmp_path):
    executor = ResearchToolExecutor(settings(tmp_path), FixtureWeb())
    session, state = ResearchSession(), InvestigationState()
    arguments = {
        "document_id": "doc-1",
        "passage_id": "p1",
        "quote_anchor": "",
    }

    unavailable = executor.execute("record_evidence", arguments, state, session)
    executor.execute("fetch", {"url": "https://fixture.test/advisory"}, state, session)
    recorded = executor.execute("record_evidence", arguments, state, session)

    assert unavailable["instruction"] == "Fetch a search result before recording evidence."
    assert unavailable["available_document_ids"] == []
    assert recorded["evidence_id"] == "doc-1:p1"


def test_fetch_failure_is_recoverable(tmp_path):
    executor = ResearchToolExecutor(settings(tmp_path), FailingFetchWeb())
    session, state = ResearchSession(), InvestigationState()
    result = executor.execute("fetch", {"url": "https://fixture.test/forbidden"}, state, session)
    assert "HTTPStatusError" in result["error"]
    repeated = executor.execute("fetch", {"url": "https://fixture.test/forbidden"}, state, session)
    assert "already attempted" in repeated["error"]


def test_tool_errors_redact_configured_credentials(tmp_path):
    configured = settings(tmp_path).__class__(**{
        **settings(tmp_path).__dict__,
        "api_key": "model-secret",
        "tavily_api_key": "search-secret",
    })

    class SecretErrorWeb(FixtureWeb):
        def search(self, query):
            raise RuntimeError("provider included model-secret and search-secret")

    result = ResearchToolExecutor(configured, SecretErrorWeb()).execute(
        "search",
        {"query": "VULN-1"},
        InvestigationState(),
        ResearchSession(),
    )

    assert "model-secret" not in result["error"]
    assert "search-secret" not in result["error"]
    assert result["error"].count("[REDACTED]") == 2


def test_cached_web_client_extracts_html(tmp_path):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="<html><body><main><p>Important vulnerability evidence with enough context for reliable extraction.</p></main></body></html>"))
    document = CachedWebClient(
        settings(tmp_path),
        http_client=httpx.Client(transport=transport),
        url_policy=public_url_policy(),
    ).fetch("https://fixture.test/page")
    assert "Important vulnerability evidence" in document.content
    assert "<main>" not in document.content
    assert document.metadata["extraction_method"] == "trafilatura"
    assert document.metadata["extraction_input_chars"] > document.metadata["extraction_output_chars"]


def test_cached_web_client_records_raw_extraction_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr("cve_agent.adapters.trafilatura.extract", lambda *_args, **_kwargs: None)
    raw = "<html><body>Fallback vulnerability evidence.</body></html>"
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text=raw))

    document = CachedWebClient(
        settings(tmp_path),
        http_client=httpx.Client(transport=transport),
        url_policy=public_url_policy(),
    ).fetch("https://fixture.test/fallback")

    assert document.content == raw
    assert document.metadata["extraction_method"] == "raw_fallback"
    assert document.metadata["extraction_input_chars"] == len(raw)
    assert document.metadata["extraction_output_chars"] == len(raw)


def test_cached_web_client_rejects_javascript_shell_without_caching(tmp_path):
    url = "https://fixture.test/javascript-shell"
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, text="You need to enable JavaScript to run this app.")
    )
    client = CachedWebClient(
        settings(tmp_path),
        http_client=httpx.Client(transport=transport),
        url_policy=public_url_policy(),
    )

    with pytest.raises(UnusableDocumentError, match="JavaScript placeholder"):
        client.fetch(url)

    assert not client._cache("fetch", url).exists()


def test_cached_web_client_rejects_legacy_cached_javascript_shell(tmp_path):
    client = CachedWebClient(settings(tmp_path), url_policy=public_url_policy())
    url = "https://fixture.test/legacy-javascript-shell"
    document = Document(
        url,
        "Application",
        "Please enable JavaScript to continue.",
        document_id="legacy-shell",
        requested_url=url,
    )
    client._cache("fetch", url).write_text(json.dumps(document.__dict__), encoding="utf-8")

    with pytest.raises(UnusableDocumentError, match="choose another source"):
        client.fetch(url)


def test_cached_web_client_accepts_legacy_document_metadata(tmp_path):
    client = CachedWebClient(settings(tmp_path), url_policy=public_url_policy())
    url = "https://fixture.test/legacy"
    legacy = Document(
        url,
        "Legacy advisory",
        "Legacy cached vulnerability evidence.",
        {"truncated": False, "download_bytes": 42, "content_type": "text/plain"},
        "legacy-doc",
        url,
    )
    client._cache("fetch", url).write_text(json.dumps(legacy.__dict__), encoding="utf-8")

    document = client.fetch(url)

    assert document.document_id == "legacy-doc"
    assert document.metadata["download_bytes"] == 42
    assert "extraction_method" not in document.metadata


def test_cached_web_client_records_redirect_provenance(tmp_path):
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/final"})
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="Resolved vulnerability evidence.")

    client = CachedWebClient(
        settings(tmp_path),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        url_policy=public_url_policy(),
    )
    document = client.fetch("https://fixture.test/start")
    assert document.requested_url == "https://fixture.test/start"
    assert document.url == "https://fixture.test/final"
    assert document.redirect_chain == ("https://fixture.test/start", "https://fixture.test/final")


def test_cached_web_client_blocks_private_redirect_before_request(tmp_path):
    requested = []

    def handler(request):
        requested.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://127.0.0.1/private"})

    client = CachedWebClient(
        settings(tmp_path),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        url_policy=public_url_policy(),
    )

    with pytest.raises(PublicWebUrlError, match="non-public address"):
        client.fetch("https://fixture.test/start")
    assert requested == ["https://fixture.test/start"]


def test_cached_web_client_bounds_redirects_without_retrying_chain(tmp_path):
    requested = []

    def handler(request):
        requested.append(str(request.url))
        return httpx.Response(302, headers={"location": "/next"})

    client = CachedWebClient(
        settings(tmp_path),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        url_policy=public_url_policy(),
    )

    with pytest.raises(PublicWebUrlError, match="exceeded 10 redirects"):
        client.fetch("https://fixture.test/start")
    assert len(requested) == 11


def test_cached_web_client_discards_non_public_search_results(tmp_path):
    client = CachedWebClient(
        settings(tmp_path),
        searcher=lambda _query: [
            SearchResult("Public", "https://fixture.test/advisory"),
            SearchResult("Private", "http://127.0.0.1/internal"),
        ],
        url_policy=public_url_policy(),
    )

    assert [item.title for item in client.search("VULN-1")] == ["Public"]


def test_cached_web_client_discards_malformed_cached_search_result_with_reason(tmp_path, caplog):
    client = CachedWebClient(settings(tmp_path), url_policy=public_url_policy())
    query = "VULN-1 advisory"
    client._cache("search", query).write_text(
        json.dumps([
            {
                "title": "Malformed",
                "url": r"https://www\.sentinelone.com/blog",
                "snippet": "cached result",
            }
        ]),
        encoding="utf-8",
    )
    caplog.set_level(logging.WARNING, logger="cve_agent.adapters")

    assert client.search(query) == []
    assert "detail=public-web URL has an invalid hostname" in caplog.text


def test_public_web_fetch_failure_has_traceable_tool_error(tmp_path):
    client = CachedWebClient(settings(tmp_path), url_policy=public_url_policy())
    result = ResearchToolExecutor(settings(tmp_path), client).execute(
        "fetch",
        {"url": "http://127.0.0.1/private"},
        InvestigationState(),
        ResearchSession(),
    )

    assert "fetch failed (PublicWebUrlError)" in result["error"]
    assert "non-public address: 127.0.0.1" in result["error"]


def test_fetch_logs_strip_query_strings_and_fragments(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="cve_agent.adapters")
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="Useful vulnerability evidence."))
    url = "https://fixture.test/advisory?temporary-secret=value#private"

    CachedWebClient(
        settings(tmp_path),
        http_client=httpx.Client(transport=transport),
        url_policy=public_url_policy(),
    ).fetch(url)

    assert "https://fixture.test/advisory" in caplog.text
    assert "temporary-secret" not in caplog.text
    assert "#private" not in caplog.text


def test_cached_web_client_rejects_large_or_non_text_responses(tmp_path):
    small_limit = settings(tmp_path).__class__(**{**settings(tmp_path).__dict__, "max_download_bytes": 5})
    large_transport = httpx.MockTransport(lambda request: httpx.Response(200, headers={"content-type": "text/plain"}, content=b"too large"))
    try:
        CachedWebClient(
            small_limit,
            http_client=httpx.Client(transport=large_transport),
            url_policy=public_url_policy(),
        ).fetch("https://fixture.test/large")
    except ValueError as exc:
        assert "max_download_bytes" in str(exc)
    else:
        raise AssertionError("expected the streamed size limit to reject the response")

    binary_transport = httpx.MockTransport(lambda request: httpx.Response(200, headers={"content-type": "application/octet-stream"}, content=b"binary"))
    try:
        CachedWebClient(
            settings(tmp_path),
            http_client=httpx.Client(transport=binary_transport),
            url_policy=public_url_policy(),
        ).fetch("https://fixture.test/binary")
    except ValueError as exc:
        assert "unsupported content type" in str(exc)
    else:
        raise AssertionError("expected binary content to be rejected")


def test_tavily_search_provider_maps_results(tmp_path):
    configured = settings(tmp_path).__class__(**{**settings(tmp_path).__dict__, "tavily_api_key": "fixture-key"})
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"results": [{"title": "Advisory", "url": "https://fixture.test/advisory", "content": "memory corruption"}]}))
    results = TavilySearchProvider(configured, http_client=httpx.Client(transport=transport)).search("VULN-1")
    assert results == [SearchResult("Advisory", "https://fixture.test/advisory", "memory corruption")]
