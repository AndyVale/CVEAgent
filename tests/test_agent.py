import json
from types import SimpleNamespace

import httpx

from cve_agent.adapters import CachedWebClient, TavilySearchProvider
from cve_agent.agent import InvestigationAgent
from cve_agent.config import Settings
from cve_agent.models import CVERecord, ClassificationStatus, Document, EvidenceRecord, InvestigationState, SearchResult
from cve_agent.taxonomy import Taxonomy, TaxonomyLabel


def settings(tmp_path):
    return Settings(
        model="fixture-model", endpoint="https://fixture.test/v1", api_key=None,
        max_tokens=500, temperature=0.0, top_p=1.0, llm_timeout=5, llm_retry_count=0,
        llm_retry_wait=0.01, llm_retry_max_wait=0.02, llm_min_request_interval=0.0,
        nvd_base_url="https://nvd.test", nvd_timeout=5, nvd_retry_count=0, web_timeout=5, web_retry_count=0,
        web_provider="tavily", tavily_base_url="https://api.tavily.com", tavily_max_results=5,
        tavily_search_depth="basic", tavily_api_key=None, cache_dir=tmp_path / "cache",
        max_document_chars=10000, max_preview_chars=1000, max_download_bytes=100000, database=tmp_path / "db.sqlite",
        token_budget=5000, max_agent_turns=8, max_search_calls=1, max_fetch_calls=1,
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


class FullFlowClient:
    def __init__(self, *, malformed_first=False, malformed_chunk=False):
        self.requests = []
        self.research_step = -1 if malformed_first else 0
        self.malformed_chunk = malformed_chunk
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
                ("record_evidence", {"document_id": "doc-1", "passage_id": "doc-1:p1", "quote_anchor": ""}),
                ("finish_investigation", {"information_status": "sufficient", "summary": "The product corrupts memory while processing aggregate input."}),
            ]
            name, arguments = steps[self.research_step]
            self.research_step += 1
            return response(Message([ToolCall(f"call-{self.research_step}", name, arguments)]))
        system = kwargs["messages"][0]["content"]
        if system.startswith("Evaluate every"):
            if self.malformed_chunk:
                self.malformed_chunk = False
                return response(Message(content='{"wrong":"shape"}'))
            payload = json.loads(kwargs["messages"][1]["content"])
            return response(Message(content=json.dumps({"chunk_id": payload["chunk_id"], "supported": [{
                "label": payload["labels"][0]["id"], "confidence": 0.9,
                "evidence": [{"evidence_id": "doc-1:p1", "explanation": "The exact passage supports the label."}],
            }]})))
        return response(Message(content=json.dumps({"status": "classified", "labels": [{
            "label": "MEMORY", "confidence": 0.9,
            "evidence": [{"evidence_id": "doc-1:p1", "explanation": "The exact passage supports the label."}],
        }]})))


def taxonomy():
    return Taxonomy((TaxonomyLabel("MEMORY", "Memory Safety Error", "Invalid memory access or corruption."),))


def test_agent_collects_evidence_then_classifies_complete_taxonomy(tmp_path):
    client = FullFlowClient()
    result = InvestigationAgent(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("VULN-1", "A vulnerability exists."), taxonomy(), InvestigationState())
    assert result.status == ClassificationStatus.CLASSIFIED
    assert result.labels[0].label == "MEMORY"
    assert result.labels[0].evidence[0].quote == "The issue causes memory corruption in aggregate processing."
    assert result.operational["coverage"]["complete"] is True
    research_contexts = [json.loads(item["messages"][1]["content"]) for item in client.requests if "tools" in item]
    assert all("taxonomy" not in context for context in research_contexts)


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
    chunk_requests = [item for item in client.requests if item["messages"][0]["content"].startswith("Evaluate every")]
    assert len(chunk_requests) == 2
    assert "response was invalid" in chunk_requests[1]["messages"][-1]["content"]


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
                if system.startswith("Evaluate every"):
                    payload = json.loads(kwargs["messages"][1]["content"])
                    return response(Message(content=json.dumps({"chunk_id": payload["chunk_id"], "supported": []})))
            return super().create(**kwargs)

    result = InvestigationAgent(configured, FixtureWeb(), LimitedClient()).classify(CVERecord("VULN-1", "fixture"), taxonomy(), InvestigationState())
    assert result.status == ClassificationStatus.PARTIAL
    assert result.operational["stop_reason"] == "investigation_limit"
    assert result.operational["coverage"]["complete"] is True


def test_record_evidence_resolves_anchor_and_reuses_fetch(tmp_path):
    class CountingWeb(FixtureWeb):
        def __init__(self):
            self.fetches = 0

        def fetch(self, url):
            self.fetches += 1
            return super().fetch(url)

    web = CountingWeb()
    agent = InvestigationAgent(settings(tmp_path), web, FullFlowClient())
    documents, state = {}, InvestigationState()
    first = agent._execute("fetch", {"url": "https://fixture.test/advisory"}, state, documents, 0, 0, set())
    second = agent._execute("fetch", {"url": "https://fixture.test/advisory"}, state, documents, 0, 1, set())
    recorded = agent._execute("record_evidence", {"document_id": "doc-1", "passage_id": "", "quote_anchor": "issue causes memory corruption aggregate processing"}, state, documents, 0, 1, set())
    assert web.fetches == 1
    assert second["document_id"] == first["document_id"]
    assert recorded["evidence_id"] == "doc-1:p1"
    assert state.evidence[0].verification == "fuzzy_anchor"


def test_fetch_failure_is_recoverable(tmp_path):
    agent = InvestigationAgent(settings(tmp_path), FailingFetchWeb(), FullFlowClient())
    failed_urls = set()
    result = agent._execute("fetch", {"url": "https://fixture.test/forbidden"}, InvestigationState(), {}, 0, 0, failed_urls)
    assert "HTTPStatusError" in result["error"]
    repeated = agent._execute("fetch", {"url": "https://fixture.test/forbidden"}, InvestigationState(), {}, 0, 0, failed_urls)
    assert "already failed" in repeated["error"]


def test_cached_web_client_extracts_html(tmp_path):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="<html><body><main><p>Important vulnerability evidence with enough context for reliable extraction.</p></main></body></html>"))
    document = CachedWebClient(settings(tmp_path), http_client=httpx.Client(transport=transport)).fetch("https://fixture.test/page")
    assert "Important vulnerability evidence" in document.content
    assert "<main>" not in document.content


def test_cached_web_client_records_redirect_provenance(tmp_path):
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/final"})
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="Resolved vulnerability evidence.")

    client = CachedWebClient(settings(tmp_path), http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    document = client.fetch("https://fixture.test/start")
    assert document.requested_url == "https://fixture.test/start"
    assert document.url == "https://fixture.test/final"
    assert document.redirect_chain == ("https://fixture.test/start", "https://fixture.test/final")


def test_cached_web_client_rejects_large_or_non_text_responses(tmp_path):
    small_limit = settings(tmp_path).__class__(**{**settings(tmp_path).__dict__, "max_download_bytes": 5})
    large_transport = httpx.MockTransport(lambda request: httpx.Response(200, headers={"content-type": "text/plain"}, content=b"too large"))
    try:
        CachedWebClient(small_limit, http_client=httpx.Client(transport=large_transport)).fetch("https://fixture.test/large")
    except ValueError as exc:
        assert "max_download_bytes" in str(exc)
    else:
        raise AssertionError("expected the streamed size limit to reject the response")

    binary_transport = httpx.MockTransport(lambda request: httpx.Response(200, headers={"content-type": "application/octet-stream"}, content=b"binary"))
    try:
        CachedWebClient(settings(tmp_path), http_client=httpx.Client(transport=binary_transport)).fetch("https://fixture.test/binary")
    except ValueError as exc:
        assert "unsupported content type" in str(exc)
    else:
        raise AssertionError("expected binary content to be rejected")


def test_tavily_search_provider_maps_results(tmp_path):
    configured = settings(tmp_path).__class__(**{**settings(tmp_path).__dict__, "tavily_api_key": "fixture-key"})
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"results": [{"title": "Advisory", "url": "https://fixture.test/advisory", "content": "memory corruption"}]}))
    results = TavilySearchProvider(configured, http_client=httpx.Client(transport=transport)).search("VULN-1")
    assert results == [SearchResult("Advisory", "https://fixture.test/advisory", "memory corruption")]
