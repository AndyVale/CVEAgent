import json
from types import SimpleNamespace

import httpx

from cve_agent.adapters import CachedWebClient
from cve_agent.adapters import TavilySearchProvider
from cve_agent.agent import InvestigationAgent
from cve_agent.config import Settings
from cve_agent.models import CVERecord, InvestigationState, SearchResult
from cve_agent.taxonomy import Taxonomy, TaxonomyLabel


def settings(tmp_path):
    return Settings(
        model="fixture-model", endpoint="https://fixture.test/v1", api_key=None,
        max_tokens=500, temperature=0.0, top_p=1.0, llm_timeout=5, llm_retry_count=0, llm_retry_wait=0.01, llm_retry_max_wait=0.02,
        nvd_base_url="https://nvd.test", nvd_timeout=5, retry_count=0, web_timeout=5,
        web_provider="tavily", tavily_base_url="https://api.tavily.com", tavily_max_results=5,
        tavily_search_depth="basic", tavily_api_key=None,
        cache_dir=tmp_path / "cache", max_document_chars=10000, max_preview_chars=1000,
        database=tmp_path / "db.sqlite", token_budget=5000, max_agent_turns=8,
        max_search_calls=1, max_fetch_calls=1, max_investigation_seconds=30,
    )


class FixtureWeb:
    def search(self, query):
        return [SearchResult("Advisory", "https://fixture.test/advisory", "memory corruption")]

    def fetch(self, url):
        from cve_agent.models import Document
        return Document(url, "Advisory", "The issue causes memory corruption in aggregate processing.", document_id="doc-1")


class FailingFetchWeb(FixtureWeb):
    def fetch(self, url):
        raise httpx.HTTPStatusError("forbidden", request=httpx.Request("GET", url), response=httpx.Response(403, request=httpx.Request("GET", url)))


class ToolCall:
    def __init__(self, call_id, name, arguments):
        self.id = call_id
        self.function = SimpleNamespace(name=name, arguments=json.dumps(arguments))


class Message:
    def __init__(self, calls):
        self.tool_calls = calls
        self.content = None

    def model_dump(self, exclude_none=True):
        return {"role": "assistant", "tool_calls": [{"id": call.id, "type": "function", "function": {"name": call.function.name, "arguments": call.function.arguments}} for call in self.tool_calls]}


class AgentClient:
    def __init__(self):
        self.requests = []
        self.steps = [
            ("search", {"query": "CVE-1 aggregate memory corruption"}),
            ("fetch", {"url": "https://fixture.test/advisory"}),
            ("record_evidence", {"document_id": "doc-1", "quote": "memory corruption", "explanation": "The advisory directly describes the impact."}),
            ("finish_investigation", {"status": "classified", "labels": [{"label": "CWE-119", "confidence": 0.9, "evidence": [{"url": "https://fixture.test/advisory", "quote": "memory corruption", "explanation": "The advisory directly describes the impact."}]}]}),
        ]
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.requests.append(kwargs)
        name, arguments = self.steps[len(self.requests) - 1]
        usage = SimpleNamespace(model_dump=lambda: {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15})
        return SimpleNamespace(choices=[SimpleNamespace(message=Message([ToolCall(f"call-{len(self.requests)}", name, arguments)]))], usage=usage)


def test_agent_reports_empty_provider_response(tmp_path):
    class EmptyResponseClient:
        def __init__(self):
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=lambda **kwargs: SimpleNamespace(
                id="req-empty", model="fixture-model", choices=None, error=None
            )))

    client = EmptyResponseClient()
    taxonomy = Taxonomy((TaxonomyLabel("CWE-119", "Memory Buffer Errors", "memory buffer errors"),))
    try:
        InvestigationAgent(settings(tmp_path), FixtureWeb(), client).classify(
            CVERecord("CVE-1", "A vulnerability exists."), [], taxonomy, InvestigationState()
        )
    except RuntimeError as exc:
        assert "no usable choices" in str(exc)
        assert "req-empty" in str(exc)
    else:
        raise AssertionError("expected empty provider response to fail clearly")


def test_agent_promotes_only_recorded_evidence(tmp_path):
    client = AgentClient()
    taxonomy = Taxonomy((TaxonomyLabel("CWE-119", "Memory Buffer Errors", "memory buffer errors"),))
    result = InvestigationAgent(settings(tmp_path), FixtureWeb(), client).classify(CVERecord("CVE-1", "A vulnerability exists."), [], taxonomy, InvestigationState())
    assert result.status == "classified"
    assert result.labels[0].label == "CWE-119"
    assert len(client.requests) == 4
    assert all(request["tool_choice"] == "auto" for request in client.requests)
    assert all(request["parallel_tool_calls"] is False for request in client.requests)
    final_context = json.loads(client.requests[-1]["messages"][1]["content"])
    assert final_context["recorded_evidence"][0]["quote"] == "memory corruption"
    assert final_context["fetched_urls"] == ["https://fixture.test/advisory"]
    assert final_context["available_documents"][0]["document_id"] == "doc-1"


def test_cached_web_client_extracts_and_bounds_html(tmp_path):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="<html><head><title>Advisory</title></head><body><nav>Noise</nav><main><p>Important vulnerability evidence.</p></main></body></html>"))
    client = CachedWebClient(settings(tmp_path), http_client=httpx.Client(transport=transport))
    document = client.fetch("https://fixture.test/page")
    assert document.document_id
    assert "Important vulnerability evidence." in document.content
    assert "<main>" not in document.content


def test_agent_stops_when_turn_limit_is_reached(tmp_path):
    client = AgentClient()
    configured = settings(tmp_path)
    configured = configured.__class__(**{**configured.__dict__, "max_agent_turns": 1})
    result = InvestigationAgent(configured, FixtureWeb(), client).classify(
        CVERecord("CVE-1", "A vulnerability exists."), [],
        Taxonomy((TaxonomyLabel("CWE-119", "Memory Buffer Errors", "memory buffer errors"),)), InvestigationState(),
    )
    assert result.status == "not_enough_information"
    assert result.operational["stop_reason"] == "investigation_limit"


def test_tavily_search_provider_maps_results_and_authenticates(tmp_path):
    configured = settings(tmp_path).__class__(**{**settings(tmp_path).__dict__, "tavily_api_key": "tvly-fixture"})
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"results": [{"title": "Advisory", "url": "https://fixture.test/advisory", "content": "memory corruption"}]}))
    provider = TavilySearchProvider(configured, http_client=httpx.Client(transport=transport))
    results = provider.search("CVE-1")
    assert results == [SearchResult("Advisory", "https://fixture.test/advisory", "memory corruption")]


def test_fetch_failure_is_returned_to_agent_instead_of_escaping(tmp_path):
    agent = InvestigationAgent(settings(tmp_path), FailingFetchWeb(), AgentClient())
    failed_urls = set()
    result = agent._execute("fetch", {"url": "https://fixture.test/forbidden"}, InvestigationState(), {}, 0, 0, failed_urls)
    assert result["url"] == "https://fixture.test/forbidden"
    assert "HTTPStatusError" in result["error"]
    assert "Continue with another source" in result["error"]
    repeated = agent._execute("fetch", {"url": "https://fixture.test/forbidden"}, InvestigationState(), {}, 0, 0, failed_urls)
    assert "already failed" in repeated["error"]


def test_repeated_fetch_reuses_document_without_network_call(tmp_path):
    class CountingWeb(FixtureWeb):
        def __init__(self):
            self.fetches = 0

        def fetch(self, url):
            self.fetches += 1
            return super().fetch(url)

    web = CountingWeb()
    agent = InvestigationAgent(settings(tmp_path), web, AgentClient())
    documents = {}
    state = InvestigationState()
    first = agent._execute("fetch", {"url": "https://fixture.test/advisory"}, state, documents, 0, 0, set())
    second = agent._execute("fetch", {"url": "https://fixture.test/advisory"}, state, documents, 0, 1, set())
    assert web.fetches == 1
    assert second["document_id"] == first["document_id"]
    assert "no network request was made" in second["instruction"]
