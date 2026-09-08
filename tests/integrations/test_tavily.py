import httpx

from cve_agent.core.sources import SearchResult
from cve_agent.integrations.tavily import TavilySearchProvider
from tests.support.agent import settings


def test_tavily_search_provider_maps_results(tmp_path):
    configured = settings(tmp_path).__class__(**{**settings(tmp_path).__dict__, "tavily_api_key": "fixture-key"})
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"results": [{"title": "Advisory", "url": "https://fixture.test/advisory", "content": "memory corruption"}]}))
    results = TavilySearchProvider(configured, http_client=httpx.Client(transport=transport)).search("VULN-1")
    assert results == [SearchResult("Advisory", "https://fixture.test/advisory", "memory corruption")]
