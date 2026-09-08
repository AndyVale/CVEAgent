from __future__ import annotations

import logging
import time

import httpx

from cve_agent.core.config import Settings
from cve_agent.core.sources import SearchResult


logger = logging.getLogger("cve_agent.adapters")


class TavilySearchProvider:
    """Search adapter for Tavily's authenticated REST API."""

    def __init__(self, settings: Settings, http_client: httpx.Client | None = None):
        self.settings = settings
        self.http_client = http_client

    def search(self, query: str) -> list[SearchResult]:
        if not self.settings.tavily_api_key:
            raise RuntimeError("TAVILY_API_KEY is not configured; set it in the environment to enable web search")
        payload = {
            "query": query,
            "search_depth": self.settings.tavily_search_depth,
            "max_results": self.settings.tavily_max_results,
            "include_answer": False,
            "include_raw_content": False,
        }
        headers = {"Authorization": f"Bearer {self.settings.tavily_api_key}", "Content-Type": "application/json"}
        for attempt in range(self.settings.web_retry_count + 1):
            try:
                logger.info(
                    "Tavily search attempt=%d/%d query_chars=%d depth=%s max_results=%d",
                    attempt + 1,
                    self.settings.web_retry_count + 1,
                    len(query),
                    self.settings.tavily_search_depth,
                    self.settings.tavily_max_results,
                )
                if self.http_client is None:
                    with httpx.Client(timeout=self.settings.web_timeout, headers={"User-Agent": "cve-agent/0.1"}) as client:
                        response = client.post(f"{self.settings.tavily_base_url.rstrip('/')}/search", json=payload, headers=headers)
                else:
                    response = self.http_client.post(f"{self.settings.tavily_base_url.rstrip('/')}/search", json=payload, headers=headers)
                if response.status_code == 401:
                    raise RuntimeError("Tavily rejected TAVILY_API_KEY (HTTP 401)")
                if response.status_code == 429 or response.status_code >= 500:
                    response.raise_for_status()
                response.raise_for_status()
                data = response.json()
                results = [SearchResult(item.get("title", ""), item["url"], item.get("content", "")) for item in data.get("results", []) if item.get("url")]
                logger.info("Tavily search finished results=%d", len(results))
                return results
            except RuntimeError:
                raise
            except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError, httpx.HTTPStatusError) as exc:
                logger.warning(
                    "Tavily search failed attempt=%d/%d retrying=%s error_type=%s",
                    attempt + 1,
                    self.settings.web_retry_count + 1,
                    attempt < self.settings.web_retry_count,
                    type(exc).__name__,
                )
                if attempt >= self.settings.web_retry_count:
                    raise
                time.sleep(0.2 * (2**attempt))
        raise RuntimeError("Tavily search failed")
