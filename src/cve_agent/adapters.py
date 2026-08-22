from __future__ import annotations

import json
import time
import urllib.parse
import urllib.error
import urllib.request
import hashlib
import logging
from pathlib import Path
from typing import Any, Callable

import httpx
import trafilatura

from cve_agent.config import Settings
from cve_agent.models import CVERecord, Document, Reference, SearchResult


logger = logging.getLogger(__name__)


def _request_json(url: str, timeout: float, retries: int, headers: dict[str, str] | None = None) -> Any:
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read())
        except (TimeoutError, urllib.error.URLError):
            if attempt >= retries:
                raise
            time.sleep(0.2 * (2**attempt))


class NVDClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def get_cve(self, cve_id: str) -> CVERecord:
        url = f"{self.settings.nvd_base_url}?{urllib.parse.urlencode({'cveId': cve_id})}"
        payload = _request_json(url, self.settings.nvd_timeout, self.settings.retry_count)
        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            raise LookupError(f"CVE not found: {cve_id}")
        cve = vulnerabilities[0].get("cve", {})
        descriptions = cve.get("descriptions", [])
        description = next((x.get("value", "") for x in descriptions if x.get("lang") == "en"), descriptions[0].get("value", "") if descriptions else "")
        references = tuple(Reference(x.get("url", ""), x.get("source"), tuple(x.get("tags", []))) for x in cve.get("references", []) if x.get("url"))
        return CVERecord(cve.get("id", cve_id), description, references, {"published": cve.get("published"), "last_modified": cve.get("lastModified"), "source_identifier": cve.get("sourceIdentifier")})


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
        for attempt in range(self.settings.retry_count + 1):
            try:
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
                return [SearchResult(item.get("title", ""), item["url"], item.get("content", "")) for item in data.get("results", []) if item.get("url")]
            except RuntimeError:
                raise
            except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError, httpx.HTTPStatusError):
                if attempt >= self.settings.retry_count:
                    raise
                time.sleep(0.2 * (2**attempt))
        raise RuntimeError("Tavily search failed")


class CachedWebClient:
    def __init__(self, settings: Settings, searcher: Callable[[str], list[SearchResult]] | None = None, http_client: httpx.Client | None = None):
        self.settings = settings
        self.searcher = searcher
        self.http_client = http_client
        self.settings.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache(self, prefix: str, key: str) -> Path:
        import hashlib
        return self.settings.cache_dir / f"{prefix}-{hashlib.sha256(key.encode()).hexdigest()}.json"

    def search(self, query: str) -> list[SearchResult]:
        path = self._cache("search", query)
        if path.exists():
            logger.info("search cache hit query_chars=%d", len(query))
            return [SearchResult(**item) for item in json.loads(path.read_text(encoding="utf-8"))]
        if self.searcher is None:
            raise RuntimeError("no web search provider configured")
        logger.info("search cache miss query_chars=%d", len(query))
        results = self.searcher(query)
        path.write_text(json.dumps([x.__dict__ for x in results]), encoding="utf-8")
        return results

    def fetch(self, url: str) -> Document:
        path = self._cache("fetch", url)
        if path.exists():
            document = Document(**json.loads(path.read_text(encoding="utf-8")))
            logger.info("fetch cache hit url=%s document_id=%s chars=%d", url, document.document_id, len(document.content))
            return document
        logger.info("fetch cache miss url=%s", url)
        for attempt in range(self.settings.retry_count + 1):
            try:
                logger.info("fetch attempt=%d/%d url=%s", attempt + 1, self.settings.retry_count + 1, url)
                if self.http_client is None:
                    with httpx.Client(timeout=self.settings.web_timeout, follow_redirects=True, headers={"User-Agent": "cve-agent/0.1"}) as client:
                        response = client.get(url)
                else:
                    response = self.http_client.get(url)
                logger.info("fetch response status=%d final_url=%s content_type=%s bytes=%d", response.status_code, response.url, response.headers.get("content-type", "unknown"), len(response.content))
                response.raise_for_status()
                raw_response = response.text
                break
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                retryable = status == 408 or status == 425 or status == 429 or status >= 500
                logger.warning("fetch HTTP failure status=%d retryable=%s url=%s", status, retryable, url)
                if not retryable or attempt >= self.settings.retry_count:
                    raise
                time.sleep(0.2 * (2**attempt))
            except httpx.RequestError as exc:
                logger.warning("fetch network failure type=%s message=%s url=%s", type(exc).__name__, str(exc), url)
                if attempt >= self.settings.retry_count:
                    raise
                time.sleep(0.2 * (2**attempt))
        raw_content = raw_response[: self.settings.max_document_chars]
        content = trafilatura.extract(raw_content, url=url, include_comments=False, include_tables=True) or raw_content
        content = content[: self.settings.max_document_chars]
        logger.info("fetch extracted url=%s raw_chars=%d extracted_chars=%d extraction_used_fallback=%s", url, len(raw_response), len(content), content == raw_content)
        metadata = trafilatura.extract_metadata(raw_content, default_url=url) if raw_content else None
        title = (metadata.title or "") if metadata else ""
        document = Document(url=url, title=title, content=content, metadata={"truncated": len(raw_response) > len(raw_content)}, document_id=hashlib.sha256(url.encode()).hexdigest()[:16])
        path.write_text(json.dumps(document.__dict__), encoding="utf-8")
        return document
