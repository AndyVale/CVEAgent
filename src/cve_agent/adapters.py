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
from cve_agent.identifiers import normalize_cve_id
from cve_agent.logging_config import safe_url
from cve_agent.models import CVERecord, Document, Reference, SearchResult
from cve_agent.web_policy import PublicWebUrlError, PublicWebUrlPolicy


logger = logging.getLogger(__name__)


def _request_json(url: str, timeout: float, retries: int, headers: dict[str, str] | None = None) -> Any:
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers=headers or {})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read())
        except (TimeoutError, urllib.error.URLError) as exc:
            logger.warning(
                "NVD request failed attempt=%d/%d retrying=%s error_type=%s",
                attempt + 1,
                retries + 1,
                attempt < retries,
                type(exc).__name__,
            )
            if attempt >= retries:
                raise
            time.sleep(0.2 * (2**attempt))


class NVDClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def get_cve(self, cve_id: str) -> CVERecord:
        cve_id = normalize_cve_id(cve_id)
        logger.info("[%s] NVD request started", cve_id)
        url = f"{self.settings.nvd_base_url}?{urllib.parse.urlencode({'cveId': cve_id})}"
        payload = _request_json(url, self.settings.nvd_timeout, self.settings.nvd_retry_count)
        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            raise LookupError(f"CVE not found: {cve_id}")
        cve = vulnerabilities[0].get("cve", {})
        try:
            returned_cve_id = normalize_cve_id(cve.get("id"))
        except ValueError as exc:
            raise LookupError("NVD returned a response without a valid CVE ID") from exc
        if returned_cve_id != cve_id:
            raise LookupError(f"NVD returned {returned_cve_id} for requested {cve_id}")
        descriptions = cve.get("descriptions", [])
        description = next((x.get("value", "") for x in descriptions if x.get("lang") == "en"), descriptions[0].get("value", "") if descriptions else "")
        references = tuple(Reference(x.get("url", ""), x.get("source"), tuple(x.get("tags", []))) for x in cve.get("references", []) if x.get("url"))
        record = CVERecord(returned_cve_id, description, references, {"published": cve.get("published"), "last_modified": cve.get("lastModified"), "source_identifier": cve.get("sourceIdentifier")})
        logger.info("[%s] NVD request finished description_chars=%d references=%d", cve_id, len(description), len(references))
        return record


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


class CachedWebClient:
    def __init__(
        self,
        settings: Settings,
        searcher: Callable[[str], list[SearchResult]] | None = None,
        http_client: httpx.Client | None = None,
        url_policy: PublicWebUrlPolicy | None = None,
    ):
        self.settings = settings
        self.searcher = searcher
        self.http_client = http_client
        self.url_policy = url_policy or PublicWebUrlPolicy()
        self.settings.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache(self, prefix: str, key: str) -> Path:
        import hashlib
        return self.settings.cache_dir / f"{prefix}-{hashlib.sha256(key.encode()).hexdigest()}.json"

    def search(self, query: str) -> list[SearchResult]:
        path = self._cache("search", query)
        if path.exists():
            logger.info("search cache hit query_chars=%d", len(query))
            cached = [SearchResult(**item) for item in json.loads(path.read_text(encoding="utf-8"))]
            return self._public_search_results(cached)
        if self.searcher is None:
            raise RuntimeError("no web search provider configured")
        logger.info("search cache miss query_chars=%d", len(query))
        results = self._public_search_results(self.searcher(query))
        path.write_text(json.dumps([x.__dict__ for x in results]), encoding="utf-8")
        logger.info("search cached query_chars=%d results=%d", len(query), len(results))
        return results

    def fetch(self, url: str) -> Document:
        self.url_policy.validate(url)
        path = self._cache("fetch", url)
        if path.exists():
            cached = json.loads(path.read_text(encoding="utf-8"))
            cached["redirect_chain"] = tuple(cached.get("redirect_chain", ()))
            document = Document(**cached)
            self._validate_document_urls(document)
            logger.info("fetch cache hit url=%s document_id=%s chars=%d", safe_url(url), document.document_id, len(document.content))
            return document
        logger.info("fetch cache miss url=%s", safe_url(url))
        for attempt in range(self.settings.web_retry_count + 1):
            try:
                logger.info("fetch attempt=%d/%d url=%s", attempt + 1, self.settings.web_retry_count + 1, safe_url(url))
                raw_bytes, response_url, redirect_chain, content_type, encoding = self._download(url)
                logger.info("fetch response final_url=%s content_type=%s bytes=%d", safe_url(response_url), content_type or "unknown", len(raw_bytes))
                raw_response = raw_bytes.decode(encoding or "utf-8", errors="replace")
                break
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                retryable = status == 408 or status == 425 or status == 429 or status >= 500
                logger.warning("fetch HTTP failure status=%d retryable=%s url=%s", status, retryable, safe_url(url))
                if not retryable or attempt >= self.settings.web_retry_count:
                    raise
                time.sleep(0.2 * (2**attempt))
            except httpx.RequestError as exc:
                logger.warning("fetch network failure type=%s url=%s", type(exc).__name__, safe_url(url))
                if attempt >= self.settings.web_retry_count:
                    raise
                time.sleep(0.2 * (2**attempt))
        raw_content = raw_response[: self.settings.max_document_chars]
        extraction_url = safe_url(response_url)
        content = trafilatura.extract(raw_content, url=extraction_url, include_comments=False, include_tables=True) or raw_content
        content = content[: self.settings.max_document_chars]
        logger.info("fetch extracted url=%s raw_chars=%d extracted_chars=%d extraction_used_fallback=%s", safe_url(url), len(raw_response), len(content), content == raw_content)
        metadata = trafilatura.extract_metadata(raw_content, default_url=extraction_url) if raw_content else None
        title = (metadata.title or "") if metadata else ""
        document = Document(
            url=response_url,
            title=title,
            content=content,
            metadata={"truncated": len(raw_response) > len(raw_content), "download_bytes": len(raw_bytes), "content_type": content_type},
            document_id=hashlib.sha256(url.encode()).hexdigest()[:16],
            requested_url=url,
            redirect_chain=redirect_chain,
        )
        path.write_text(json.dumps(document.__dict__), encoding="utf-8")
        return document

    def _public_search_results(self, results: list[SearchResult]) -> list[SearchResult]:
        accepted: list[SearchResult] = []
        for result in results:
            rejection = self.url_policy.rejection_reason(result.url)
            if rejection:
                logger.warning(
                    "discarding non-public search result url=%s detail=%s",
                    safe_url(str(result.url)),
                    rejection,
                )
            else:
                accepted.append(result)
        return accepted

    def _validate_document_urls(self, document: Document) -> None:
        urls = (
            document.requested_url or document.url,
            *document.redirect_chain,
            document.url,
        )
        for item in dict.fromkeys(urls):
            self.url_policy.validate(item)

    def _download(self, url: str) -> tuple[bytes, str, tuple[str, ...], str, str | None]:
        client = self.http_client or httpx.Client(timeout=self.settings.web_timeout, headers={"User-Agent": "cve-agent/0.1"})
        close_client = self.http_client is None
        try:
            current_url = url
            redirect_chain: list[str] = []
            for _ in range(11):
                self.url_policy.validate(current_url)
                with client.stream("GET", current_url, follow_redirects=False) as response:
                    response_url = str(response.url)
                    self.url_policy.validate(response_url)
                    if response.has_redirect_location:
                        redirect_chain.append(response_url)
                        current_url = str(response.url.join(response.headers["location"]))
                        continue
                    response.raise_for_status()
                    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    if content_type and not _is_text_content_type(content_type):
                        raise ValueError(f"unsupported content type: {content_type}")
                    chunks: list[bytes] = []
                    size = 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > self.settings.max_download_bytes:
                            raise ValueError(f"response exceeds max_download_bytes={self.settings.max_download_bytes}")
                        chunks.append(chunk)
                    return (
                        b"".join(chunks),
                        response_url,
                        tuple((*redirect_chain, response_url)),
                        content_type,
                        response.encoding,
                    )
            raise PublicWebUrlError("public-web fetch exceeded 10 redirects")
        finally:
            if close_client:
                client.close()


def _is_text_content_type(content_type: str) -> bool:
    return content_type.startswith("text/") or content_type in {
        "application/json",
        "application/xml",
        "application/xhtml+xml",
        "application/rss+xml",
    }
