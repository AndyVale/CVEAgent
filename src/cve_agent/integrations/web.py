from __future__ import annotations

from typing import Callable
import hashlib
import logging
import time

import httpx
import trafilatura

from cve_agent.core.config import Settings
from cve_agent.core.sources import Document, SearchResult
from cve_agent.integrations.content import _ensure_usable_document_content, _is_text_content_type
from cve_agent.integrations.web_policy import PublicWebUrlError, PublicWebUrlPolicy
from cve_agent.runtime.diagnostics import safe_url


logger = logging.getLogger("cve_agent.adapters")



class WebClient:
    """Uncached web retrieval with bounded downloads and public-URL validation."""

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

    def search(self, query: str) -> list[SearchResult]:
        if self.searcher is None:
            raise RuntimeError("no web search provider configured")
        return self.searcher(query)

    def fetch(self, url: str) -> Document:
        self.url_policy.validate(url)
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
        extraction_url = safe_url(response_url)
        extracted = trafilatura.extract(
            raw_response,
            url=extraction_url,
            include_comments=False,
            include_tables=True,
        )
        extraction_method = "trafilatura" if extracted and extracted.strip() else "raw_fallback"
        extracted_content = extracted if extraction_method == "trafilatura" else raw_response
        content = extracted_content[: self.settings.max_document_chars]
        _ensure_usable_document_content(content)
        logger.info(
            "fetch extracted url=%s input_chars=%d output_chars=%d extraction_method=%s",
            safe_url(url),
            len(raw_response),
            len(content),
            extraction_method,
        )
        metadata = trafilatura.extract_metadata(raw_response, default_url=extraction_url) if raw_response else None
        title = (metadata.title or "") if metadata else ""
        document = Document(
            url=response_url,
            title=title,
            content=content,
            metadata={
                "truncated": len(extracted_content) > len(content),
                "download_bytes": len(raw_bytes),
                "content_type": content_type,
                "extraction_method": extraction_method,
                "extraction_input_chars": len(raw_response),
                "extraction_output_chars": len(content),
            },
            document_id=hashlib.sha256(url.encode()).hexdigest()[:16],
            requested_url=url,
            redirect_chain=redirect_chain,
        )
        return document

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
