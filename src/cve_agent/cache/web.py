from __future__ import annotations

import json
import logging

from cve_agent.cache.disk import JsonDiskCache
from cve_agent.core.ports import WebSource
from cve_agent.core.sources import Document, SearchResult
from cve_agent.integrations.content import _ensure_usable_document_content
from cve_agent.integrations.web_policy import PublicWebUrlPolicy
from cve_agent.integrations.web_validation import public_search_results, validate_document_urls
from cve_agent.runtime.diagnostics import safe_url


logger = logging.getLogger("cve_agent.adapters")



class CachedWebClient:
    """Cache a web source while validating cached documents before reuse."""

    def __init__(self, source: WebSource, cache: JsonDiskCache, url_policy: PublicWebUrlPolicy):
        self.source = source
        self.cache = cache
        self.url_policy = url_policy

    def search(self, query: str) -> list[SearchResult]:
        path = self.cache.path("search", query)
        if path.exists():
            logger.info("search cache hit query_chars=%d", len(query))
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(payload, list):
                    raise TypeError("invalid search cache structure")
                cached = [SearchResult(**item) for item in payload]
                if not all(isinstance(value, str) for item in cached for value in (item.title, item.url, item.snippet)):
                    raise TypeError("invalid search cache fields")
            except (ValueError, TypeError, UnicodeError):
                logger.warning("invalid search cache entry; fetching fresh results")
            else:
                return public_search_results(cached, self.url_policy)
        logger.info("search cache miss query_chars=%d", len(query))
        results = public_search_results(self.source.search(query), self.url_policy)
        self.cache.write(path, json.dumps([x.__dict__ for x in results]))
        logger.info("search cached query_chars=%d results=%d", len(query), len(results))
        return results

    def fetch(self, url: str) -> Document:
        self.url_policy.validate(url)
        path = self.cache.path("fetch", url)
        if path.exists():
            try:
                cached = json.loads(path.read_text(encoding="utf-8"))
                redirects = cached.get("redirect_chain", [])
                if not isinstance(redirects, list):
                    raise TypeError("invalid document redirects")
                cached["redirect_chain"] = tuple(redirects)
                document = Document(**cached)
                if not all(isinstance(value, str) for value in (
                    document.url, document.requested_url, document.title, document.content,
                    document.document_id, *document.redirect_chain,
                )) or not isinstance(document.metadata, dict):
                    raise TypeError("invalid document cache fields")
            except (ValueError, TypeError, AttributeError, UnicodeError):
                logger.warning("invalid document cache entry; fetching fresh document")
            else:
                validate_document_urls(document, self.url_policy)
                _ensure_usable_document_content(document.content)
                logger.info("fetch cache hit url=%s document_id=%s chars=%d", safe_url(url), document.document_id, len(document.content))
                return document
        logger.info("fetch cache miss url=%s", safe_url(url))
        document = self.source.fetch(url)
        self.cache.write(path, json.dumps(document.__dict__))
        return document
