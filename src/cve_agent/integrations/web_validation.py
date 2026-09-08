from __future__ import annotations

import logging

from cve_agent.core.sources import Document, SearchResult
from cve_agent.integrations.web_policy import PublicWebUrlPolicy
from cve_agent.runtime.diagnostics import safe_url


logger = logging.getLogger("cve_agent.adapters")

def public_search_results(results: list[SearchResult], url_policy: PublicWebUrlPolicy) -> list[SearchResult]:
    accepted: list[SearchResult] = []
    for result in results:
        rejection = url_policy.rejection_reason(result.url)
        if rejection:
            logger.warning(
                "discarding non-public search result url=%s detail=%s",
                safe_url(str(result.url)),
                rejection,
            )
        else:
            accepted.append(result)
    return accepted


def validate_document_urls(document: Document, url_policy: PublicWebUrlPolicy) -> None:
    urls = (
        document.requested_url or document.url,
        *document.redirect_chain,
        document.url,
    )
    for item in dict.fromkeys(urls):
        url_policy.validate(item)
