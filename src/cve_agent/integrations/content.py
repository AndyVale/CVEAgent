from __future__ import annotations


class UnusableDocumentError(ValueError):
    """Raised when retrieval succeeds but yields no usable page content."""


_JAVASCRIPT_SHELL_TEXTS = frozenset({
    "javascript is required to view this site",
    "please enable javascript to continue",
    "please enable javascript to view this site",
    "please enable javascript to view this website",
    "you need to enable javascript to run this app",
})


def _ensure_usable_document_content(content: str) -> None:
    normalized = " ".join(content.split()).casefold().strip(" .!?")
    if normalized in _JAVASCRIPT_SHELL_TEXTS:
        raise UnusableDocumentError(
            "retrieved page contains only a JavaScript placeholder; choose another source"
        )


def _is_text_content_type(content_type: str) -> bool:
    return content_type.startswith("text/") or content_type in {
        "application/json",
        "application/xml",
        "application/xhtml+xml",
        "application/rss+xml",
    }
