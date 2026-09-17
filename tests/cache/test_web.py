from dataclasses import replace
import json
import logging

import httpx
import pytest

from cve_agent.core.sources import Document, SearchResult
from cve_agent.integrations.content import UnusableDocumentError
from cve_agent.integrations.web_policy import PublicWebUrlError
from tests.support.agent import cached_web_client, public_url_policy, settings


def test_cached_web_client_extracts_html(tmp_path):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="<html><body><main><p>Important vulnerability evidence with enough context for reliable extraction.</p></main></body></html>"))
    document = cached_web_client(
        settings(tmp_path),
        http_client=httpx.Client(transport=transport),
        url_policy=public_url_policy(),
    ).fetch("https://fixture.test/page")
    assert "Important vulnerability evidence" in document.content
    assert "<main>" not in document.content
    assert document.metadata["extraction_method"] == "trafilatura"
    assert document.metadata["extraction_input_chars"] > document.metadata["extraction_output_chars"]


def test_cached_web_client_extracts_before_bounding_document_text(tmp_path, monkeypatch):
    raw = "<html>" + ("navigation " * 20) + "<main>useful evidence</main></html>"
    extracted = "Useful vulnerability evidence found after the noisy page prefix."
    observed: list[str] = []

    def extract(content, **_kwargs):
        observed.append(content)
        return extracted

    monkeypatch.setattr("cve_agent.integrations.web.trafilatura.extract", extract)
    configured = replace(settings(tmp_path), max_document_chars=32, max_preview_chars=16)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text=raw))

    document = cached_web_client(
        configured,
        http_client=httpx.Client(transport=transport),
        url_policy=public_url_policy(),
    ).fetch("https://fixture.test/large-page")

    assert observed == [raw]
    assert document.content == extracted[:32]
    assert document.metadata["extraction_input_chars"] == len(raw)
    assert document.metadata["extraction_output_chars"] == 32
    assert document.metadata["truncated"] is True


def test_cached_web_client_records_raw_extraction_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr("cve_agent.integrations.web.trafilatura.extract", lambda *_args, **_kwargs: None)
    raw = "<html><body>Fallback vulnerability evidence.</body></html>"
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text=raw))

    document = cached_web_client(
        settings(tmp_path),
        http_client=httpx.Client(transport=transport),
        url_policy=public_url_policy(),
    ).fetch("https://fixture.test/fallback")

    assert document.content == raw
    assert document.metadata["extraction_method"] == "raw_fallback"
    assert document.metadata["extraction_input_chars"] == len(raw)
    assert document.metadata["extraction_output_chars"] == len(raw)


def test_cached_web_client_rejects_javascript_shell_without_caching(tmp_path):
    url = "https://fixture.test/javascript-shell"
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, text="You need to enable JavaScript to run this app.")
    )
    client = cached_web_client(
        settings(tmp_path),
        http_client=httpx.Client(transport=transport),
        url_policy=public_url_policy(),
    )

    with pytest.raises(UnusableDocumentError, match="JavaScript placeholder"):
        client.fetch(url)

    assert not client.cache.path("fetch", url).exists()


def test_cached_web_client_rejects_legacy_cached_javascript_shell(tmp_path):
    client = cached_web_client(settings(tmp_path), url_policy=public_url_policy())
    url = "https://fixture.test/legacy-javascript-shell"
    document = Document(
        url,
        "Application",
        "Please enable JavaScript to continue.",
        document_id="legacy-shell",
        requested_url=url,
    )
    client.cache.write(client.cache.path("fetch", url), json.dumps(document.__dict__))

    with pytest.raises(UnusableDocumentError, match="choose another source"):
        client.fetch(url)


def test_cached_web_client_accepts_legacy_document_metadata(tmp_path):
    client = cached_web_client(settings(tmp_path), url_policy=public_url_policy())
    url = "https://fixture.test/legacy"
    legacy = Document(
        url,
        "Legacy advisory",
        "Legacy cached vulnerability evidence.",
        {"truncated": False, "download_bytes": 42, "content_type": "text/plain"},
        "legacy-doc",
        url,
    )
    client.cache.write(client.cache.path("fetch", url), json.dumps(legacy.__dict__))

    document = client.fetch(url)

    assert document.document_id == "legacy-doc"
    assert document.metadata["download_bytes"] == 42
    assert "extraction_method" not in document.metadata


def test_cached_web_client_records_redirect_provenance(tmp_path):
    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/final"})
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="Resolved vulnerability evidence.")

    client = cached_web_client(
        settings(tmp_path),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        url_policy=public_url_policy(),
    )
    document = client.fetch("https://fixture.test/start")
    assert document.requested_url == "https://fixture.test/start"
    assert document.url == "https://fixture.test/final"
    assert document.redirect_chain == ("https://fixture.test/start", "https://fixture.test/final")


def test_cached_web_client_blocks_private_redirect_before_request(tmp_path):
    requested = []

    def handler(request):
        requested.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://127.0.0.1/private"})

    client = cached_web_client(
        settings(tmp_path),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        url_policy=public_url_policy(),
    )

    with pytest.raises(PublicWebUrlError, match="non-public address"):
        client.fetch("https://fixture.test/start")
    assert requested == ["https://93.184.216.34/start"]


def test_cached_web_client_bounds_redirects_without_retrying_chain(tmp_path):
    requested = []

    def handler(request):
        requested.append(str(request.url))
        return httpx.Response(302, headers={"location": "/next"})

    client = cached_web_client(
        settings(tmp_path),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        url_policy=public_url_policy(),
    )

    with pytest.raises(PublicWebUrlError, match="exceeded 10 redirects"):
        client.fetch("https://fixture.test/start")
    assert len(requested) == 11


def test_cached_web_client_discards_non_public_search_results(tmp_path):
    client = cached_web_client(
        settings(tmp_path),
        searcher=lambda _query: [
            SearchResult("Public", "https://fixture.test/advisory"),
            SearchResult("Private", "http://127.0.0.1/internal"),
        ],
        url_policy=public_url_policy(),
    )

    assert [item.title for item in client.search("VULN-1")] == ["Public"]
    assert client.cache.directory.is_dir()


def test_cached_web_client_does_not_create_cache_directory_during_construction(tmp_path):
    client = cached_web_client(settings(tmp_path), url_policy=public_url_policy())

    assert not client.cache.directory.exists()


def test_cached_web_client_discards_malformed_cached_search_result_with_reason(tmp_path, caplog):
    client = cached_web_client(settings(tmp_path), url_policy=public_url_policy())
    query = "VULN-1 advisory"
    client.cache.write(
        client.cache.path("search", query),
        json.dumps([
            {
                "title": "Malformed",
                "url": r"https://www\.sentinelone.com/blog",
                "snippet": "cached result",
            }
        ]),
    )
    caplog.set_level(logging.WARNING, logger="cve_agent.adapters")

    assert client.search(query) == []
    assert "detail=public-web URL has an invalid hostname" in caplog.text


def test_fetch_logs_strip_query_strings_and_fragments(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="cve_agent.adapters")
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="Useful vulnerability evidence."))
    url = "https://fixture.test/advisory?temporary-secret=value#private"

    cached_web_client(
        settings(tmp_path),
        http_client=httpx.Client(transport=transport),
        url_policy=public_url_policy(),
    ).fetch(url)

    assert "https://fixture.test/advisory" in caplog.text
    assert "temporary-secret" not in caplog.text
    assert "#private" not in caplog.text


def test_cached_web_client_rejects_large_or_non_text_responses(tmp_path):
    small_limit = settings(tmp_path).__class__(**{**settings(tmp_path).__dict__, "max_download_bytes": 5})
    large_transport = httpx.MockTransport(lambda request: httpx.Response(200, headers={"content-type": "text/plain"}, content=b"too large"))
    try:
        cached_web_client(
            small_limit,
            http_client=httpx.Client(transport=large_transport),
            url_policy=public_url_policy(),
        ).fetch("https://fixture.test/large")
    except ValueError as exc:
        assert "max_download_bytes" in str(exc)
    else:
        raise AssertionError("expected the streamed size limit to reject the response")

    binary_transport = httpx.MockTransport(lambda request: httpx.Response(200, headers={"content-type": "application/octet-stream"}, content=b"binary"))
    try:
        cached_web_client(
            settings(tmp_path),
            http_client=httpx.Client(transport=binary_transport),
            url_policy=public_url_policy(),
        ).fetch("https://fixture.test/binary")
    except ValueError as exc:
        assert "unsupported content type" in str(exc)
    else:
        raise AssertionError("expected binary content to be rejected")
