import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cve_agent.cache.disk import JsonDiskCache
from cve_agent.cache.web import CachedWebClient
from cve_agent.core.sources import Document, SearchResult
from cve_agent.integrations.web_policy import PublicWebUrlError
from tests.support.agent import public_url_policy


@pytest.mark.parametrize('kind', ['search', 'fetch'])
@pytest.mark.parametrize('payload', ['{', 'null', '42', '[null]', '{"url": 42}', '\udcff'])
def test_invalid_cache_is_replaced_and_reused(tmp_path, kind, payload):
    calls = []
    result = [SearchResult('Advisory', 'https://fixture.test/page')] if kind == 'search' else Document('https://fixture.test/page', content='Useful vulnerability evidence.')

    def retrieve(key):
        calls.append(key)
        return result

    cache = JsonDiskCache(tmp_path)
    client = CachedWebClient(SimpleNamespace(search=retrieve, fetch=retrieve), cache, public_url_policy())
    key = 'query' if kind == 'search' else 'https://fixture.test/page'
    cache.path(kind, key).write_bytes(payload.encode('utf-8', errors='surrogateescape'))
    assert getattr(client, kind)(key) == result
    assert getattr(client, kind)(key) == result
    assert calls == [key]


def test_failed_atomic_write_preserves_previous_cache(tmp_path, monkeypatch):
    cache = JsonDiskCache(tmp_path)
    path = cache.path('search', 'query')
    cache.write(path, '[]')

    def fail(*args):
        raise OSError('disk unavailable')

    monkeypatch.setattr('cve_agent.cache.disk.os.replace', fail)
    with pytest.raises(OSError, match='disk unavailable'):
        cache.write(path, '[{}]')
    assert path.read_text() == '[]'
    assert list(tmp_path.iterdir()) == [path]


def test_cache_read_permission_errors_are_not_treated_as_corruption(tmp_path, monkeypatch):
    cache = JsonDiskCache(tmp_path)
    cache.write(cache.path('search', 'query'), '[]')
    client = CachedWebClient(SimpleNamespace(), cache, public_url_policy())

    def fail(*args, **kwargs):
        raise PermissionError('not readable')

    monkeypatch.setattr(Path, 'read_text', fail)
    with pytest.raises(PermissionError):
        client.search('query')


def test_cached_private_document_is_rejected_without_refetch(tmp_path):
    cache = JsonDiskCache(tmp_path)
    url = 'https://fixture.test/page'
    cache.write(cache.path('fetch', url), json.dumps(Document('http://127.0.0.1/private', content='Evidence.').__dict__))
    client = CachedWebClient(SimpleNamespace(), cache, public_url_policy())
    with pytest.raises(PublicWebUrlError):
        client.fetch(url)


@pytest.mark.parametrize('payload', ['{}', '[{"title": null, "url": "https://fixture.test/page"}]'])
def test_invalid_search_structure_refetches(tmp_path, payload):
    cache = JsonDiskCache(tmp_path)
    cache.write(cache.path('search', 'query'), payload)
    calls = []
    client = CachedWebClient(SimpleNamespace(search=lambda key: calls.append(key) or []), cache, public_url_policy())
    assert client.search('query') == []
    assert calls == ['query']


def test_failed_refetch_preserves_bad_entry_and_propagates_provider_error(tmp_path):
    cache = JsonDiskCache(tmp_path)
    path = cache.path('search', 'query')
    cache.write(path, '{')

    def fail(key):
        raise RuntimeError('provider unavailable')

    client = CachedWebClient(SimpleNamespace(search=fail), cache, public_url_policy())
    with pytest.raises(RuntimeError, match='provider unavailable'):
        client.search('query')
    assert path.read_text() == '{'
