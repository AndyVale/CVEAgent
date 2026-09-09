from dataclasses import replace

import httpx
import pytest

from cve_agent.application.factory import create_web_source
from cve_agent.integrations.http import HttpClientSession
from cve_agent.integrations.web import WebClient
from cve_agent.integrations.web_policy import PublicWebUrlError
from tests.support.agent import public_url_policy, settings


def test_default_web_clients_reuse_connections_and_release_both_pools(tmp_path, monkeypatch):
    clients, requests = [], []
    real_client = httpx.Client

    def respond(request):
        requests.append(request)
        if request.method == 'POST':
            return httpx.Response(200, json={'results': []}, headers={'set-cookie': 'session=fixture'})
        return httpx.Response(200, text='Useful vulnerability evidence.', headers={'set-cookie': 'session=fixture'})

    def client_factory(**kwargs):
        client = real_client(transport=httpx.MockTransport(respond), **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr('cve_agent.integrations.http.httpx.Client', client_factory)
    source = create_web_source(replace(settings(tmp_path), tavily_api_key='fixture-key'), url_policy=public_url_policy())
    assert clients == []
    try:
        source.fetch('https://fixture.test/first')
        source.fetch('https://fixture.test/second')
        source.search('first')
        source.search('second')
        assert len(clients) == 2
        assert all(not client.is_closed for client in clients)
        assert all('cookie' not in request.headers for request in requests)
        assert all('authorization' not in request.headers for request in requests[:2])
        assert all(request.headers['authorization'] == 'Bearer fixture-key' for request in requests[2:])
    finally:
        source.close()
    assert all(client.is_closed for client in clients)
    source.close()
    try:
        source.fetch('https://fixture.test/third')
        assert len(clients) == 3
    finally:
        source.close()
    assert all(client.is_closed for client in clients)


def test_injected_http_client_remains_open():
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200))) as client:
        session = HttpClientSession(5, client)
        assert session.get() is client
        session.close()
        assert not client.is_closed


def test_uncached_fetch_still_rejects_private_url_before_request(tmp_path):
    requests = []
    with httpx.Client(transport=httpx.MockTransport(lambda request: requests.append(request))) as client:
        source = WebClient(settings(tmp_path), http_client=client, url_policy=public_url_policy())
        with pytest.raises(PublicWebUrlError):
            source.fetch('http://127.0.0.1/private')
        assert not requests
