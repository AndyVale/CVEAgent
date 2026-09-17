from dataclasses import replace

import httpx
import pytest

from cve_agent.application.factory import create_web_source
from cve_agent.integrations.http import HttpClientSession
from cve_agent.integrations.web import WebClient
from cve_agent.integrations.web_policy import PublicWebUrlError, PublicWebUrlPolicy
from tests.support.agent import public_url_policy, settings


def test_default_web_clients_reuse_client_instances_and_release_both_pools(tmp_path, monkeypatch):
    clients, requests, client_options = [], [], []
    real_client = httpx.Client

    def respond(request):
        requests.append(request)
        if request.method == 'POST':
            return httpx.Response(200, json={'results': []}, headers={'set-cookie': 'session=fixture'})
        return httpx.Response(200, text='Useful vulnerability evidence.', headers={'set-cookie': 'session=fixture'})

    def client_factory(**kwargs):
        client_options.append(kwargs)
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
        assert client_options[0]['trust_env'] is False
        assert client_options[0]['limits'].max_keepalive_connections == 0
        assert client_options[1]['trust_env'] is True
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


def test_uncached_fetch_connects_to_the_approved_ip_without_resolving_again(tmp_path):
    resolutions = []
    requests = []

    def resolver(hostname, port):
        resolutions.append((hostname, port))
        return ("93.184.216.34",) if len(resolutions) == 1 else ("127.0.0.1",)

    def respond(request):
        requests.append(request)
        return httpx.Response(200, text="Useful vulnerability evidence.")

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        source = WebClient(
            settings(tmp_path), http_client=client,
            url_policy=PublicWebUrlPolicy(resolver),
        )
        document = source.fetch("https://rebinding.test:8443/advisory")

    assert resolutions == [("rebinding.test", 8443)]
    assert [str(request.url) for request in requests] == ["https://93.184.216.34:8443/advisory"]
    assert requests[0].headers["host"] == "rebinding.test:8443"
    assert requests[0].extensions["sni_hostname"] == "rebinding.test"
    assert document.url == "https://rebinding.test:8443/advisory"
    assert document.requested_url == document.url


def test_redirect_hops_pin_separate_addresses_and_preserve_logical_urls(tmp_path):
    requests = []
    addresses = {"first.test": "93.184.216.34", "second.test": "8.8.8.8"}
    policy = PublicWebUrlPolicy(lambda hostname, _port: (addresses[hostname],))

    def respond(request):
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(302, headers={"location": "https://second.test/final"})
        return httpx.Response(200, text="Useful vulnerability evidence.")

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        document = WebClient(settings(tmp_path), http_client=client, url_policy=policy).fetch(
            "https://first.test/start"
        )

    assert [str(request.url) for request in requests] == [
        "https://93.184.216.34/start", "https://8.8.8.8/final",
    ]
    assert [request.headers["host"] for request in requests] == ["first.test", "second.test"]
    assert [request.extensions["sni_hostname"] for request in requests] == ["first.test", "second.test"]
    assert document.url == "https://second.test/final"
    assert document.redirect_chain == ("https://first.test/start", "https://second.test/final")


def test_uncached_fetch_supports_approved_ipv6_address(tmp_path):
    requests = []
    policy = PublicWebUrlPolicy(
        lambda _hostname, _port: ("2606:2800:220:1:248:1893:25c8:1946",)
    )

    def respond(request):
        requests.append(request)
        return httpx.Response(200, text="Useful vulnerability evidence.")

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        document = WebClient(settings(tmp_path), http_client=client, url_policy=policy).fetch(
            "https://ipv6.test/advisory"
        )

    assert str(requests[0].url) == "https://[2606:2800:220:1:248:1893:25c8:1946]/advisory"
    assert requests[0].headers["host"] == "ipv6.test"
    assert requests[0].extensions["sni_hostname"] == "ipv6.test"
    assert document.url == "https://ipv6.test/advisory"


def test_default_page_fetch_does_not_forward_cookies_across_redirect_hosts(tmp_path, monkeypatch):
    requests = []
    real_client = httpx.Client

    def respond(request):
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(302, headers={
                "location": "https://second.test/final", "set-cookie": "session=fixture",
            })
        return httpx.Response(200, text="Useful vulnerability evidence.")

    monkeypatch.setattr(
        "cve_agent.integrations.http.httpx.Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(respond), **kwargs),
    )
    policy = PublicWebUrlPolicy(lambda _hostname, _port: ("93.184.216.34",))
    source = WebClient(settings(tmp_path), url_policy=policy)
    try:
        source.fetch("https://first.test/start")
    finally:
        source.close()

    assert [request.headers["host"] for request in requests] == ["first.test", "second.test"]
    assert all("cookie" not in request.headers for request in requests)
