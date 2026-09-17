from io import BytesIO
import urllib.error

import pytest

from cve_agent.core.config import load_settings
from cve_agent.integrations.nvd import NVDClient
import cve_agent.integrations.nvd as adapters


def test_nvd_client_normalizes_and_verifies_response_identifier(monkeypatch):
    requested_urls = []

    def request_json(url, *_args, **_kwargs):
        requested_urls.append(url)
        return {"vulnerabilities": [{"cve": {"id": "CVE-2024-12345", "descriptions": []}}]}

    monkeypatch.setattr(adapters, "_request_json", request_json)
    record = NVDClient(load_settings("config.example.toml")).get_cve("cve-2024-12345")

    assert record.cve_id == "CVE-2024-12345"
    assert "CVE-2024-12345" in requested_urls[0]


def test_nvd_client_rejects_mismatched_response_identifier(monkeypatch):
    monkeypatch.setattr(
        adapters,
        "_request_json",
        lambda *_args, **_kwargs: {
            "vulnerabilities": [{"cve": {"id": "CVE-2024-9999", "descriptions": []}}]
        },
    )

    with pytest.raises(LookupError, match="returned CVE-2024-9999"):
        NVDClient(load_settings("config.example.toml")).get_cve("CVE-2024-12345")


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
def test_nvd_permanent_http_error_is_not_retried(monkeypatch, status):
    attempts = []

    def fail(_request, *, timeout):
        attempts.append(timeout)
        raise urllib.error.HTTPError("https://nvd.test", status, "permanent", {}, None)

    monkeypatch.setattr(adapters.urllib.request, "urlopen", fail)
    monkeypatch.setattr(adapters.time, "sleep", lambda _seconds: pytest.fail("unexpected retry"))

    with pytest.raises(urllib.error.HTTPError) as error:
        adapters._request_json("https://nvd.test", timeout=5, retries=2)

    assert error.value.code == status
    assert attempts == [5]


@pytest.mark.parametrize("status", [408, 425, 429, 500, 503])
def test_nvd_transient_http_error_is_retried(monkeypatch, status):
    attempts = []
    sleeps = []

    def respond(_request, *, timeout):
        attempts.append(timeout)
        if len(attempts) == 1:
            raise urllib.error.HTTPError("https://nvd.test", status, "transient", {}, None)
        return BytesIO(b'{"vulnerabilities": []}')

    monkeypatch.setattr(adapters.urllib.request, "urlopen", respond)
    monkeypatch.setattr(adapters.time, "sleep", sleeps.append)

    assert adapters._request_json("https://nvd.test", timeout=5, retries=2) == {"vulnerabilities": []}
    assert attempts == [5, 5]
    assert sleeps == [0.2]


def test_nvd_network_timeout_exhausts_bounded_retries(monkeypatch):
    attempts = []
    sleeps = []

    def timeout(_request, *, timeout):
        attempts.append(timeout)
        raise TimeoutError("network timeout")

    monkeypatch.setattr(adapters.urllib.request, "urlopen", timeout)
    monkeypatch.setattr(adapters.time, "sleep", sleeps.append)

    with pytest.raises(TimeoutError):
        adapters._request_json("https://nvd.test", timeout=5, retries=2)

    assert attempts == [5, 5, 5]
    assert sleeps == [0.2, 0.4]
