import pytest

from cve_agent import adapters
from cve_agent.adapters import NVDClient
from cve_agent.config import load_settings


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
