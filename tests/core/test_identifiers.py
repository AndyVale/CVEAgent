import pytest

from cve_agent.core.identifiers import CVEIdentifierError, normalize_cve_id


def test_normalizes_cve_identifiers():
    assert normalize_cve_id(" cve-2024-12345 ") == "CVE-2024-12345"


@pytest.mark.parametrize("value", [None, "", "CVE-24-1234", "CVE-2024-123", "VULN-2024-1234"])
def test_rejects_invalid_cve_identifiers(value):
    with pytest.raises(CVEIdentifierError):
        normalize_cve_id(value)
