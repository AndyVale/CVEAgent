import pytest

from cve_agent.web_policy import PublicWebUrlError, PublicWebUrlPolicy


def public_resolver(_hostname, _port):
    return ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")


def test_public_web_policy_accepts_http_and_https_public_hosts():
    policy = PublicWebUrlPolicy(public_resolver)

    assert policy.validate("https://example.test/advisory") == "https://example.test/advisory"
    assert policy.validate("http://93.184.216.34/report") == "http://93.184.216.34/report"


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "https://user:password@example.test/report",
        "http://localhost/report",
        "http://service.localhost/report",
        "http://127.0.0.1/report",
        "http://10.0.0.1/report",
        "http://169.254.169.254/latest/meta-data",
        "http://0177.0.0.1/report",
        "http://[::1]/report",
    ],
)
def test_public_web_policy_rejects_non_public_destinations(url):
    with pytest.raises(PublicWebUrlError):
        PublicWebUrlPolicy(public_resolver).validate(url)


def test_public_web_policy_rejects_hosts_with_mixed_public_and_private_dns():
    policy = PublicWebUrlPolicy(lambda _hostname, _port: ("93.184.216.34", "127.0.0.1"))

    with pytest.raises(PublicWebUrlError, match="non-public address"):
        policy.validate("https://rebinding.test/report")


def test_public_web_policy_reports_escaped_hostname_without_exception_control_flow():
    policy = PublicWebUrlPolicy(public_resolver)

    assert (
        policy.rejection_reason(r"https://www\.sentinelone.com/blog")
        == "public-web URL has an invalid hostname"
    )


def test_public_web_policy_returns_parse_error_detail():
    reason = PublicWebUrlPolicy(public_resolver).rejection_reason("https://example.test:99999/report")

    assert reason == "invalid public-web URL: Port out of range 0-65535"
