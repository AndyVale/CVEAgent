import pytest

from cve_agent.core.investigation import InvestigationState
from cve_agent.core.sources import CVERecord, Document, SearchResult
from cve_agent.investigation.provenance import ResearchProvenanceRecorder
from cve_agent.investigation.session import ResearchSession
from cve_agent.investigation.tools import ResearchToolExecutor
from tests.support.agent import FailingFetchWeb, FixtureWeb, cached_web_client, public_url_policy, settings


def test_record_evidence_resolves_anchor_and_reuses_fetch(tmp_path):
    class CountingWeb(FixtureWeb):
        def __init__(self):
            self.fetches = 0

        def fetch(self, url):
            self.fetches += 1
            return super().fetch(url)

    web = CountingWeb()
    executor = ResearchToolExecutor(settings(tmp_path), web)
    state = InvestigationState()
    session = ResearchSession(provenance=ResearchProvenanceRecorder(
        CVERecord("CVE-2024-12345", "Fixture vulnerability."),
        state,
        max_preview_chars=settings(tmp_path).max_preview_chars,
    ))
    first = executor.execute("fetch", {"url": "https://fixture.test/advisory"}, state, session)
    session.provenance.record_tool_call("fetch", {"url": "https://fixture.test/advisory"}, first, session.documents)
    second = executor.execute("fetch", {"url": "https://fixture.test/advisory"}, state, session)
    session.provenance.record_tool_call("fetch", {"url": "https://fixture.test/advisory"}, second, session.documents)
    third = executor.execute("fetch", {"url": "https://fixture.test/advisory"}, state, session)
    session.provenance.record_tool_call("fetch", {"url": "https://fixture.test/advisory"}, third, session.documents)
    recorded = executor.execute(
        "record_evidence",
        {"document_id": "doc-1", "passage_id": "", "quote_anchor": "issue causes memory corruption aggregate processing"},
        state,
        session,
    )
    assert web.fetches == 1
    assert session.fetches == 1
    assert first["reused"] is False
    assert second["reused"] is True
    assert third["reused"] is True
    assert "error" in third
    assert "passages" not in third
    assert [item.reused for item in state.provenance.fetches] == [False, True, True]
    assert second["document_id"] == first["document_id"]
    assert recorded["evidence_id"] == "doc-1:p1"
    assert "quote" not in recorded
    assert state.evidence[0].verification == "fuzzy_anchor"

    repeated = executor.execute(
        "record_evidence",
        {"document_id": "doc-1", "passage_id": "p1", "quote_anchor": ""},
        state,
        session,
    )
    assert repeated == {
        "recorded": False,
        "evidence_id": "doc-1:p1",
        "evidence_count": 1,
        "instruction": "This evidence is already recorded; continue without recording it again.",
    }


@pytest.mark.parametrize(
    "equivalent_url",
    [
        "HTTPS://FIXTURE.TEST:443/advisory#section",
        "https://fixture.test:443/advisory",
        "https://fixture.test/advisory#other",
    ],
)
def test_fetch_reuses_normalized_url_variants_without_consuming_quota(tmp_path, equivalent_url):
    class CountingWeb(FixtureWeb):
        def __init__(self):
            self.fetches = 0

        def fetch(self, url):
            self.fetches += 1
            return super().fetch(url)

    web = CountingWeb()
    executor = ResearchToolExecutor(settings(tmp_path), web)
    session, state = ResearchSession(), InvestigationState()

    executor.execute("fetch", {"url": "https://fixture.test/advisory"}, state, session)
    reused = executor.execute("fetch", {"url": equivalent_url}, state, session)

    assert reused["reused"] is True
    assert web.fetches == 1
    assert session.fetches == 1


def test_search_omits_results_for_available_requested_and_resolved_urls(tmp_path):
    class ExistingAndNovelWeb(FixtureWeb):
        def search(self, query):
            return [
                SearchResult("Requested", "https://fixture.test/start"),
                SearchResult("Resolved", "https://fixture.test/final#section"),
                SearchResult("Novel", "https://fixture.test/novel"),
            ]

        def fetch(self, url):
            return Document(
                "https://fixture.test/final",
                "Advisory",
                "Substantive redirected vulnerability evidence.",
                document_id="redirected",
                requested_url=url,
            )

    executor = ResearchToolExecutor(settings(tmp_path), ExistingAndNovelWeb())
    session, state = ResearchSession(), InvestigationState()

    executor.execute("fetch", {"url": "https://fixture.test/start"}, state, session)
    result = executor.execute("search", {"query": "new technical evidence"}, state, session)

    assert [item["url"] for item in result["results"]] == ["https://fixture.test/novel"]
    assert result["available_results_omitted"] == 2
    assert "available_documents" in result["instruction"]


def test_fetch_reuses_both_sides_of_a_redirect(tmp_path):
    class RedirectWeb(FixtureWeb):
        def __init__(self):
            self.fetches = 0

        def fetch(self, url):
            self.fetches += 1
            return Document(
                "https://fixture.test/final",
                "Advisory",
                "Substantive redirected vulnerability evidence.",
                document_id="redirected",
                requested_url=url,
                redirect_chain=(url, "https://fixture.test/final"),
            )

    web = RedirectWeb()
    executor = ResearchToolExecutor(settings(tmp_path), web)
    session, state = ResearchSession(), InvestigationState()

    first = executor.execute("fetch", {"url": "https://fixture.test/start"}, state, session)
    resolved = executor.execute("fetch", {"url": "https://fixture.test/final#details"}, state, session)

    assert first["reused"] is False
    assert resolved["reused"] is True
    assert web.fetches == 1


def test_fetch_normalizes_an_implicit_root_path(tmp_path):
    class CountingWeb(FixtureWeb):
        def __init__(self):
            self.fetches = 0

        def fetch(self, url):
            self.fetches += 1
            return Document(url, content="Substantive vulnerability evidence.", document_id="root-doc")

    web = CountingWeb()
    executor = ResearchToolExecutor(settings(tmp_path), web)
    session, state = ResearchSession(), InvestigationState()

    executor.execute("fetch", {"url": "https://fixture.test"}, state, session)
    reused = executor.execute("fetch", {"url": "https://fixture.test/#details"}, state, session)

    assert reused["reused"] is True
    assert web.fetches == 1


def test_fetch_keeps_distinct_query_strings_separate(tmp_path):
    class CountingWeb(FixtureWeb):
        def __init__(self):
            self.fetches = 0

        def fetch(self, url):
            self.fetches += 1
            return Document(url, content="Substantive vulnerability evidence.", document_id=f"doc-{self.fetches}")

    configured = settings(tmp_path).__class__(**{**settings(tmp_path).__dict__, "max_fetch_calls": 2})
    web = CountingWeb()
    executor = ResearchToolExecutor(configured, web)
    session, state = ResearchSession(), InvestigationState()

    first = executor.execute("fetch", {"url": "https://fixture.test/advisory?version=1"}, state, session)
    second = executor.execute("fetch", {"url": "https://fixture.test/advisory?version=2"}, state, session)

    assert first["reused"] is False
    assert second["reused"] is False
    assert web.fetches == 2
    assert session.fetches == 2


def test_unavailable_document_does_not_poison_later_evidence_retry(tmp_path):
    executor = ResearchToolExecutor(settings(tmp_path), FixtureWeb())
    session, state = ResearchSession(), InvestigationState()
    arguments = {
        "document_id": "doc-1",
        "passage_id": "p1",
        "quote_anchor": "",
    }

    unavailable = executor.execute("record_evidence", arguments, state, session)
    executor.execute("fetch", {"url": "https://fixture.test/advisory"}, state, session)
    recorded = executor.execute("record_evidence", arguments, state, session)

    assert unavailable["instruction"] == "Fetch a search result before recording evidence."
    assert unavailable["available_document_ids"] == []
    assert recorded["evidence_id"] == "doc-1:p1"


def test_fetch_failure_is_recoverable(tmp_path):
    executor = ResearchToolExecutor(settings(tmp_path), FailingFetchWeb())
    session, state = ResearchSession(), InvestigationState()
    result = executor.execute("fetch", {"url": "https://fixture.test/forbidden"}, state, session)
    assert "HTTPStatusError" in result["error"]
    repeated = executor.execute("fetch", {"url": "https://fixture.test/forbidden"}, state, session)
    assert "already attempted" in repeated["error"]


def test_tool_errors_redact_configured_credentials(tmp_path):
    configured = settings(tmp_path).__class__(**{
        **settings(tmp_path).__dict__,
        "api_key": "model-secret",
        "tavily_api_key": "search-secret",
    })

    class SecretErrorWeb(FixtureWeb):
        def search(self, query):
            raise RuntimeError("provider included model-secret and search-secret")

    result = ResearchToolExecutor(configured, SecretErrorWeb()).execute(
        "search",
        {"query": "VULN-1"},
        InvestigationState(),
        ResearchSession(),
    )

    assert "model-secret" not in result["error"]
    assert "search-secret" not in result["error"]
    assert result["error"].count("[REDACTED]") == 2


def test_public_web_fetch_failure_has_traceable_tool_error(tmp_path):
    client = cached_web_client(settings(tmp_path), url_policy=public_url_policy())
    result = ResearchToolExecutor(settings(tmp_path), client).execute(
        "fetch",
        {"url": "http://127.0.0.1/private"},
        InvestigationState(),
        ResearchSession(),
    )

    assert "fetch failed (PublicWebUrlError)" in result["error"]
    assert "non-public address: 127.0.0.1" in result["error"]
