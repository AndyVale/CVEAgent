import json

from cve_agent.core.investigation import InvestigationState
from cve_agent.core.sources import CVERecord, Document, EvidenceRecord, Reference
from cve_agent.investigation.context import (
    MAX_NVD_REFERENCE_CANDIDATES,
    _ResearchContextSerializer,
    build_research_context,
    select_reference_candidates,
)
import cve_agent.investigation.context as research_context_module


def test_research_context_prioritizes_and_bounds_nvd_references():
    generic = tuple(Reference(f"https://generic.test/{index}", tags=("Third Party Advisory",)) for index in range(30))
    vendor = Reference("https://vendor.test/advisory", tags=("Vendor Advisory",))
    cve = CVERecord("VULN-1", "fixture", generic + (vendor,))

    selected = select_reference_candidates(cve.references)
    context = build_research_context(
        cve,
        InvestigationState(),
        {},
        turn=0,
        searches=0,
        fetches=0,
        max_turns=8,
        max_searches=2,
        max_fetches=3,
    )

    assert len(selected) == MAX_NVD_REFERENCE_CANDIDATES
    assert selected[0] == vendor
    assert context["cve"]["references"][0]["url"] == vendor.url
    assert context["cve"]["reference_count"] == 31
    assert context["cve"]["omitted_reference_count"] == 31 - MAX_NVD_REFERENCE_CANDIDATES
    assert "description" not in context["cve"]
    assert "facts" not in context


def test_research_context_serializer_reuses_static_fragments_and_defers_exchange_history(monkeypatch):
    description = "Unique NVD description serialized exactly once."
    cve = CVERecord(
        "CVE-2024-12345",
        description,
        (Reference("https://vendor.test/advisory", tags=("Vendor Advisory",)),),
        {"published": "2024-01-01"},
    )
    state = InvestigationState(
        evidence=[EvidenceRecord("nvd-description", "https://nvd.test/CVE-2024-12345", description, "nvd_description")],
        tool_history=[
            {"tool": "get_cve", "status": "success"},
            {"tool": "fetch", "status": "success", "document_id": "doc-1"},
        ],
    )
    documents = {"doc-1": Document(
        "https://vendor.test/advisory",
        "Vendor advisory",
        "Technical evidence.",
        document_id="doc-1",
    )}
    encoded = []
    original_dumps = research_context_module._json_dumps

    def counting_dumps(value):
        encoded.append(value)
        return original_dumps(value)

    monkeypatch.setattr(research_context_module, "_json_dumps", counting_dumps)
    serializer = _ResearchContextSerializer(cve)
    current = serializer.render(
        state,
        documents,
        [{"role": "tool", "content": "fetch result"}],
        turn=1,
        searches=0,
        fetches=1,
        max_turns=8,
        max_searches=2,
        max_fetches=3,
    )
    initial_encodings = len(encoded)
    following = serializer.render(
        state,
        documents,
        [],
        turn=2,
        searches=0,
        fetches=1,
        max_turns=8,
        max_searches=2,
        max_fetches=3,
    )

    current_context = json.loads(current)
    following_context = json.loads(following)
    assert "description" not in current_context["cve"]
    assert current.count(description) == 1
    assert [event["tool"] for event in current_context["tool_history"]] == ["get_cve"]
    assert [event["tool"] for event in following_context["tool_history"]] == ["get_cve", "fetch"]
    assert len(encoded) == initial_encodings + 1  # Only the changed budget counters were encoded.

    state.evidence.append(EvidenceRecord("doc-1:p1", documents["doc-1"].url, "Technical evidence.", "web"))
    state.tool_history.append({"tool": "record_evidence", "status": "success", "evidence_id": "doc-1:p1"})
    documents["doc-2"] = Document("https://vendor.test/second", "Second", "More evidence.", document_id="doc-2")
    before_changes = len(encoded)
    updated = serializer.render(
        state,
        documents,
        [],
        turn=3,
        searches=0,
        fetches=2,
        max_turns=8,
        max_searches=2,
        max_fetches=3,
    )

    assert len(encoded) == before_changes + 4  # New evidence, event, document catalog, and budget.
    assert len(json.loads(updated)["recorded_evidence"]) == 2

    state.evidence[:] = [state.evidence[-1]]
    state.tool_history.reverse()
    documents.pop("doc-1")
    rebuilt = json.loads(serializer.render(
        state,
        documents,
        [],
        turn=4,
        searches=0,
        fetches=2,
        max_turns=8,
        max_searches=2,
        max_fetches=3,
    ))

    assert [item["evidence_id"] for item in rebuilt["recorded_evidence"]] == ["doc-1:p1"]
    assert [item["tool"] for item in rebuilt["tool_history"]] == ["record_evidence", "fetch", "get_cve"]
    assert [item["document_id"] for item in rebuilt["available_documents"]] == ["doc-2"]


def test_research_context_identifies_both_urls_of_fetched_documents():
    document = Document(
        "https://vendor.test/final",
        "Vendor advisory",
        "Technical vulnerability evidence.",
        document_id="vendor-doc",
        requested_url="https://vendor.test/start",
    )

    context = build_research_context(
        CVERecord("VULN-1", "fixture"),
        InvestigationState(),
        {"vendor-doc": document},
        turn=1,
        searches=0,
        fetches=1,
        max_turns=8,
        max_searches=2,
        max_fetches=3,
    )

    assert context["available_documents"] == [{
        "document_id": "vendor-doc",
        "requested_url": "https://vendor.test/start",
        "resolved_url": "https://vendor.test/final",
        "title": "Vendor advisory",
    }]
