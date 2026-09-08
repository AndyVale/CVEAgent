from __future__ import annotations

from cve_agent.classification.provenance import build_public_provenance, record_label_links
from cve_agent.core.investigation import InvestigationAspect, InvestigationFinding, InvestigationState
from cve_agent.core.results import Evidence, LabelClassification
from cve_agent.core.sources import CVERecord, Document, EvidenceRecord, Reference
from cve_agent.core.taxonomy import Taxonomy, TaxonomyLabel
from cve_agent.core.urls import extract_cve_ids, normalize_url
from cve_agent.investigation.evidence import build_passages, store_passage_evidence
from cve_agent.investigation.provenance import ResearchProvenanceRecorder
from cve_agent.persistence.writer import Database


def _state(cve_id: str, description: str) -> InvestigationState:
    return InvestigationState(evidence=[EvidenceRecord(
        "nvd-description",
        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        description,
        "nvd_description",
    )])


def test_provenance_records_complete_multi_origin_chain_and_public_label_subset(tmp_path):
    cve_id = "CVE-2024-12345"
    requested_url = "HTTPS://vendor.test:443/advisory#details"
    cve = CVERecord(
        cve_id,
        "A target-specific NVD description.",
        (Reference("https://vendor.test/advisory", "Vendor", ("Vendor Advisory",)),),
        {"published": "2024-01-01"},
    )
    state = _state(cve_id, cve.description)
    recorder = ResearchProvenanceRecorder(cve, state, max_preview_chars=10_000)

    recorder.record_tool_call(
        "search",
        {"query": f"{cve_id} vendor root cause"},
        {"results": [
            {"title": "Vendor advisory", "url": requested_url, "snippet": "Technical details."},
            {"title": "Unused analysis", "url": "https://unused.test/report", "snippet": "Unused lead."},
        ]},
        {},
    )
    document = Document(
        url="https://vendor.test/final-advisory",
        title=f"Security advisory for {cve_id}",
        content=(
            "Affected versions use the vulnerable parser.\n"
            f"The parser for {cve_id} trusts an attacker-controlled length.\n"
            "Successful exploitation discloses memory. A comparison mentions CVE-2023-9999."
        ),
        metadata={
            "extraction_method": "trafilatura",
            "extraction_input_chars": 1_200,
            "extraction_output_chars": 180,
            "truncated": False,
            "download_bytes": 1_500,
            "content_type": "text/html",
        },
        document_id="vendor-doc",
        requested_url=requested_url,
        redirect_chain=(requested_url, "https://vendor.test/final-advisory"),
    )
    documents = {"vendor-doc": document}
    recorder.record_tool_call(
        "fetch",
        {"url": requested_url},
        {
            "document_id": "vendor-doc",
            "url": document.url,
            "passages": [],
            "truncated": False,
        },
        documents,
    )
    unused_document = Document(
        "https://unused.test/report",
        "Unused report",
        "This fetched lead did not support a retained finding.",
        document_id="unused-doc",
        requested_url="https://unused.test/report",
    )
    documents["unused-doc"] = unused_document
    recorder.record_tool_call(
        "fetch",
        {"url": unused_document.url},
        {"document_id": unused_document.document_id, "url": unused_document.url},
        documents,
    )

    passage = build_passages("vendor-doc", document.content, max_chars=10_000)[0]
    record, _ = store_passage_evidence(state, document, passage, verification="finish_reference")
    recorder.record_tool_call(
        "finish_investigation",
        {},
        {"information_status": "sufficient", "finding_count": 1, "promoted_evidence": 1},
        documents,
    )
    state.findings = [InvestigationFinding(
        InvestigationAspect.ROOT_CAUSE,
        "The parser trusts an attacker-controlled length.",
        (record.evidence_id,),
    )]
    labels = [LabelClassification("LENGTH-TRUST", 0.94, (Evidence(
        record.url,
        record.quote,
        "The cited parser behavior satisfies the label definition.",
        record.evidence_id,
    ),))]
    taxonomy = Taxonomy((TaxonomyLabel(
        "LENGTH-TRUST",
        "Trusted Length",
        "The implementation trusts an attacker-controlled length.",
    ),))
    record_label_links(labels, state, taxonomy)
    public = build_public_provenance(labels, state)

    source = next(item for item in state.provenance.sources if item.document_id == "vendor-doc")
    assert len(source.passages) == 1
    assert {candidate.kind for candidate in state.provenance.candidates if candidate.candidate_id in source.candidate_ids} == {
        "nvd_reference",
        "web_search",
    }
    assert source.association.status == "direct"
    assert source.association.target_mentions == ("title", "content")
    assert source.association.other_cve_ids == ("CVE-2023-9999",)
    assert source.retrieval.extraction_method == "trafilatura"
    assert source.retrieval.extraction_input_chars == 1_200
    assert len(state.provenance.candidates) == 3  # NVD reference plus both search results.
    assert {item.document_id for item in state.provenance.sources} >= {"vendor-doc", "unused-doc"}
    assert state.provenance.label_links[0].evidence[0]["evidence_id"] == "vendor-doc:p1"
    assert state.provenance.label_links[0].description == taxonomy.labels[0].description

    assert [item["source_id"] for item in public["sources"]] == ["source:web:vendor-doc"]
    assert public["format_version"] == 2
    assert {item["kind"] for item in public["sources"][0]["origins"]} == {"nvd_reference", "web_search"}
    assert public["sources"][0]["fetches"][0]["fetch_id"] == "fetch-1"
    assert public["sources"][0]["retrieval"] == {
        "extraction_method": "trafilatura",
        "extraction_input_chars": 1_200,
        "extraction_output_chars": 180,
        "truncated": False,
        "download_bytes": 1_500,
        "content_type": "text/html",
    }
    evidence = public["evidence"][0]
    assert evidence["evidence_id"] == "vendor-doc:p1"
    assert evidence["selection_event_id"] == "event-5"
    assert evidence["context"] == {"before": None, "after": None}
    assert evidence["findings"][0]["statement"] == state.findings[0].statement
    assert public["labels"][0]["label"] == "LENGTH-TRUST"

    with Database(tmp_path / "provenance.sqlite3") as database:
        run_id = database.start_run(taxonomy=taxonomy, model="fixture", settings={})
        database.save_investigation(run_id, 0, cve_id, "investigating", state)
        persisted = database.get_provenance(run_id, cve_id)
    assert {item["document_id"] for item in persisted["sources"]} >= {
        "vendor-doc",
        "unused-doc",
    }


def test_provenance_warns_but_retains_an_unverified_direct_source():
    cve = CVERecord("CVE-2024-12345", "NVD description.")
    state = _state(cve.cve_id, cve.description)
    recorder = ResearchProvenanceRecorder(cve, state, max_preview_chars=2_000)
    document = Document(
        "https://blog.test/generic",
        "Generic report",
        "This page discusses CVE-2020-1111 without naming the target vulnerability.",
        document_id="generic-doc",
        requested_url="https://blog.test/generic",
    )
    recorder.record_tool_call(
        "fetch",
        {"url": document.requested_url},
        {"document_id": document.document_id, "url": document.url},
        {document.document_id: document},
    )

    source = next(item for item in state.provenance.sources if item.document_id == "generic-doc")
    assert source.association.status == "unverified"
    assert source.association.other_cve_ids == ("CVE-2020-1111",)
    assert source.association.warnings == (
        "target_cve_not_explicitly_mentioned",
        "weak_target_association",
        "other_cves_mentioned_without_target",
    )
    assert source.retrieval.extraction_method == "unknown"
    assert source.retrieval.extraction_input_chars is None
    assert source.candidate_ids  # The unmatched URL is retained as a direct-fetch candidate.


def test_targeted_search_and_nvd_reference_are_distinct_indirect_associations():
    cve = CVERecord(
        "CVE-2024-12345",
        "NVD description.",
        (Reference("https://vendor.test/patch"),),
    )
    state = _state(cve.cve_id, cve.description)
    recorder = ResearchProvenanceRecorder(cve, state, max_preview_chars=2_000)
    recorder.record_tool_call(
        "search",
        {"query": f"{cve.cve_id} technical analysis"},
        {"results": [{"title": "Analysis", "url": "https://analysis.test/page", "snippet": "Details"}]},
        {},
    )
    documents = {
        "patch": Document("https://vendor.test/patch", content="Patch contents.", document_id="patch"),
        "analysis": Document("https://analysis.test/page", content="Technical contents.", document_id="analysis"),
    }
    for document in documents.values():
        recorder.record_tool_call(
            "fetch",
            {"url": document.url},
            {"document_id": document.document_id, "url": document.url},
            documents,
        )

    statuses = {item.document_id: item.association.status for item in state.provenance.sources}
    assert statuses["patch"] == "nvd_linked"
    assert statuses["analysis"] == "search_linked"


def test_failed_calls_and_legacy_evidence_remain_auditable():
    cve = CVERecord("CVE-2024-12345", "NVD description.")
    state = _state(cve.cve_id, cve.description)
    state.evidence.append(EvidenceRecord("legacy-evidence", "https://legacy.test", "Legacy quote.", "web"))
    recorder = ResearchProvenanceRecorder(cve, state, max_preview_chars=2_000)
    recorder.record_tool_call(
        "fetch",
        {"url": "https://failed.test"},
        {"error": "fetch failed (TimeoutError): timed out"},
        {},
    )
    labels = [LabelClassification("LEGACY", 0.7, (Evidence(
        "https://legacy.test",
        "Legacy quote.",
        "Legacy explanation.",
        "legacy-evidence",
    ),))]
    public = build_public_provenance(labels, state)

    assert state.provenance.fetches[-1].status == "error"
    assert state.provenance.events[-1].error == "fetch failed (TimeoutError): timed out"
    assert public["sources"][0]["cve_association"]["warnings"] == ("provenance_trace_unavailable",)


def test_label_trace_snapshots_the_definition_and_ancestor_path():
    taxonomy = Taxonomy((
        TaxonomyLabel("ROOT", "Root family", "Broad definition."),
        TaxonomyLabel("CHILD", "Specific child", "Specific definition.", "ROOT"),
    ))
    state = InvestigationState()
    labels = [LabelClassification("CHILD", 0.9, ())]

    record_label_links(labels, state, taxonomy)
    public = build_public_provenance(labels, state)

    assert public["labels"] == [{
        "label": "CHILD",
        "name": "Specific child",
        "description": "Specific definition.",
        "confidence": 0.9,
        "evidence": (),
        "ancestor_path": ({
            "id": "ROOT",
            "name": "Root family",
            "description": "Broad definition.",
        },),
    }]


def test_url_and_cve_normalization_are_deterministic():
    assert normalize_url("HTTPS://Example.COM:443/path?q=1#fragment") == "https://example.com/path?q=1"
    assert extract_cve_ids("CVE\u20112024\u201112345 and cve_2020_9999") == {
        "CVE-2024-12345",
        "CVE-2020-9999",
    }
