from cve_agent.core.investigation import InvestigationAspect, InvestigationState
from cve_agent.core.sources import Document, EvidenceRecord
from cve_agent.investigation.evidence import build_passages
from cve_agent.investigation.profile import build_investigation_profile
from tests.support.agent import FixtureWeb, finish_arguments, settings


def test_finish_investigation_promotes_fetched_passages_and_discards_only_unsupported_findings(tmp_path):
    documents = {"doc-1": FixtureWeb().fetch("https://fixture.test/advisory")}
    arguments = finish_arguments()
    arguments["findings"].append({
        "aspect": "impact",
        "statement": "Unsupported impact claim.",
        "evidence_ids": ["doc-1:p99"],
    })
    arguments["unknowns"] = [{"aspect": "root_cause", "explanation": "Legacy field is ignored."}]
    state = InvestigationState()

    outcome = build_investigation_profile(arguments, state, documents, max_preview_chars=settings(tmp_path).max_preview_chars)

    assert outcome.information_status == "sufficient"
    assert [item.aspect for item in outcome.findings] == [InvestigationAspect.ROOT_CAUSE]
    assert outcome.discarded_findings == 1
    assert outcome.discarded_reasons == ("no_usable_evidence",)
    assert outcome.evidence_issues[0].reason == "unknown_evidence"
    assert outcome.promoted_evidence == 1
    assert state.evidence[0].evidence_id == "doc-1:p1"
    assert state.evidence[0].verification == "finish_reference"


def test_finish_investigation_derives_insufficient_without_core_mechanism_or_web_evidence(tmp_path):
    state = InvestigationState(evidence=[EvidenceRecord("nvd-description", "https://nvd.test/VULN-1", "Known impact.", "nvd_description")])
    outcome = build_investigation_profile(
        finish_arguments("nvd-description", mechanism_supported=False),
        state,
        {},
        max_preview_chars=settings(tmp_path).max_preview_chars,
    )

    assert outcome.information_status == "insufficient"
    assert outcome.findings[0].aspect == InvestigationAspect.IMPACT


def test_finish_investigation_auto_promotes_an_unrecorded_late_passage(tmp_path):
    content = "\n".join(f"Passage {index}: " + "technical detail " * 10 for index in range(1, 20))
    document = Document("https://fixture.test/long", "Long advisory", content, document_id="doc-late")
    late_passage = build_passages("doc-late", content, max_chars=settings(tmp_path).max_preview_chars)[-1]
    arguments = finish_arguments(late_passage.passage_id)

    outcome = build_investigation_profile(
        arguments,
        InvestigationState(),
        {"doc-late": document},
        max_preview_chars=settings(tmp_path).max_preview_chars,
    )

    assert outcome.findings[0].evidence_ids == (late_passage.passage_id,)
    assert outcome.promoted_evidence == 1


def test_finish_validation_does_not_promote_evidence_before_acceptance(tmp_path):
    documents = {"doc-1": FixtureWeb().fetch("https://fixture.test/advisory")}
    state = InvestigationState()

    outcome = build_investigation_profile(
        finish_arguments(),
        state,
        documents,
        max_preview_chars=settings(tmp_path).max_preview_chars,
        promote_evidence=False,
    )

    assert outcome.findings[0].evidence_ids == ("doc-1:p1",)
    assert outcome.promoted_evidence == 1
    assert state.evidence == []
