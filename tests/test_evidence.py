import pytest

from cve_agent.evidence import EvidenceResolutionError, build_passages, resolve_passage, unusable_evidence_reason


def test_passage_ids_are_stable_and_exact():
    passages = build_passages("doc", "First exact paragraph.\n\nSecond exact paragraph.", max_chars=1000)
    assert [item.passage_id for item in passages] == ["doc:p1"]
    assert passages[0].text == "First exact paragraph.\nSecond exact paragraph."


def test_passages_pack_short_lines_and_keep_every_piece_bounded():
    content = "\n".join(f"Line {index}: " + "technical evidence " * 8 for index in range(18))

    passages = build_passages("doc", content, max_chars=10_000)

    assert 2 <= len(passages) < 18
    assert all(len(item.text) <= 1_100 for item in passages)
    assert "Line 0" in passages[0].text
    assert "Line 17" in passages[-1].text


@pytest.mark.parametrize("reference", ["1", "p1", "doc:1", "doc:p1"])
def test_passage_ids_accept_document_local_shorthand(reference):
    passages = build_passages("doc", "First exact paragraph.\n\nSecond exact paragraph.", max_chars=1000)
    assert resolve_passage(passages, passage_id=reference).passage_id == "doc:p1"


def test_fuzzy_anchor_requires_one_clear_match():
    passages = build_passages("doc", "Alpha memory corruption details.\n\nBeta authorization details.", max_chars=1000)
    assert resolve_passage(passages, quote_anchor="alpha memory corruption detail").passage_id == "doc:p1"
    with pytest.raises(EvidenceResolutionError, match="does not match"):
        resolve_passage(passages, quote_anchor="unrelated database behavior")


def test_repeated_anchor_is_ambiguous():
    passages = build_passages(
        "doc",
        "Repeated evidence phrase one. " + "A" * 900 + "\nRepeated evidence phrase two. " + "B" * 900,
        max_chars=3_000,
    )
    with pytest.raises(EvidenceResolutionError, match="multiple passages"):
        resolve_passage(passages, quote_anchor="repeated evidence phrase")


@pytest.mark.parametrize("text", ["", "<div></div>", "'uri' => p", "exec_payload(p)"])
def test_mechanically_unusable_fragments_are_rejected(text):
    assert unusable_evidence_reason(text) is not None


def test_short_complete_sources_and_substantive_sentences_are_retained():
    assert unusable_evidence_reason("Use after free.") is None
    assert unusable_evidence_reason("Tiny.", complete_source=True) is None
