import pytest

from cve_agent.evidence import EvidenceResolutionError, build_passages, resolve_passage


def test_passage_ids_are_stable_and_exact():
    passages = build_passages("doc", "First exact paragraph.\n\nSecond exact paragraph.", max_chars=1000)
    assert [item.passage_id for item in passages] == ["doc:p1", "doc:p2"]
    assert passages[1].text == "Second exact paragraph."


def test_fuzzy_anchor_requires_one_clear_match():
    passages = build_passages("doc", "Alpha memory corruption details.\n\nBeta authorization details.", max_chars=1000)
    assert resolve_passage(passages, quote_anchor="alpha memory corruption detail").passage_id == "doc:p1"
    with pytest.raises(EvidenceResolutionError, match="does not match"):
        resolve_passage(passages, quote_anchor="unrelated database behavior")


def test_repeated_anchor_is_ambiguous():
    passages = build_passages("doc", "Repeated evidence phrase one.\n\nRepeated evidence phrase two.", max_chars=1000)
    with pytest.raises(EvidenceResolutionError, match="multiple passages"):
        resolve_passage(passages, quote_anchor="repeated evidence phrase")
