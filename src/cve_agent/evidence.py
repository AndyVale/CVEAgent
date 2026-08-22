from __future__ import annotations

import re
from difflib import SequenceMatcher

from cve_agent.models import Passage


class EvidenceResolutionError(ValueError):
    """Raised when an evidence locator cannot resolve to one canonical passage."""


def build_passages(document_id: str, content: str, *, max_chars: int, passage_chars: int = 900) -> tuple[Passage, ...]:
    """Create stable bounded passages from the exact preview shown to the model."""
    preview = content[:max_chars]
    blocks = [block.strip() for block in re.split(r"\n\s*\n|\n", preview) if block.strip()]
    pieces: list[str] = []
    for block in blocks:
        while len(block) > passage_chars:
            split_at = block.rfind(" ", 0, passage_chars + 1)
            if split_at < passage_chars // 2:
                split_at = passage_chars
            pieces.append(block[:split_at].strip())
            block = block[split_at:].strip()
        if block:
            pieces.append(block)
    return tuple(Passage(f"{document_id}:p{index}", text) for index, text in enumerate(pieces, start=1))


def resolve_passage(passages: tuple[Passage, ...], *, passage_id: str = "", quote_anchor: str = "") -> Passage:
    """Resolve an exact passage ID or a unique normalized/fuzzy quote anchor."""
    if passage_id:
        matches = [passage for passage in passages if passage.passage_id == passage_id]
        if len(matches) == 1:
            return matches[0]
        raise EvidenceResolutionError(f"unknown passage_id: {passage_id}")

    normalized_anchor = _normalize(quote_anchor)
    if not normalized_anchor:
        raise EvidenceResolutionError("provide passage_id or a non-empty quote_anchor")

    containing = [passage for passage in passages if normalized_anchor in _normalize(passage.text)]
    if len(containing) == 1:
        return containing[0]
    if len(containing) > 1:
        raise EvidenceResolutionError("quote_anchor matches multiple passages; use passage_id")

    scored = sorted(
        ((SequenceMatcher(None, normalized_anchor, _normalize(passage.text)).ratio(), passage) for passage in passages),
        key=lambda item: item[0],
        reverse=True,
    )
    if not scored or scored[0][0] < 0.72:
        raise EvidenceResolutionError("quote_anchor does not match a fetched passage")
    if len(scored) > 1 and scored[0][0] - scored[1][0] < 0.08:
        raise EvidenceResolutionError("quote_anchor is ambiguous; use passage_id")
    return scored[0][1]


def _normalize(value: str) -> str:
    return " ".join(value.casefold().split())
