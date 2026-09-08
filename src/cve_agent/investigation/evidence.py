from __future__ import annotations

from difflib import SequenceMatcher
import html
import re

from cve_agent.core.investigation import InvestigationState
from cve_agent.core.sources import Document, EvidenceRecord, Passage


class EvidenceResolutionError(ValueError):
    """Raised when an evidence locator cannot resolve to one canonical passage."""


_HTML_TAG_PATTERN = re.compile(r"<[^>]*>")
_WORD_PATTERN = re.compile(r"\w+(?:[\N{RIGHT SINGLE QUOTATION MARK}'-]\w+)*", re.UNICODE)
_MIN_FRAGMENT_WORDS = 3
_MIN_FRAGMENT_ALNUM = 24


def store_passage_evidence(
    state: InvestigationState,
    document: Document,
    passage: Passage,
    *,
    verification: str,
) -> tuple[EvidenceRecord, bool]:
    """Store one canonical passage without duplicating evidence construction paths."""
    existing = next((item for item in state.evidence if item.evidence_id == passage.passage_id), None)
    if existing is not None:
        return existing, False
    record = EvidenceRecord(
        passage.passage_id,
        document.url,
        passage.text,
        "web",
        document.requested_url or document.url,
        verification,
    )
    state.evidence.append(record)
    return record, True


def build_passages(document_id: str, content: str, *, max_chars: int, passage_chars: int = 900) -> tuple[Passage, ...]:
    """Create stable, coherent passages from the exact bounded preview shown to the model."""
    if passage_chars <= 0:
        raise ValueError("passage_chars must be positive")
    preview = content[:max_chars].replace("\r\n", "\n").replace("\r", "\n")
    blocks = [line.strip() for line in preview.split("\n") if line.strip()]
    segments = [segment for block in blocks for segment in _split_block(block, passage_chars)]
    pieces: list[str] = []
    current = ""
    overflow_limit = passage_chars + 200
    short_limit = max(1, passage_chars // 4)
    for segment in segments:
        candidate = f"{current}\n{segment}" if current else segment
        if len(candidate) <= passage_chars:
            current = candidate
            continue
        if current and len(current) < short_limit and len(candidate) <= overflow_limit:
            pieces.append(candidate)
            current = ""
            continue
        if current:
            pieces.append(current)
        current = segment
    if current:
        if pieces and len(current) < short_limit and len(pieces[-1]) + 1 + len(current) <= overflow_limit:
            pieces[-1] = f"{pieces[-1]}\n{current}"
        else:
            pieces.append(current)
    return tuple(Passage(f"{document_id}:p{index}", text) for index, text in enumerate(pieces, start=1))


def unusable_evidence_reason(text: str, *, complete_source: bool = False) -> str | None:
    """Return a narrow mechanical rejection reason without judging semantic support."""
    visible = html.unescape(_HTML_TAG_PATTERN.sub(" ", text))
    normalized = " ".join(visible.split())
    alphanumeric = sum(character.isalnum() for character in normalized)
    if not normalized or alphanumeric == 0:
        return "empty_or_markup_only"
    if not complete_source and len(_WORD_PATTERN.findall(normalized)) < _MIN_FRAGMENT_WORDS and alphanumeric < _MIN_FRAGMENT_ALNUM:
        return "fragment_too_short"
    return None


def _split_block(block: str, passage_chars: int) -> tuple[str, ...]:
    pieces: list[str] = []
    remainder = block
    while len(remainder) > passage_chars:
        split_at = remainder.rfind(" ", 0, passage_chars + 1)
        if split_at < passage_chars // 2:
            split_at = passage_chars
        pieces.append(remainder[:split_at].strip())
        remainder = remainder[split_at:].strip()
    if remainder:
        if pieces and len(pieces[-1]) + 1 + len(remainder) <= passage_chars + 200:
            pieces[-1] = f"{pieces[-1]} {remainder}"
        else:
            pieces.append(remainder)
    return tuple(piece for piece in pieces if piece)


def resolve_passage(passages: tuple[Passage, ...], *, passage_id: str = "", quote_anchor: str = "") -> Passage:
    """Resolve an exact passage ID or a unique normalized/fuzzy quote anchor."""
    if passage_id:
        matches = passage_id_candidates(passages, passage_id)
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise EvidenceResolutionError(f"ambiguous passage_id shorthand: {passage_id}")
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


def passage_id_candidates(passages: tuple[Passage, ...], passage_id: str) -> tuple[Passage, ...]:
    """Return exact or shorthand passage-ID candidates without raising on model input."""
    reference = passage_id.strip()
    exact = tuple(passage for passage in passages if passage.passage_id == reference)
    if exact:
        return exact

    local = re.fullmatch(r"p?(\d+)", reference, flags=re.IGNORECASE)
    if local:
        suffix = f":p{int(local.group(1))}"
        return tuple(passage for passage in passages if passage.passage_id.endswith(suffix))

    qualified = re.fullmatch(r"(.+):p?(\d+)", reference, flags=re.IGNORECASE)
    if qualified:
        canonical = f"{qualified.group(1)}:p{int(qualified.group(2))}"
        return tuple(passage for passage in passages if passage.passage_id == canonical)
    return ()


def _normalize(value: str) -> str:
    return " ".join(value.casefold().split())
