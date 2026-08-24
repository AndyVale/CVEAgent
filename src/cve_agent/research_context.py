from __future__ import annotations

from dataclasses import asdict
from typing import Any

from cve_agent.models import CVERecord, Document, InvestigationState, Reference


MAX_NVD_REFERENCE_CANDIDATES = 24

_REFERENCE_TAG_PRIORITY = {
    "vendor advisory": 0,
    "patch": 1,
    "release notes": 2,
    "mitigation": 3,
    "product": 4,
    "exploit": 5,
    "technical description": 6,
    "third party advisory": 7,
}


def build_research_context(
    cve: CVERecord,
    state: InvestigationState,
    documents: dict[str, Document],
    *,
    turn: int,
    searches: int,
    fetches: int,
    max_turns: int,
    max_searches: int,
    max_fetches: int,
) -> dict[str, Any]:
    """Build a bounded, taxonomy-free context for one research turn."""
    references = select_reference_candidates(cve.references)
    return {
        "cve": {
            "cve_id": cve.cve_id,
            "description": cve.description,
            "metadata": cve.metadata,
            "references": [asdict(item) for item in references],
            "reference_count": len(cve.references),
            "omitted_reference_count": len(cve.references) - len(references),
        },
        "recorded_evidence": [asdict(item) for item in state.evidence],
        "tool_history": state.tool_history,
        "available_documents": [
            {"document_id": key, "url": value.url, "title": value.title}
            for key, value in documents.items()
        ],
        "investigation_budget": {
            "turn": turn,
            "max_turns": max_turns,
            "searches_used": searches,
            "max_searches": max_searches,
            "fetches_used": fetches,
            "max_fetches": max_fetches,
        },
    }


def select_reference_candidates(
    references: tuple[Reference, ...],
    *,
    limit: int = MAX_NVD_REFERENCE_CANDIDATES,
) -> tuple[Reference, ...]:
    """Keep the most actionable NVD references without growing every model turn."""
    if limit <= 0:
        return ()

    unique: list[tuple[int, Reference]] = []
    seen_urls: set[str] = set()
    for position, reference in enumerate(references):
        if reference.url in seen_urls:
            continue
        seen_urls.add(reference.url)
        unique.append((position, reference))

    ranked = sorted(
        unique,
        key=lambda item: (_reference_priority(item[1]), item[0]),
    )
    return tuple(reference for _, reference in ranked[:limit])


def _reference_priority(reference: Reference) -> int:
    priorities = (
        _REFERENCE_TAG_PRIORITY.get(tag.casefold(), len(_REFERENCE_TAG_PRIORITY))
        for tag in reference.tags
    )
    return min(priorities, default=len(_REFERENCE_TAG_PRIORITY))
