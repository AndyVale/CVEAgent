from __future__ import annotations

from dataclasses import asdict
from typing import Any
import json

from cve_agent.core.investigation import InvestigationState
from cve_agent.core.sources import CVERecord, Document, Reference


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
        "cve": _cve_context(cve, references),
        "recorded_evidence": [asdict(item) for item in state.evidence],
        "tool_history": state.tool_history,
        "available_documents": _available_documents(documents),
        "investigation_budget": _investigation_budget(
            turn,
            searches,
            fetches,
            max_turns,
            max_searches,
            max_fetches,
        ),
    }


class _ResearchContextSerializer:
    """Serialize immutable research-context entries once per investigation."""

    def __init__(self, cve: CVERecord, references: tuple[Reference, ...] | None = None):
        selected = references if references is not None else select_reference_candidates(cve.references)
        self._cve_json = _json_dumps(_cve_context(cve, selected))
        self._evidence_snapshot: tuple[Any, ...] = ()
        self._evidence_json: list[str] = []
        self._history_snapshot: tuple[dict[str, Any], ...] = ()
        self._history_json: list[str] = []
        self._document_snapshot: tuple[tuple[str, Document], ...] = ()
        self._documents_json = "[]"

    def render(
        self,
        state: InvestigationState,
        documents: dict[str, Document],
        exchange: list[dict[str, Any]],
        *,
        turn: int,
        searches: int,
        fetches: int,
        max_turns: int,
        max_searches: int,
        max_fetches: int,
    ) -> str:
        self._sync_evidence(state)
        self._sync_history(state)
        self._sync_documents(documents)
        represented_events = sum(item.get("role") == "tool" for item in exchange)
        visible_history = max(0, len(self._history_json) - represented_events)
        budget_json = _json_dumps(_investigation_budget(
            turn,
            searches,
            fetches,
            max_turns,
            max_searches,
            max_fetches,
        ))
        return (
            '{"cve":' + self._cve_json
            + ',"recorded_evidence":' + _json_array(self._evidence_json)
            + ',"tool_history":' + _json_array(self._history_json[:visible_history])
            + ',"available_documents":' + self._documents_json
            + ',"investigation_budget":' + budget_json
            + "}"
        )

    def _sync_evidence(self, state: InvestigationState) -> None:
        current = tuple(state.evidence)
        common = _common_prefix(self._evidence_snapshot, current)
        if common < len(self._evidence_json):
            del self._evidence_json[common:]
        self._evidence_json.extend(_json_dumps(asdict(item)) for item in current[common:])
        self._evidence_snapshot = current

    def _sync_history(self, state: InvestigationState) -> None:
        current = tuple(state.tool_history)
        common = _identity_prefix(self._history_snapshot, current)
        if common < len(self._history_json):
            del self._history_json[common:]
        self._history_json.extend(_json_dumps(item) for item in state.tool_history[common:])
        self._history_snapshot = current

    def _sync_documents(self, documents: dict[str, Document]) -> None:
        current = tuple(documents.items())
        unchanged = len(current) == len(self._document_snapshot) and all(
            old_key == new_key and old_document is new_document
            for (old_key, old_document), (new_key, new_document) in zip(self._document_snapshot, current)
        )
        if unchanged:
            return
        self._documents_json = _json_dumps(_available_documents(documents))
        self._document_snapshot = current


def _cve_context(cve: CVERecord, references: tuple[Reference, ...]) -> dict[str, Any]:
    return {
        "cve_id": cve.cve_id,
        "metadata": cve.metadata,
        "references": [asdict(item) for item in references],
        "reference_count": len(cve.references),
        "omitted_reference_count": len(cve.references) - len(references),
    }


def _available_documents(documents: dict[str, Document]) -> list[dict[str, Any]]:
    return [
        {
            "document_id": key,
            "requested_url": value.requested_url or value.url,
            "resolved_url": value.url,
            "title": value.title,
        }
        for key, value in documents.items()
    ]


def _investigation_budget(
    turn: int,
    searches: int,
    fetches: int,
    max_turns: int,
    max_searches: int,
    max_fetches: int,
) -> dict[str, int]:
    return {
        "turn": turn,
        "max_turns": max_turns,
        "searches_used": searches,
        "max_searches": max_searches,
        "fetches_used": fetches,
        "max_fetches": max_fetches,
    }


def _common_prefix(previous: tuple[Any, ...], current: tuple[Any, ...]) -> int:
    common = 0
    for old, new in zip(previous, current):
        if old != new:
            break
        common += 1
    return common


def _identity_prefix(previous: tuple[Any, ...], current: tuple[Any, ...]) -> int:
    common = 0
    for old, new in zip(previous, current):
        if old is not new:
            break
        common += 1
    return common


def _json_array(items: list[str]) -> str:
    return "[" + ",".join(items) + "]"


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


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
