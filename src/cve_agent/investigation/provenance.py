from __future__ import annotations

from dataclasses import replace
from typing import Any
import urllib.parse

from cve_agent.core.investigation import InvestigationState
from cve_agent.core.provenance import (
    EvidenceTrace,
    FetchTrace,
    ProvenanceEvent,
    ProvenanceSearch,
    RetrievalTrace,
    SourceAssociation,
    SourceCandidate,
    SourceTrace,
)
from cve_agent.core.sources import CVERecord, Document, Passage
from cve_agent.core.urls import canonical_cve_id
from cve_agent.core.urls import extract_cve_ids
from cve_agent.core.urls import normalize_url
from cve_agent.investigation.context import select_reference_candidates
from cve_agent.investigation.evidence import build_passages


_MAX_QUERY_CHARS = 500


_MAX_TITLE_CHARS = 300


_MAX_SNIPPET_CHARS = 800


_MAX_ERROR_CHARS = 500


class ResearchProvenanceRecorder:
    """Record a bounded, model-independent audit of one CVE investigation."""

    def __init__(self, cve: CVERecord, state: InvestigationState, *, max_preview_chars: int):
        self.cve = cve
        self.state = state
        self.max_preview_chars = max_preview_chars
        self.ledger = state.provenance
        self._initialize()

    def record_tool_call(
        self,
        name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        documents: dict[str, Document],
    ) -> None:
        event_id = f"event-{len(self.ledger.events) + 1}"
        status = "error" if "error" in result else "success"
        error = _bounded(result.get("error"), _MAX_ERROR_CHARS) or None
        details: dict[str, Any] = {}

        if name == "search":
            search_id = f"search-{len(self.ledger.searches) + 1}"
            query = _bounded(arguments.get("query"), _MAX_QUERY_CHARS)
            candidate_ids: list[str] = []
            if status == "success":
                for rank, raw in enumerate(result.get("results", []), start=1):
                    if not isinstance(raw, dict) or not raw.get("url"):
                        continue
                    candidate_id = f"{search_id}:result-{rank}"
                    self.ledger.candidates.append(SourceCandidate(
                        candidate_id=candidate_id,
                        kind="web_search",
                        url=str(raw["url"]),
                        title=_bounded(raw.get("title"), _MAX_TITLE_CHARS),
                        snippet=_bounded(raw.get("snippet"), _MAX_SNIPPET_CHARS),
                        query=query,
                        search_id=search_id,
                        rank=rank,
                    ))
                    candidate_ids.append(candidate_id)
            self.ledger.searches.append(ProvenanceSearch(search_id, query, status, tuple(candidate_ids), error))
            details = {"search_id": search_id, "query": query, "candidate_ids": candidate_ids}

        elif name == "fetch":
            fetch_id = f"fetch-{len(self.ledger.fetches) + 1}"
            requested_url = str(arguments.get("url", result.get("url", "")))
            candidate_ids = self._matching_candidates(requested_url)
            if not candidate_ids:
                direct_id = f"{fetch_id}:direct"
                self.ledger.candidates.append(SourceCandidate(direct_id, "direct_fetch", requested_url))
                candidate_ids = (direct_id,)

            document = self._result_document(result, documents)
            reused = result.get("reused") is True and document is not None
            document_id = (document.document_id or requested_url) if document else None
            trace = FetchTrace(
                fetch_id=fetch_id,
                status=status,
                requested_url=requested_url,
                candidate_ids=candidate_ids,
                document_id=document_id,
                source_id=f"source:web:{document_id}" if document_id else None,
                resolved_url=document.url if document else None,
                redirect_chain=document.redirect_chain if document else (),
                reused=reused,
                error=error,
            )
            self.ledger.fetches.append(trace)
            if document is not None:
                self._record_source(document, candidate_ids)
            details = {
                "fetch_id": fetch_id,
                "requested_url": requested_url,
                "candidate_ids": list(candidate_ids),
                "document_id": trace.document_id,
                "reused": reused,
            }

        elif name == "record_evidence":
            details = {
                "document_id": arguments.get("document_id"),
                "passage_id": arguments.get("passage_id"),
                "quote_anchor": _bounded(arguments.get("quote_anchor"), 300),
                "evidence_id": result.get("evidence_id"),
            }
            self.sync_evidence(documents, selection_event_id=event_id)

        elif name == "finish_investigation":
            details = {
                "information_status": result.get("information_status"),
                "finding_count": result.get("finding_count", 0),
                "discarded_findings": result.get("discarded_findings", 0),
                "discarded_by_reason": result.get("discarded_by_reason", {}),
                "promoted_evidence": result.get("promoted_evidence", 0),
                "evidence_issues": result.get("evidence_issues", []),
                "fallback_reason": result.get("fallback_reason"),
                "submitted_summary": _bounded(arguments.get("summary"), 2_000),
                "submitted_findings": _bounded_findings(arguments.get("findings")),
            }
            self.sync_evidence(documents, selection_event_id=event_id)

        else:
            details = {"arguments": _bounded_mapping(arguments)}

        self.ledger.events.append(ProvenanceEvent(
            event_id=event_id,
            action=name,
            status=status,
            details=details,
            error=error,
        ))

    def sync_evidence(
        self,
        documents: dict[str, Document],
        *,
        selection_event_id: str | None = None,
    ) -> None:
        existing = {item.evidence_id for item in self.ledger.evidence}
        source_by_document = {item.document_id: item for item in self.ledger.sources}
        for record in self.state.evidence:
            if record.evidence_id in existing:
                continue
            if record.source_type == "nvd_description":
                self.ledger.evidence.append(EvidenceTrace(
                    record.evidence_id,
                    "source:nvd",
                    record.evidence_id,
                    record.verification,
                    selection_event_id,
                ))
                existing.add(record.evidence_id)
                continue

            document_id = record.evidence_id.rsplit(":p", 1)[0]
            document = documents.get(document_id)
            if document is None:
                document = next(
                    (
                        item for item in documents.values()
                        if (item.document_id or item.url) == document_id
                        or item.url == record.url
                        or item.requested_url == record.requested_url
                    ),
                    None,
                )
            if document is not None and document_id not in source_by_document:
                self._record_source(document, self._matching_candidates(document.requested_url or document.url))
                source_by_document = {item.document_id: item for item in self.ledger.sources}
            source = source_by_document.get(document_id)
            if source is None:
                continue
            passage_ids = [item.passage_id for item in source.passages]
            try:
                position = passage_ids.index(record.evidence_id)
            except ValueError:
                position = -1
            self.ledger.evidence.append(EvidenceTrace(
                evidence_id=record.evidence_id,
                source_id=source.source_id,
                passage_id=record.evidence_id,
                selection_method=record.verification,
                selection_event_id=selection_event_id,
                previous_passage_id=passage_ids[position - 1] if position > 0 else None,
                next_passage_id=passage_ids[position + 1] if 0 <= position < len(passage_ids) - 1 else None,
            ))
            existing.add(record.evidence_id)

    def _initialize(self) -> None:
        if self.ledger.target_cve_id and self.ledger.target_cve_id != self.cve.cve_id:
            raise ValueError(
                f"provenance target {self.ledger.target_cve_id!r} does not match {self.cve.cve_id!r}"
            )
        initialized = not self.ledger.target_cve_id
        if initialized:
            self.ledger.target_cve_id = self.cve.cve_id
            self.ledger.nvd_metadata = _bounded_json_mapping(self.cve.metadata)
            self.ledger.nvd_reference_count = len(self.cve.references)
            references = select_reference_candidates(self.cve.references)
            self.ledger.omitted_nvd_references = len(self.cve.references) - len(references)
            for position, reference in enumerate(references, start=1):
                self.ledger.candidates.append(SourceCandidate(
                    candidate_id=f"nvd-reference-{position}",
                    kind="nvd_reference",
                    url=reference.url,
                    source=reference.source,
                    tags=reference.tags,
                ))

            nvd_url = f"https://nvd.nist.gov/vuln/detail/{self.cve.cve_id}"
            nvd_passages = (
                (Passage("nvd-description", self.cve.description),)
                if self.cve.description.strip()
                else ()
            )
            self.ledger.sources.append(SourceTrace(
                source_id="source:nvd",
                document_id="nvd-record",
                title=f"NVD record for {self.cve.cve_id}",
                requested_url=nvd_url,
                resolved_url=nvd_url,
                redirect_chain=(),
                candidate_ids=(),
                association=SourceAssociation(
                    status="direct",
                    target_cve_id=self.cve.cve_id,
                    target_mentions=("resolved_url",),
                ),
                passages=nvd_passages,
            ))
            self.ledger.events.append(ProvenanceEvent(
                event_id="event-1",
                action="get_cve",
                status="success",
                details={
                    "source": "NVD",
                    "cve_id": self.cve.cve_id,
                    "description_evidence_id": "nvd-description" if nvd_passages else None,
                    "reference_candidate_ids": [item.candidate_id for item in self.ledger.candidates],
                    "reference_count": len(self.cve.references),
                    "omitted_reference_count": self.ledger.omitted_nvd_references,
                },
            ))
        self.sync_evidence({}, selection_event_id="event-1" if initialized else None)

    def _matching_candidates(self, requested_url: str) -> tuple[str, ...]:
        normalized = normalize_url(requested_url)
        return tuple(
            item.candidate_id
            for item in self.ledger.candidates
            if normalize_url(item.url) == normalized
        )

    @staticmethod
    def _result_document(result: dict[str, Any], documents: dict[str, Document]) -> Document | None:
        document_id = result.get("document_id")
        if document_id in documents:
            return documents[document_id]
        return next(
            (
                item for item in documents.values()
                if (item.document_id or item.url) == document_id
                or item.url == result.get("url")
            ),
            None,
        )

    def _record_source(self, document: Document, candidate_ids: tuple[str, ...]) -> None:
        document_id = document.document_id or document.url
        source_id = f"source:web:{document_id}"
        for position, source in enumerate(self.ledger.sources):
            if source.source_id != source_id:
                continue
            merged = tuple(dict.fromkeys((*source.candidate_ids, *candidate_ids)))
            if merged != source.candidate_ids:
                merged_candidates = [
                    item for item in self.ledger.candidates if item.candidate_id in merged
                ]
                self.ledger.sources[position] = replace(
                    source,
                    candidate_ids=merged,
                    association=source_association(self.cve.cve_id, document, merged_candidates),
                )
            return

        candidates = [item for item in self.ledger.candidates if item.candidate_id in candidate_ids]
        passages = build_passages(document_id, document.content, max_chars=self.max_preview_chars)
        self.ledger.sources.append(SourceTrace(
            source_id=source_id,
            document_id=document_id,
            title=document.title,
            requested_url=document.requested_url or document.url,
            resolved_url=document.url,
            redirect_chain=document.redirect_chain,
            candidate_ids=candidate_ids,
            association=source_association(self.cve.cve_id, document, candidates),
            passages=passages,
            retrieval=_retrieval_trace(document),
        ))


def source_association(
    cve_id: str,
    document: Document,
    candidates: list[SourceCandidate],
) -> SourceAssociation:
    target = canonical_cve_id(cve_id)
    locations = tuple(
        location
        for location, value in (
            ("requested_url", urllib.parse.unquote(document.requested_url or document.url)),
            ("resolved_url", urllib.parse.unquote(document.url)),
            ("title", document.title),
            ("content", document.content),
        )
        if target in extract_cve_ids(value)
    )
    discovered = set().union(
        extract_cve_ids(document.requested_url),
        extract_cve_ids(document.url),
        extract_cve_ids(document.title),
        extract_cve_ids(document.content),
    )
    other_ids = tuple(sorted(discovered - {target}))
    kinds = {item.kind for item in candidates}
    targeted_search = any(
        item.kind == "web_search"
        and target in set().union(
            extract_cve_ids(item.query),
            extract_cve_ids(item.url),
            extract_cve_ids(item.title),
            extract_cve_ids(item.snippet),
        )
        for item in candidates
    )
    if locations:
        status = "direct"
    elif "nvd_reference" in kinds:
        status = "nvd_linked"
    elif targeted_search:
        status = "search_linked"
    else:
        status = "unverified"

    warnings: list[str] = []
    if not locations:
        warnings.append("target_cve_not_explicitly_mentioned")
    if status in {"search_linked", "unverified"}:
        warnings.append("weak_target_association")
    if other_ids and not locations:
        warnings.append("other_cves_mentioned_without_target")
    return SourceAssociation(status, target, locations, other_ids, tuple(warnings))


def _retrieval_trace(document: Document) -> RetrievalTrace:
    metadata = document.metadata if isinstance(document.metadata, dict) else {}
    method = metadata.get("extraction_method")
    if method not in {"trafilatura", "raw_fallback"}:
        method = "unknown"
    return RetrievalTrace(
        extraction_method=method,
        extraction_input_chars=_optional_nonnegative_int(metadata.get("extraction_input_chars")),
        extraction_output_chars=_optional_nonnegative_int(metadata.get("extraction_output_chars")),
        truncated=metadata.get("truncated") if isinstance(metadata.get("truncated"), bool) else None,
        download_bytes=_optional_nonnegative_int(metadata.get("download_bytes")),
        content_type=metadata.get("content_type") if isinstance(metadata.get("content_type"), str) else None,
    )


def _optional_nonnegative_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _bounded(value: Any, limit: int) -> str:
    return str(value or "")[:limit]


def _bounded_mapping(value: dict[str, Any]) -> dict[str, str]:
    return {str(key)[:100]: _bounded(item, 300) for key, item in value.items()}


def _bounded_json_mapping(value: dict[str, Any]) -> dict[str, Any]:
    return {
        str(key)[:100]: _bounded_json_value(item, depth=1)
        for key, item in list(value.items())[:100]
    }


def _bounded_json_value(value: Any, *, depth: int) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:2_000]
    if depth >= 3:
        return _bounded(value, 2_000)
    if isinstance(value, dict):
        return {
            str(key)[:100]: _bounded_json_value(item, depth=depth + 1)
            for key, item in list(value.items())[:100]
        }
    if isinstance(value, (list, tuple)):
        return [_bounded_json_value(item, depth=depth + 1) for item in value[:100]]
    return _bounded(value, 2_000)


def _bounded_findings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    findings: list[dict[str, Any]] = []
    for raw in value[:20]:
        if not isinstance(raw, dict):
            continue
        raw_ids = raw.get("evidence_ids", [])
        if isinstance(raw_ids, str):
            raw_ids = [raw_ids]
        findings.append({
            "aspect": _bounded(raw.get("aspect"), 100),
            "statement": _bounded(raw.get("statement"), 2_000),
            "evidence_ids": [
                _bounded(item, 200) for item in raw_ids[:20]
            ] if isinstance(raw_ids, list) else [],
        })
    return findings
