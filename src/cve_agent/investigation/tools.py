from __future__ import annotations

from dataclasses import asdict
from typing import Any
import json

from cve_agent.core.config import Settings
from cve_agent.core.investigation import InvestigationState
from cve_agent.core.ports import WebSource
from cve_agent.core.sources import Document
from cve_agent.core.urls import normalize_url
from cve_agent.investigation.evidence import (
    EvidenceResolutionError,
    build_passages,
    resolve_passage,
    store_passage_evidence,
)
from cve_agent.investigation.session import ResearchSession
from cve_agent.runtime.diagnostics import redact_secrets


class ResearchToolExecutor:
    """Execute bounded web and evidence tools for one CVE research session."""

    def __init__(self, settings: Settings, web_source: WebSource):
        self.settings = settings
        self.web_source = web_source

    def execute(self, name: str, arguments: dict[str, Any], state: InvestigationState, session: ResearchSession) -> dict[str, Any]:
        key = (name, json.dumps(arguments, sort_keys=True))
        if name == "record_evidence" and arguments.get("document_id") not in session.documents:
            return self._record_evidence(arguments, state, session.documents)
        if key in session.seen_calls:
            if name == "fetch" and self._existing_document_result(
                str(arguments.get("url", "")), session.documents
            ) is not None:
                return self._fetch(arguments, state, session)
            if name == "fetch":
                return {"error": "this URL was already attempted"}
            return {"error": "duplicate tool call"}
        session.seen_calls.add(key)

        if name == "search":
            return self._search(arguments, session)
        if name == "fetch":
            return self._fetch(arguments, state, session)
        if name == "record_evidence":
            return self._record_evidence(arguments, state, session.documents)
        return {"error": f"unknown tool: {name}"}

    @staticmethod
    def tool_event(name: str, arguments: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        event: dict[str, Any] = {"tool": name, "status": "error" if "error" in result else "success"}
        if "error" in result:
            event["error"] = str(result["error"])[:500]
        if name == "fetch":
            event.update({
                "url": arguments.get("url", ""),
                "document_id": result.get("document_id"),
                "reused": result.get("reused") is True,
            })
        elif name == "search":
            event.update({
                "query": arguments.get("query", ""),
                "result_count": len(result.get("results", [])),
                "available_results_omitted": result.get("available_results_omitted", 0),
            })
        elif name == "record_evidence":
            event.update({
                "document_id": arguments.get("document_id"),
                "passage_id": arguments.get("passage_id"),
                "evidence_id": result.get("evidence_id"),
            })
        elif name == "finish_investigation":
            event.update({
                "information_status": result.get("information_status"),
                "finding_count": result.get("finding_count", 0),
                "discarded_findings": result.get("discarded_findings", 0),
                "discarded_by_reason": result.get("discarded_by_reason", {}),
                "promoted_evidence": result.get("promoted_evidence", 0),
                "evidence_issues": result.get("evidence_issues", []),
            })
        return event

    def _search(self, arguments: dict[str, Any], session: ResearchSession) -> dict[str, Any]:
        if session.searches >= self.settings.max_search_calls:
            return {"error": "search limit reached"}
        query = arguments["query"]
        session.searches += 1
        try:
            results = self.web_source.search(query)
        except Exception as exc:
            return {"error": self._tool_error("search", exc)}
        novel_results = [
            item for item in results
            if self._existing_document(item.url, session.documents) is None
        ]
        omitted = len(results) - len(novel_results)
        result: dict[str, Any] = {"results": [asdict(item) for item in novel_results[:10]]}
        if omitted:
            result["available_results_omitted"] = omitted
            result["instruction"] = (
                "Search results whose requested or resolved URLs are already available were omitted. "
                "Use available_documents to redisplay one intentionally."
            )
        return result

    def _fetch(self, arguments: dict[str, Any], state: InvestigationState, session: ResearchSession) -> dict[str, Any]:
        url = arguments["url"]
        existing = self._existing_document_result(url, session.documents)
        if existing:
            document_id = str(existing["document_id"])
            if document_id in session.redisplayed_documents:
                return {
                    "error": "document already redisplayed; another fetch would return the same stored passages",
                    "document_id": document_id,
                    "url": existing["url"],
                    "reused": True,
                    "instruction": "Use recorded evidence, choose another source, or finish the investigation.",
                }
            session.redisplayed_documents.add(document_id)
            existing["instruction"] = (
                "This URL is already available, so these are the same stored passages. "
                "Record every useful passage not already in recorded_evidence before another tool call; "
                "use another source when you need new information."
            )
            return existing
        if session.fetches >= self.settings.max_fetch_calls:
            return {"error": "fetch limit reached"}
        session.fetches += 1
        try:
            document = self.web_source.fetch(url)
        except Exception as exc:
            return {"error": self._tool_error("fetch", exc), "url": url}
        session.documents[document.document_id or url] = document
        if document.url not in state.visited_urls:
            state.visited_urls.append(document.url)
        result = self._document_result(document, reused=False)
        result["instruction"] = (
            "Before another tool call, record every distinct, substantive passage that could support a finding. "
            "A generic page introduction, navigation, or description of a vulnerability list is not evidence. "
            "If no passage is useful, continue without recording it."
        )
        return result

    def _record_evidence(
        self,
        arguments: dict[str, Any],
        state: InvestigationState,
        documents: dict[str, Document],
    ) -> dict[str, Any]:
        document = documents.get(arguments.get("document_id", ""))
        if document is None:
            available_ids = list(documents)
            return {
                "error": "document not found",
                "instruction": (
                    "Use one of the available document IDs."
                    if available_ids
                    else "Fetch a search result before recording evidence."
                ),
                "available_document_ids": available_ids,
            }
        passages = build_passages(
            document.document_id or document.url,
            document.content,
            max_chars=self.settings.max_preview_chars,
        )
        try:
            passage = resolve_passage(
                passages,
                passage_id=str(arguments.get("passage_id", "")).strip(),
                quote_anchor=str(arguments.get("quote_anchor", "")).strip(),
            )
        except EvidenceResolutionError as exc:
            return {"error": str(exc), "available_passage_ids": [item.passage_id for item in passages]}
        record, created = store_passage_evidence(
            state,
            document,
            passage,
            verification="passage_id" if arguments.get("passage_id") else "fuzzy_anchor",
        )
        result = {
            "recorded": True,
            "evidence_id": record.evidence_id,
            "evidence_count": len(state.evidence),
        }
        if not created:
            result.update({
                "recorded": False,
                "instruction": "This evidence is already recorded; continue without recording it again.",
            })
        return result

    def _existing_document_result(self, url: str, documents: dict[str, Document]) -> dict[str, Any] | None:
        document = self._existing_document(url, documents)
        return self._document_result(document, reused=True) if document is not None else None

    @staticmethod
    def _existing_document(url: str, documents: dict[str, Document]) -> Document | None:
        normalized = normalize_url(url)
        for document in documents.values():
            known_urls = (document.url, document.requested_url or document.url)
            if normalized in {normalize_url(item) for item in known_urls}:
                return document
        return None

    def _document_result(self, document: Document, *, reused: bool) -> dict[str, Any]:
        passages = build_passages(
            document.document_id or document.url,
            document.content,
            max_chars=self.settings.max_preview_chars,
        )
        return {
            "document_id": document.document_id or document.url,
            "url": document.url,
            "title": document.title,
            "passages": [asdict(item) for item in passages],
            "truncated": len(document.content) > self.settings.max_preview_chars,
            "reused": reused,
        }

    def _tool_error(self, operation: str, exc: Exception) -> str:
        detail = redact_secrets(exc, self.settings.api_key, self.settings.tavily_api_key)
        return f"{operation} failed ({type(exc).__name__}): {detail}. Continue with another source or finish with available evidence."
