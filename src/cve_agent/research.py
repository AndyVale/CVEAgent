from __future__ import annotations

import json
import logging
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from cve_agent.budget import BudgetExceeded, TokenBudget
from cve_agent.config import Settings
from cve_agent.evidence import EvidenceResolutionError, build_passages, resolve_passage, store_passage_evidence
from cve_agent.investigation import build_investigation_profile
from cve_agent.logging_config import LogTone, log_extra, redact_secrets, safe_url
from cve_agent.models import CVERecord, Document, EvidenceRecord, InvestigationFinding, InvestigationState, InvestigationStopReason
from cve_agent.ports import WebSource
from cve_agent.prompts import RESEARCH_SYSTEM_PROMPT
from cve_agent.provenance import ResearchProvenanceRecorder, normalize_url
from cve_agent.research_context import _ResearchContextSerializer, select_reference_candidates
from cve_agent.schemas import research_tools


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResearchOutcome:
    information_status: str
    summary: str
    complete: bool
    turns: int
    duration_seconds: float
    stop_reason: InvestigationStopReason | None = None
    findings: tuple[InvestigationFinding, ...] = ()
    discarded_findings: int = 0
    promoted_evidence: int = 0
    discarded_reasons: tuple[str, ...] = ()


@dataclass
class ResearchSession:
    documents: dict[str, Document] = field(default_factory=dict)
    searches: int = 0
    fetches: int = 0
    turns: int = 0
    seen_calls: set[tuple[str, str]] = field(default_factory=set)
    redisplayed_documents: set[str] = field(default_factory=set)
    exchange: list[dict[str, Any]] = field(default_factory=list)
    provenance: ResearchProvenanceRecorder | None = None
    finish_corrections: int = 0
    pending_finish_arguments: dict[str, Any] | None = None
    pending_finish_documents: dict[str, Document] | None = None


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


class ResearchRunner:
    """Drive taxonomy-independent model research for one CVE."""

    def __init__(self, settings: Settings, web_source: WebSource, chat: Callable[..., Any]):
        self.settings = settings
        self.tools = ResearchToolExecutor(settings, web_source)
        self.chat = chat

    def run(
        self,
        cve: CVERecord,
        state: InvestigationState,
        budget: TokenBudget,
        started: float,
        checkpoint: Callable[[], None],
    ) -> ResearchOutcome:
        session = ResearchSession(
            provenance=ResearchProvenanceRecorder(
                cve,
                state,
                max_preview_chars=self.settings.max_preview_chars,
            )
        )
        checkpoint()
        reference_candidates = select_reference_candidates(cve.references)
        context_serializer = _ResearchContextSerializer(cve, reference_candidates)
        logger.info(
            "[%s] research started max_turns=%d max_searches=%d max_fetches=%d max_seconds=%.1f nvd_references=%d reference_candidates=%d omitted_references=%d",
            cve.cve_id,
            self.settings.max_agent_turns,
            self.settings.max_search_calls,
            self.settings.max_fetch_calls,
            self.settings.max_investigation_seconds,
            len(cve.references),
            len(reference_candidates),
            len(cve.references) - len(reference_candidates),
            extra=log_extra(section=True),
        )
        while True:
            elapsed = time.monotonic() - started
            if session.turns >= self.settings.max_agent_turns or elapsed >= self.settings.max_investigation_seconds:
                if session.pending_finish_arguments is not None:
                    return self._accept_finish(
                        cve.cve_id,
                        session.pending_finish_arguments,
                        state,
                        session,
                        budget,
                        started,
                        checkpoint,
                        documents=session.pending_finish_documents or {},
                        fallback_reason="correction_limit_reached",
                    )
                return self._stopped(cve.cve_id, session.turns, elapsed, InvestigationStopReason.INVESTIGATION_LIMIT)
            correction_turn = session.pending_finish_arguments is not None
            try:
                response = self.chat(
                    cve.cve_id,
                    budget,
                    "investigation",
                    messages=[
                        {"role": "system", "content": RESEARCH_SYSTEM_PROMPT},
                        {
                            "role": "user",
                            "content": context_serializer.render(
                                state,
                                session.documents,
                                session.exchange,
                                turn=session.turns,
                                searches=session.searches,
                                fetches=session.fetches,
                                max_turns=self.settings.max_agent_turns,
                                max_searches=self.settings.max_search_calls,
                                max_fetches=self.settings.max_fetch_calls,
                            ),
                        },
                    ] + session.exchange,
                    tools=research_tools(session.documents),
                    tool_choice="auto",
                    parallel_tool_calls=False,
                )
            except BudgetExceeded:
                if session.pending_finish_arguments is not None:
                    return self._accept_finish(
                        cve.cve_id,
                        session.pending_finish_arguments,
                        state,
                        session,
                        budget,
                        started,
                        checkpoint,
                        documents=session.pending_finish_documents or {},
                        fallback_reason="correction_budget_exceeded",
                    )
                return self._stopped(cve.cve_id, session.turns, elapsed, InvestigationStopReason.TOKEN_BUDGET)

            session.turns += 1
            message = response.choices[0].message
            calls = message.tool_calls or []
            logger.info("[%s] research turn=%d model_tool_calls=%d", cve.cve_id, session.turns, len(calls))
            if not calls:
                logger.warning("[%s] research turn=%d returned no tool call; requesting one", cve.cve_id, session.turns)
                if correction_turn and session.pending_finish_arguments is not None:
                    session.exchange = [{"role": "user", "content": self._finish_correction_instruction()}]
                else:
                    session.exchange = [{"role": "user", "content": "Use a provided tool and finish by calling finish_investigation."}]
                continue

            current_exchange = [{"role": "assistant", **message.model_dump(exclude_none=True)}]
            for call in calls:
                name = call.function.name
                try:
                    arguments = _decode_tool_arguments(call.function.arguments)
                except ValueError as exc:
                    result = {"error": f"invalid tool arguments: {exc}", "instruction": "Correct the arguments and call a provided tool again."}
                    self._checkpoint_tool(cve.cve_id, name, {}, result, state, session, budget, checkpoint)
                    current_exchange.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)})
                    continue

                if name == "finish_investigation":
                    draft = build_investigation_profile(
                        arguments,
                        state,
                        session.documents,
                        max_preview_chars=self.settings.max_preview_chars,
                        promote_evidence=False,
                    )
                    can_correct = (
                        bool(draft.evidence_issues)
                        and not correction_turn
                        and session.finish_corrections == 0
                        and session.turns < self.settings.max_agent_turns
                        and time.monotonic() - started < self.settings.max_investigation_seconds
                    )
                    if can_correct:
                        result = {
                            "error": "finish_investigation contains invalid evidence citations",
                            "instruction": self._finish_correction_instruction(),
                            "evidence_issues": [asdict(item) for item in draft.evidence_issues],
                            "retained_finding_count": len(draft.findings),
                            "discarded_findings": draft.discarded_findings,
                            "discarded_by_reason": _reason_counts(draft.discarded_reasons),
                        }
                        self._checkpoint_tool(cve.cve_id, name, arguments, result, state, session, budget, checkpoint)
                        current_exchange.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result, ensure_ascii=False)})
                        session.finish_corrections += 1
                        session.pending_finish_arguments = arguments
                        session.pending_finish_documents = dict(session.documents)
                        break
                    return self._accept_finish(
                        cve.cve_id,
                        arguments,
                        state,
                        session,
                        budget,
                        started,
                        checkpoint,
                        documents=session.documents,
                    )

                try:
                    result = self.tools.execute(name, arguments, state, session)
                except (KeyError, TypeError, ValueError) as exc:
                    result = {"error": f"invalid tool arguments: {exc}", "instruction": "Correct the arguments and try again."}
                self._checkpoint_tool(cve.cve_id, name, arguments, result, state, session, budget, checkpoint)
                current_exchange.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result, ensure_ascii=False)})
            if correction_turn and session.pending_finish_arguments is not None:
                current_exchange.append({"role": "user", "content": self._finish_correction_instruction()})
            session.exchange = current_exchange

    @staticmethod
    def _finish_correction_instruction() -> str:
        return (
            "Correct the rejected finish_investigation submission. You may search or fetch a different source "
            "when the available documents do not contain substantive evidence. Fetching an available document "
            "URL once is permitted to redisplay its stored passages, but it supplies no new information and "
            "further repeats return an error. Immediately "
            "after a fetch, record each distinct substantive passage that supports a finding before another tool "
            "call. Use only IDs from the fetched document; do not record nvd-description or evidence already in "
            "recorded_evidence. Then call finish_investigation once using only substantive, unambiguous evidence "
            "IDs; preserve each independently supported mechanism or security-boundary failure as its own finding, "
            "including an unauthenticated attacker acting as a trusted service. A statement that code execution "
            "is possible is not its mechanism: establish the attacker-input-to-interpreter transition or omit "
            "that mechanism. Additional targeted research remains appropriate when it may reveal another mechanism, "
            "an important precondition, conflicting evidence, or information that could change classification. When "
            "another source is expected only to restate recorded facts, finish without exhausting the remaining "
            "budget, and retain valid findings."
        )

    def _accept_finish(
        self,
        cve_id: str,
        arguments: dict[str, Any],
        state: InvestigationState,
        session: ResearchSession,
        budget: TokenBudget,
        started: float,
        checkpoint: Callable[[], None],
        *,
        documents: dict[str, Document],
        fallback_reason: str | None = None,
    ) -> ResearchOutcome:
        profile = build_investigation_profile(
            arguments,
            state,
            documents,
            max_preview_chars=self.settings.max_preview_chars,
            promote_evidence=True,
        )
        result = {
            "status": "accepted",
            "information_status": profile.information_status,
            "finding_count": len(profile.findings),
            "discarded_findings": profile.discarded_findings,
            "discarded_by_reason": _reason_counts(profile.discarded_reasons),
            "promoted_evidence": profile.promoted_evidence,
            "evidence_issues": [asdict(item) for item in profile.evidence_issues],
        }
        if fallback_reason:
            result["fallback_reason"] = fallback_reason
        self._checkpoint_tool(cve_id, "finish_investigation", arguments, result, state, session, budget, checkpoint)
        logger.info(
            "[%s] research finished status=%s findings=%d aspects=%s discarded=%d discarded_by_reason=%s promoted_evidence=%d turns=%d fallback=%s",
            cve_id,
            profile.information_status,
            len(profile.findings),
            ",".join(dict.fromkeys(item.aspect.value for item in profile.findings)) or "none",
            profile.discarded_findings,
            _reason_counts(profile.discarded_reasons),
            profile.promoted_evidence,
            session.turns,
            fallback_reason or "none",
            extra=log_extra(
                LogTone.SUCCESS if profile.information_status == "sufficient" else LogTone.INCOMPLETE
            ),
        )
        session.pending_finish_arguments = None
        session.pending_finish_documents = None
        return ResearchOutcome(
            profile.information_status,
            profile.summary,
            True,
            session.turns,
            time.monotonic() - started,
            findings=profile.findings,
            discarded_findings=profile.discarded_findings,
            promoted_evidence=profile.promoted_evidence,
            discarded_reasons=profile.discarded_reasons,
        )

    def _checkpoint_tool(
        self,
        cve_id: str,
        name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        state: InvestigationState,
        session: ResearchSession,
        budget: TokenBudget,
        checkpoint: Callable[[], None],
    ) -> None:
        if session.provenance is None:
            raise AssertionError("research session lacks a provenance recorder")
        session.provenance.record_tool_call(name, arguments, result, session.documents)
        event = self.tools.tool_event(name, arguments, result)
        state.tool_history.append(event)
        state.token_usage = budget.to_dict()
        checkpoint()
        if "error" in result:
            context = (
                f" query={_bounded_text(arguments.get('query', ''))!r}"
                if name == "search"
                else f" url={safe_url(str(arguments.get('url', '')))}"
                if name == "fetch"
                else ""
            )
            logger.warning(
                "[%s] research tool=%s status=error%s detail=%s",
                cve_id,
                name,
                context,
                str(result["error"])[:240],
            )
            return
        if name == "search":
            logger.info(
                "[%s] research tool=search status=success query=%r query_chars=%d results=%d available_results_omitted=%d",
                cve_id,
                _bounded_text(arguments.get("query", "")),
                len(str(arguments.get("query", ""))),
                len(result.get("results", [])),
                result.get("available_results_omitted", 0),
            )
        elif name == "fetch":
            fetch_trace = state.provenance.fetches[-1]
            source_trace = next(
                (
                    item for item in state.provenance.sources
                    if item.document_id == fetch_trace.document_id
                ),
                None,
            )
            candidate_by_id = {item.candidate_id: item for item in state.provenance.candidates}
            origin_kinds = ",".join(dict.fromkeys(
                candidate_by_id[candidate_id].kind
                for candidate_id in fetch_trace.candidate_ids
                if candidate_id in candidate_by_id
            )) or "unknown"
            logger.info(
                "[%s] research tool=fetch status=success url=%s document_id=%s passages=%d truncated=%s reused=%s origins=%s cve_association=%s",
                cve_id,
                safe_url(str(result.get("url", arguments.get("url", "")))),
                result.get("document_id"),
                len(result.get("passages", [])),
                result.get("truncated", False),
                result.get("reused") is True,
                origin_kinds,
                source_trace.association.status if source_trace else "unavailable",
            )
            if source_trace and source_trace.association.warnings:
                logger.warning(
                    "[%s] source association warning document_id=%s status=%s warnings=%s other_cves=%s",
                    cve_id,
                    source_trace.document_id,
                    source_trace.association.status,
                    ",".join(source_trace.association.warnings),
                    ",".join(source_trace.association.other_cve_ids) or "none",
                )
        elif name == "record_evidence":
            evidence_trace = next(
                (
                    item for item in state.provenance.evidence
                    if item.evidence_id == result.get("evidence_id")
                ),
                None,
            )
            logger.info(
                "[%s] research tool=record_evidence status=success evidence_id=%s evidence_count=%d selection_method=%s",
                cve_id,
                result.get("evidence_id"),
                result.get("evidence_count", 0),
                evidence_trace.selection_method if evidence_trace else "unavailable",
            )

    @staticmethod
    def _stopped(cve_id: str, turns: int, elapsed: float, reason: InvestigationStopReason) -> ResearchOutcome:
        summary = (
            "Investigation stopped to preserve the classification reserve."
            if reason == InvestigationStopReason.TOKEN_BUDGET
            else "Investigation stopped before the model finished."
        )
        logger.warning("[%s] research stopped reason=%s turns=%d duration_seconds=%.3f", cve_id, reason.value, turns, elapsed)
        return ResearchOutcome("insufficient", summary, False, turns, elapsed, reason)


def _decode_tool_arguments(value: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"arguments are not valid JSON: {exc.msg}") from exc
    if not isinstance(decoded, dict):
        raise ValueError("tool arguments must be an object")
    return decoded


def _bounded_text(value: Any, limit: int = 180) -> str:
    normalized = " ".join(str(value).split())
    return normalized if len(normalized) <= limit else normalized[: limit - 1] + "…"


def _reason_counts(reasons: tuple[str, ...]) -> dict[str, int]:
    return dict(sorted(Counter(reasons).items()))
