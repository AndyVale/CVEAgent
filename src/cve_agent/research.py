from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from cve_agent.budget import BudgetExceeded, TokenBudget
from cve_agent.config import Settings
from cve_agent.evidence import EvidenceResolutionError, build_passages, resolve_passage
from cve_agent.investigation import build_investigation_profile
from cve_agent.logging_config import redact_secrets, safe_url
from cve_agent.models import CVERecord, Document, EvidenceRecord, InvestigationFinding, InvestigationState, InvestigationStopReason
from cve_agent.ports import WebSource
from cve_agent.prompts import RESEARCH_SYSTEM_PROMPT
from cve_agent.research_context import build_research_context, select_reference_candidates
from cve_agent.schemas import AGENT_TOOLS


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


@dataclass
class ResearchSession:
    documents: dict[str, Document] = field(default_factory=dict)
    searches: int = 0
    fetches: int = 0
    turns: int = 0
    seen_calls: set[tuple[str, str]] = field(default_factory=set)
    exchange: list[dict[str, Any]] = field(default_factory=list)


class ResearchToolExecutor:
    """Execute bounded web and evidence tools for one CVE research session."""

    def __init__(self, settings: Settings, web_source: WebSource):
        self.settings = settings
        self.web_source = web_source

    def execute(self, name: str, arguments: dict[str, Any], state: InvestigationState, session: ResearchSession) -> dict[str, Any]:
        key = (name, json.dumps(arguments, sort_keys=True))
        if key in session.seen_calls:
            return self._duplicate_result(name, arguments, session.documents)
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
            event.update({"url": arguments.get("url", ""), "document_id": result.get("document_id")})
        elif name == "search":
            event.update({"query": arguments.get("query", ""), "result_count": len(result.get("results", []))})
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
                "promoted_evidence": result.get("promoted_evidence", 0),
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
        return {"results": [asdict(item) for item in results[:10]]}

    def _fetch(self, arguments: dict[str, Any], state: InvestigationState, session: ResearchSession) -> dict[str, Any]:
        url = arguments["url"]
        existing = self._existing_document_result(url, session.documents)
        if existing:
            existing["instruction"] = "This URL is already available; record a passage or finish."
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
        return self._document_result(document)

    def _record_evidence(
        self,
        arguments: dict[str, Any],
        state: InvestigationState,
        documents: dict[str, Document],
    ) -> dict[str, Any]:
        document = documents.get(arguments["document_id"])
        if document is None:
            return {"error": "document not found"}
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
        record = EvidenceRecord(
            passage.passage_id,
            document.url,
            passage.text,
            "web",
            document.requested_url or document.url,
            "passage_id" if arguments.get("passage_id") else "fuzzy_anchor",
        )
        if all(existing.evidence_id != record.evidence_id for existing in state.evidence):
            state.evidence.append(record)
        return {
            "recorded": True,
            "evidence_id": record.evidence_id,
            "quote": record.quote,
            "evidence_count": len(state.evidence),
        }

    def _existing_document_result(self, url: str, documents: dict[str, Document]) -> dict[str, Any] | None:
        for document in documents.values():
            if document.url == url or document.requested_url == url:
                return self._document_result(document)
        return None

    def _document_result(self, document: Document) -> dict[str, Any]:
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
        }

    def _duplicate_result(self, name: str, arguments: dict[str, Any], documents: dict[str, Document]) -> dict[str, Any]:
        if name == "fetch":
            return self._existing_document_result(arguments.get("url", ""), documents) or {"error": "this URL was already attempted"}
        return {"error": "duplicate tool call"}

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
        session = ResearchSession()
        reference_candidates = select_reference_candidates(cve.references)
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
        )
        while True:
            elapsed = time.monotonic() - started
            if session.turns >= self.settings.max_agent_turns or elapsed >= self.settings.max_investigation_seconds:
                return self._stopped(cve.cve_id, session.turns, elapsed, InvestigationStopReason.INVESTIGATION_LIMIT)
            try:
                response = self.chat(
                    cve.cve_id,
                    budget,
                    "investigation",
                    messages=[
                        {"role": "system", "content": RESEARCH_SYSTEM_PROMPT},
                        {
                            "role": "user",
                            "content": json.dumps(
                                build_research_context(
                                    cve,
                                    state,
                                    session.documents,
                                    turn=session.turns,
                                    searches=session.searches,
                                    fetches=session.fetches,
                                    max_turns=self.settings.max_agent_turns,
                                    max_searches=self.settings.max_search_calls,
                                    max_fetches=self.settings.max_fetch_calls,
                                ),
                                ensure_ascii=False,
                            ),
                        },
                    ] + session.exchange,
                    tools=AGENT_TOOLS,
                    tool_choice="auto",
                    parallel_tool_calls=False,
                )
            except BudgetExceeded:
                return self._stopped(cve.cve_id, session.turns, elapsed, InvestigationStopReason.TOKEN_BUDGET)

            session.turns += 1
            message = response.choices[0].message
            calls = message.tool_calls or []
            logger.info("[%s] research turn=%d model_tool_calls=%d", cve.cve_id, session.turns, len(calls))
            if not calls:
                logger.warning("[%s] research turn=%d returned no tool call; requesting one", cve.cve_id, session.turns)
                session.exchange = [{"role": "user", "content": "Use a provided tool and finish by calling finish_investigation."}]
                continue

            current_exchange = [{"role": "assistant", **message.model_dump(exclude_none=True)}]
            for call in calls:
                name = call.function.name
                try:
                    arguments = _decode_tool_arguments(call.function.arguments)
                except ValueError as exc:
                    result = {"error": f"invalid tool arguments: {exc}", "instruction": "Correct the arguments and call a provided tool again."}
                    self._checkpoint_tool(cve.cve_id, name, {}, result, state, budget, checkpoint)
                    current_exchange.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)})
                    continue

                if name == "finish_investigation":
                    profile = build_investigation_profile(
                        arguments,
                        state,
                        session.documents,
                        max_preview_chars=self.settings.max_preview_chars,
                    )
                    result = {
                        "status": "accepted",
                        "information_status": profile.information_status,
                        "finding_count": len(profile.findings),
                        "discarded_findings": profile.discarded_findings,
                        "promoted_evidence": profile.promoted_evidence,
                    }
                    self._checkpoint_tool(cve.cve_id, name, arguments, result, state, budget, checkpoint)
                    logger.info(
                        "[%s] research finished status=%s findings=%d aspects=%s discarded=%d promoted_evidence=%d turns=%d",
                        cve.cve_id,
                        profile.information_status,
                        len(profile.findings),
                        ",".join(dict.fromkeys(item.aspect.value for item in profile.findings)) or "none",
                        profile.discarded_findings,
                        profile.promoted_evidence,
                        session.turns,
                    )
                    return ResearchOutcome(
                        profile.information_status,
                        profile.summary,
                        True,
                        session.turns,
                        time.monotonic() - started,
                        findings=profile.findings,
                        discarded_findings=profile.discarded_findings,
                        promoted_evidence=profile.promoted_evidence,
                    )

                try:
                    result = self.tools.execute(name, arguments, state, session)
                except (KeyError, TypeError, ValueError) as exc:
                    result = {"error": f"invalid tool arguments: {exc}", "instruction": "Correct the arguments and try again."}
                self._checkpoint_tool(cve.cve_id, name, arguments, result, state, budget, checkpoint)
                current_exchange.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result, ensure_ascii=False)})
            session.exchange = current_exchange

    def _checkpoint_tool(
        self,
        cve_id: str,
        name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        state: InvestigationState,
        budget: TokenBudget,
        checkpoint: Callable[[], None],
    ) -> None:
        event = self.tools.tool_event(name, arguments, result)
        state.tool_history.append(event)
        state.token_usage = budget.to_dict()
        checkpoint()
        if "error" in result:
            logger.warning(
                "[%s] research tool=%s status=error%s detail=%s",
                cve_id,
                name,
                f" query={_bounded_text(arguments.get('query', ''))!r}" if name == "search" else "",
                str(result["error"])[:240],
            )
            return
        if name == "search":
            logger.info(
                "[%s] research tool=search status=success query=%r query_chars=%d results=%d",
                cve_id,
                _bounded_text(arguments.get("query", "")),
                len(str(arguments.get("query", ""))),
                len(result.get("results", [])),
            )
        elif name == "fetch":
            logger.info(
                "[%s] research tool=fetch status=success url=%s document_id=%s passages=%d truncated=%s",
                cve_id,
                safe_url(str(result.get("url", arguments.get("url", "")))),
                result.get("document_id"),
                len(result.get("passages", [])),
                result.get("truncated", False),
            )
        elif name == "record_evidence":
            logger.info(
                "[%s] research tool=record_evidence status=success evidence_id=%s evidence_count=%d",
                cve_id,
                result.get("evidence_id"),
                result.get("evidence_count", 0),
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
