from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from typing import Any, Callable
import json
import logging
import time

from cve_agent.core.config import Settings
from cve_agent.core.investigation import InvestigationState, InvestigationStopReason
from cve_agent.core.ports import WebSource
from cve_agent.core.research import ResearchOutcome
from cve_agent.core.sources import CVERecord, Document
from cve_agent.investigation.context import _ResearchContextSerializer, select_reference_candidates
from cve_agent.investigation.diagnostics import _bounded_text
from cve_agent.investigation.profile import build_investigation_profile
from cve_agent.investigation.prompts import RESEARCH_SYSTEM_PROMPT
from cve_agent.investigation.provenance import ResearchProvenanceRecorder
from cve_agent.investigation.schemas import research_tools
from cve_agent.investigation.session import ResearchSession
from cve_agent.investigation.tools import ResearchToolExecutor
from cve_agent.runtime.budget import BudgetExceeded, TokenBudget
from cve_agent.runtime.diagnostics import LogTone, log_extra, safe_url
from cve_agent.runtime.ports import ModelCall


logger = logging.getLogger("cve_agent.research")


class ResearchRunner:
    """Drive taxonomy-independent model research for one CVE."""

    def __init__(self, settings: Settings, web_source: WebSource, chat: ModelCall):
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


def _reason_counts(reasons: tuple[str, ...]) -> dict[str, int]:
    return dict(sorted(Counter(reasons).items()))
