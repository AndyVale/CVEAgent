from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable

from openai import OpenAI

from cve_agent.budget import BudgetExceeded, TokenBudget, create_budget_plan
from cve_agent.classification import apply_hierarchy_policy, chunk_taxonomy, estimate_tokens, label_dict
from cve_agent.config import Settings
from cve_agent.evidence import EvidenceResolutionError, build_passages, resolve_passage
from cve_agent.llm import RequestPacer, call_chat_completion
from cve_agent.models import CVERecord, ClassificationResult, ClassificationStatus, Document, EvidenceRecord, InvestigationState, InvestigationStopReason
from cve_agent.ports import WebSource
from cve_agent.schemas import AGENT_TOOLS
from cve_agent.taxonomy import Taxonomy
from cve_agent.validation import validate_classification


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResearchOutcome:
    information_status: str
    summary: str
    complete: bool
    turns: int
    duration_seconds: float
    stop_reason: InvestigationStopReason | None = None


class InvestigationAgent:
    """Collect generic vulnerability evidence, then exhaustively classify a taxonomy."""

    def __init__(self, settings: Settings, web_source: WebSource, client: OpenAI | None = None):
        self.settings = settings
        self.web_source = web_source
        self.request_pacer = RequestPacer(settings.llm_min_request_interval)
        self.client = client or OpenAI(api_key=settings.api_key or "EMPTY", base_url=settings.endpoint, timeout=settings.llm_timeout, max_retries=0)

    def preflight(self, taxonomy: Taxonomy) -> None:
        chunks = chunk_taxonomy(taxonomy, available_tokens=max(256, self.settings.max_input_tokens_per_request - 1200))
        create_budget_plan(chunks, self.settings)

    def classify(self, cve: CVERecord, taxonomy: Taxonomy, state: InvestigationState, checkpoint: Callable[[], None] | None = None) -> ClassificationResult:
        logger.info("[%s] agent started: taxonomy_labels=%d", cve.cve_id, len(taxonomy.labels))
        started = time.monotonic()
        base_context = {"cve": asdict(cve), "facts": state.facts, "evidence": [asdict(item) for item in state.evidence]}
        available_label_tokens = self.settings.max_input_tokens_per_request - estimate_tokens(base_context) - 1200
        chunks = chunk_taxonomy(taxonomy, available_tokens=max(256, available_label_tokens))
        budget = TokenBudget(create_budget_plan(chunks, self.settings), self.settings)
        checkpoint_fn = checkpoint or (lambda: None)
        research = self._investigate(cve, state, budget, started, checkpoint_fn)
        if research.summary:
            state.facts.append(research.summary)

        supported: list[dict[str, Any]] = []
        validated_candidates = []
        completed_chunks = 0
        evaluated_labels = 0
        classification_stop_reason: InvestigationStopReason | None = None
        for chunk in chunks:
            try:
                raw_supported = self._classify_chunk(cve, chunk.chunk_id, chunk.labels, state, budget)
            except BudgetExceeded:
                classification_stop_reason = InvestigationStopReason.TOKEN_BUDGET
                break
            if raw_supported:
                _, materialized = validate_classification(ClassificationStatus.CLASSIFIED, raw_supported, taxonomy, state.evidence)
                validated_candidates.extend(materialized)
                supported.extend(raw_supported)
            completed_chunks += 1
            evaluated_labels += len(chunk.labels)
            state.tool_history.append({"tool": "classify_taxonomy_chunk", "status": "success", "chunk_id": chunk.chunk_id, "label_count": len(chunk.labels), "supported_count": len(raw_supported)})
            state.token_usage = budget.to_dict()
            checkpoint_fn()

        coverage_complete = completed_chunks == len(chunks)
        if supported and coverage_complete:
            try:
                status, labels = self._adjudicate(cve, supported, taxonomy, state, budget)
            except BudgetExceeded:
                classification_stop_reason = InvestigationStopReason.TOKEN_BUDGET
                status, labels = ClassificationStatus.PARTIAL, validated_candidates
            labels = apply_hierarchy_policy(labels, taxonomy)
        elif supported:
            status, labels = ClassificationStatus.PARTIAL, apply_hierarchy_policy(validated_candidates, taxonomy)
        elif coverage_complete:
            status = ClassificationStatus.NO_MATCHING_LABEL if research.information_status == "sufficient" else ClassificationStatus.NOT_ENOUGH_INFORMATION
            labels = []
        else:
            status, labels = ClassificationStatus.PARTIAL, []

        coverage = {
            "total_chunks": len(chunks),
            "completed_chunks": completed_chunks,
            "total_labels": len(taxonomy.labels),
            "evaluated_labels": evaluated_labels,
            "complete": coverage_complete,
        }
        if not research.complete or not coverage_complete or classification_stop_reason or budget.exhausted:
            status = ClassificationStatus.PARTIAL
        state.token_usage = budget.to_dict()
        operational: dict[str, Any] = {
            "turns": research.turns,
            "duration_seconds": round(time.monotonic() - started, 3),
            "token_usage": budget.to_dict(),
            "coverage": coverage,
            "research_information_status": research.information_status,
        }
        stop_reason = classification_stop_reason or research.stop_reason
        if stop_reason:
            operational["stop_reason"] = stop_reason
        return ClassificationResult(cve.cve_id, status, labels, operational=operational)

    def _investigate(self, cve: CVERecord, state: InvestigationState, budget: TokenBudget, started: float, checkpoint: Callable[[], None]) -> ResearchOutcome:
        documents: dict[str, Document] = {}
        searches = fetches = turns = 0
        seen_calls: set[tuple[str, str]] = set()
        failed_fetches: set[str] = set()
        exchange: list[dict[str, Any]] = []
        while True:
            elapsed = time.monotonic() - started
            if turns >= self.settings.max_agent_turns or elapsed >= self.settings.max_investigation_seconds:
                return ResearchOutcome("insufficient", "Investigation stopped before the model finished.", False, turns, elapsed, InvestigationStopReason.INVESTIGATION_LIMIT)
            try:
                response = self._chat(
                    cve.cve_id,
                    budget,
                    "investigation",
                    messages=[
                        {"role": "system", "content": self._system_prompt()},
                        {"role": "user", "content": json.dumps(self._context(cve, state, documents, turns, searches, fetches), ensure_ascii=False)},
                    ] + exchange,
                    tools=AGENT_TOOLS,
                    tool_choice="auto",
                    parallel_tool_calls=False,
                )
            except BudgetExceeded:
                return ResearchOutcome("insufficient", "Investigation stopped to preserve the classification reserve.", False, turns, elapsed, InvestigationStopReason.TOKEN_BUDGET)
            turns += 1
            message = response.choices[0].message
            logger.info("[%s] research turn=%d tool_calls=%d tokens=%d", cve.cve_id, turns, len(message.tool_calls or []), budget.total_tokens)
            if not message.tool_calls:
                exchange = [{"role": "user", "content": "Use a provided tool and finish by calling finish_investigation."}]
                continue

            current_exchange = [{"role": "assistant", **message.model_dump(exclude_none=True)}]
            for call in message.tool_calls:
                name = call.function.name
                try:
                    arguments = json.loads(call.function.arguments)
                    if not isinstance(arguments, dict):
                        raise ValueError("tool arguments must be an object")
                except (json.JSONDecodeError, ValueError) as exc:
                    result = {"error": f"invalid tool arguments: {exc}", "instruction": "Correct the arguments and call a provided tool again."}
                    state.tool_history.append(self._tool_event(name, {}, result))
                    state.token_usage = budget.to_dict()
                    checkpoint()
                    current_exchange.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)})
                    continue

                key = (name, json.dumps(arguments, sort_keys=True))
                if name == "finish_investigation":
                    try:
                        outcome = self._research_finish(arguments, turns, time.monotonic() - started)
                        state.tool_history.append(self._tool_event(name, arguments, {"status": "accepted"}))
                        state.token_usage = budget.to_dict()
                        checkpoint()
                        return outcome
                    except ValueError as exc:
                        result = {"error": str(exc), "instruction": "Correct the finish arguments and try again."}
                elif key in seen_calls:
                    result = self._duplicate_result(name, arguments, documents)
                else:
                    seen_calls.add(key)
                    result = self._execute(name, arguments, state, documents, searches, fetches, failed_fetches)
                    if name == "search" and "error" not in result:
                        searches += 1
                    if name == "fetch" and "error" not in result:
                        fetches += 1
                state.tool_history.append(self._tool_event(name, arguments, result))
                state.token_usage = budget.to_dict()
                checkpoint()
                current_exchange.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result, ensure_ascii=False)})
            exchange = current_exchange

    def _classify_chunk(self, cve: CVERecord, chunk_id: int, labels: tuple[Any, ...], state: InvestigationState, budget: TokenBudget) -> list[dict[str, Any]]:
        payload = {
            "chunk_id": chunk_id,
            "vulnerability_facts": state.facts,
            "evidence": [asdict(item) for item in state.evidence],
            "labels": [label_dict(item) for item in labels],
        }
        response = self._chat(
            cve.cve_id,
            budget,
            "classification",
            messages=[
                {"role": "system", "content": "Evaluate every supplied taxonomy label independently. Return JSON with chunk_id and supported, where supported is an array of {label, confidence, evidence:[{evidence_id, explanation}]}. Include only evidence-backed labels and use only supplied IDs and evidence IDs."},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
            ],
            response_format={"type": "json_object"},
        )
        decoded = self._decode_json_content(response)
        if decoded.get("chunk_id") != chunk_id:
            raise ValueError(f"classifier returned chunk_id {decoded.get('chunk_id')!r}, expected {chunk_id}")
        supported = decoded.get("supported")
        if not isinstance(supported, list):
            raise ValueError("taxonomy chunk response requires a supported array")
        allowed = {item.id for item in labels}
        outside = [item.get("label") for item in supported if not isinstance(item, dict) or item.get("label") not in allowed]
        if outside:
            raise ValueError(f"taxonomy chunk returned labels outside its chunk: {outside}")
        return supported

    def _adjudicate(self, cve: CVERecord, candidates: list[dict[str, Any]], taxonomy: Taxonomy, state: InvestigationState, budget: TokenBudget):
        candidate_ids = {item["label"] for item in candidates}
        payload = {
            "candidates": candidates,
            "candidate_definitions": [label_dict(label) for label in taxonomy.labels if label.id in candidate_ids],
            "evidence": [asdict(item) for item in state.evidence],
        }
        response = self._chat(
            cve.cve_id,
            budget,
            "classification",
            messages=[
                {"role": "system", "content": "Adjudicate the evidence-backed candidates. Return JSON {status, labels}; status is classified, no_matching_label, or not_enough_information. Each label contains label, confidence, and evidence associations with evidence_id and explanation. Do not add labels outside the candidates."},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
            ],
            response_format={"type": "json_object"},
        )
        decoded = self._decode_json_content(response)
        raw_labels = decoded.get("labels")
        if isinstance(raw_labels, list):
            outside = [item.get("label") for item in raw_labels if not isinstance(item, dict) or item.get("label") not in candidate_ids]
            if outside:
                raise ValueError(f"adjudicator added non-candidate labels: {outside}")
        return validate_classification(decoded.get("status"), raw_labels, taxonomy, state.evidence)

    def _chat(self, context: str, budget: TokenBudget, stage: str, **request: Any):
        request_max_tokens = budget.admit(stage, request)
        response = call_chat_completion(
            self.client,
            self.settings,
            logger,
            context=context,
            request_pacer=self.request_pacer,
            model=self.settings.model,
            temperature=self.settings.temperature,
            top_p=self.settings.top_p,
            max_tokens=request_max_tokens,
            **request,
        )
        budget.record(response, request)
        return response

    @staticmethod
    def _decode_json_content(response: Any) -> dict[str, Any]:
        content = (response.choices[0].message.content or "").strip()
        if "</think>" in content:
            content = content.rsplit("</think>", 1)[1].strip()
        content = content.removeprefix("```json").removesuffix("```").strip()
        try:
            decoded = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError("provider returned non-JSON classification content") from exc
        if not isinstance(decoded, dict):
            raise ValueError("classification response must be a JSON object")
        return decoded

    def _execute(self, name, arguments, state, documents, searches, fetches, failed_fetches):
        if name == "search":
            if searches >= self.settings.max_search_calls:
                return {"error": "search limit reached"}
            try:
                results = self.web_source.search(arguments["query"])
            except Exception as exc:
                return {"error": self._tool_error("search", exc)}
            return {"results": [asdict(item) for item in results[:10]]}
        if name == "fetch":
            existing = self._existing_document_result(arguments["url"], documents)
            if existing:
                existing["instruction"] = "This URL is already available; record a passage or finish."
                return existing
            if fetches >= self.settings.max_fetch_calls:
                return {"error": "fetch limit reached"}
            url = arguments["url"]
            if url in failed_fetches:
                return {"error": "this URL already failed during the current investigation"}
            try:
                document = self.web_source.fetch(url)
            except Exception as exc:
                failed_fetches.add(url)
                return {"error": self._tool_error("fetch", exc), "url": url}
            documents[document.document_id or url] = document
            if document.url not in state.visited_urls:
                state.visited_urls.append(document.url)
            return self._document_result(document)
        if name == "record_evidence":
            document = documents.get(arguments["document_id"])
            if document is None:
                return {"error": "document not found"}
            passages = build_passages(document.document_id or document.url, document.content, max_chars=self.settings.max_preview_chars)
            try:
                passage = resolve_passage(passages, passage_id=str(arguments.get("passage_id", "")).strip(), quote_anchor=str(arguments.get("quote_anchor", "")).strip())
            except EvidenceResolutionError as exc:
                return {"error": str(exc), "available_passage_ids": [item.passage_id for item in passages]}
            record = EvidenceRecord(passage.passage_id, document.url, passage.text, "web", document.requested_url or document.url, "passage_id" if arguments.get("passage_id") else "fuzzy_anchor")
            if all(existing.evidence_id != record.evidence_id for existing in state.evidence):
                state.evidence.append(record)
            return {"recorded": True, "evidence_id": record.evidence_id, "quote": record.quote, "evidence_count": len(state.evidence)}
        return {"error": f"unknown tool: {name}"}

    @staticmethod
    def _research_finish(arguments: dict[str, Any], turns: int, duration: float) -> ResearchOutcome:
        status = arguments.get("information_status")
        summary = arguments.get("summary")
        if status not in {"sufficient", "insufficient"}:
            raise ValueError("information_status must be sufficient or insufficient")
        if not isinstance(summary, str) or not summary.strip():
            raise ValueError("summary must be a non-empty string")
        return ResearchOutcome(status, summary.strip(), True, turns, duration)

    def _context(self, cve, state, documents, turns, searches, fetches):
        return {
            "cve": asdict(cve),
            "facts": state.facts,
            "recorded_evidence": [asdict(item) for item in state.evidence],
            "tool_history": state.tool_history,
            "available_documents": [{"document_id": key, "url": value.url, "title": value.title} for key, value in documents.items()],
            "investigation_budget": {"turn": turns, "max_turns": self.settings.max_agent_turns, "searches_used": searches, "max_searches": self.settings.max_search_calls, "fetches_used": fetches, "max_fetches": self.settings.max_fetch_calls},
        }

    @staticmethod
    def _system_prompt() -> str:
        return (
            "Investigate the vulnerability mechanism without assigning taxonomy labels. The NVD record and description are supplied and may already be sufficient. "
            "Use one strong reference when clarification is needed, record exact passages by passage ID, avoid duplicate searches or fetches, and finish with a concise factual summary. "
            "Do not infer or mention labels from any particular taxonomy."
        )

    @staticmethod
    def _tool_error(operation: str, exc: Exception) -> str:
        return f"{operation} failed ({type(exc).__name__}): {exc}. Continue with another source or finish with available evidence."

    def _duplicate_result(self, name, arguments, documents):
        if name == "fetch":
            return self._existing_document_result(arguments.get("url", ""), documents) or {"error": "this URL was already attempted"}
        return {"error": "duplicate tool call"}

    @staticmethod
    def _tool_event(name, arguments, result):
        event = {"tool": name, "status": "error" if "error" in result else "success"}
        if "error" in result:
            event["error"] = str(result["error"])[:500]
        if name == "fetch":
            event.update({"url": arguments.get("url", ""), "document_id": result.get("document_id")})
        elif name == "search":
            event.update({"query": arguments.get("query", ""), "result_count": len(result.get("results", []))})
        elif name == "record_evidence":
            event.update({"document_id": arguments.get("document_id"), "passage_id": arguments.get("passage_id"), "evidence_id": result.get("evidence_id")})
        elif name == "finish_investigation":
            event.update({"information_status": arguments.get("information_status")})
        return event

    def _existing_document_result(self, url, documents):
        for document in documents.values():
            if document.url == url or document.requested_url == url:
                return self._document_result(document)
        return None

    def _document_result(self, document):
        passages = build_passages(document.document_id or document.url, document.content, max_chars=self.settings.max_preview_chars)
        return {"document_id": document.document_id or document.url, "url": document.url, "title": document.title, "passages": [asdict(item) for item in passages], "truncated": len(document.content) > self.settings.max_preview_chars}
