from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict
from typing import Any

from openai import OpenAI

from .config import Settings
from .llm import call_chat_completion
from .models import CVERecord, ClassificationResult, Document, Evidence, InvestigationState, LabelClassification, SearchResult
from .ports import WebSource
from .schemas import AGENT_TOOLS
from .taxonomy import Taxonomy


logger = logging.getLogger(__name__)

class InvestigationAgent:
    def __init__(self, settings: Settings, web_source: WebSource, client: OpenAI | None = None):
        self.settings = settings
        self.web_source = web_source
        self.client = client or OpenAI(api_key=settings.api_key or "EMPTY", base_url=settings.endpoint, timeout=settings.llm_timeout, max_retries=0)

    def classify(self, cve: CVERecord, evidence: list[Document | SearchResult], taxonomy: Taxonomy, state: InvestigationState) -> ClassificationResult:
        logger.info("[%s] agent started: taxonomy_labels=%d", cve.cve_id, len(taxonomy.labels))
        started = time.monotonic()
        documents: dict[str, Document] = {}
        searches = 0
        fetches = 0
        turns = 0
        seen_calls: set[tuple[str, str]] = set()
        failed_fetches: set[str] = set()
        usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        base_messages = [{"role": "system", "content": self._system_prompt()}, {"role": "user", "content": json.dumps(self._context(cve, taxonomy, state, documents, turns, searches, fetches), ensure_ascii=False)}]
        exchange: list[dict[str, Any]] = []

        while True:
            base_messages[1] = {"role": "user", "content": json.dumps(self._context(cve, taxonomy, state, documents, turns, searches, fetches), ensure_ascii=False)}
            if turns >= self.settings.max_agent_turns or time.monotonic() - started >= self.settings.max_investigation_seconds:
                logger.info("[%s] stopping: investigation limit reached turns=%d", cve.cve_id, turns)
                return ClassificationResult(cve.cve_id, "partial", operational={"stop_reason": "investigation_limit", "token_usage": usage})
            if usage["total_tokens"] >= self.settings.token_budget:
                logger.info("[%s] stopping: token budget reached total_tokens=%d", cve.cve_id, usage["total_tokens"])
                return ClassificationResult(cve.cve_id, "partial", operational={"stop_reason": "token_budget", "token_usage": usage})
            remaining_tokens = max(1, self.settings.token_budget - usage["total_tokens"])
            response = call_chat_completion(
                self.client,
                self.settings,
                logger,
                model=self.settings.model,
                temperature=self.settings.temperature,
                top_p=self.settings.top_p,
                max_tokens=min(self.settings.max_tokens, remaining_tokens),
                messages=base_messages + exchange,
                tools=AGENT_TOOLS,
                tool_choice="auto",
                parallel_tool_calls=False,
                context=cve.cve_id,
            )
            turns += 1
            turn_usage = response.usage.model_dump() if response.usage else {}
            for key in usage:
                usage[key] += int(turn_usage.get(key, 0))
            state.token_usage = usage.copy()
            message = response.choices[0].message
            logger.info("[%s] agent turn=%d tool_calls=%d tokens=%d", cve.cve_id, turns, len(message.tool_calls or []), usage["total_tokens"])
            if not message.tool_calls:
                if turns >= self.settings.max_agent_turns:
                    return ClassificationResult(cve.cve_id, "partial", operational={"stop_reason": "no_finish_tool", "token_usage": usage})
                exchange = [{"role": "user", "content": "Use one of the provided tools. Finish by calling finish_investigation."}]
                continue
            assistant_message = message.model_dump(exclude_none=True)
            current_exchange = [{"role": "assistant", **assistant_message}]
            for call in message.tool_calls:
                name = call.function.name
                arguments = json.loads(call.function.arguments)
                logger.info("[%s] tool requested: %s params=%s", cve.cve_id, name, self._log_arguments(arguments))
                key = (name, json.dumps(arguments, sort_keys=True))
                if key in seen_calls and name != "finish_investigation":
                    if name == "fetch":
                        result = self._existing_document_result(arguments["url"], documents)
                        if result:
                            result["instruction"] = "This URL was already fetched. Do not fetch it again; record an exact quote from this preview now, or call finish_investigation."
                        else:
                            result = {"error": "this URL was already attempted; choose another source or finish_investigation"}
                    else:
                        result = {"error": "duplicate tool call; choose a different action or call finish_investigation"}
                elif name == "finish_investigation":
                    result = {"ready": True}
                else:
                    seen_calls.add(key)
                    result = self._execute(name, arguments, state, documents, searches, fetches, failed_fetches)
                    if name == "search" and "error" not in result: searches += 1
                    if name == "fetch" and "error" not in result: fetches += 1
                if "error" in result:
                    logger.warning("[%s] tool completed: %s error=%s", cve.cve_id, name, result["error"])
                else:
                    logger.info("[%s] tool completed: %s%s", cve.cve_id, name, " (success)")
                if name == "finish_investigation":
                    try:
                        final_result = self._finish(cve, arguments, taxonomy, state, usage, started, turns)
                        state.tool_history.append(self._tool_event(name, arguments, {"status": "accepted"}))
                        logger.info("[%s] finish accepted: status=%s labels=%d evidence=%d", cve.cve_id, final_result.status, len(final_result.labels), len(state.evidence))
                        return final_result
                    except ValueError as exc:
                        logger.info("[%s] finish rejected: %s", cve.cve_id, exc)
                        result = {"error": str(exc), "instruction": "Correct the classification and call finish_investigation again."}
                state.tool_history.append(self._tool_event(name, arguments, result))
                current_exchange.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result, ensure_ascii=False)})
            exchange = current_exchange

    def _execute(self, name, arguments, state, documents, searches, fetches, failed_fetches):
        if name == "search":
            if searches >= self.settings.max_search_calls:
                return {"error": "search limit reached"}
            try:
                results = self.web_source.search(arguments["query"])
            except Exception as exc:
                logger.warning("search failed type=%s message=%s", type(exc).__name__, exc)
                return {"error": self._tool_error("search", exc)}
            logger.info("search returned %d result(s)", len(results))
            return {"results": [asdict(item) for item in results[:10]]}
        if name == "fetch":
            existing = self._existing_document_result(arguments["url"], documents)
            if existing:
                existing["instruction"] = "This URL is already available. Record an exact quote from this preview or call finish_investigation; no network request was made."
                return existing
            if fetches >= self.settings.max_fetch_calls:
                return {"error": "fetch limit reached"}
            url = arguments["url"]
            if url in failed_fetches:
                return {"error": "this URL already failed during the current investigation; choose another source"}
            try:
                document = self.web_source.fetch(url)
            except Exception as exc:
                failed_fetches.add(url)
                logger.warning("fetch failed url=%s type=%s message=%s", url, type(exc).__name__, exc)
                return {"error": self._tool_error("fetch", exc), "url": url}
            document_id = document.document_id or arguments["url"]
            documents[document_id] = document
            state.visited_urls.append(document.url) if document.url not in state.visited_urls else None
            logger.info("fetched document=%s chars=%d", document_id, len(document.content))
            return self._document_result(document)
        if name == "record_evidence":
            document = documents.get(arguments["document_id"])
            quote = arguments.get("quote", "").strip()
            if document is None:
                return {"error": "document not found"}
            if not quote:
                return {"error": "quote must not be empty"}
            verified = quote in document.content
            state.evidence.append(Evidence(document.url, quote, arguments["explanation"]))
            logger.info("recorded evidence document=%s evidence_count=%d", arguments["document_id"], len(state.evidence))
            return {"recorded": True, "quote_verified": verified, "evidence_count": len(state.evidence)}
        return {"error": f"unknown tool: {name}"}

    @staticmethod
    def _tool_error(operation: str, exc: Exception) -> str:
        return f"{operation} failed ({type(exc).__name__}): {exc}. Continue with another source or finish with the evidence already available."

    @staticmethod
    def _log_arguments(arguments: dict[str, Any]) -> str:
        """Return tool parameters safe for verbose logs; no secrets are accepted here."""
        if "url" in arguments:
            return f"url={arguments['url']}"
        if "query" in arguments:
            return f"query={arguments['query']!r}"
        if "document_id" in arguments:
            return f"document_id={arguments['document_id']} quote_chars={len(arguments.get('quote', ''))}"
        if "status" in arguments:
            return f"status={arguments['status']} labels={len(arguments.get('labels', []))}"
        return "<none>"

    def _finish(self, cve, arguments, taxonomy, state, usage, started, turns):
        status = arguments.get("status")
        labels = [LabelClassification(item["label"], float(item["confidence"]), tuple(Evidence(**e) for e in item["evidence"])) for item in arguments.get("labels", [])]
        invalid = [item.label for item in labels if item.label not in taxonomy.by_id]
        if invalid:
            raise ValueError(f"classifier returned labels outside taxonomy: {invalid}")
        if status == "not_enough_information" and labels:
            raise ValueError("not_enough_information results cannot contain labels")
        all_evidence = { (item.url, item.quote) for item in state.evidence }
        if any(not item.evidence or any((e.url, e.quote) not in all_evidence for e in item.evidence) for item in labels):
            raise ValueError("classification evidence must be recorded during the investigation")
        return ClassificationResult(cve.cve_id, status, labels, operational={"turns": turns, "duration_seconds": round(time.monotonic() - started, 3), "token_usage": usage})

    def _context(self, cve, taxonomy, state, documents, turns, searches, fetches):
        return {
            "cve": asdict(cve),
            "taxonomy": taxonomy.to_dict(),
            "facts": state.facts,
            "recorded_evidence": [asdict(item) for item in state.evidence],
            "tool_history": state.tool_history,
            "fetched_urls": state.visited_urls,
            "available_documents": [
                {"document_id": document_id, "url": document.url, "title": document.title, "content_chars": len(document.content)}
                for document_id, document in documents.items()
            ],
            "investigation_budget": {
                "turn": turns,
                "max_turns": self.settings.max_agent_turns,
                "searches_used": searches,
                "max_searches": self.settings.max_search_calls,
                "fetches_used": fetches,
                "max_fetches": self.settings.max_fetch_calls,
            },
            "token_usage": state.token_usage,
        }

    def _system_prompt(self):
        return (
            "You are an evidence-backed CVE classification investigator. Work quickly and stop when the evidence is sufficient. "
            "The NVD record, description, metadata, and references are already supplied; do not fetch the NVD detail page just because it is a reference. "
            "The initial NVD description is valid evidence and may be sufficient for classification. First decide whether it already supports a taxonomy label. If one reliable reference can resolve the uncertainty, fetch only that source. "
            "Use this short workflow: fetch one strong source, immediately record one exact useful quote, then finish_investigation. "
            "Never fetch the same URL twice, never repeat a search, and do not search for marginal confirmation. "
            "Finish as soon as you can: use classified with only taxonomy IDs supported by recorded evidence, or use not_enough_information when the evidence genuinely cannot support a label. "
            "Do not spend turns restating the problem. Finish only by calling finish_investigation."
        )

    @staticmethod
    def _tool_event(name, arguments, result):
        event = {"tool": name, "status": "error" if "error" in result else "success"}
        if "error" in result:
            event["error"] = str(result["error"])[:500]
        if name == "fetch":
            event.update({
                "url": arguments.get("url", ""),
                "document_id": result.get("document_id"),
                "content_chars": len(result.get("content", "")),
                "reused": "already fetched" in result.get("instruction", "") or "no network request" in result.get("instruction", ""),
            })
        elif name == "search":
            event.update({"query": arguments.get("query", ""), "result_count": len(result.get("results", []))})
        elif name == "record_evidence":
            event.update({"document_id": arguments.get("document_id"), "quote_chars": len(arguments.get("quote", "")), "quote_verified": result.get("quote_verified")})
        elif name == "finish_investigation":
            event.update({"requested_status": arguments.get("status"), "label_count": len(arguments.get("labels", []))})
        return event

    def _existing_document_result(self, url, documents):
        for document in documents.values():
            if document.url == url:
                return self._document_result(document)
        return None

    def _document_result(self, document):
        return {
            "document_id": document.document_id or document.url,
            "url": document.url,
            "title": document.title,
            "content": document.content[:self.settings.max_preview_chars],
            "truncated": len(document.content) > self.settings.max_preview_chars,
        }
