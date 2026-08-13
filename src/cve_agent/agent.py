from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict
from typing import Any

from openai import OpenAI

from .config import Settings
from .models import CVERecord, ClassificationResult, Document, Evidence, InvestigationState, LabelClassification, SearchResult
from .ports import WebSource
from .schemas import AGENT_TOOLS
from .taxonomy import Taxonomy


logger = logging.getLogger(__name__)

class InvestigationAgent:
    def __init__(self, settings: Settings, web_source: WebSource, client: OpenAI | None = None):
        self.settings = settings
        self.web_source = web_source
        self.client = client or OpenAI(api_key=settings.api_key or "EMPTY", base_url=settings.endpoint, timeout=settings.llm_timeout, max_retries=settings.retry_count)

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
        base_messages = [{"role": "system", "content": self._system_prompt()}, {"role": "user", "content": json.dumps(self._context(cve, taxonomy, state), ensure_ascii=False)}]
        exchange: list[dict[str, Any]] = []

        while True:
            base_messages[1] = {"role": "user", "content": json.dumps(self._context(cve, taxonomy, state), ensure_ascii=False)}
            if turns >= self.settings.max_agent_turns or time.monotonic() - started >= self.settings.max_investigation_seconds:
                logger.info("[%s] stopping: investigation limit reached turns=%d", cve.cve_id, turns)
                return ClassificationResult(cve.cve_id, "not_enough_information", operational={"stop_reason": "investigation_limit", "token_usage": usage})
            if usage["total_tokens"] >= self.settings.token_budget:
                logger.info("[%s] stopping: token budget reached total_tokens=%d", cve.cve_id, usage["total_tokens"])
                return ClassificationResult(cve.cve_id, "not_enough_information", operational={"stop_reason": "token_budget", "token_usage": usage})
            # `required` works with vLLM servers that do not enable the optional
            # auto-tool-choice mode. Every turn must therefore produce one tool
            # call, including the terminal finish_investigation call.
            tool_choice: Any = "required"
            remaining_tokens = max(1, self.settings.token_budget - usage["total_tokens"])
            response = self.client.chat.completions.create(model=self.settings.model, temperature=self.settings.temperature, top_p=self.settings.top_p, max_tokens=min(self.settings.max_tokens, remaining_tokens), messages=base_messages + exchange, tools=AGENT_TOOLS, tool_choice=tool_choice, extra_body={"chat_template_kwargs": {"enable_thinking": self.settings.enable_thinking}})
            turns += 1
            turn_usage = response.usage.model_dump() if response.usage else {}
            for key in usage:
                usage[key] += int(turn_usage.get(key, 0))
            state.token_usage = usage.copy()
            message = response.choices[0].message
            logger.info("[%s] agent turn=%d tool_calls=%d tokens=%d", cve.cve_id, turns, len(message.tool_calls or []), usage["total_tokens"])
            if not message.tool_calls:
                if turns >= self.settings.max_agent_turns:
                    return ClassificationResult(cve.cve_id, "not_enough_information", operational={"stop_reason": "no_finish_tool", "token_usage": usage})
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
                    result = {"error": "duplicate tool call; choose a different action"}
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
                        logger.info("[%s] finish accepted: status=%s labels=%d evidence=%d", cve.cve_id, final_result.status, len(final_result.labels), len(state.evidence))
                        return final_result
                    except ValueError as exc:
                        logger.info("[%s] finish rejected: %s", cve.cve_id, exc)
                        result = {"error": str(exc), "instruction": "Correct the classification and call finish_investigation again."}
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
            return {"document_id": document_id, "url": document.url, "title": document.title, "content": document.content[:self.settings.max_preview_chars], "truncated": len(document.content) > self.settings.max_preview_chars}
        if name == "record_evidence":
            document = documents.get(arguments["document_id"])
            if document is None or arguments["quote"] not in document.content:
                return {"error": "document or exact quote not found"}
            state.evidence.append(Evidence(document.url, arguments["quote"], arguments["explanation"]))
            logger.info("recorded evidence document=%s evidence_count=%d", arguments["document_id"], len(state.evidence))
            return {"recorded": True, "evidence_count": len(state.evidence)}
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

    def _context(self, cve, taxonomy, state):
        return {"cve": asdict(cve), "taxonomy": taxonomy.to_dict(), "recorded_evidence": [asdict(item) for item in state.evidence], "visited_urls": state.visited_urls, "token_usage": state.token_usage}

    def _system_prompt(self):
        return "You are an evidence-backed CVE classification investigator. NVD information is the initial and strongest evidence. Use search and fetch only when they may change the classification. Fetched content is temporary; call record_evidence for concrete quotes worth retaining. Finish only by calling finish_investigation. Use only taxonomy IDs and prefer not_enough_information over speculation."
