from __future__ import annotations

import json
import time
from dataclasses import asdict
from typing import Any

from openai import OpenAI

from .config import Settings
from .models import CVERecord, ClassificationResult, Document, Evidence, InvestigationState, LabelClassification, SearchResult
from .ports import WebSource
from .taxonomy import Taxonomy


class InvestigationLimit(Exception):
    """Raised when the agent cannot safely continue investigating."""


def _tool(name: str, description: str, parameters: dict[str, Any]) -> dict[str, Any]:
    return {"type": "function", "function": {"name": name, "description": description, "parameters": parameters, "strict": True}}


TOOLS = [
    _tool("search", "Search for sources relevant to the current CVE. Results are leads, not verified evidence; fetch a result before relying on it.", {"type": "object", "additionalProperties": False, "properties": {"query": {"type": "string"}}, "required": ["query"]}),
    _tool("fetch", "Fetch a specific URL and return a bounded, readable text preview. The result is temporary until evidence is explicitly recorded.", {"type": "object", "additionalProperties": False, "properties": {"url": {"type": "string"}}, "required": ["url"]}),
    _tool("record_evidence", "Promote a concrete quote from a fetched document into the persistent investigation evidence. Only record text actually present in the document.", {"type": "object", "additionalProperties": False, "properties": {"document_id": {"type": "string"}, "quote": {"type": "string"}, "explanation": {"type": "string"}}, "required": ["document_id", "quote", "explanation"]}),
    _tool("finish_investigation", "Finish the current CVE investigation and return the final taxonomy classification. Use not_enough_information instead of guessing.", {"type": "object", "additionalProperties": False, "properties": {"status": {"type": "string", "enum": ["classified", "not_enough_information"]}, "labels": {"type": "array", "items": {"type": "object", "additionalProperties": False, "properties": {"label": {"type": "string"}, "confidence": {"type": "number", "minimum": 0, "maximum": 1}, "evidence": {"type": "array", "items": {"type": "object", "additionalProperties": False, "properties": {"url": {"type": "string"}, "quote": {"type": "string"}, "explanation": {"type": "string"}}, "required": ["url", "quote", "explanation"]}}}, "required": ["label", "confidence", "evidence"]}}}, "required": ["status", "labels"]}),
]


class InvestigationAgent:
    def __init__(self, settings: Settings, web_source: WebSource, client: OpenAI | None = None):
        self.settings = settings
        self.web_source = web_source
        self.client = client or OpenAI(api_key=settings.api_key or "EMPTY", base_url=settings.endpoint, timeout=settings.llm_timeout, max_retries=settings.retry_count)

    def classify(self, cve: CVERecord, evidence: list[Document | SearchResult], taxonomy: Taxonomy, state: InvestigationState) -> ClassificationResult:
        started = time.monotonic()
        documents: dict[str, Document] = {}
        searches = 0
        fetches = 0
        turns = 0
        seen_calls: set[tuple[str, str]] = set()
        usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        base_messages = [{"role": "system", "content": self._system_prompt()}, {"role": "user", "content": json.dumps(self._context(cve, taxonomy, state), ensure_ascii=False)}]
        exchange: list[dict[str, Any]] = []

        while True:
            base_messages[1] = {"role": "user", "content": json.dumps(self._context(cve, taxonomy, state), ensure_ascii=False)}
            if turns >= self.settings.max_agent_turns or time.monotonic() - started >= self.settings.max_investigation_seconds:
                return ClassificationResult(cve.cve_id, "not_enough_information", operational={"stop_reason": "investigation_limit", "token_usage": usage})
            if usage["total_tokens"] >= self.settings.token_budget:
                return ClassificationResult(cve.cve_id, "not_enough_information", operational={"stop_reason": "token_budget", "token_usage": usage})
            # `required` works with vLLM servers that do not enable the optional
            # auto-tool-choice mode. Every turn must therefore produce one tool
            # call, including the terminal finish_investigation call.
            tool_choice: Any = "required"
            response = self.client.chat.completions.create(model=self.settings.model, temperature=self.settings.temperature, top_p=self.settings.top_p, max_tokens=self.settings.max_tokens, messages=base_messages + exchange, tools=TOOLS, tool_choice=tool_choice, extra_body={"chat_template_kwargs": {"enable_thinking": self.settings.enable_thinking}})
            turns += 1
            turn_usage = response.usage.model_dump() if response.usage else {}
            for key in usage:
                usage[key] += int(turn_usage.get(key, 0))
            state.token_usage = usage.copy()
            message = response.choices[0].message
            if not message.tool_calls:
                if turns >= self.settings.max_agent_turns:
                    return ClassificationResult(cve.cve_id, "not_enough_information", operational={"stop_reason": "no_finish_tool", "token_usage": usage})
                exchange = [{"role": "user", "content": "Use one of the provided tools. Finish by calling finish_investigation."}]
                continue
            assistant_message = message.model_dump(exclude_none=True)
            exchange = [{"role": "assistant", **assistant_message}]
            for call in message.tool_calls:
                name = call.function.name
                arguments = json.loads(call.function.arguments)
                key = (name, json.dumps(arguments, sort_keys=True))
                if key in seen_calls and name != "finish_investigation":
                    result = {"error": "duplicate tool call; choose a different action"}
                else:
                    seen_calls.add(key)
                    result = self._execute(name, arguments, cve, taxonomy, state, documents, searches, fetches)
                    if name == "search" and "error" not in result: searches += 1
                    if name == "fetch" and "error" not in result: fetches += 1
                if name == "finish_investigation":
                    return self._finish(cve, arguments, taxonomy, state, usage, started, turns)
                exchange.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result, ensure_ascii=False)})

    def _execute(self, name, arguments, cve, taxonomy, state, documents, searches, fetches):
        if name == "search":
            if searches >= self.settings.max_search_calls:
                return {"error": "search limit reached"}
            results = self.web_source.search(arguments["query"])
            state.visited_urls.extend(item.url for item in results if item.url not in state.visited_urls)
            return {"results": [asdict(item) for item in results[:10]]}
        if name == "fetch":
            if fetches >= self.settings.max_fetch_calls:
                return {"error": "fetch limit reached"}
            document = self.web_source.fetch(arguments["url"])
            document_id = document.document_id or arguments["url"]
            documents[document_id] = document
            state.visited_urls.append(document.url) if document.url not in state.visited_urls else None
            return {"document_id": document_id, "url": document.url, "title": document.title, "content": document.content[:self.settings.max_preview_chars], "truncated": len(document.content) > self.settings.max_preview_chars}
        if name == "record_evidence":
            document = documents.get(arguments["document_id"])
            if document is None or arguments["quote"] not in document.content:
                return {"error": "document or exact quote not found"}
            state.evidence.append(Evidence(document.url, arguments["quote"], arguments["explanation"]))
            return {"recorded": True, "evidence_count": len(state.evidence)}
        return {"error": f"unknown tool: {name}"}

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
