from __future__ import annotations

from typing import Any

from cve_agent.models import ClassificationStatus


def tool(name: str, description: str, parameters: dict[str, Any]) -> dict[str, Any]:
    return {"type": "function", "function": {"name": name, "description": description, "parameters": parameters, "strict": True}}


AGENT_TOOLS = [
    tool("search", "Search only when the NVD record and its references do not provide enough information. Results are leads, not evidence; choose at most one or two strong results to fetch.", {"type": "object", "additionalProperties": False, "properties": {"query": {"type": "string"}}, "required": ["query"]}),
    tool("fetch", "Fetch one strong source and inspect its bounded preview. If this URL was already fetched, use the returned existing preview; do not request the same URL repeatedly. After fetching, immediately call record_evidence with an exact useful quote or call finish_investigation.", {"type": "object", "additionalProperties": False, "properties": {"url": {"type": "string"}}, "required": ["url"]}),
    tool("record_evidence", "Immediately promote a concrete quote from the most recently fetched document. Prefer an exact quote from the text, but provide the best bounded excerpt or paraphrase available if exact wording is difficult. Then call finish_investigation unless another source is essential.", {"type": "object", "additionalProperties": False, "properties": {"document_id": {"type": "string"}, "quote": {"type": "string"}, "explanation": {"type": "string"}}, "required": ["document_id", "quote", "explanation"]}),
    tool("finish_investigation", "Finish now when the initial NVD description or an additional reliable source supports a decision. This is multi-label classification: assess the complete taxonomy and return every supported taxonomy ID, not only the first match. Return no_matching_label when the investigation is sufficient but no taxonomy entry applies, or not_enough_information when evidence is insufficient. Do not search or fetch merely to delay this decision.", {"type": "object", "additionalProperties": False, "properties": {"status": {"type": "string", "enum": [ClassificationStatus.CLASSIFIED.value, ClassificationStatus.NO_MATCHING_LABEL.value, ClassificationStatus.NOT_ENOUGH_INFORMATION.value]}, "labels": {"type": "array", "items": {"type": "object", "additionalProperties": False, "properties": {"label": {"type": "string"}, "confidence": {"type": "number", "minimum": 0, "maximum": 1}, "evidence": {"type": "array", "items": {"type": "object", "additionalProperties": False, "properties": {"url": {"type": "string"}, "quote": {"type": "string"}, "explanation": {"type": "string"}}, "required": ["url", "quote", "explanation"]}}}, "required": ["label", "confidence", "evidence"]}}}, "required": ["status", "labels"]}),
]
