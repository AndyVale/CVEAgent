from __future__ import annotations

from typing import Any

from cve_agent.models import ClassificationStatus


def tool(name: str, description: str, parameters: dict[str, Any]) -> dict[str, Any]:
    return {"type": "function", "function": {"name": name, "description": description, "parameters": parameters, "strict": True}}


AGENT_TOOLS = [
    tool("search", "Search only when the NVD record and its references do not provide enough information. Results are leads, not evidence; choose at most one or two strong results to fetch.", {"type": "object", "additionalProperties": False, "properties": {"query": {"type": "string"}}, "required": ["query"]}),
    tool("fetch", "Fetch one strong source and inspect its bounded numbered passages. After fetching, record useful evidence by passage ID or quote anchor, or finish.", {"type": "object", "additionalProperties": False, "properties": {"url": {"type": "string"}}, "required": ["url"]}),
    tool("record_evidence", "Promote an exact application-owned passage. Prefer passage_id. If necessary, leave passage_id empty and provide a distinctive approximate quote_anchor; it must resolve uniquely.", {"type": "object", "additionalProperties": False, "properties": {"document_id": {"type": "string"}, "passage_id": {"type": "string"}, "quote_anchor": {"type": "string"}}, "required": ["document_id", "passage_id", "quote_anchor"]}),
    tool("finish_investigation", "Finish with every supported taxonomy ID. Cite only recorded evidence IDs; the application supplies canonical URLs and exact quotes.", {"type": "object", "additionalProperties": False, "properties": {"status": {"type": "string", "enum": [ClassificationStatus.CLASSIFIED.value, ClassificationStatus.NO_MATCHING_LABEL.value, ClassificationStatus.NOT_ENOUGH_INFORMATION.value]}, "labels": {"type": "array", "items": {"type": "object", "additionalProperties": False, "properties": {"label": {"type": "string"}, "confidence": {"type": "number", "minimum": 0, "maximum": 1}, "evidence": {"type": "array", "items": {"type": "object", "additionalProperties": False, "properties": {"evidence_id": {"type": "string"}, "explanation": {"type": "string"}}, "required": ["evidence_id", "explanation"]}}}, "required": ["label", "confidence", "evidence"]}}}, "required": ["status", "labels"]}),
]
