from __future__ import annotations

from typing import Any


CLASSIFICATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "cve_id": {"type": "string"},
        "status": {"type": "string", "enum": ["classified", "not_enough_information"]},
        "labels": {"type": "array", "items": {"type": "object", "additionalProperties": False, "properties": {
            "label": {"type": "string"},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "evidence": {"type": "array", "items": {"type": "object", "additionalProperties": False, "properties": {
                "url": {"type": "string"}, "quote": {"type": "string"}, "explanation": {"type": "string"}
            }, "required": ["url", "quote", "explanation"]}},
        }, "required": ["label", "confidence", "evidence"]}},
    },
    "required": ["cve_id", "status", "labels"],
}


def tool(name: str, description: str, parameters: dict[str, Any]) -> dict[str, Any]:
    return {"type": "function", "function": {"name": name, "description": description, "parameters": parameters, "strict": True}}


AGENT_TOOLS = [
    tool("search", "Search for sources relevant to the current CVE. Results are leads, not verified evidence; fetch a result before relying on it.", {"type": "object", "additionalProperties": False, "properties": {"query": {"type": "string"}}, "required": ["query"]}),
    tool("fetch", "Fetch a specific URL and return a bounded, readable text preview. The result is temporary until evidence is explicitly recorded.", {"type": "object", "additionalProperties": False, "properties": {"url": {"type": "string"}}, "required": ["url"]}),
    tool("record_evidence", "Promote a concrete quote from a fetched document into the persistent investigation evidence. Only record text actually present in the document.", {"type": "object", "additionalProperties": False, "properties": {"document_id": {"type": "string"}, "quote": {"type": "string"}, "explanation": {"type": "string"}}, "required": ["document_id", "quote", "explanation"]}),
    tool("finish_investigation", "Finish the current CVE investigation and return the final taxonomy classification. Use not_enough_information instead of guessing.", {"type": "object", "additionalProperties": False, "properties": {"status": {"type": "string", "enum": ["classified", "not_enough_information"]}, "labels": {"type": "array", "items": {"type": "object", "additionalProperties": False, "properties": {"label": {"type": "string"}, "confidence": {"type": "number", "minimum": 0, "maximum": 1}, "evidence": {"type": "array", "items": {"type": "object", "additionalProperties": False, "properties": {"url": {"type": "string"}, "quote": {"type": "string"}, "explanation": {"type": "string"}}, "required": ["url", "quote", "explanation"]}}}, "required": ["label", "confidence", "evidence"]}}}, "required": ["status", "labels"]}),
]
