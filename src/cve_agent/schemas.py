from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from cve_agent.models import MAX_INVESTIGATION_FINDINGS, InvestigationAspect


def tool(name: str, description: str, parameters: dict[str, Any]) -> dict[str, Any]:
    return {"type": "function", "function": {"name": name, "description": description, "parameters": parameters, "strict": True}}


_ASPECT_SCHEMA = {"type": "string", "enum": [aspect.value for aspect in InvestigationAspect]}

_FINDING_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "aspect": _ASPECT_SCHEMA,
        "statement": {"type": "string", "minLength": 1},
        "evidence_ids": {"type": "array", "items": {"type": "string", "minLength": 1}, "minItems": 1},
    },
    "required": ["aspect", "statement", "evidence_ids"],
}

AGENT_TOOLS = [
    tool(
        "search",
        "Find relevant web sources using a targeted query. Results are leads only and must be fetched before they can support a finding.",
        {"type": "object", "additionalProperties": False, "properties": {"query": {"type": "string"}}, "required": ["query"]},
    ),
    tool(
        "fetch",
        "Retrieve a source and inspect its bounded numbered passages. Discard sources that contain only boilerplate or otherwise lack useful vulnerability information.",
        {"type": "object", "additionalProperties": False, "properties": {"url": {"type": "string"}}, "required": ["url"]},
    ),
    tool(
        "record_evidence",
        "Optionally preserve an important passage before using another tool. passage_id accepts the full ID or the document-local number (for example 1 or p1). Fetched passage IDs may also be cited directly in finish_investigation.",
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {"document_id": {"type": "string"}, "passage_id": {"type": "string"}, "quote_anchor": {"type": "string"}},
            "required": ["document_id", "passage_id", "quote_anchor"],
        },
    ),
    tool(
        "finish_investigation",
        "Submit the useful source-grounded findings. The aspects are high-level categories, not a checklist: omit categories that reliable sources did not establish. Fetched passages are promoted automatically when cited.",
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "findings": {"type": "array", "items": _FINDING_SCHEMA, "maxItems": MAX_INVESTIGATION_FINDINGS},
                "summary": {"type": "string", "minLength": 1},
            },
            "required": ["findings", "summary"],
        },
    ),
]


def research_tools(document_ids: Iterable[str]) -> list[dict[str, Any]]:
    """Expose evidence recording only for documents available in the current session."""
    available_ids = tuple(dict.fromkeys(document_ids))
    selected: list[dict[str, Any]] = []
    for configured_tool in AGENT_TOOLS:
        function = configured_tool["function"]
        if function["name"] != "record_evidence":
            selected.append(configured_tool)
        elif available_ids:
            selected.append(_record_evidence_tool(available_ids))
    return selected


def _record_evidence_tool(document_ids: tuple[str, ...]) -> dict[str, Any]:
    return tool(
        "record_evidence",
        "Optionally preserve an important passage from an available fetched document before using another tool.",
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "document_id": {"type": "string", "enum": list(document_ids)},
                "passage_id": {"type": "string"},
                "quote_anchor": {"type": "string"},
            },
            "required": ["document_id", "passage_id", "quote_anchor"],
        },
    )


def classification_response_format() -> dict[str, Any]:
    """Return the strict structured-output contract for one taxonomy chunk."""
    supported_label = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "label": {"type": "string", "minLength": 1},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "evidence": {"type": "array", "items": _evidence_association_schema(), "minItems": 1},
        },
        "required": ["label", "confidence", "evidence"],
    }
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "taxonomy_chunk_classification",
            "strict": True,
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "chunk_id": {"type": "integer"},
                    "supported": {"type": "array", "items": supported_label},
                },
                "required": ["chunk_id", "supported"],
            },
        },
    }


def hierarchy_routing_response_format() -> dict[str, Any]:
    """Return the strict structured-output contract for one hierarchy level chunk."""
    decision = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "label": {"type": "string", "minLength": 1},
            "decision": {"type": "string", "enum": ["supported", "uncertain", "unsupported"]},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "explanation": {"type": "string", "minLength": 1},
            "evidence": {"type": "array", "items": _evidence_association_schema()},
        },
        "required": ["label", "decision", "confidence", "explanation", "evidence"],
    }
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "hierarchy_level_routing",
            "strict": True,
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "level_id": {"type": "integer"},
                    "decisions": {"type": "array", "items": decision},
                },
                "required": ["level_id", "decisions"],
            },
        },
    }


def _evidence_association_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "evidence_id": {"type": "string", "minLength": 1},
            "explanation": {"type": "string", "minLength": 1},
        },
        "required": ["evidence_id", "explanation"],
    }
