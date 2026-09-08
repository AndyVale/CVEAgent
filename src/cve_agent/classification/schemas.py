from __future__ import annotations

from typing import Any


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
