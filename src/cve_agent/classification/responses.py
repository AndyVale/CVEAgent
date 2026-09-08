from __future__ import annotations

from typing import Any
import json


class ClassificationResponseError(ValueError):
    """A taxonomy-chunk response remained invalid after its correction attempt."""


def decode_json_content(response: Any) -> dict[str, Any] | list[Any]:
    content = (response.choices[0].message.content or "").strip()
    if "</think>" in content:
        content = content.rsplit("</think>", 1)[1].strip()
    content = content.removeprefix("```json").removesuffix("```").strip()
    try:
        decoded = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("provider returned non-JSON classification content") from exc
    if not isinstance(decoded, (dict, list)):
        raise ValueError("classification response must be a JSON object or array")
    return decoded


def supported_labels(decoded: dict[str, Any] | list[Any], chunk_id: int) -> list[Any]:
    if isinstance(decoded, list):
        return decoded
    returned_chunk_id = decoded.get("chunk_id", chunk_id)
    if returned_chunk_id != chunk_id:
        raise ValueError(f"classifier returned chunk_id {returned_chunk_id!r}, expected {chunk_id}")
    supported = decoded.get("supported")
    if supported is None:
        supported = decoded.get("supported_labels", decoded.get("labels"))
    if not isinstance(supported, list):
        raise ValueError("taxonomy chunk response requires a supported array")
    return supported
