from __future__ import annotations

from typing import Any


def _bounded_text(value: Any, limit: int = 180) -> str:
    normalized = " ".join(str(value).split())
    return normalized if len(normalized) <= limit else normalized[: limit - 1] + "…"
