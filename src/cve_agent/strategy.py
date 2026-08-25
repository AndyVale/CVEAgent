from __future__ import annotations

from enum import StrEnum


class ClassificationStrategy(StrEnum):
    AUTO = "auto"
    HYBRID = "hybrid"
    EXHAUSTIVE = "exhaustive"


class EffectiveClassificationStrategy(StrEnum):
    HYBRID = "hybrid"
    EXHAUSTIVE = "exhaustive"
