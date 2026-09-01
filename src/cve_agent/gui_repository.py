"""Compatibility imports for the unified persistence repository."""

from cve_agent.config import settings_fingerprint
from cve_agent.persistence import (
    AnalysisRepository,
    AnalysisSummary,
    StoredAnalysis,
    parse_analysis_id,
)


GuiAnalysisRepository = AnalysisRepository

__all__ = [
    "AnalysisSummary",
    "GuiAnalysisRepository",
    "StoredAnalysis",
    "parse_analysis_id",
    "settings_fingerprint",
]
