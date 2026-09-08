from __future__ import annotations

from typing import Callable
import logging

from cve_agent.classification.contracts import ClassificationScanner, TaxonomyScanOutcome
from cve_agent.classification.exhaustive import ExhaustiveTaxonomyScanner
from cve_agent.classification.hybrid import HybridTaxonomyScanner
from cve_agent.classification.planning import ClassificationPlan
from cve_agent.core.config import Settings
from cve_agent.core.investigation import InvestigationState
from cve_agent.core.sources import CVERecord
from cve_agent.core.strategy import EffectiveClassificationStrategy
from cve_agent.core.taxonomy import Taxonomy
from cve_agent.runtime.budget import TokenBudget
from cve_agent.runtime.ports import ModelCall


logger = logging.getLogger("cve_agent.agent")


def scan_taxonomy(
    settings: Settings,
    chat: ModelCall,
    plan: ClassificationPlan,
    cve: CVERecord,
    taxonomy: Taxonomy,
    state: InvestigationState,
    budget: TokenBudget,
    checkpoint: Callable[[], None],
) -> TaxonomyScanOutcome:
    if plan.effective_strategy == EffectiveClassificationStrategy.HYBRID:
        scanner: ClassificationScanner = HybridTaxonomyScanner(settings, chat)
    else:
        scanner = ExhaustiveTaxonomyScanner(chat, plan.chunks)
    return scanner.scan(
        cve,
        taxonomy,
        state,
        budget,
        checkpoint,
    )
