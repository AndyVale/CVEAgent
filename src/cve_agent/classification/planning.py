from __future__ import annotations

from dataclasses import dataclass
import logging

from cve_agent.classification.budget import (
    create_budget_plan,
    create_hybrid_budget_plan,
    taxonomy_input_tokens,
)
from cve_agent.classification.taxonomy import TaxonomyChunk, chunk_taxonomy, is_hierarchical
from cve_agent.core.config import Settings
from cve_agent.core.strategy import EffectiveClassificationStrategy
from cve_agent.core.taxonomy import Taxonomy
from cve_agent.runtime.budget import BudgetPlan


logger = logging.getLogger("cve_agent.agent")

@dataclass(frozen=True)
class ClassificationPlan:
    effective_strategy: EffectiveClassificationStrategy
    chunks: tuple[TaxonomyChunk, ...]
    budget: BudgetPlan



class ClassificationPlanner:
    def __init__(self, settings: Settings):
        self.settings = settings

    def _taxonomy_chunks(self, taxonomy: Taxonomy):
        return chunk_taxonomy(
            taxonomy,
            available_tokens=taxonomy_input_tokens(self.settings),
        )

    def plan(self, taxonomy: Taxonomy) -> ClassificationPlan:
        chunks = self._taxonomy_chunks(taxonomy)
        hierarchical = is_hierarchical(taxonomy)
        configured = self.settings.classification_strategy
        if not hierarchical:
            effective = EffectiveClassificationStrategy.EXHAUSTIVE
            logger.info(
                "flat taxonomy uses linear exhaustive classification; ignoring configured_strategy=%s",
                configured.value,
            )
        elif configured.value == EffectiveClassificationStrategy.EXHAUSTIVE.value:
            effective = EffectiveClassificationStrategy.EXHAUSTIVE
        elif configured.value == EffectiveClassificationStrategy.HYBRID.value:
            effective = EffectiveClassificationStrategy.HYBRID
        else:
            effective = (
                EffectiveClassificationStrategy.EXHAUSTIVE
                if len(chunks) <= 1
                else EffectiveClassificationStrategy.HYBRID
            )
        budget = (
            create_budget_plan(chunks, self.settings)
            if effective == EffectiveClassificationStrategy.EXHAUSTIVE
            else create_hybrid_budget_plan(taxonomy, self.settings)
        )
        return ClassificationPlan(effective, chunks, budget)
