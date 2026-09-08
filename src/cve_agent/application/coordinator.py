from __future__ import annotations

from typing import Callable
import logging
import time

from openai import OpenAI

from cve_agent.classification.finalization import finalize_result
from cve_agent.classification.planning import ClassificationPlanner
from cve_agent.classification.scanning import scan_taxonomy
from cve_agent.core.config import Settings
from cve_agent.core.investigation import InvestigationState
from cve_agent.core.ports import WebSource
from cve_agent.core.results import ClassificationResult
from cve_agent.core.sources import CVERecord
from cve_agent.core.taxonomy import Taxonomy
from cve_agent.investigation.runner import ResearchRunner
from cve_agent.runtime.budget import TokenBudget
from cve_agent.runtime.model import BudgetedModelCall


logger = logging.getLogger("cve_agent.agent")



class ClassificationCoordinator:
    """Coordinate research and taxonomy classification under one token budget."""

    def __init__(self, settings: Settings, web_source: WebSource, client: OpenAI | None = None):
        self.settings = settings
        self.web_source = web_source
        self.planner = ClassificationPlanner(settings)
        self.model_call = BudgetedModelCall(settings, client)

    def preflight(self, taxonomy: Taxonomy) -> None:
        classification_plan = self.planner.plan(taxonomy)
        plan = classification_plan.budget
        logger.info(
            "classification preflight configured_strategy=%s effective_strategy=%s labels=%d chunks=%d base_budget=%d expanded_budget=%d reserve=%d investigation_limit=%d",
            self.settings.classification_strategy.value,
            classification_plan.effective_strategy.value,
            len(taxonomy.labels),
            len(classification_plan.chunks),
            plan.base_budget,
            plan.expanded_budget,
            plan.classification_reserve,
            plan.investigation_limit,
        )

    def classify(
        self,
        cve: CVERecord,
        taxonomy: Taxonomy,
        state: InvestigationState,
        checkpoint: Callable[[], None] | None = None,
    ) -> ClassificationResult:
        started = time.monotonic()
        classification_plan = self.planner.plan(taxonomy)
        plan = classification_plan.budget
        budget = TokenBudget(plan, self.settings)
        checkpoint_fn = checkpoint or (lambda: None)
        logger.info(
            "[%s] agent started taxonomy_labels=%d configured_strategy=%s effective_strategy=%s chunks=%d classification_reserve=%d investigation_limit=%d",
            cve.cve_id,
            len(taxonomy.labels),
            self.settings.classification_strategy.value,
            classification_plan.effective_strategy.value,
            len(classification_plan.chunks),
            plan.classification_reserve,
            plan.investigation_limit,
        )

        research = ResearchRunner(self.settings, self.web_source, self.model_call).run(
            cve,
            state,
            budget,
            started,
            checkpoint_fn,
        )
        state.research_information_status = research.information_status
        state.research_summary = research.summary
        state.findings = list(research.findings)
        checkpoint_fn()
        logger.info(
            "[%s] research profile stored status=%s findings=%d evidence=%d complete=%s",
            cve.cve_id,
            research.information_status,
            len(state.findings),
            len(state.evidence),
            research.complete,
        )

        scan = scan_taxonomy(
            self.settings, self.model_call,
            classification_plan,
            cve,
            taxonomy,
            state,
            budget,
            checkpoint_fn,
        )
        return finalize_result(
            self.settings, classification_plan, cve, taxonomy, state, budget,
            research, scan, started, checkpoint_fn,
        )
