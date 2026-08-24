from __future__ import annotations

import logging
import time
from typing import Any, Callable

from openai import OpenAI

from cve_agent.budget import BudgetExceeded, TokenBudget, create_budget_plan, taxonomy_input_tokens
from cve_agent.classification import apply_hierarchy_policy, chunk_taxonomy, estimate_tokens
from cve_agent.config import Settings
from cve_agent.llm import RequestPacer, call_chat_completion
from cve_agent.models import CVERecord, ClassificationResult, ClassificationStatus, InvestigationState
from cve_agent.ports import WebSource
from cve_agent.research import ResearchRunner
from cve_agent.taxonomy import Taxonomy
from cve_agent.taxonomy_scan import TaxonomyScanner


logger = logging.getLogger(__name__)


class InvestigationAgent:
    """Orchestrate generic CVE research and exhaustive taxonomy classification."""

    def __init__(self, settings: Settings, web_source: WebSource, client: OpenAI | None = None):
        self.settings = settings
        self.web_source = web_source
        self.request_pacer = RequestPacer(settings.llm_min_request_interval)
        self.client = client or OpenAI(
            api_key=settings.api_key or "EMPTY",
            base_url=settings.endpoint,
            timeout=settings.llm_timeout,
            max_retries=0,
        )

    def preflight(self, taxonomy: Taxonomy) -> None:
        chunks = self._taxonomy_chunks(taxonomy)
        plan = create_budget_plan(chunks, self.settings)
        logger.info(
            "classification preflight labels=%d chunks=%d base_budget=%d expanded_budget=%d reserve=%d investigation_limit=%d",
            len(taxonomy.labels),
            len(chunks),
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
        chunks = self._taxonomy_chunks(taxonomy)
        plan = create_budget_plan(chunks, self.settings)
        budget = TokenBudget(plan, self.settings)
        checkpoint_fn = checkpoint or (lambda: None)
        logger.info(
            "[%s] agent started taxonomy_labels=%d chunks=%d classification_reserve=%d investigation_limit=%d",
            cve.cve_id,
            len(taxonomy.labels),
            len(chunks),
            plan.classification_reserve,
            plan.investigation_limit,
        )

        research = ResearchRunner(self.settings, self.web_source, self._chat).run(
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

        scan = TaxonomyScanner(self._chat).scan(
            cve,
            taxonomy,
            chunks,
            state,
            budget,
            checkpoint_fn,
        )
        coverage_complete = scan.completed_chunks == len(chunks)
        candidates = list(scan.candidates)
        if candidates and coverage_complete:
            status = ClassificationStatus.CLASSIFIED
            labels = apply_hierarchy_policy(candidates, taxonomy)
        elif candidates:
            status = ClassificationStatus.PARTIAL
            labels = apply_hierarchy_policy(candidates, taxonomy)
        elif coverage_complete:
            status = (
                ClassificationStatus.NO_MATCHING_LABEL
                if research.information_status == "sufficient"
                else ClassificationStatus.NOT_ENOUGH_INFORMATION
            )
            labels = []
        else:
            status, labels = ClassificationStatus.PARTIAL, []

        coverage = {
            "total_chunks": len(chunks),
            "completed_chunks": scan.completed_chunks,
            "total_labels": len(taxonomy.labels),
            "evaluated_labels": scan.evaluated_labels,
            "complete": coverage_complete,
        }
        if not research.complete or not coverage_complete or scan.stop_reason or budget.exhausted:
            status = ClassificationStatus.PARTIAL
        state.token_usage = budget.to_dict()
        operational: dict[str, Any] = {
            "turns": research.turns,
            "duration_seconds": round(time.monotonic() - started, 3),
            "token_usage": budget.to_dict(),
            "coverage": coverage,
            "research_information_status": research.information_status,
            "research_profile": {
                "findings": len(research.findings),
                "discarded_findings": research.discarded_findings,
                "promoted_evidence": research.promoted_evidence,
            },
        }
        stop_reason = scan.stop_reason or research.stop_reason
        if stop_reason:
            operational["stop_reason"] = stop_reason
        if scan.error:
            operational["stop_detail"] = scan.error

        logger.info(
            "[%s] agent finished status=%s labels=%d coverage=%d/%d tokens=%d stop_reason=%s duration_seconds=%.3f",
            cve.cve_id,
            status.value,
            len(labels),
            scan.completed_chunks,
            len(chunks),
            budget.total_tokens,
            stop_reason.value if stop_reason else "none",
            time.monotonic() - started,
        )
        return ClassificationResult(cve.cve_id, status, labels, operational=operational)

    def _chat(self, context: str, budget: TokenBudget, stage: str, **request: Any) -> Any:
        estimated_prompt = estimate_tokens(request)
        used_before = budget.total_tokens
        interaction = budget.reported_interactions + budget.estimated_interactions + 1
        try:
            request_max_tokens = budget.admit(stage, request)
        except BudgetExceeded as exc:
            logger.warning(
                "[%s] LLM request rejected stage=%s interaction=%d estimated_prompt_tokens=%d used_tokens=%d detail=%s",
                context,
                stage,
                interaction,
                estimated_prompt,
                budget.total_tokens,
                str(exc),
            )
            raise
        logger.info(
            "[%s] LLM request started stage=%s interaction=%d estimated_prompt_tokens=%d max_completion_tokens=%d used_tokens=%d",
            context,
            stage,
            interaction,
            estimated_prompt,
            request_max_tokens,
            used_before,
        )
        response = call_chat_completion(
            self.client,
            self.settings,
            logger,
            context=context,
            request_pacer=self.request_pacer,
            model=self.settings.model,
            temperature=self.settings.temperature,
            top_p=self.settings.top_p,
            max_tokens=request_max_tokens,
            **request,
        )
        prompt_before = budget.prompt_tokens
        completion_before = budget.completion_tokens
        budget.record(response, request)
        finish_reason = getattr(response.choices[0], "finish_reason", None)
        logger.info(
            "[%s] LLM request finished stage=%s interaction=%d prompt_tokens=%d completion_tokens=%d total_tokens=%d cumulative_tokens=%d finish_reason=%s",
            context,
            stage,
            interaction,
            budget.prompt_tokens - prompt_before,
            budget.completion_tokens - completion_before,
            budget.total_tokens - used_before,
            budget.total_tokens,
            finish_reason,
        )
        return response

    def _taxonomy_chunks(self, taxonomy: Taxonomy):
        return chunk_taxonomy(
            taxonomy,
            available_tokens=taxonomy_input_tokens(self.settings),
        )
