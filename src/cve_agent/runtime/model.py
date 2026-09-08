from __future__ import annotations

from typing import Any
import logging

from openai import OpenAI

from cve_agent.core.config import Settings
from cve_agent.runtime.budget import BudgetExceeded, TokenBudget
from cve_agent.runtime.llm import RequestPacer, call_chat_completion
from cve_agent.runtime.tokens import estimate_tokens


logger = logging.getLogger("cve_agent.agent")

class BudgetedModelCall:
    def __init__(self, settings: Settings, client: OpenAI | None = None):
        self.settings = settings
        self.request_pacer = RequestPacer(settings.llm_min_request_interval)
        self.client = client or OpenAI(
            api_key=settings.api_key or "EMPTY",
            base_url=settings.endpoint,
            timeout=settings.llm_timeout,
            max_retries=0,
        )

    def __call__(self, context: str, budget: TokenBudget, stage: str, **request: Any) -> Any:
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
