from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cve_agent.core.config import Settings
from cve_agent.runtime.tokens import estimate_tokens


class BudgetExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class BudgetPlan:
    base_budget: int
    expanded_budget: int
    classification_reserve: int
    investigation_limit: int


class TokenBudget:
    def __init__(self, plan: BudgetPlan, settings: Settings):
        self.plan = plan
        self.settings = settings
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.reported_interactions = 0
        self.estimated_interactions = 0
        self.exhausted = False

    def admit(self, stage: str, request: dict[str, Any]) -> int:
        estimated_prompt = estimate_tokens(request)
        if estimated_prompt > self.settings.max_input_tokens_per_request:
            raise BudgetExceeded(
                f"estimated prompt size {estimated_prompt} exceeds max_input_tokens_per_request={self.settings.max_input_tokens_per_request}"
            )
        limit = self.plan.investigation_limit if stage == "investigation" else self.plan.expanded_budget
        remaining = limit - self.total_tokens - estimated_prompt
        if remaining <= 0:
            self.exhausted = True
            raise BudgetExceeded(f"{stage} token allowance exhausted")
        return min(self.settings.max_tokens, remaining)

    def record(self, response: Any, request: dict[str, Any]) -> None:
        usage = response.usage.model_dump() if getattr(response, "usage", None) else {}
        prompt = int(usage.get("prompt_tokens", 0))
        completion = int(usage.get("completion_tokens", 0))
        total = int(usage.get("total_tokens", 0))
        if prompt or completion or total:
            if not total:
                total = prompt + completion
            self.reported_interactions += 1
        else:
            prompt = estimate_tokens(request)
            message = response.choices[0].message
            completion = estimate_tokens(message.model_dump(exclude_none=True) if hasattr(message, "model_dump") else getattr(message, "content", ""))
            total = prompt + completion
            self.estimated_interactions += 1
        self.prompt_tokens += prompt
        self.completion_tokens += completion
        self.total_tokens += total
        if self.total_tokens > self.plan.expanded_budget:
            self.exhausted = True

    def to_dict(self) -> dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "reported_interactions": self.reported_interactions,
            "estimated_interactions": self.estimated_interactions,
            "base_budget": self.plan.base_budget,
            "expanded_budget": self.plan.expanded_budget,
            "classification_reserve": self.plan.classification_reserve,
            "investigation_limit": self.plan.investigation_limit,
        }
