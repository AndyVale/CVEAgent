from typing import Any, Protocol

from cve_agent.runtime.budget import TokenBudget


class ModelCall(Protocol):
    """Budget-aware model invocation shared by research and taxonomy scanning."""

    def __call__(self, context: str, budget: TokenBudget, stage: str, **request: Any) -> Any: ...
