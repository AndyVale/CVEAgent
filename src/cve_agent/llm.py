from __future__ import annotations

import json
import logging
from typing import Any

from openai import APIConnectionError, APITimeoutError, InternalServerError, OpenAI, RateLimitError
from tenacity import Retrying, retry_if_exception_type, stop_after_attempt, wait_exponential

from cve_agent.config import Settings


class EmptyCompletionError(RuntimeError):
    """The provider returned a response object without a usable choice."""

    def __init__(self, response: Any):
        self.response = response
        super().__init__(f"LLM returned no usable choices ({response_summary(response)})")


def response_summary(response: Any) -> str:
    """Return safe response metadata and provider error details for diagnostics."""
    if response is None:
        return "response=None"
    error = getattr(response, "error", None)
    error_detail = "none"
    if error is not None:
        if isinstance(error, dict):
            error_detail = json.dumps(error, ensure_ascii=False, default=str, sort_keys=True)
        else:
            error_detail = repr(error)
    return (
        f"response_type={type(response).__name__} "
        f"response_id={getattr(response, 'id', None)!r} "
        f"model={getattr(response, 'model', None)!r} "
        f"error={error_detail} "
        f"finish_reason={getattr(response, 'finish_reason', None)!r}"
    )


def call_chat_completion(client: OpenAI, settings: Settings, logger: logging.Logger, *, context: str, **request: Any) -> Any:
    """Call the provider with bounded exponential retries for transient failures."""
    retryable = (APIConnectionError, APITimeoutError, InternalServerError, RateLimitError, EmptyCompletionError)

    def log_retry(retry_state) -> None:
        logger.warning(
            "[%s] LLM interaction failed; retrying attempt=%d/%d wait=%.1fs error=%s",
            context,
            retry_state.attempt_number,
            settings.llm_retry_count + 1,
            retry_state.next_action.sleep if retry_state.next_action else 0.0,
            retry_state.outcome.exception() if retry_state.outcome else "unknown",
        )

    for attempt in Retrying(
        stop=stop_after_attempt(settings.llm_retry_count + 1),
        wait=wait_exponential(multiplier=settings.llm_retry_wait, max=settings.llm_retry_max_wait),
        retry=retry_if_exception_type(retryable),
        before_sleep=log_retry,
        reraise=True,
    ):
        with attempt:
            response = client.chat.completions.create(**request)
            if response is None or not getattr(response, "choices", None):
                logger.error("[%s] LLM provider returned unusable response: %s", context, response_summary(response))
                raise EmptyCompletionError(response)
            return response
