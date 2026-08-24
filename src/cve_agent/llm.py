from __future__ import annotations

import json
import logging
import time
from typing import Any

from openai import APIConnectionError, APITimeoutError, InternalServerError, OpenAI, RateLimitError
from tenacity import Retrying, retry_if_exception_type, stop_after_attempt, wait_exponential

from cve_agent.config import Settings
from cve_agent.logging_config import redact_secrets


class EmptyCompletionError(RuntimeError):
    """The provider returned a response object without a usable choice."""

    def __init__(self, response: Any, diagnostic: str | None = None):
        self.response = response
        super().__init__(f"LLM returned no usable choices ({diagnostic or response_summary(response)})")


class RequestPacer:
    """Enforce a minimum interval between starts of model requests."""

    def __init__(self, minimum_interval: float):
        self.minimum_interval = max(0.0, minimum_interval)
        self._last_request_started: float | None = None

    def wait(self, logger: logging.Logger, context: str) -> None:
        if self._last_request_started is not None:
            elapsed = time.monotonic() - self._last_request_started
            remaining = self.minimum_interval - elapsed
            if remaining > 0:
                logger.info("[%s] waiting %.1fs before next LLM request", context, remaining)
                time.sleep(remaining)
        self._last_request_started = time.monotonic()


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


def call_chat_completion(client: OpenAI, settings: Settings, logger: logging.Logger, *, context: str, request_pacer: RequestPacer | None = None, **request: Any) -> Any:
    """Call the provider with bounded exponential retries for transient failures."""
    retryable = (APIConnectionError, APITimeoutError, InternalServerError, RateLimitError, EmptyCompletionError)

    def log_retry(retry_state) -> None:
        exception = retry_state.outcome.exception() if retry_state.outcome else "unknown"
        logger.warning(
            "[%s] LLM interaction failed; retrying attempt=%d/%d wait=%.1fs error=%s",
            context,
            retry_state.attempt_number,
            settings.llm_retry_count + 1,
            retry_state.next_action.sleep if retry_state.next_action else 0.0,
            redact_secrets(exception, settings.api_key, settings.tavily_api_key),
        )

    for attempt in Retrying(
        stop=stop_after_attempt(settings.llm_retry_count + 1),
        wait=wait_exponential(multiplier=settings.llm_retry_wait, max=settings.llm_retry_max_wait),
        retry=retry_if_exception_type(retryable),
        before_sleep=log_retry,
        reraise=True,
    ):
        with attempt:
            if request_pacer is not None:
                request_pacer.wait(logger, context)
            response = client.chat.completions.create(**request)
            if response is None or not getattr(response, "choices", None):
                diagnostic = redact_secrets(
                    response_summary(response),
                    settings.api_key,
                    settings.tavily_api_key,
                )
                logger.error(
                    "[%s] LLM provider returned unusable response: %s",
                    context,
                    diagnostic,
                )
                raise EmptyCompletionError(response, diagnostic)
            return response
