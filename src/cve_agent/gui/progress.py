from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol
import logging

from cve_agent.core.config import Settings
from cve_agent.runtime.diagnostics import LogTone, redact_secrets


class EventSink(Protocol):
    def add_event(self, *, tone: str, component: str, message: str) -> None: ...


class _ProgressHandler(logging.Handler):
    def __init__(self, running: EventSink, settings: Settings):
        super().__init__(logging.INFO)
        self.running = running
        self.settings = settings

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = redact_secrets(record.getMessage(), self.settings.api_key, self.settings.tavily_api_key)
            tone = getattr(record, "tone", None) or _level_tone(record.levelno)
            component = record.name.removeprefix("cve_agent.").upper()
            self.running.add_event(tone=str(tone), component=component, message=message)
        except Exception:
            self.handleError(record)


def _event(*, tone: str, component: str, message: str) -> dict[str, Any]:
    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tone": tone,
        "component": component,
        "message": message,
    }


def _level_tone(level: int) -> str:
    if level >= logging.ERROR:
        return LogTone.ERROR.value
    if level >= logging.WARNING:
        return LogTone.WARNING.value
    return LogTone.NORMAL.value


def _result_tone(status: str) -> str:
    if status == "failed":
        return LogTone.ERROR.value
    if status in {"partial", "not_enough_information"}:
        return LogTone.INCOMPLETE.value
    return LogTone.SUCCESS.value
