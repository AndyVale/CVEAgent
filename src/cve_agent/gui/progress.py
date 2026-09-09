from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Iterator, Protocol
import logging
import threading

from cve_agent.core.config import Settings
from cve_agent.runtime.diagnostics import LogTone, redact_secrets


class EventSink(Protocol):
    def add_event(self, *, tone: str, component: str, message: str) -> None: ...


_active_capture: ContextVar[object | None] = ContextVar("cve_agent_gui_progress", default=None)
_logging_lock = threading.RLock()
_capture_count = 0
_previous_logging: tuple[int, bool] | None = None


class _ProgressHandler(logging.Handler):
    def __init__(self, running: EventSink, settings: Settings, capture_id: object):
        super().__init__(logging.INFO)
        self.running = running
        self.settings = settings
        self.capture_id = capture_id

    def emit(self, record: logging.LogRecord) -> None:
        if _active_capture.get() is not self.capture_id:
            return
        try:
            message = redact_secrets(record.getMessage(), self.settings.api_key, self.settings.tavily_api_key)
            tone = getattr(record, "tone", None) or _level_tone(record.levelno)
            component = record.name.removeprefix("cve_agent.").upper()
            self.running.add_event(tone=str(tone), component=component, message=message)
        except Exception:
            self.handleError(record)


@contextmanager
def capture_progress(running: EventSink, settings: Settings) -> Iterator[None]:
    """Route only diagnostics emitted by this execution context to one analysis."""
    global _capture_count, _previous_logging
    capture_id = object()
    handler = _ProgressHandler(running, settings, capture_id)
    package_logger = logging.getLogger("cve_agent")
    with _logging_lock:
        if _capture_count == 0:
            _previous_logging = (package_logger.level, package_logger.propagate)
            package_logger.setLevel(logging.INFO)
            package_logger.propagate = False
        _capture_count += 1
        package_logger.addHandler(handler)
    token = _active_capture.set(capture_id)
    try:
        yield
    finally:
        _active_capture.reset(token)
        with _logging_lock:
            package_logger.removeHandler(handler)
            handler.close()
            _capture_count -= 1
            if _capture_count == 0 and _previous_logging is not None:
                package_logger.setLevel(_previous_logging[0])
                package_logger.propagate = _previous_logging[1]
                _previous_logging = None


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
