from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TextIO
import logging
import os
import sys

from cve_agent.runtime.diagnostics import LogTone


_COLORS = {
    LogTone.NORMAL: "\033[36m",
    LogTone.SUCCESS: "\033[32m",
    LogTone.INCOMPLETE: "\033[35m",
    LogTone.WARNING: "\033[33m",
    LogTone.ERROR: "\033[31m",
}


_TONES_BY_VALUE = {tone.value: tone for tone in LogTone}


_RESET = "\033[0m"


class VerboseFormatter(logging.Formatter):
    """Format application logs as readable, optionally colored terminal events."""

    def __init__(self, *, color: bool) -> None:
        super().__init__(datefmt="%H:%M:%S")
        self.color = color

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        tone = self._tone(record)
        badge = self._badge(record, tone)
        component = record.name.removeprefix("cve_agent.").upper()
        prefix = f"{self.formatTime(record, self.datefmt)}  {badge:<10}  {component:<18}  "
        continuation = " " * len(prefix)
        lines = message.splitlines() or [""]
        rendered = "\n".join(
            (prefix if index == 0 else continuation) + line if line else ""
            for index, line in enumerate(lines)
        )
        if self.color:
            rendered = f"{_COLORS[tone]}{rendered}{_RESET}"
        if getattr(record, "section_break", False):
            rendered = "\n" + rendered
        if record.exc_info:
            exception = self.formatException(record.exc_info)
            if self.color:
                exception = f"{_COLORS[LogTone.ERROR]}{exception}{_RESET}"
            rendered = f"{rendered}\n{exception}"
        return rendered

    @staticmethod
    def _tone(record: logging.LogRecord) -> LogTone:
        configured = getattr(record, "tone", None)
        if isinstance(configured, LogTone):
            return configured
        if isinstance(configured, str) and configured in _TONES_BY_VALUE:
            return _TONES_BY_VALUE[configured]
        if record.levelno >= logging.ERROR:
            return LogTone.ERROR
        if record.levelno >= logging.WARNING:
            return LogTone.WARNING
        return LogTone.NORMAL

    @staticmethod
    def _badge(record: logging.LogRecord, tone: LogTone) -> str:
        if tone == LogTone.SUCCESS:
            return "COMPLETE"
        if tone == LogTone.INCOMPLETE:
            return "INCOMPLETE"
        if tone == LogTone.WARNING:
            return "WARNING"
        if tone == LogTone.ERROR:
            return "ERROR"
        return record.levelname


def supports_color(stream: TextIO) -> bool:
    """Enable ANSI colors only for an interactive terminal that has not opted out."""
    return "NO_COLOR" not in os.environ and bool(getattr(stream, "isatty", lambda: False)())


@contextmanager
def verbose_logging(enabled: bool) -> Iterator[None]:
    """Install and fully restore the CLI's scoped verbose logging configuration."""
    if not enabled:
        yield
        return

    package_logger = logging.getLogger("cve_agent")
    previous_level = package_logger.level
    previous_propagate = package_logger.propagate
    noisy_levels = {
        "httpx": logging.WARNING,
        "httpcore": logging.WARNING,
        "openai": logging.WARNING,
        "trafilatura": logging.CRITICAL,
    }
    noisy_loggers = {name: logging.getLogger(name) for name in noisy_levels}
    previous_noisy_levels = {name: item.level for name, item in noisy_loggers.items()}
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(VerboseFormatter(color=supports_color(sys.stderr)))
    package_logger.addHandler(handler)
    package_logger.setLevel(logging.INFO)
    package_logger.propagate = False
    for name, item in noisy_loggers.items():
        item.setLevel(noisy_levels[name])
    try:
        yield
    finally:
        package_logger.removeHandler(handler)
        handler.close()
        package_logger.setLevel(previous_level)
        package_logger.propagate = previous_propagate
        for name, item in noisy_loggers.items():
            item.setLevel(previous_noisy_levels[name])
