from __future__ import annotations

import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import urlsplit, urlunsplit


def redact_secrets(value: object, *secrets: str | None) -> str:
    """Remove configured credential values from diagnostic text."""
    redacted = str(value)
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def safe_url(value: str) -> str:
    """Keep useful URL provenance in logs without query strings or fragments."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "invalid-url"
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


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
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
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
