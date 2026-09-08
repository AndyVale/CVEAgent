from __future__ import annotations

from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit


class LogTone(StrEnum):
    NORMAL = "normal"
    SUCCESS = "success"
    INCOMPLETE = "incomplete"
    WARNING = "warning"
    ERROR = "error"


def log_extra(tone: LogTone = LogTone.NORMAL, *, section: bool = False) -> dict[str, object]:
    """Return structured terminal presentation hints without changing log severity."""
    return {"tone": tone.value, "section_break": section}


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
