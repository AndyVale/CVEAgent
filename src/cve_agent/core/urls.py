from __future__ import annotations

from typing import Any
import re
import urllib.parse


_CVE_PATTERN = re.compile(
    r"(?i)\bCVE[\s_\-\u2010\u2011\u2012\u2013\u2014\u2212]+"
    r"(\d{4})[\s_\-\u2010\u2011\u2012\u2013\u2014\u2212]+(\d{4,12})\b"
)


def normalize_url(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value.strip())
        hostname = (parsed.hostname or "").casefold()
        port = parsed.port
        default_port = (
            parsed.scheme.casefold() == "http" and port == 80
        ) or (
            parsed.scheme.casefold() == "https" and port == 443
        )
        if port and not default_port:
            hostname = f"{hostname}:{port}"
        return urllib.parse.urlunsplit((
            parsed.scheme.casefold(),
            hostname,
            parsed.path or "/",
            parsed.query,
            "",
        ))
    except ValueError:
        return value.strip()


def extract_cve_ids(value: Any) -> set[str]:
    return {
        f"CVE-{match.group(1)}-{match.group(2)}".upper()
        for match in _CVE_PATTERN.finditer(str(value or ""))
    }


def canonical_cve_id(value: str) -> str:
    matches = extract_cve_ids(value)
    return next(iter(matches), value.strip().upper())
