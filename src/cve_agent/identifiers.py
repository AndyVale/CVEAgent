from __future__ import annotations

import re
from typing import Any


_CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,12}$", re.IGNORECASE)


class CVEIdentifierError(ValueError):
    """Raised when a CVE identifier violates the public input contract."""


def normalize_cve_id(value: Any) -> str:
    if not isinstance(value, str) or not _CVE_ID_PATTERN.fullmatch(value.strip()):
        raise CVEIdentifierError("enter a CVE ID such as CVE-2021-44228")
    return value.strip().upper()
