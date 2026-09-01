from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Serialize JSON data deterministically for storage identities."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def json_fingerprint(value: Any) -> str:
    """Return the SHA-256 identity of a canonical JSON value."""
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()
