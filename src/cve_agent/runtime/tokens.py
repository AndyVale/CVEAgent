from __future__ import annotations

import json


def estimate_tokens(value: object) -> int:
    """Return a conservative provider-neutral token estimate."""
    serialized = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return max(1, (len(serialized) + 2) // 3)
