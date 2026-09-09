from __future__ import annotations

import httpx


class HttpClientSession:
    """Reuse connections while keeping injected clients under caller ownership."""

    def __init__(self, timeout: float, client: httpx.Client | None = None):
        self.timeout = timeout
        self._injected = client
        self._owned: httpx.Client | None = None

    def get(self) -> httpx.Client:
        if self._injected is not None:
            return self._injected
        if self._owned is None:
            self._owned = httpx.Client(timeout=self.timeout, headers={"User-Agent": "cve-agent/0.1"})
        # Previously each logical request had a fresh cookie jar. Reuse the
        # connections without carrying website cookies into another request.
        self._owned.cookies.clear()
        return self._owned

    def close(self) -> None:
        if self._owned is not None:
            client, self._owned = self._owned, None
            client.close()
