from __future__ import annotations

import httpx


class HttpClientSession:
    """Manage an optional shared client while leaving injected clients caller-owned."""

    def __init__(
        self,
        timeout: float,
        client: httpx.Client | None = None,
        *,
        trust_env: bool = True,
        keepalive: bool = True,
    ):
        self.timeout = timeout
        self._injected = client
        self._owned: httpx.Client | None = None
        self._trust_env = trust_env
        self._keepalive = keepalive

    def get(self) -> httpx.Client:
        if self._injected is not None:
            return self._injected
        if self._owned is None:
            connection_options = {} if self._keepalive else {
                "limits": httpx.Limits(max_keepalive_connections=0),
            }
            self._owned = httpx.Client(
                timeout=self.timeout,
                headers={"User-Agent": "cve-agent/0.1"},
                trust_env=self._trust_env,
                **connection_options,
            )
        # Do not carry website cookies into another request or redirect hop.
        self._owned.cookies.clear()
        return self._owned

    def close(self) -> None:
        if self._owned is not None:
            client, self._owned = self._owned, None
            client.close()
