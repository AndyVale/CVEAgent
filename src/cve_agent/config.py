from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    model: str
    endpoint: str
    api_key: str | None
    max_tokens: int
    temperature: float
    top_p: float
    llm_timeout: float
    enable_thinking: bool
    nvd_base_url: str
    nvd_timeout: float
    retry_count: int
    web_timeout: float
    cache_dir: Path
    database: Path
    token_budget: int


def load_settings(path: str | Path = "config.toml") -> Settings:
    with Path(path).open("rb") as handle:
        raw = tomllib.load(handle)
    runtime, nvd, web, storage, limits = (raw.get(x, {}) for x in ("runtime", "nvd", "web", "storage", "limits"))
    return Settings(
        model=runtime.get("model", "Qwen/Qwen3-8B"), endpoint=runtime.get("endpoint", "http://localhost:8000/v1"),
        api_key=os.getenv("VLLM_API_KEY"), max_tokens=int(runtime.get("max_tokens", 2048)),
        temperature=float(runtime.get("temperature", 0.0)), top_p=float(runtime.get("top_p", 1.0)),
        llm_timeout=float(runtime.get("timeout_seconds", 120)),
        enable_thinking=bool(runtime.get("enable_thinking", False)),
        nvd_base_url=nvd.get("base_url", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
        nvd_timeout=float(nvd.get("timeout_seconds", 20)), retry_count=int(nvd.get("retry_count", 2)), web_timeout=float(web.get("timeout_seconds", 20)),
        cache_dir=Path(web.get("cache_dir", ".cache/cve-agent/web")), database=Path(storage.get("database", ".data/cve-agent.sqlite3")),
        token_budget=int(limits.get("token_budget", 12000)),
    )
