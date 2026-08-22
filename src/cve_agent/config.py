from __future__ import annotations

import os
import tomllib
from dataclasses import asdict, dataclass
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
    llm_retry_count: int
    llm_retry_wait: float
    llm_retry_max_wait: float
    llm_min_request_interval: float
    nvd_base_url: str
    nvd_timeout: float
    nvd_retry_count: int
    web_timeout: float
    web_retry_count: int
    web_provider: str
    tavily_base_url: str
    tavily_max_results: int
    tavily_search_depth: str
    tavily_api_key: str | None
    cache_dir: Path
    max_document_chars: int
    max_preview_chars: int
    max_download_bytes: int
    database: Path
    token_budget: int
    max_agent_turns: int
    max_search_calls: int
    max_fetch_calls: int
    max_investigation_seconds: float
    max_input_tokens_per_request: int = 12000
    finalization_overrun_percent: float = 15.0


def load_settings(path: str | Path = "config.toml") -> Settings:
    config_path = Path(path).resolve()
    with config_path.open("rb") as handle:
        raw = tomllib.load(handle)
    runtime, nvd, web, storage, limits = (raw.get(x, {}) for x in ("runtime", "nvd", "web", "storage", "limits"))
    settings = Settings(
        model=runtime.get("model", "nvidia/nemotron-3-ultra-550b-a55b:free"), endpoint=runtime.get("endpoint", "https://openrouter.ai/api/v1"),
        api_key=os.getenv("API_KEY"), max_tokens=int(runtime.get("max_tokens", 2048)),
        temperature=float(runtime.get("temperature", 0.0)), top_p=float(runtime.get("top_p", 1.0)),
        llm_timeout=float(runtime.get("timeout_seconds", 120)),
        llm_retry_count=int(runtime.get("retry_count", 2)),
        llm_retry_wait=float(runtime.get("retry_wait_seconds", 1.0)),
        llm_retry_max_wait=float(runtime.get("retry_max_wait_seconds", 8.0)),
        llm_min_request_interval=float(runtime.get("min_request_interval_seconds", 0.0)),
        nvd_base_url=nvd.get("base_url", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
        nvd_timeout=float(nvd.get("timeout_seconds", 20)), nvd_retry_count=int(nvd.get("retry_count", 2)), web_timeout=float(web.get("timeout_seconds", 20)),
        web_retry_count=int(web.get("retry_count", 2)),
        web_provider=str(web.get("provider", "tavily")), tavily_base_url=str(web.get("tavily_base_url", "https://api.tavily.com")),
        tavily_max_results=int(web.get("tavily_max_results", 5)), tavily_search_depth=str(web.get("tavily_search_depth", "basic")),
        tavily_api_key=os.getenv("TAVILY_API_KEY"),
        cache_dir=_resolve_path(config_path.parent, web.get("cache_dir", ".cache/cve-agent/web")),
        max_document_chars=int(web.get("max_document_chars", 100000)), max_preview_chars=int(web.get("max_preview_chars", 12000)),
        max_download_bytes=int(web.get("max_download_bytes", 2_000_000)),
        database=_resolve_path(config_path.parent, storage.get("database", ".data/cve-agent.sqlite3")), token_budget=int(limits.get("token_budget", 12000)),
        max_agent_turns=int(limits.get("max_agent_turns", 20)), max_search_calls=int(limits.get("max_search_calls", 5)),
        max_fetch_calls=int(limits.get("max_fetch_calls", 8)), max_investigation_seconds=float(limits.get("max_investigation_seconds", 300)),
        max_input_tokens_per_request=int(limits.get("max_input_tokens_per_request", 12000)),
        finalization_overrun_percent=float(limits.get("finalization_overrun_percent", 15.0)),
    )
    _validate_settings(settings)
    return settings


def _resolve_path(base: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base / path


def _validate_settings(settings: Settings) -> None:
    if not settings.model.strip() or not settings.endpoint.strip():
        raise ValueError("runtime model and endpoint must be non-empty")
    if settings.max_tokens <= 0 or settings.max_input_tokens_per_request <= 0 or settings.token_budget <= 0:
        raise ValueError("token limits must be positive")
    if not 0 <= settings.temperature <= 2 or not 0 < settings.top_p <= 1:
        raise ValueError("temperature must be in [0, 2] and top_p in (0, 1]")
    if settings.llm_timeout <= 0 or settings.nvd_timeout <= 0 or settings.web_timeout <= 0:
        raise ValueError("timeouts must be positive")
    if min(settings.llm_retry_count, settings.nvd_retry_count, settings.web_retry_count) < 0:
        raise ValueError("retry counts must be non-negative")
    if min(settings.llm_retry_wait, settings.llm_retry_max_wait, settings.llm_min_request_interval) < 0:
        raise ValueError("LLM wait settings must be non-negative")
    if settings.llm_retry_max_wait < settings.llm_retry_wait:
        raise ValueError("retry_max_wait_seconds must be at least retry_wait_seconds")
    if settings.web_provider not in {"tavily", "none"}:
        raise ValueError(f"unsupported web provider: {settings.web_provider!r}")
    if settings.tavily_max_results <= 0 or settings.tavily_search_depth not in {"basic", "advanced"}:
        raise ValueError("invalid Tavily result limit or search depth")
    if settings.max_document_chars <= 0 or settings.max_preview_chars <= 0 or settings.max_download_bytes <= 0:
        raise ValueError("web content limits must be positive")
    if settings.max_preview_chars > settings.max_document_chars:
        raise ValueError("max_preview_chars cannot exceed max_document_chars")
    if min(settings.max_agent_turns, settings.max_search_calls, settings.max_fetch_calls) < 0 or settings.max_investigation_seconds <= 0:
        raise ValueError("investigation limits must be non-negative and duration must be positive")
    if not 0 <= settings.finalization_overrun_percent <= 100:
        raise ValueError("finalization_overrun_percent must be in [0, 100]")


def format_settings_table(settings: Settings) -> str:
    """Format the effective non-secret settings as a compact grouped table."""
    groups = [
        ("LLM", [
            ("Model", settings.model),
            ("Endpoint", settings.endpoint),
            ("Max tokens", settings.max_tokens),
            ("Temperature / top-p", f"{settings.temperature} / {settings.top_p}"),
            ("Timeout", f"{settings.llm_timeout}s"),
            ("Retries", settings.llm_retry_count),
            ("Retry backoff", f"{settings.llm_retry_wait}s to {settings.llm_retry_max_wait}s"),
            ("Min request interval", f"{settings.llm_min_request_interval}s"),
            ("API key", "configured" if settings.api_key else "not configured"),
        ]),
        ("Investigation limits", [
            ("Token budget", settings.token_budget),
            ("Max input tokens/request", settings.max_input_tokens_per_request),
            ("Finalization overrun", f"{settings.finalization_overrun_percent}%"),
            ("Max turns", settings.max_agent_turns),
            ("Max searches / fetches", f"{settings.max_search_calls} / {settings.max_fetch_calls}"),
            ("Max duration", f"{settings.max_investigation_seconds}s"),
        ]),
        ("Data sources", [
            ("NVD", settings.nvd_base_url),
            ("Web provider", settings.web_provider),
            ("Tavily endpoint", settings.tavily_base_url),
            ("Tavily API key", "configured" if settings.tavily_api_key else "not configured"),
            ("NVD timeout / retries", f"{settings.nvd_timeout}s / {settings.nvd_retry_count}"),
            ("Web timeout / retries", f"{settings.web_timeout}s / {settings.web_retry_count}"),
        ]),
        ("Storage", [
            ("Database", settings.database),
            ("Web cache", settings.cache_dir),
            ("Document / preview chars", f"{settings.max_document_chars} / {settings.max_preview_chars}"),
            ("Max download bytes", settings.max_download_bytes),
        ]),
    ]
    label_width = max(len(label) for _, rows in groups for label, _ in rows)
    lines = ["effective configuration"]
    for title, rows in groups:
        lines.extend(["", f"[{title}]"])
        lines.append(f"  {'Setting':<{label_width}}  Value")
        lines.append(f"  {'-' * label_width}  {'-' * 32}")
        lines.extend(f"  {label:<{label_width}}  {value}" for label, value in rows)
    return "\n".join(lines)


def non_secret_settings(settings: Settings) -> dict[str, object]:
    values = asdict(settings)
    values.pop("api_key", None)
    values.pop("tavily_api_key", None)
    return {key: str(value) if isinstance(value, Path) else value for key, value in values.items()}
