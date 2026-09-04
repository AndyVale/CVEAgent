from __future__ import annotations

import math
import os
import re
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from cve_agent.serialization import json_fingerprint
from cve_agent.strategy import ClassificationStrategy


_INTEGER_PATTERN = re.compile(r"^[+-]?\d+$")


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
    classification_strategy: ClassificationStrategy = ClassificationStrategy.AUTO
    pruning_confidence_threshold: float = 0.8


def load_settings(
    path: str | Path = "config.toml",
    *,
    relative_to: str | Path | None = None,
) -> Settings:
    config_path = Path(path).resolve()
    relative_path_base = Path(relative_to).resolve() if relative_to is not None else config_path.parent
    with config_path.open("rb") as handle:
        raw = tomllib.load(handle)
    runtime, nvd, web, storage, limits, classification = (
        raw.get(x, {}) for x in ("runtime", "nvd", "web", "storage", "limits", "classification")
    )
    try:
        classification_strategy = ClassificationStrategy(classification.get("strategy", ClassificationStrategy.AUTO.value))
    except ValueError as exc:
        raise ValueError(f"unsupported classification strategy: {classification.get('strategy')!r}") from exc
    settings = Settings(
        model=_text(runtime.get("model", "nvidia/nemotron-3-ultra-550b-a55b:free"), "runtime.model"),
        endpoint=_text(runtime.get("endpoint", "https://openrouter.ai/api/v1"), "runtime.endpoint"),
        api_key=os.getenv("API_KEY"),
        max_tokens=parse_integer(runtime.get("max_tokens", 2048), "runtime.max_tokens"),
        temperature=parse_finite_number(runtime.get("temperature", 0.0), "runtime.temperature"),
        top_p=parse_finite_number(runtime.get("top_p", 1.0), "runtime.top_p"),
        llm_timeout=parse_finite_number(runtime.get("timeout_seconds", 120), "runtime.timeout_seconds"),
        llm_retry_count=parse_integer(runtime.get("retry_count", 2), "runtime.retry_count"),
        llm_retry_wait=parse_finite_number(runtime.get("retry_wait_seconds", 1.0), "runtime.retry_wait_seconds"),
        llm_retry_max_wait=parse_finite_number(runtime.get("retry_max_wait_seconds", 8.0), "runtime.retry_max_wait_seconds"),
        llm_min_request_interval=parse_finite_number(runtime.get("min_request_interval_seconds", 0.0), "runtime.min_request_interval_seconds"),
        nvd_base_url=_text(nvd.get("base_url", "https://services.nvd.nist.gov/rest/json/cves/2.0"), "nvd.base_url"),
        nvd_timeout=parse_finite_number(nvd.get("timeout_seconds", 20), "nvd.timeout_seconds"),
        nvd_retry_count=parse_integer(nvd.get("retry_count", 2), "nvd.retry_count"),
        web_timeout=parse_finite_number(web.get("timeout_seconds", 20), "web.timeout_seconds"),
        web_retry_count=parse_integer(web.get("retry_count", 2), "web.retry_count"),
        web_provider=_text(web.get("provider", "tavily"), "web.provider"),
        tavily_base_url=_text(web.get("tavily_base_url", "https://api.tavily.com"), "web.tavily_base_url"),
        tavily_max_results=parse_integer(web.get("tavily_max_results", 5), "web.tavily_max_results"),
        tavily_search_depth=_text(web.get("tavily_search_depth", "basic"), "web.tavily_search_depth"),
        tavily_api_key=os.getenv("TAVILY_API_KEY"),
        cache_dir=_resolve_path(relative_path_base, web.get("cache_dir", ".cache/cve-agent/web")),
        max_document_chars=parse_integer(web.get("max_document_chars", 100000), "web.max_document_chars"),
        max_preview_chars=parse_integer(web.get("max_preview_chars", 12000), "web.max_preview_chars"),
        max_download_bytes=parse_integer(web.get("max_download_bytes", 2_000_000), "web.max_download_bytes"),
        database=_resolve_path(relative_path_base, storage.get("database", ".data/cve-agent.sqlite3")),
        token_budget=parse_integer(limits.get("token_budget", 12000), "limits.token_budget"),
        max_agent_turns=parse_integer(limits.get("max_agent_turns", 20), "limits.max_agent_turns"),
        max_search_calls=parse_integer(limits.get("max_search_calls", 5), "limits.max_search_calls"),
        max_fetch_calls=parse_integer(limits.get("max_fetch_calls", 8), "limits.max_fetch_calls"),
        max_investigation_seconds=parse_finite_number(limits.get("max_investigation_seconds", 300), "limits.max_investigation_seconds"),
        max_input_tokens_per_request=parse_integer(limits.get("max_input_tokens_per_request", 12000), "limits.max_input_tokens_per_request"),
        finalization_overrun_percent=parse_finite_number(limits.get("finalization_overrun_percent", 15.0), "limits.finalization_overrun_percent"),
        classification_strategy=classification_strategy,
        pruning_confidence_threshold=parse_finite_number(
            classification.get("pruning_confidence_threshold", 0.8),
            "classification.pruning_confidence_threshold",
        ),
    )
    validate_settings(settings)
    return settings


def _resolve_path(base: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base / path


def parse_integer(value: Any, name: str) -> int:
    """Parse an integer without silently truncating fractional values."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and _INTEGER_PATTERN.fullmatch(value.strip()):
        return int(value)
    raise ValueError(f"{name} must be an integer")


def parse_finite_number(value: Any, name: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a finite number")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a finite number") from exc
    if not math.isfinite(parsed):
        raise ValueError(f"{name} must be a finite number")
    return parsed


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def validate_settings(settings: Settings) -> None:
    """Validate an effective settings snapshot built by any presentation layer."""
    for name, value in (
        ("max_tokens", settings.max_tokens),
        ("llm_retry_count", settings.llm_retry_count),
        ("nvd_retry_count", settings.nvd_retry_count),
        ("web_retry_count", settings.web_retry_count),
        ("tavily_max_results", settings.tavily_max_results),
        ("max_document_chars", settings.max_document_chars),
        ("max_preview_chars", settings.max_preview_chars),
        ("max_download_bytes", settings.max_download_bytes),
        ("token_budget", settings.token_budget),
        ("max_agent_turns", settings.max_agent_turns),
        ("max_search_calls", settings.max_search_calls),
        ("max_fetch_calls", settings.max_fetch_calls),
        ("max_input_tokens_per_request", settings.max_input_tokens_per_request),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
    for name, value in (
        ("temperature", settings.temperature),
        ("top_p", settings.top_p),
        ("llm_timeout", settings.llm_timeout),
        ("llm_retry_wait", settings.llm_retry_wait),
        ("llm_retry_max_wait", settings.llm_retry_max_wait),
        ("llm_min_request_interval", settings.llm_min_request_interval),
        ("nvd_timeout", settings.nvd_timeout),
        ("web_timeout", settings.web_timeout),
        ("max_investigation_seconds", settings.max_investigation_seconds),
        ("finalization_overrun_percent", settings.finalization_overrun_percent),
        ("pruning_confidence_threshold", settings.pruning_confidence_threshold),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError(f"{name} must be a finite number")
    if not isinstance(settings.model, str) or not isinstance(settings.endpoint, str):
        raise ValueError("runtime model and endpoint must be strings")
    if not settings.model.strip() or not settings.endpoint.strip():
        raise ValueError("runtime model and endpoint must be non-empty")
    endpoints = [
        ("runtime endpoint", settings.endpoint),
        ("NVD endpoint", settings.nvd_base_url),
    ]
    if settings.web_provider == "tavily":
        endpoints.append(("Tavily endpoint", settings.tavily_base_url))
    for name, value in endpoints:
        if not isinstance(value, str):
            raise ValueError(f"{name} must be an HTTP(S) URL")
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"{name} must be an HTTP(S) URL")
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
    if settings.web_provider == "tavily" and (
        settings.tavily_max_results <= 0 or settings.tavily_search_depth not in {"basic", "advanced"}
    ):
        raise ValueError("invalid Tavily result limit or search depth")
    if settings.max_document_chars <= 0 or settings.max_preview_chars <= 0 or settings.max_download_bytes <= 0:
        raise ValueError("web content limits must be positive")
    if settings.max_preview_chars > settings.max_document_chars:
        raise ValueError("max_preview_chars cannot exceed max_document_chars")
    if settings.max_agent_turns <= 0 or min(settings.max_search_calls, settings.max_fetch_calls) < 0:
        raise ValueError("maximum turns must be positive; search and fetch limits must be non-negative")
    if settings.max_investigation_seconds <= 0:
        raise ValueError("maximum investigation duration must be positive")
    if not 0 <= settings.finalization_overrun_percent <= 100:
        raise ValueError("finalization_overrun_percent must be in [0, 100]")
    if not 0 <= settings.pruning_confidence_threshold <= 1:
        raise ValueError("pruning_confidence_threshold must be in [0, 1]")


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
        ("Classification", [
            ("Requested strategy", settings.classification_strategy.value),
            ("Pruning threshold", settings.pruning_confidence_threshold),
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


def non_secret_settings(settings: Settings | Mapping[str, Any]) -> dict[str, object]:
    values = asdict(settings) if isinstance(settings, Settings) else dict(settings)
    values.pop("api_key", None)
    values.pop("tavily_api_key", None)
    return {
        key: str(value) if isinstance(value, Path) else value
        for key, value in values.items()
        if not key.startswith("_")
    }


def settings_fingerprint(settings: Settings | Mapping[str, Any]) -> str:
    return json_fingerprint(non_secret_settings(settings))
