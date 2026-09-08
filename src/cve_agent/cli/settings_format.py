from __future__ import annotations

from cve_agent.core.config import Settings


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
