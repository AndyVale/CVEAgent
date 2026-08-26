from __future__ import annotations

import json
import threading
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

from cve_agent.config import Settings, load_settings, validate_settings
from cve_agent.strategy import ClassificationStrategy


class GuiConfigurationError(ValueError):
    """Raised when GUI-owned configuration is invalid."""


@dataclass(frozen=True)
class SettingField:
    name: str
    label: str
    group: str
    kind: str
    choices: tuple[str, ...] = ()
    step: str | None = None


CHAT_SETTING_FIELDS = (
    SettingField("model", "Model", "LLM", "text"),
    SettingField("endpoint", "Endpoint", "LLM", "url"),
    SettingField("max_tokens", "Max completion tokens", "LLM", "integer"),
    SettingField("temperature", "Temperature", "LLM", "number", step="0.1"),
    SettingField("top_p", "Top-p", "LLM", "number", step="0.1"),
    SettingField("llm_timeout", "Timeout (seconds)", "LLM", "number", step="0.1"),
    SettingField("llm_retry_count", "Retry count", "LLM", "integer"),
    SettingField("llm_retry_wait", "Initial retry wait", "LLM", "number", step="0.1"),
    SettingField("llm_retry_max_wait", "Maximum retry wait", "LLM", "number", step="0.1"),
    SettingField("llm_min_request_interval", "Minimum request interval", "LLM", "number", step="0.1"),
    SettingField("token_budget", "Token budget", "Investigation", "integer"),
    SettingField("max_input_tokens_per_request", "Maximum input tokens/request", "Investigation", "integer"),
    SettingField("finalization_overrun_percent", "Finalization overrun (%)", "Investigation", "number", step="0.1"),
    SettingField("max_agent_turns", "Maximum turns", "Investigation", "integer"),
    SettingField("max_search_calls", "Maximum searches", "Investigation", "integer"),
    SettingField("max_fetch_calls", "Maximum fetches", "Investigation", "integer"),
    SettingField("max_investigation_seconds", "Maximum duration (seconds)", "Investigation", "number", step="1"),
    SettingField("classification_strategy", "Strategy", "Classification", "select", ("auto", "hybrid", "exhaustive")),
    SettingField("pruning_confidence_threshold", "Pruning threshold", "Classification", "number", step="0.05"),
    SettingField("nvd_base_url", "NVD endpoint", "Data sources", "url"),
    SettingField("nvd_timeout", "NVD timeout", "Data sources", "number", step="0.1"),
    SettingField("nvd_retry_count", "NVD retries", "Data sources", "integer"),
    SettingField("web_provider", "Web provider", "Data sources", "select", ("tavily", "none")),
    SettingField("tavily_base_url", "Tavily endpoint", "Data sources", "url"),
    SettingField("tavily_max_results", "Search result limit", "Data sources", "integer"),
    SettingField("tavily_search_depth", "Search depth", "Data sources", "select", ("basic", "advanced")),
    SettingField("web_timeout", "Web timeout", "Data sources", "number", step="0.1"),
    SettingField("web_retry_count", "Web retries", "Data sources", "integer"),
    SettingField("cache_dir", "Web cache directory", "Content limits", "path"),
    SettingField("max_document_chars", "Maximum document characters", "Content limits", "integer"),
    SettingField("max_preview_chars", "Maximum preview characters", "Content limits", "integer"),
    SettingField("max_download_bytes", "Maximum download bytes", "Content limits", "integer"),
)

_FIELDS_BY_NAME = {field.name: field for field in CHAT_SETTING_FIELDS}


@dataclass(frozen=True)
class GlobalGuiSettings:
    database_path: Path
    default_config_path: Path
    default_taxonomy_path: Path

    def to_dict(self) -> dict[str, str]:
        return {
            "database_path": str(self.database_path),
            "default_config_path": str(self.default_config_path),
            "default_taxonomy_path": str(self.default_taxonomy_path),
        }


class GlobalSettingsStore:
    """Persist machine-local GUI defaults outside classification run snapshots."""

    def __init__(self, path: str | Path, fallback: GlobalGuiSettings):
        self.path = Path(path).resolve()
        self.fallback = fallback
        self._lock = threading.RLock()
        self._settings = self._load()

    def get(self) -> GlobalGuiSettings:
        with self._lock:
            return self._settings

    def update(self, raw: dict[str, Any]) -> GlobalGuiSettings:
        with self._lock:
            candidate = self.validate(raw)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(self.path.suffix + ".tmp")
            temporary.write_text(json.dumps(candidate.to_dict(), indent=2), encoding="utf-8")
            temporary.replace(self.path)
            self._settings = candidate
            return candidate

    def validate(self, raw: dict[str, Any]) -> GlobalGuiSettings:
        try:
            candidate = GlobalGuiSettings(
                database_path=_absolute_path(raw["database_path"]),
                default_config_path=_absolute_path(raw["default_config_path"]),
                default_taxonomy_path=_absolute_path(raw["default_taxonomy_path"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GuiConfigurationError("global settings require database, config, and taxonomy paths") from exc
        if not candidate.default_config_path.is_file():
            raise GuiConfigurationError(f"configuration file does not exist: {candidate.default_config_path}")
        if not candidate.default_taxonomy_path.is_file():
            raise GuiConfigurationError(f"taxonomy file does not exist: {candidate.default_taxonomy_path}")
        try:
            load_settings(candidate.default_config_path)
        except (OSError, ValueError) as exc:
            raise GuiConfigurationError(str(exc)) from exc
        return candidate

    def _load(self) -> GlobalGuiSettings:
        if not self.path.exists():
            return self.fallback
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            return GlobalGuiSettings(
                database_path=_absolute_path(raw["database_path"]),
                default_config_path=_absolute_path(raw["default_config_path"]),
                default_taxonomy_path=_absolute_path(raw["default_taxonomy_path"]),
            )
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return self.fallback


def apply_chat_overrides(
    base: Settings,
    raw: dict[str, Any],
    *,
    config_directory: Path,
    database_path: Path,
) -> Settings:
    if not isinstance(raw, dict):
        raise GuiConfigurationError("chat configuration values must be an object")
    unknown = sorted(set(raw) - set(_FIELDS_BY_NAME))
    if unknown:
        raise GuiConfigurationError(f"unknown chat configuration fields: {unknown}")
    converted: dict[str, Any] = {}
    for name, value in raw.items():
        converted[name] = _convert_value(_FIELDS_BY_NAME[name], value, config_directory)
    candidate = replace(base, **converted, database=database_path.resolve())
    try:
        validate_settings(candidate)
    except ValueError as exc:
        raise GuiConfigurationError(str(exc)) from exc
    return candidate


def settings_values(settings: Settings) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field in CHAT_SETTING_FIELDS:
        value = getattr(settings, field.name)
        if isinstance(value, (Path, StrEnum)):
            value = str(value)
        result[field.name] = value
    return result


def public_configuration(
    *,
    settings: Settings | dict[str, Any],
    taxonomy_path: str | Path | None,
    taxonomy_name: str,
    taxonomy_fingerprint: str,
    taxonomy_labels: int | None,
    hierarchy_policy: str | None,
    config_path: str | Path | None,
) -> dict[str, Any]:
    values = settings_values(settings) if isinstance(settings, Settings) else {
        field.name: settings.get(field.name)
        for field in CHAT_SETTING_FIELDS
        if field.name in settings
    }
    groups: list[dict[str, Any]] = []
    for group_name in dict.fromkeys(field.group for field in CHAT_SETTING_FIELDS):
        fields = []
        for field in CHAT_SETTING_FIELDS:
            if field.group != group_name or field.name not in values:
                continue
            fields.append({
                "name": field.name,
                "label": field.label,
                "kind": field.kind,
                "choices": list(field.choices),
                "step": field.step,
                "value": values[field.name],
            })
        groups.append({"name": group_name, "fields": fields})
    return {
        "taxonomy": {
            "name": taxonomy_name,
            "path": str(taxonomy_path) if taxonomy_path else None,
            "fingerprint": taxonomy_fingerprint,
            "labels": taxonomy_labels,
            "hierarchy_policy": hierarchy_policy,
        },
        "config_path": str(config_path) if config_path else None,
        "values": values,
        "groups": groups,
    }


def taxonomy_display_name(path: str | Path) -> str:
    taxonomy_path = Path(path)
    try:
        raw = json.loads(taxonomy_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return taxonomy_path.stem
    name = raw.get("name") if isinstance(raw, dict) else None
    return name.strip() if isinstance(name, str) and name.strip() else taxonomy_path.stem


def _convert_value(field: SettingField, value: Any, base: Path) -> Any:
    try:
        if field.kind == "integer":
            if isinstance(value, bool):
                raise ValueError
            return int(value)
        if field.kind == "number":
            if isinstance(value, bool):
                raise ValueError
            return float(value)
        if field.kind == "path":
            path = Path(str(value)).expanduser()
            return path.resolve() if path.is_absolute() else (base / path).resolve()
        if field.name == "classification_strategy":
            return ClassificationStrategy(str(value))
        text = str(value).strip()
        if not text:
            raise ValueError
        if field.choices and text not in field.choices:
            raise ValueError
        return text
    except (TypeError, ValueError) as exc:
        raise GuiConfigurationError(f"invalid value for {field.label}: {value!r}") from exc


def _absolute_path(value: Any) -> Path:
    if not isinstance(value, (str, Path)) or not str(value).strip():
        raise ValueError("path must be non-empty")
    return Path(value).expanduser().resolve()
