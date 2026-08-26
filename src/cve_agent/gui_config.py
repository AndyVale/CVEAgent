from __future__ import annotations

import json
import os
import shutil
import stat
import threading
import tomllib
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from tomlkit import dumps as dump_toml
from tomlkit import parse as parse_toml
from tomlkit import table as toml_table
from tomlkit.exceptions import ParseError

from cve_agent.config import Settings, load_settings, validate_settings
from cve_agent.gui_paths import GuiPathError, GuiPathPolicy
from cve_agent.strategy import ClassificationStrategy


GUI_CONFIG_FILENAME = "config.gui.toml"


class GuiConfigurationError(GuiPathError):
    """Raised when GUI-owned configuration is invalid."""


@dataclass(frozen=True)
class SettingField:
    name: str
    label: str
    group: str
    kind: str
    choices: tuple[str, ...] = ()
    step: str | None = None
    minimum: int | float | None = None
    maximum: int | float | None = None
    exclusive_minimum: bool = False
    hierarchical_only: bool = False
    depends_on: str | None = None
    depends_values: tuple[str, ...] = ()


CHAT_SETTING_FIELDS = (
    SettingField("model", "Model", "LLM", "text"),
    SettingField("endpoint", "Endpoint", "LLM", "url"),
    SettingField("max_tokens", "Max completion tokens", "LLM", "integer", minimum=1),
    SettingField("temperature", "Temperature", "LLM", "number", step="0.1", minimum=0, maximum=2),
    SettingField("top_p", "Top-p", "LLM", "number", step="0.1", minimum=0, maximum=1, exclusive_minimum=True),
    SettingField("llm_timeout", "Timeout (seconds)", "LLM", "number", step="0.1", minimum=0, exclusive_minimum=True),
    SettingField("llm_retry_count", "Retry count", "LLM", "integer", minimum=0),
    SettingField("llm_retry_wait", "Initial retry wait", "LLM", "number", step="0.1", minimum=0),
    SettingField("llm_retry_max_wait", "Maximum retry wait", "LLM", "number", step="0.1", minimum=0),
    SettingField("llm_min_request_interval", "Minimum request interval", "LLM", "number", step="0.1", minimum=0),
    SettingField("token_budget", "Token budget", "Investigation", "integer", minimum=1),
    SettingField("max_input_tokens_per_request", "Maximum input tokens/request", "Investigation", "integer", minimum=1),
    SettingField("finalization_overrun_percent", "Finalization overrun (%)", "Investigation", "number", step="0.1", minimum=0, maximum=100),
    SettingField("max_agent_turns", "Maximum turns", "Investigation", "integer", minimum=1),
    SettingField("max_search_calls", "Maximum searches", "Investigation", "integer", minimum=0, depends_on="web_provider", depends_values=("tavily",)),
    SettingField("max_fetch_calls", "Maximum fetches", "Investigation", "integer", minimum=0, depends_on="web_provider", depends_values=("tavily",)),
    SettingField("max_investigation_seconds", "Maximum duration (seconds)", "Investigation", "number", step="1", minimum=0, exclusive_minimum=True),
    SettingField("classification_strategy", "Strategy", "Classification", "select", ("auto", "hybrid", "exhaustive"), hierarchical_only=True),
    SettingField("pruning_confidence_threshold", "Pruning threshold", "Classification", "number", step="0.05", minimum=0, maximum=1, hierarchical_only=True, depends_on="classification_strategy", depends_values=("auto", "hybrid")),
    SettingField("nvd_base_url", "NVD endpoint", "Data sources", "url"),
    SettingField("nvd_timeout", "NVD timeout", "Data sources", "number", step="0.1", minimum=0, exclusive_minimum=True),
    SettingField("nvd_retry_count", "NVD retries", "Data sources", "integer", minimum=0),
    SettingField("web_provider", "Web provider", "Data sources", "select", ("tavily", "none")),
    SettingField("tavily_base_url", "Tavily endpoint", "Data sources", "url", depends_on="web_provider", depends_values=("tavily",)),
    SettingField("tavily_max_results", "Search result limit", "Data sources", "integer", minimum=1, depends_on="web_provider", depends_values=("tavily",)),
    SettingField("tavily_search_depth", "Search depth", "Data sources", "select", ("basic", "advanced"), depends_on="web_provider", depends_values=("tavily",)),
    SettingField("web_timeout", "Web timeout", "Data sources", "number", step="0.1", minimum=0, exclusive_minimum=True, depends_on="web_provider", depends_values=("tavily",)),
    SettingField("web_retry_count", "Web retries", "Data sources", "integer", minimum=0, depends_on="web_provider", depends_values=("tavily",)),
    SettingField("max_document_chars", "Maximum document characters", "Content limits", "integer", minimum=1, depends_on="web_provider", depends_values=("tavily",)),
    SettingField("max_preview_chars", "Maximum preview characters", "Content limits", "integer", minimum=1, depends_on="web_provider", depends_values=("tavily",)),
    SettingField("max_download_bytes", "Maximum download bytes", "Content limits", "integer", minimum=1, depends_on="web_provider", depends_values=("tavily",)),
)

_FIELDS_BY_NAME = {field.name: field for field in CHAT_SETTING_FIELDS}

_TOML_LOCATIONS = {
    "model": ("runtime", "model"),
    "endpoint": ("runtime", "endpoint"),
    "max_tokens": ("runtime", "max_tokens"),
    "temperature": ("runtime", "temperature"),
    "top_p": ("runtime", "top_p"),
    "llm_timeout": ("runtime", "timeout_seconds"),
    "llm_retry_count": ("runtime", "retry_count"),
    "llm_retry_wait": ("runtime", "retry_wait_seconds"),
    "llm_retry_max_wait": ("runtime", "retry_max_wait_seconds"),
    "llm_min_request_interval": ("runtime", "min_request_interval_seconds"),
    "nvd_base_url": ("nvd", "base_url"),
    "nvd_timeout": ("nvd", "timeout_seconds"),
    "nvd_retry_count": ("nvd", "retry_count"),
    "web_provider": ("web", "provider"),
    "tavily_base_url": ("web", "tavily_base_url"),
    "tavily_max_results": ("web", "tavily_max_results"),
    "tavily_search_depth": ("web", "tavily_search_depth"),
    "web_timeout": ("web", "timeout_seconds"),
    "web_retry_count": ("web", "retry_count"),
    "max_document_chars": ("web", "max_document_chars"),
    "max_preview_chars": ("web", "max_preview_chars"),
    "max_download_bytes": ("web", "max_download_bytes"),
    "token_budget": ("limits", "token_budget"),
    "max_agent_turns": ("limits", "max_agent_turns"),
    "max_search_calls": ("limits", "max_search_calls"),
    "max_fetch_calls": ("limits", "max_fetch_calls"),
    "max_investigation_seconds": ("limits", "max_investigation_seconds"),
    "max_input_tokens_per_request": ("limits", "max_input_tokens_per_request"),
    "finalization_overrun_percent": ("limits", "finalization_overrun_percent"),
    "classification_strategy": ("classification", "strategy"),
    "pruning_confidence_threshold": ("classification", "pruning_confidence_threshold"),
}


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

    def __init__(
        self,
        path: str | Path,
        fallback: GlobalGuiSettings,
        path_policy: GuiPathPolicy,
    ):
        self.path_policy = path_policy
        self.path = path_policy.state_file(path)
        self._lock = threading.RLock()
        self.fallback = self.validate(fallback.to_dict())
        self._settings = self._load()

    def get(self) -> GlobalGuiSettings:
        with self._lock:
            return self._settings

    def update(self, raw: dict[str, Any]) -> GlobalGuiSettings:
        with self._lock:
            candidate = self.validate(raw)
            temporary_path: Path | None = None
            try:
                with NamedTemporaryFile(
                    "w",
                    encoding="utf-8",
                    dir=self.path.parent,
                    prefix=f".{self.path.name}.",
                    suffix=".tmp",
                    delete=False,
                ) as temporary:
                    json.dump(candidate.to_dict(), temporary, indent=2)
                    temporary.write("\n")
                    temporary.flush()
                    os.fsync(temporary.fileno())
                    temporary_path = Path(temporary.name)
                temporary_path.replace(self.path)
                temporary_path = None
            except OSError as exc:
                raise GuiConfigurationError(f"could not update GUI state: {exc}") from exc
            finally:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)
            self._settings = candidate
            return candidate

    def validate(self, raw: dict[str, Any]) -> GlobalGuiSettings:
        if not isinstance(raw, dict):
            raise GuiConfigurationError("global settings must be an object")
        unknown = sorted(
            set(raw) - {"database_path", "default_config_path", "default_taxonomy_path"}
        )
        if unknown:
            raise GuiConfigurationError(f"unknown global setting fields: {unknown}")
        try:
            candidate = GlobalGuiSettings(
                database_path=self.path_policy.database_file(raw["database_path"]),
                default_config_path=self.path_policy.configuration_file(raw["default_config_path"]),
                default_taxonomy_path=self.path_policy.taxonomy_file(raw["default_taxonomy_path"]),
            )
        except KeyError as exc:
            raise GuiConfigurationError("global settings require database, config, and taxonomy paths") from exc
        except GuiPathError as exc:
            raise GuiConfigurationError(str(exc)) from exc
        try:
            loaded = load_settings(candidate.default_config_path)
            self.path_policy.database_file(loaded.database)
            self.path_policy.cache_directory(loaded.cache_dir)
        except (OSError, ValueError, GuiPathError) as exc:
            raise GuiConfigurationError(str(exc)) from exc
        return candidate

    def _load(self) -> GlobalGuiSettings:
        if not self.path.exists():
            return self.fallback
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            return self.validate(raw)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return self.fallback


def ensure_gui_config(source: str | Path, path_policy: GuiPathPolicy) -> Path:
    """Create the GUI-owned TOML beside a source configuration without changing the source."""
    source_path = path_policy.configuration_file(source, must_exist=False)
    target_path = path_policy.configuration_file(
        source_path if source_path.name == GUI_CONFIG_FILENAME else source_path.with_name(GUI_CONFIG_FILENAME),
        must_exist=False,
    )
    if target_path.is_file():
        return target_path
    path_policy.configuration_file(source_path)
    try:
        shutil.copy2(source_path, target_path)
    except OSError as exc:
        raise GuiConfigurationError(f"could not create GUI configuration {target_path}: {exc}") from exc
    return target_path


def apply_chat_overrides(
    base: Settings,
    raw: dict[str, Any],
    *,
    database_path: Path,
    path_policy: GuiPathPolicy,
) -> Settings:
    if not isinstance(raw, dict):
        raise GuiConfigurationError("chat configuration values must be an object")
    unknown = sorted(set(raw) - set(_FIELDS_BY_NAME))
    if unknown:
        raise GuiConfigurationError(f"unknown chat configuration fields: {unknown}")
    converted: dict[str, Any] = {}
    for name, value in raw.items():
        converted[name] = _convert_value(_FIELDS_BY_NAME[name], value, path_policy)
    candidate = replace(base, **converted, database=path_policy.database_file(database_path))
    try:
        validate_settings(candidate)
        path_policy.cache_directory(candidate.cache_dir)
    except (ValueError, GuiPathError) as exc:
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
    taxonomy_hierarchical: bool | None,
    hierarchy_policy: str | None,
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
            public_field = {
                "name": field.name,
                "label": field.label,
                "kind": field.kind,
                "choices": list(field.choices),
                "step": field.step,
                "value": values[field.name],
            }
            if field.minimum is not None:
                public_field["minimum"] = field.minimum
            if field.maximum is not None:
                public_field["maximum"] = field.maximum
            if field.exclusive_minimum:
                public_field["exclusive_minimum"] = True
            if field.hierarchical_only:
                public_field["hierarchical_only"] = True
            if field.depends_on:
                public_field["depends_on"] = field.depends_on
                public_field["depends_values"] = list(field.depends_values)
            fields.append(public_field)
        groups.append({"name": group_name, "fields": fields})
    return {
        "taxonomy": {
            "name": taxonomy_name,
            "path": str(taxonomy_path) if taxonomy_path else None,
            "fingerprint": taxonomy_fingerprint,
            "labels": taxonomy_labels,
            "hierarchical": taxonomy_hierarchical,
            "hierarchy_policy": hierarchy_policy,
        },
        "values": values,
        "groups": groups,
    }


def write_gui_settings(path: str | Path, settings: Settings, path_policy: GuiPathPolicy) -> None:
    """Atomically persist validated GUI-editable values while preserving unrelated TOML content."""
    config_path = path_policy.gui_configuration_file(path)
    path_policy.database_file(settings.database)
    path_policy.cache_directory(settings.cache_dir)
    temporary_path: Path | None = None
    try:
        document = parse_toml(config_path.read_text(encoding="utf-8"))
        for field in CHAT_SETTING_FIELDS:
            section_name, key = _TOML_LOCATIONS[field.name]
            if section_name not in document:
                document[section_name] = toml_table()
            section = document[section_name]
            if not isinstance(section, dict):
                raise GuiConfigurationError(f"TOML section [{section_name}] must be a table")
            value = getattr(settings, field.name)
            if isinstance(value, Path):
                value = str(value.relative_to(path_policy.project_root))
            elif isinstance(value, StrEnum):
                value = str(value)
            section[key] = value
        serialized = dump_toml(document)
        tomllib.loads(serialized)
        with NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=config_path.parent,
            prefix=f".{config_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(serialized)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        temporary_path.chmod(stat.S_IMODE(config_path.stat().st_mode))
        temporary_path.replace(config_path)
        temporary_path = None
    except GuiConfigurationError:
        raise
    except (OSError, ParseError, tomllib.TOMLDecodeError, TypeError, ValueError) as exc:
        raise GuiConfigurationError(f"could not update GUI configuration {config_path}: {exc}") from exc
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def taxonomy_display_name(path: str | Path) -> str:
    taxonomy_path = Path(path)
    try:
        raw = json.loads(taxonomy_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return taxonomy_path.stem
    name = raw.get("name") if isinstance(raw, dict) else None
    return name.strip() if isinstance(name, str) and name.strip() else taxonomy_path.stem


def _convert_value(field: SettingField, value: Any, path_policy: GuiPathPolicy) -> Any:
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
            return path_policy.cache_directory(value)
        if field.name == "classification_strategy":
            return ClassificationStrategy(str(value))
        text = str(value).strip()
        if not text:
            raise ValueError
        if field.choices and text not in field.choices:
            raise ValueError
        return text
    except GuiPathError as exc:
        raise GuiConfigurationError(str(exc)) from exc
    except (TypeError, ValueError) as exc:
        raise GuiConfigurationError(f"invalid value for {field.label}: {value!r}") from exc
