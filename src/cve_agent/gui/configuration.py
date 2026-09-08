from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from cve_agent.application.factory import create_history_repository
from cve_agent.classification.taxonomy import is_hierarchical
from cve_agent.core.config import Settings, non_secret_settings, settings_fingerprint
from cve_agent.core.identifiers import CVEIdentifierError, normalize_cve_id as normalize_public_cve_id
from cve_agent.core.taxonomy import Taxonomy, load_taxonomy
from cve_agent.gui.config import (
    GlobalSettingsStore,
    GuiConfigurationError,
    apply_chat_overrides,
    load_gui_settings,
    public_configuration,
    write_gui_settings,
)
from cve_agent.gui.paths import GuiPathError


@dataclass(frozen=True)
class AnalysisConfiguration:
    settings: Settings
    taxonomy: Taxonomy
    taxonomy_path: Path
    taxonomy_name: str
    taxonomy_fingerprint: str
    settings_fingerprint: str

    def to_public_dict(self) -> dict[str, Any]:
        return public_configuration(
            settings=self.settings,
            taxonomy_path=self.taxonomy_path,
            taxonomy_name=self.taxonomy_name,
            taxonomy_fingerprint=self.taxonomy_fingerprint,
            taxonomy_labels=len(self.taxonomy.labels),
            taxonomy_hierarchical=is_hierarchical(self.taxonomy),
            hierarchy_policy=self.taxonomy.hierarchy_policy.value,
        )


def normalize_cve_id(value: Any) -> str:
    try:
        return normalize_public_cve_id(value)
    except CVEIdentifierError as exc:
        raise GuiConfigurationError("enter a CVE ID such as CVE-2021-44228") from exc


def _path_choices(paths: tuple[Path, ...], root: Path, prefix: str) -> list[dict[str, str]]:
    return [
        {
            "path": str(path),
            "value": f"{prefix}{path.relative_to(root)}",
            "label": str(path.relative_to(root)),
        }
        for path in paths
    ]


class ConfigurationService:
    """Resolve immutable analysis drafts and validate GUI-owned settings writes."""

    def __init__(self, settings_store: GlobalSettingsStore, repositories, has_active_analysis: Callable[[], bool], lock):
        self.settings_store = settings_store
        self.path_policy = settings_store.path_policy
        self.repositories = repositories
        self.has_active_analysis = has_active_analysis
        self._lock = lock

    def global_settings(self) -> dict[str, str]:
        return self.settings_store.get().to_dict()

    def path_options(self) -> dict[str, Any]:
        return {
            "configuration": {
                "prefix": "src/cve_agent/gui/",
                "name": self.settings_store.get().default_config_path.name,
            },
            "taxonomies": _path_choices(
                self.path_policy.taxonomy_files(),
                self.path_policy.fixtures_root,
                "fixtures/",
            ),
            "databases": _path_choices(
                self.path_policy.database_files(),
                self.path_policy.data_root,
                ".data/",
            ),
        }

    def update_global_settings(self, raw: dict[str, Any]) -> dict[str, str]:
        if self.has_active_analysis():
            raise GuiConfigurationError("global settings cannot change while an analysis is running")
        if not isinstance(raw, dict):
            raise GuiConfigurationError("global settings must be an object")
        unknown = sorted(set(raw) - {"database_path", "default_taxonomy_path"})
        if unknown:
            raise GuiConfigurationError(f"unknown global setting fields: {unknown}")
        normalized = {
            **raw,
            "default_config_path": str(self.settings_store.get().default_config_path),
        }
        candidate = self.settings_store.validate(normalized)
        load_taxonomy(candidate.default_taxonomy_path)
        repository = create_history_repository(candidate.database_path)
        repository.initialize()
        updated = self.settings_store.update(normalized)
        with self._lock:
            self.repositories.replace(repository, updated.database_path)
        return updated.to_dict()

    def update_analysis_options(self, raw: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise GuiConfigurationError("analysis options must be an object")
        unknown = sorted(set(raw) - {"taxonomy_path", "values"})
        if unknown:
            raise GuiConfigurationError(f"unknown analysis option fields: {unknown}")
        values = raw.get("values", {})
        global_settings = self.settings_store.get()
        taxonomy_path = raw.get("taxonomy_path") or global_settings.default_taxonomy_path
        with self._lock:
            configuration = self.resolve(
                taxonomy_path=taxonomy_path,
                values=values,
            )
            write_gui_settings(
                global_settings.default_config_path,
                configuration.settings,
                self.path_policy,
            )
            return self.resolve(
                taxonomy_path=taxonomy_path,
                values={},
            ).to_public_dict()

    def resolve(
        self,
        *,
        taxonomy_path: str | Path,
        values: Any,
    ) -> AnalysisConfiguration:
        global_settings = self.settings_store.get()
        try:
            resolved_config = self.path_policy.configuration_file(global_settings.default_config_path)
            resolved_taxonomy = self.path_policy.taxonomy_file(taxonomy_path)
            base = load_gui_settings(resolved_config, self.path_policy)
            taxonomy = load_taxonomy(resolved_taxonomy)
        except (OSError, ValueError, GuiPathError) as exc:
            raise GuiConfigurationError(str(exc)) from exc
        settings = apply_chat_overrides(
            base,
            values,
            database_path=global_settings.database_path,
            path_policy=self.path_policy,
        )
        fingerprint = taxonomy.fingerprint
        return AnalysisConfiguration(
            settings=settings,
            taxonomy=taxonomy,
            taxonomy_path=resolved_taxonomy,
            taxonomy_name=taxonomy.display_name,
            taxonomy_fingerprint=fingerprint,
            settings_fingerprint=settings_fingerprint(non_secret_settings(settings)),
        )
