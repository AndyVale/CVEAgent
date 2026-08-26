import json
from dataclasses import replace
from pathlib import Path

import pytest

from cve_agent.config import load_settings
from cve_agent.gui_config import (
    GlobalGuiSettings,
    GlobalSettingsStore,
    GuiConfigurationError,
    apply_chat_overrides,
    public_configuration,
    settings_values,
)


def test_chat_overrides_convert_values_validate_and_force_global_database(tmp_path):
    base = load_settings("config.example.toml")
    database = tmp_path / "history.sqlite3"

    settings = apply_chat_overrides(
        base,
        {
            "max_tokens": "3072",
            "temperature": "0.4",
            "classification_strategy": "exhaustive",
            "cache_dir": "local-cache",
        },
        config_directory=tmp_path,
        database_path=database,
    )

    assert settings.max_tokens == 3072
    assert settings.temperature == 0.4
    assert settings.classification_strategy.value == "exhaustive"
    assert settings.cache_dir == tmp_path / "local-cache"
    assert settings.database == database


def test_chat_overrides_reject_unknown_fields_and_invalid_ranges(tmp_path):
    base = load_settings("config.example.toml")

    with pytest.raises(GuiConfigurationError, match="unknown chat configuration"):
        apply_chat_overrides(base, {"api_key": "secret"}, config_directory=tmp_path, database_path=tmp_path / "db")
    with pytest.raises(GuiConfigurationError, match="pruning_confidence_threshold"):
        apply_chat_overrides(
            base,
            {"pruning_confidence_threshold": 1.5},
            config_directory=tmp_path,
            database_path=tmp_path / "db",
        )


def test_public_configuration_contains_editable_fields_but_no_secrets(tmp_path):
    settings = replace(
        load_settings("config.example.toml"),
        api_key="private-provider-key",
        tavily_api_key="private-search-key",
    )

    configuration = public_configuration(
        settings=settings,
        taxonomy_path=tmp_path / "taxonomy.json",
        taxonomy_name="Fixture taxonomy",
        taxonomy_fingerprint="abc",
        taxonomy_labels=4,
        hierarchy_policy="most_specific",
        config_path=tmp_path / "config.toml",
    )

    serialized = json.dumps(configuration)
    assert "private-provider-key" not in serialized
    assert "private-search-key" not in serialized
    assert configuration["values"] == settings_values(settings)
    assert configuration["taxonomy"]["labels"] == 4


def test_global_settings_store_persists_validated_paths(tmp_path):
    config = Path("config.example.toml").resolve()
    taxonomy = Path("fixtures/flat_taxonomy.json").resolve()
    state_path = tmp_path / "gui-settings.json"
    fallback = GlobalGuiSettings(tmp_path / "fallback.sqlite3", config, taxonomy)
    store = GlobalSettingsStore(state_path, fallback)

    updated = store.update({
        "database_path": str(tmp_path / "selected.sqlite3"),
        "default_config_path": str(config),
        "default_taxonomy_path": str(taxonomy),
    })

    assert updated.database_path == tmp_path / "selected.sqlite3"
    assert GlobalSettingsStore(state_path, fallback).get() == updated


def test_global_settings_store_does_not_persist_missing_files(tmp_path):
    config = Path("config.example.toml").resolve()
    taxonomy = Path("fixtures/flat_taxonomy.json").resolve()
    state_path = tmp_path / "gui-settings.json"
    store = GlobalSettingsStore(state_path, GlobalGuiSettings(tmp_path / "db", config, taxonomy))

    with pytest.raises(GuiConfigurationError, match="taxonomy file does not exist"):
        store.update({
            "database_path": str(tmp_path / "selected.sqlite3"),
            "default_config_path": str(config),
            "default_taxonomy_path": str(tmp_path / "missing.json"),
        })

    assert not state_path.exists()
