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
from cve_agent.gui_paths import GuiPathPolicy


def gui_project(tmp_path):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (tmp_path / ".data").mkdir()
    (tmp_path / ".cache").mkdir()
    config = tmp_path / "config.gui.toml"
    config.write_text(Path("config.example.toml").read_text(encoding="utf-8"), encoding="utf-8")
    taxonomy = fixtures / "taxonomy.json"
    taxonomy.write_text(Path("fixtures/flat_taxonomy.json").read_text(encoding="utf-8"), encoding="utf-8")
    return GuiPathPolicy(tmp_path), config, taxonomy


def test_chat_overrides_convert_values_validate_and_force_global_database(tmp_path):
    policy, config, _ = gui_project(tmp_path)
    base = load_settings(config)
    database = tmp_path / ".data" / "history.sqlite3"

    settings = apply_chat_overrides(
        base,
        {
            "max_tokens": "3072",
            "temperature": "0.4",
            "classification_strategy": "exhaustive",
        },
        database_path=database,
        path_policy=policy,
    )

    assert settings.max_tokens == 3072
    assert settings.temperature == 0.4
    assert settings.classification_strategy.value == "exhaustive"
    assert settings.cache_dir == tmp_path / ".cache" / "cve-agent" / "web"
    assert settings.database == database


def test_chat_overrides_reject_unknown_fields_and_invalid_ranges(tmp_path):
    policy, config, _ = gui_project(tmp_path)
    base = load_settings(config)
    database = tmp_path / ".data" / "db.sqlite3"

    with pytest.raises(GuiConfigurationError, match="unknown chat configuration"):
        apply_chat_overrides(
            base,
            {"api_key": "secret"},
            database_path=database,
            path_policy=policy,
        )
    with pytest.raises(GuiConfigurationError, match="pruning_confidence_threshold"):
        apply_chat_overrides(
            base,
            {"pruning_confidence_threshold": 1.5},
            database_path=database,
            path_policy=policy,
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
        taxonomy_hierarchical=False,
        hierarchy_policy="most_specific",
    )

    serialized = json.dumps(configuration)
    assert "private-provider-key" not in serialized
    assert "private-search-key" not in serialized
    assert configuration["values"] == settings_values(settings)
    assert configuration["taxonomy"]["labels"] == 4
    assert configuration["taxonomy"]["hierarchical"] is False
    fields = {field["name"]: field for group in configuration["groups"] for field in group["fields"]}
    assert fields["temperature"]["minimum"] == 0
    assert fields["temperature"]["maximum"] == 2
    assert fields["top_p"]["exclusive_minimum"] is True
    assert fields["classification_strategy"]["hierarchical_only"] is True
    assert fields["tavily_max_results"]["depends_values"] == ["tavily"]


def test_global_settings_store_persists_validated_paths(tmp_path):
    policy, config, taxonomy = gui_project(tmp_path)
    state_path = tmp_path / ".data" / "gui-settings.json"
    fallback = GlobalGuiSettings(tmp_path / ".data" / "fallback.sqlite3", config, taxonomy)
    store = GlobalSettingsStore(state_path, fallback, policy)

    updated = store.update({
        "database_path": str(tmp_path / ".data" / "selected.sqlite3"),
        "default_config_path": str(config),
        "default_taxonomy_path": str(taxonomy),
    })

    assert updated.database_path == tmp_path / ".data" / "selected.sqlite3"
    assert GlobalSettingsStore(state_path, fallback, policy).get() == updated


def test_global_settings_store_does_not_persist_missing_files(tmp_path):
    policy, config, taxonomy = gui_project(tmp_path)
    state_path = tmp_path / ".data" / "gui-settings.json"
    store = GlobalSettingsStore(
        state_path,
        GlobalGuiSettings(tmp_path / ".data" / "db.sqlite3", config, taxonomy),
        policy,
    )

    with pytest.raises(GuiConfigurationError, match="taxonomy file does not exist"):
        store.update({
            "database_path": str(tmp_path / ".data" / "selected.sqlite3"),
            "default_config_path": str(config),
            "default_taxonomy_path": str(tmp_path / "fixtures" / "missing.json"),
        })

    assert not state_path.exists()


def test_global_settings_store_rejects_invalid_sqlite_destinations(tmp_path):
    policy, config, taxonomy = gui_project(tmp_path)
    store = GlobalSettingsStore(
        tmp_path / ".data" / "gui-settings.json",
        GlobalGuiSettings(tmp_path / ".data" / "fallback.sqlite3", config, taxonomy),
        policy,
    )
    base = {
        "default_config_path": str(config),
        "default_taxonomy_path": str(taxonomy),
    }

    with pytest.raises(GuiConfigurationError, match="database directory does not exist"):
        store.update({**base, "database_path": str(tmp_path / ".data" / "missing" / "history.sqlite3")})
    directory = tmp_path / ".data" / "not-a-file.sqlite3"
    directory.mkdir()
    with pytest.raises(GuiConfigurationError, match="database path is not a file"):
        store.update({**base, "database_path": str(directory)})
