from pathlib import Path

import pytest

from cve_agent.gui.paths import GuiPathError, GuiPathPolicy


def project_layout(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "fixtures").mkdir()
    gui_root = root / "src" / "cve_agent" / "gui"
    gui_root.mkdir(parents=True)
    policy = GuiPathPolicy(root)
    policy.prepare_runtime_directories()
    config = gui_root / "config.gui.toml"
    config.write_text("[storage]\ndatabase = '.data/results.sqlite3'\n", encoding="utf-8")
    taxonomy = root / "fixtures" / "taxonomy.json"
    taxonomy.write_text('{"labels": []}', encoding="utf-8")
    return policy, config, taxonomy


def test_gui_paths_accept_only_project_owned_locations(tmp_path):
    policy, config, taxonomy = project_layout(tmp_path)

    assert policy.configuration_file(config) == config
    assert policy.taxonomy_file(taxonomy) == taxonomy
    assert policy.database_file(".data/results.sqlite3") == policy.data_root / "results.sqlite3"
    assert policy.state_file(".data/gui.json") == policy.data_root / "gui.json"
    assert policy.cache_directory(".cache/web") == policy.cache_root / "web"


@pytest.mark.parametrize(
    ("method", "value", "message"),
    [
        ("configuration_file", "nested/config.toml", "project root"),
        ("taxonomy_file", "fixtures/../taxonomy.json", "inside fixtures"),
        ("database_file", ".data/../results.sqlite3", "inside .data"),
        ("state_file", ".data/../gui.json", "inside .data"),
        ("cache_directory", ".cache/../../cache", "inside .cache"),
    ],
)
def test_gui_paths_reject_parent_traversal_and_wrong_scopes(tmp_path, method, value, message):
    policy, _, _ = project_layout(tmp_path)

    with pytest.raises(GuiPathError, match=message):
        getattr(policy, method)(value)


def test_gui_paths_reject_symlink_escapes(tmp_path):
    policy, _, _ = project_layout(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_taxonomy = outside / "taxonomy.json"
    outside_taxonomy.write_text('{"labels": []}', encoding="utf-8")
    outside_database = outside / "history.sqlite3"
    outside_database.touch()
    taxonomy_link = policy.fixtures_root / "linked.json"
    database_link = policy.data_root / "linked.sqlite3"
    taxonomy_link.symlink_to(outside_taxonomy)
    database_link.symlink_to(outside_database)

    with pytest.raises(GuiPathError, match="inside fixtures"):
        policy.taxonomy_file(taxonomy_link)
    with pytest.raises(GuiPathError, match="inside .data"):
        policy.database_file(database_link)


def test_gui_paths_reject_symlinked_managed_directories(tmp_path):
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "fixtures").mkdir()
    (root / "src" / "cve_agent" / "gui").mkdir(parents=True)
    (root / ".data").mkdir()
    (root / ".cache").symlink_to(outside, target_is_directory=True)

    with pytest.raises(GuiPathError, match="symbolic link"):
        GuiPathPolicy(root).prepare_runtime_directories()


def test_gui_paths_require_expected_file_extensions(tmp_path):
    policy, _, _ = project_layout(tmp_path)
    wrong_taxonomy = policy.fixtures_root / "taxonomy.txt"
    wrong_taxonomy.touch()

    with pytest.raises(GuiPathError, match="extension"):
        policy.taxonomy_file(wrong_taxonomy)
    with pytest.raises(GuiPathError, match="extension"):
        policy.database_file(".data/history.json")


def test_gui_write_target_is_always_the_dedicated_configuration(tmp_path):
    policy, config, _ = project_layout(tmp_path)
    other_toml = policy.project_root / "other.toml"
    other_toml.write_text("[runtime]\n", encoding="utf-8")

    assert policy.gui_configuration_file(config) == config
    with pytest.raises(GuiPathError, match="config.gui.toml"):
        policy.gui_configuration_file(other_toml)
