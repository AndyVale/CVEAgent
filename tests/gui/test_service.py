from pathlib import Path
import logging

import pytest

from cve_agent.application.pipeline import Pipeline
from cve_agent.application.service import ClassificationApplication
from cve_agent.core.config import non_secret_settings
from cve_agent.core.investigation import InvestigationState
from cve_agent.core.results import ClassificationResult, Evidence, LabelClassification
from cve_agent.core.sources import CVERecord
from cve_agent.gui.config import (
    GlobalGuiSettings,
    GlobalSettingsStore,
    GuiConfigurationError,
    load_gui_settings,
)
from cve_agent.gui.configuration import normalize_cve_id
from cve_agent.gui.paths import GuiPathPolicy
from cve_agent.gui.service import GuiService
from cve_agent.persistence.writer import Database


class ImmediateExecutor:
    def submit(self, function, *args, **kwargs):
        function(*args, **kwargs)


class Source:
    def get_cve(self, cve_id):
        return CVERecord(cve_id, "Fixture vulnerability description.")


class Classifier:
    def classify(self, cve, taxonomy, state, checkpoint=None):
        logging.getLogger("cve_agent.fixture").info("[%s] fixture classification step", cve.cve_id)
        return ClassificationResult(
            cve.cve_id,
            "classified",
            [LabelClassification(
                taxonomy.labels[0].id,
                0.91,
                (Evidence("https://example.test/source", "Exact fixture quote.", "Fixture explanation."),),
            )],
        )


def service(tmp_path):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    taxonomy = fixtures / "flat_taxonomy.json"
    taxonomy.write_text(
        Path("fixtures/flat_taxonomy.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    policy = GuiPathPolicy(tmp_path)
    gui_root = tmp_path / "src" / "cve_agent" / "gui"
    gui_root.mkdir(parents=True)
    policy.prepare_runtime_directories()
    config = gui_root / "config.gui.toml"
    template = Path("config.example.toml").read_text(encoding="utf-8")
    config.write_text(
        template.replace("[runtime]\n", "[runtime]\n# keep this GUI-only option\nenable_thinking = true\n", 1),
        encoding="utf-8",
    )
    database = tmp_path / ".data" / "gui.sqlite3"
    store = GlobalSettingsStore(
        tmp_path / ".data" / "gui-settings.json",
        GlobalGuiSettings(database, config, taxonomy),
        policy,
    )

    def factory(settings):
        return ClassificationApplication(Pipeline(
            Source(),
            Classifier(),
            Database(settings.database),
            run_metadata={"model": settings.model, "settings": non_secret_settings(settings)},
        ))

    return GuiService(store, application_factory=factory, executor=ImmediateExecutor())


def test_service_creates_new_runs_and_loads_saved_results_without_rerunning(tmp_path):
    gui = service(tmp_path)
    defaults = gui.defaults()

    started = gui.start_analysis({
        "cve_id": "cve-2024-12345",
        "configuration": {
            "taxonomy_path": defaults["taxonomy"]["path"],
            "values": defaults["values"],
        },
    })
    analysis = gui.get_analysis(started["id"])

    assert analysis["lifecycle"] == "completed"
    assert analysis["result"]["labels"][0]["evidence"][0]["quote"] == "Exact fixture quote."
    assert any("fixture classification step" in event["message"] for event in analysis["events"])
    assert gui.history()[0]["cve_id"] == "CVE-2024-12345"
    assert gui.defaults()["taxonomy"]["path"] == defaults["taxonomy"]["path"]

    cached = gui.start_analysis({
        "cve_id": "CVE-2024-12345",
        "configuration": {
            "taxonomy_path": defaults["taxonomy"]["path"],
            "values": defaults["values"],
        },
    })
    assert cached["already_running"] is False
    second = gui.get_analysis(cached["id"])
    assert second["id"] != analysis["id"]
    assert len(gui.history()) == 2
    assert gui.get_analysis(analysis["id"])["result"] == analysis["result"]
    assert len(gui.history()) == 2


def test_fresh_defaults_use_saved_config_while_old_analysis_keeps_its_snapshot(tmp_path):
    gui = service(tmp_path)
    original = gui.defaults()
    started = gui.start_analysis({
        "cve_id": "CVE-2024-12345",
        "configuration": {
            "taxonomy_path": original["taxonomy"]["path"],
            "values": original["values"],
        },
    })
    completed = gui.get_analysis(started["id"])
    changed_values = dict(original["values"])
    changed_values["temperature"] = 0.6
    gui.update_analysis_options({
        "taxonomy_path": original["taxonomy"]["path"],
        "values": changed_values,
    })

    fresh_defaults = gui.defaults()
    copied_defaults = gui.defaults(completed["id"])
    stored_again = gui.get_analysis(completed["id"])

    assert fresh_defaults["values"]["temperature"] == 0.6
    assert copied_defaults["values"]["temperature"] == original["values"]["temperature"]
    assert copied_defaults["taxonomy"] == completed["configuration"]["taxonomy"]
    assert stored_again["configuration"] == completed["configuration"]


def test_service_displays_recovered_stale_analysis_as_interrupted(tmp_path):
    gui = service(tmp_path)
    settings = gui.settings_store.get()
    taxonomy = gui.configuration.resolve(
        taxonomy_path=settings.default_taxonomy_path,
        values={},
    ).taxonomy
    with Database(settings.database_path) as database:
        run_id = database.start_run(taxonomy=taxonomy, model="fixture", settings={})
        database.save_investigation(
            run_id,
            0,
            "CVE-2024-12345",
            "investigating",
            InvestigationState(),
        )
        database.connection.execute(
            "UPDATE analyses SET updated_at='2020-01-01T00:00:00+00:00'"
        )
        database.connection.commit()
    gui.repositories.get().initialize()

    stored = gui.get_analysis(f"{run_id}:0")

    assert stored["lifecycle"] == "interrupted"
    assert stored["error"] == "analysis process stopped before completion"


def test_service_rejects_invalid_cve_and_secret_overrides(tmp_path):
    gui = service(tmp_path)

    with pytest.raises(GuiConfigurationError, match="CVE ID"):
        gui.start_analysis({"cve_id": "not-a-cve"})
    with pytest.raises(GuiConfigurationError, match="unknown chat configuration"):
        gui.start_analysis({"cve_id": "CVE-2024-1234", "configuration": {"values": {"api_key": "secret"}}})
    with pytest.raises(GuiConfigurationError, match="unknown analysis configuration"):
        gui.start_analysis({
            "cve_id": "CVE-2024-1234",
            "configuration": {"config_path": "/tmp/attacker.toml"},
        })
    with pytest.raises(GuiConfigurationError, match="CVE ID"):
        gui.start_analysis({"cve_id": "CVE-2024-" + "1" * 100})


def test_service_rejects_taxonomy_and_cache_path_escapes(tmp_path):
    gui = service(tmp_path)
    defaults = gui.defaults()
    outside_taxonomy = tmp_path / "outside.json"
    outside_taxonomy.write_text('{"labels": []}', encoding="utf-8")

    with pytest.raises(GuiConfigurationError, match="inside fixtures"):
        gui.update_analysis_options({
            "taxonomy_path": str(outside_taxonomy),
            "values": defaults["values"],
        })

    escaped_values = dict(defaults["values"])
    escaped_values["cache_dir"] = str(tmp_path / "outside-cache")
    with pytest.raises(GuiConfigurationError, match="unknown chat configuration"):
        gui.update_analysis_options({
            "taxonomy_path": defaults["taxonomy"]["path"],
            "values": escaped_values,
        })


def test_service_validates_and_persists_gui_options_without_touching_unknown_toml(tmp_path):
    gui = service(tmp_path)
    defaults = gui.defaults()
    config_path = gui.settings_store.get().default_config_path
    original = config_path.read_text(encoding="utf-8")
    values = dict(defaults["values"])
    values["temperature"] = 0.4

    updated = gui.update_analysis_options({
        "taxonomy_path": defaults["taxonomy"]["path"],
        "values": values,
    })

    persisted = config_path.read_text(encoding="utf-8")
    assert updated["values"]["temperature"] == 0.4
    assert updated["taxonomy"]["hierarchical"] is False
    assert "# keep this GUI-only option" in persisted
    assert "enable_thinking = true" in persisted
    assert load_gui_settings(config_path, gui.configuration.path_policy).temperature == 0.4

    invalid_values = dict(updated["values"])
    invalid_values["temperature"] = 3
    with pytest.raises(GuiConfigurationError, match="temperature"):
        gui.update_analysis_options({
            "taxonomy_path": defaults["taxonomy"]["path"],
            "values": invalid_values,
        })
    assert config_path.read_text(encoding="utf-8") == persisted
    assert original != persisted


def test_global_settings_keep_the_gui_configuration_fixed(tmp_path):
    gui = service(tmp_path)
    taxonomy = tmp_path / "fixtures" / "flat_taxonomy.json"
    gui_config = tmp_path / "src" / "cve_agent" / "gui" / "config.gui.toml"
    gui_original = gui_config.read_text(encoding="utf-8")

    updated = gui.update_global_settings({
        "database_path": str(tmp_path / ".data" / "history.sqlite3"),
        "default_taxonomy_path": str(taxonomy),
    })

    assert updated["default_config_path"] == str(gui_config)
    assert gui_config.read_text(encoding="utf-8") == gui_original
    with pytest.raises(GuiConfigurationError, match="unknown global setting"):
        gui.update_global_settings({
            "database_path": updated["database_path"],
            "default_taxonomy_path": str(taxonomy),
            "default_config_path": str(tmp_path / "other.toml"),
        })


def test_service_lists_only_scoped_path_choices(tmp_path):
    gui = service(tmp_path)

    options = gui.path_options()

    assert options["configuration"] == {
        "prefix": "src/cve_agent/gui/",
        "name": "config.gui.toml",
    }
    assert options["taxonomies"][0]["value"] == "fixtures/flat_taxonomy.json"
    assert options["databases"][0]["value"] == ".data/gui.sqlite3"


def test_normalize_cve_id_is_case_insensitive_but_strict():
    assert normalize_cve_id(" cve-2021-44228 ") == "CVE-2021-44228"
    with pytest.raises(GuiConfigurationError):
        normalize_cve_id("CVE-21-1")


def test_progress_write_failure_preserves_result_and_displays_warning(tmp_path, monkeypatch):
    from cve_agent.core.errors import PersistenceError

    gui = service(tmp_path)

    def fail(*args):
        raise PersistenceError('event storage unavailable')

    monkeypatch.setattr(gui.repositories.get(), 'save_events', fail)
    started = gui.start_analysis({'cve_id': 'CVE-2024-12345'})
    analysis = gui.get_analysis(started['id'])
    assert analysis['lifecycle'] == 'completed'
    assert analysis['error'] is None
    assert analysis['result']['status'] == 'classified'
    assert analysis['events'][-1]['tone'] == 'warning'
    assert 'progress log could not be saved' in analysis['events'][-1]['message']
    assert not gui.jobs.has_active()
    cached = gui.start_analysis({'cve_id': 'CVE-2024-12345'})
    assert cached['already_running'] is False
    assert gui.get_analysis(cached['id'])['id'] != analysis['id']


def test_history_search_and_click_route_do_not_create_new_results(tmp_path):
    from cve_agent.gui.app import create_gui_app

    gui = service(tmp_path)
    first = gui.start_analysis({'cve_id': 'CVE-2020-2889'})
    second = gui.start_analysis({'cve_id': 'CVE-2020-2889'})
    app = create_gui_app(gui).test_client()
    for query in ['2889', '2020', 'cve-2020-2889']:
        response = app.get('/api/history', query_string={'q': query}).json
        assert len(response['analyses']) == 2
        assert response['has_more'] is False
        for item in response['analyses']:
            loaded = app.get(f"/api/analyses/{item['id']}").json
            assert loaded['id'] == item['id']
            assert loaded['lifecycle'] == 'completed'
    assert len(gui.history()) == 2
    assert gui.get_analysis(first['id'])['id'] != gui.get_analysis(second['id'])['id']
    assert app.get('/api/history?q=missing').json['analyses'] == []
    for query in ['offset=-1', 'offset=oops', 'q=' + 'x' * 201]:
        assert app.get('/api/history?' + query).status_code == 400


def test_gui_normalizes_cve_before_deduplicating_active_runs(tmp_path):
    from tests.gui.test_jobs import QueuedExecutor

    gui = service(tmp_path)
    executor = QueuedExecutor()
    gui.jobs._executor = executor
    first = gui.start_analysis({'cve_id': ' cve-2020-2889 '})
    second = gui.start_analysis({'cve_id': 'CVE-2020-2889'})
    assert second['already_running'] is True
    assert first['id'] == second['id']
    assert len(executor.calls) == 1
    assert gui.history() == []
    function, args = executor.calls.pop()
    function(*args)
    assert len(gui.history()) == 1
    third = gui.start_analysis({'cve_id': 'CVE-2020-2889'})
    assert third['already_running'] is False
    assert third['id'] != first['id']
