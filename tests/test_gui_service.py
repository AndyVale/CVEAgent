import logging
from pathlib import Path

import pytest

from cve_agent.application import ClassificationApplication
from cve_agent.config import non_secret_settings
from cve_agent.gui_config import GlobalGuiSettings, GlobalSettingsStore, GuiConfigurationError
from cve_agent.gui_service import GuiService, normalize_cve_id
from cve_agent.models import CVERecord, ClassificationResult, Evidence, LabelClassification
from cve_agent.persistence import Database
from cve_agent.pipeline import Pipeline


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
    config = Path("config.example.toml").resolve()
    taxonomy = Path("fixtures/flat_taxonomy.json").resolve()
    database = tmp_path / "gui.sqlite3"
    store = GlobalSettingsStore(
        tmp_path / "gui-settings.json",
        GlobalGuiSettings(database, config, taxonomy),
    )

    def factory(settings):
        return ClassificationApplication(Pipeline(
            Source(),
            Classifier(),
            Database(settings.database),
            run_metadata={"model": settings.model, "settings": non_secret_settings(settings)},
        ))

    return GuiService(store, application_factory=factory, executor=ImmediateExecutor())


def test_service_runs_persists_progress_and_reuses_exact_cache(tmp_path):
    gui = service(tmp_path)
    defaults = gui.defaults()

    started = gui.start_analysis({
        "cve_id": "cve-2024-12345",
        "configuration": {
            "taxonomy_path": defaults["taxonomy"]["path"],
            "config_path": defaults["config_path"],
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
            "config_path": defaults["config_path"],
            "values": defaults["values"],
        },
    })
    assert cached == {"id": analysis["id"], "cached": True, "lifecycle": "completed"}
    assert len(gui.history()) == 1


def test_service_rejects_invalid_cve_and_secret_overrides(tmp_path):
    gui = service(tmp_path)

    with pytest.raises(GuiConfigurationError, match="CVE ID"):
        gui.start_analysis({"cve_id": "not-a-cve"})
    with pytest.raises(GuiConfigurationError, match="unknown chat configuration"):
        gui.start_analysis({"cve_id": "CVE-2024-1234", "configuration": {"values": {"api_key": "secret"}}})


def test_normalize_cve_id_is_case_insensitive_but_strict():
    assert normalize_cve_id(" cve-2021-44228 ") == "CVE-2021-44228"
    with pytest.raises(GuiConfigurationError):
        normalize_cve_id("CVE-21-1")
