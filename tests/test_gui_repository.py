from cve_agent.gui_repository import GuiAnalysisRepository, parse_analysis_id, settings_fingerprint
from cve_agent.models import ClassificationResult, InvestigationState, LabelClassification
from cve_agent.persistence import Database


def persisted_analysis(path, *, cve_id="CVE-2024-1000", status="classified"):
    settings = {"model": "fixture-model", "temperature": 0.0}
    with Database(path) as database:
        run_id = database.start_run(taxonomy_sha256="taxonomy-digest", model="fixture-model", settings=settings)
        result = ClassificationResult(
            cve_id,
            status,
            [LabelClassification("GENERIC", 0.9, ())] if status == "classified" else [],
            operational={"run_id": run_id},
        )
        database.save_investigation(run_id, 0, cve_id, status, InvestigationState(), result)
        database.finish_run(run_id, "complete")
    return f"{run_id}:0", settings


def test_repository_reads_core_history_and_gui_snapshot(tmp_path):
    path = tmp_path / "history.sqlite3"
    analysis_id, settings = persisted_analysis(path)
    repository = GuiAnalysisRepository(path)
    repository.initialize()
    repository.save_snapshot(
        analysis_id,
        taxonomy_path="/fixture/taxonomy.json",
        taxonomy_name="Fixture taxonomy",
        config_path="/fixture/config.toml",
        settings_fingerprint_value=settings_fingerprint(settings),
        taxonomy_labels=5,
        hierarchy_policy="most_specific",
    )
    repository.save_events(analysis_id, [{
        "created_at": "2026-01-01T00:00:00+00:00",
        "tone": "normal",
        "component": "PIPELINE",
        "message": "Started",
    }])

    stored = repository.get_analysis(analysis_id)

    assert stored is not None
    assert stored.taxonomy_name == "Fixture taxonomy"
    assert stored.taxonomy_labels == 5
    assert repository.list_analyses()[0].analysis_id == analysis_id
    assert repository.get_events(analysis_id)[0]["message"] == "Started"
    assert repository.find_cached(
        cve_id="CVE-2024-1000",
        taxonomy_fingerprint="taxonomy-digest",
        settings_fingerprint_value=settings_fingerprint(settings),
    ).analysis_id == analysis_id


def test_repository_keeps_cli_created_rows_readable_without_gui_metadata(tmp_path):
    path = tmp_path / "history.sqlite3"
    analysis_id, _ = persisted_analysis(path)
    repository = GuiAnalysisRepository(path)
    repository.initialize()

    stored = repository.get_analysis(analysis_id)

    assert stored is not None
    assert stored.taxonomy_path is None
    assert stored.taxonomy_name is None
    assert repository.get_events(analysis_id) == []


def test_partial_results_are_not_used_as_complete_cache_entries(tmp_path):
    path = tmp_path / "history.sqlite3"
    _, settings = persisted_analysis(path, status="partial")
    repository = GuiAnalysisRepository(path)
    repository.initialize()

    assert repository.find_cached(
        cve_id="CVE-2024-1000",
        taxonomy_fingerprint="taxonomy-digest",
        settings_fingerprint_value=settings_fingerprint(settings),
    ) is None


def test_analysis_ids_are_strictly_parsed():
    assert parse_analysis_id("12:3") == (12, 3)
