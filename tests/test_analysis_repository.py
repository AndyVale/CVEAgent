import sqlite3

import pytest

from cve_agent.config import settings_fingerprint
from cve_agent.models import ClassificationResult, InvestigationState, LabelClassification
from cve_agent.persistence import AnalysisRepository, Database, parse_analysis_id
from cve_agent.taxonomy import HierarchyPolicy, Taxonomy, TaxonomyLabel


def fixture_taxonomy(source_path=None):
    return Taxonomy(
        (TaxonomyLabel("GENERIC", "Generic", "Original definition"),),
        HierarchyPolicy.MOST_SPECIFIC,
        "Fixture taxonomy",
        {"owner": "tests"},
        str(source_path) if source_path else None,
    )


def persisted_analysis(path, *, cve_id="CVE-2024-1000", status="classified", source_path=None):
    settings = {"model": "fixture-model", "temperature": 0.0}
    taxonomy = fixture_taxonomy(source_path)
    with Database(path) as database:
        run_id = database.start_run(taxonomy=taxonomy, model="fixture-model", settings=settings)
        result = ClassificationResult(
            cve_id,
            status,
            [LabelClassification("GENERIC", 0.9, ())] if status == "classified" else [],
            operational={"run_id": run_id},
        )
        database.save_investigation(run_id, 0, cve_id, status, InvestigationState(), result)
        database.finish_run(run_id, "complete")
    return f"{run_id}:0", settings, taxonomy


def test_repository_reads_shared_snapshot_events_and_exact_cache(tmp_path):
    path = tmp_path / "history.sqlite3"
    source_path = tmp_path / "taxonomy.json"
    source_path.write_text('{"labels": []}', encoding="utf-8")
    analysis_id, settings, taxonomy = persisted_analysis(path, source_path=source_path)
    repository = AnalysisRepository(path)
    repository.initialize()
    repository.save_events(analysis_id, [{
        "created_at": "2026-01-01T00:00:00+00:00",
        "tone": "normal",
        "component": "PIPELINE",
        "message": "Started",
    }])

    stored = repository.get_analysis(analysis_id)
    summary = repository.list_analyses()[0]

    assert stored is not None
    assert stored.taxonomy is not None
    assert stored.taxonomy.to_dict() == taxonomy.to_dict()
    assert stored.taxonomy_path == str(source_path)
    assert stored.taxonomy_name == "Fixture taxonomy"
    assert stored.taxonomy_labels == 1
    assert stored.result["labels"][0]["label"] == "GENERIC"
    assert repository.get_events(analysis_id)[0]["message"] == "Started"
    assert summary.analysis_id == analysis_id
    assert summary.label_ids == ("GENERIC",)
    cached = repository.find_cached(
        cve_id="CVE-2024-1000",
        taxonomy_fingerprint=taxonomy.fingerprint,
        settings_fingerprint_value=settings_fingerprint(settings),
    )
    assert cached is not None and cached.analysis_id == analysis_id


def test_taxonomy_snapshot_survives_source_file_changes(tmp_path):
    path = tmp_path / "history.sqlite3"
    source_path = tmp_path / "taxonomy.json"
    source_path.write_text("original", encoding="utf-8")
    analysis_id, _, _ = persisted_analysis(path, source_path=source_path)
    source_path.write_text("changed", encoding="utf-8")

    stored = AnalysisRepository(path).get_analysis(analysis_id)

    assert stored is not None and stored.taxonomy is not None
    assert stored.taxonomy.by_id["GENERIC"].description == "Original definition"


def test_partial_results_are_not_used_as_complete_cache_entries(tmp_path):
    path = tmp_path / "history.sqlite3"
    _, settings, taxonomy = persisted_analysis(path, status="partial")
    repository = AnalysisRepository(path)
    repository.initialize()

    assert repository.find_cached(
        cve_id="CVE-2024-1000",
        taxonomy_fingerprint=taxonomy.fingerprint,
        settings_fingerprint_value=settings_fingerprint(settings),
    ) is None


def test_repository_recovers_stale_investigations_as_interrupted(tmp_path):
    path = tmp_path / "history.sqlite3"
    taxonomy = fixture_taxonomy()
    with Database(path) as database:
        run_id = database.start_run(taxonomy=taxonomy, model="fixture", settings={})
        database.save_investigation(
            run_id,
            0,
            "CVE-2024-1000",
            "investigating",
            InvestigationState(),
        )
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE analyses SET updated_at='2020-01-01T00:00:00+00:00'"
        )

    repository = AnalysisRepository(path)
    assert repository.recover_stale(before="2021-01-01T00:00:00+00:00") == 1
    stored = repository.get_analysis(f"{run_id}:0")

    assert stored is not None
    assert stored.status == "interrupted"
    assert stored.run_status == "interrupted"
    assert stored.error == "analysis process stopped before completion"


def test_repository_recovers_stale_terminal_and_empty_runs(tmp_path):
    path = tmp_path / "history.sqlite3"
    taxonomy = fixture_taxonomy()
    with Database(path) as database:
        terminal_run = database.start_run(taxonomy=taxonomy, model="fixture", settings={})
        result = ClassificationResult("CVE-2024-1000", "not_enough_information")
        database.save_investigation(
            terminal_run,
            0,
            result.cve_id,
            result.status,
            InvestigationState(),
            result,
        )
        empty_run = database.start_run(taxonomy=taxonomy, model="fixture", settings={})
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE analyses SET updated_at='2020-01-01T00:00:00+00:00'"
        )
        connection.execute(
            "UPDATE runs SET started_at='2020-01-01T00:00:00+00:00'"
        )

    repository = AnalysisRepository(path)
    repository.recover_stale(before="2021-01-01T00:00:00+00:00")

    with Database(path) as database:
        assert database.get_run(terminal_run)["status"] == "complete"
        assert database.get_run(empty_run)["status"] == "interrupted"


def test_event_queries_support_sequence_deltas(tmp_path):
    path = tmp_path / "history.sqlite3"
    analysis_id, _, _ = persisted_analysis(path)
    repository = AnalysisRepository(path)
    repository.save_events(analysis_id, [
        {"created_at": "one", "message": "first"},
        {"created_at": "two", "message": "second"},
    ])

    assert [event["message"] for event in repository.get_events(analysis_id, after_sequence=0)] == [
        "second"
    ]


def test_analysis_ids_are_strictly_parsed():
    assert parse_analysis_id("12:3") == (12, 3)
    with pytest.raises(ValueError):
        parse_analysis_id(f"{2**63}:0")
