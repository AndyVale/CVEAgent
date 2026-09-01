import json
import sqlite3

import pytest

from cve_agent.models import CVERecord, ClassificationResult, InvestigationState
from cve_agent.persistence import Database, IncompatibleDatabaseError, PersistenceError
from cve_agent.pipeline import Pipeline
from cve_agent.taxonomy import Taxonomy, TaxonomyLabel


class Source:
    def get_cve(self, cve_id):
        return CVERecord(cve_id, "Generic vulnerability description.")


class Classifier:
    def classify(self, cve, taxonomy, state, checkpoint=None):
        state.facts.append("Checkpointed generic fact.")
        if checkpoint:
            checkpoint()
        return ClassificationResult(cve.cve_id, "not_enough_information")


def taxonomy():
    return Taxonomy((TaxonomyLabel("GENERIC", "Generic", "Generic taxonomy label."),))


def test_repeated_cve_runs_keep_distinct_results(tmp_path):
    path = tmp_path / "runs.sqlite3"
    pipeline = Pipeline(Source(), Classifier(), Database(path))
    first = pipeline.run(["VULN-1"], taxonomy())[0]
    second = pipeline.run(["VULN-1"], taxonomy())[0]
    assert first.operational["run_id"] != second.operational["run_id"]
    with Database(path) as database:
        assert database.get(first.operational["run_id"], "VULN-1") is not None
        assert database.get(second.operational["run_id"], "VULN-1") is not None


def test_pipeline_checkpoints_intermediate_state(tmp_path):
    class CountingDatabase(Database):
        saves = 0

        def save_investigation(self, *args, **kwargs):
            self.saves += 1
            return super().save_investigation(*args, **kwargs)

    database = CountingDatabase(tmp_path / "checkpoints.sqlite3")
    Pipeline(Source(), Classifier(), database).run(["VULN-1"], taxonomy())
    assert database.saves >= 3


def test_legacy_schema_requires_explicit_recreation(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE investigations (cve_id TEXT PRIMARY KEY)")
    connection.commit()
    connection.close()
    database = Database(path)
    with pytest.raises(IncompatibleDatabaseError, match="move or remove it explicitly"):
        with database:
            pass
    assert database.connection is None


def test_schema_v2_requires_explicit_recreation(tmp_path):
    path = tmp_path / "version-two.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    connection.execute("INSERT INTO schema_meta VALUES('schema_version','2')")
    connection.commit()
    connection.close()

    with pytest.raises(IncompatibleDatabaseError, match="schema version '2'"):
        with Database(path):
            pass


def test_fresh_schema_separates_snapshots_payloads_events_and_provenance(tmp_path):
    path = tmp_path / "schema.sqlite3"
    with Database(path) as database:
        run_id = database.start_run(
            taxonomy=taxonomy(),
            model="fixture",
            settings={"temperature": 0.0, "api_key": "must-not-persist"},
        )
        state = InvestigationState()
        state.token_usage = {"total_tokens": 10}
        database.save_investigation(run_id, 0, "VULN-1", "investigating", state)
        checkpoint = database.get(run_id, "VULN-1")
        assert checkpoint["payload_kind"] == "checkpoint"
        database.save_investigation(
            run_id,
            0,
            "VULN-1",
            "not_enough_information",
            state,
            ClassificationResult(
                "VULN-1",
                "not_enough_information",
                operational={"token_usage": state.token_usage, "coverage": {"complete": True}},
            ),
        )
        result_row = database.get(run_id, "VULN-1")
        result_payload = json.loads(result_row["payload_json"])
        run = database.get_run(run_id)

    assert result_row["payload_kind"] == "result"
    assert result_payload["classification"]["operational"]["token_usage"] == {"total_tokens": 10}
    assert "token_usage" not in result_payload["investigation"]
    assert "coverage_json" not in result_row.keys()
    assert "token_usage_json" not in result_row.keys()
    assert json.loads(run["taxonomy_json"])["labels"][0]["id"] == "GENERIC"
    assert json.loads(run["settings_json"]) == {"temperature": 0.0}
    with sqlite3.connect(path) as connection:
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert {
        "runs",
        "analyses",
        "analysis_payloads",
        "analysis_events",
        "provenance_records",
    } <= tables
    assert "investigations" not in tables
    assert "gui_analysis_meta" not in tables


def test_persistence_failure_is_fatal(tmp_path):
    class FailingDatabase(Database):
        def save_investigation(self, *args, **kwargs):
            raise PersistenceError("fixture persistence failure")

    with pytest.raises(PersistenceError, match="fixture persistence failure"):
        Pipeline(Source(), Classifier(), FailingDatabase(tmp_path / "failure.sqlite3")).run(["VULN-1"], taxonomy())
