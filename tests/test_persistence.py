import sqlite3

import pytest

from cve_agent.models import CVERecord, ClassificationResult
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
    with pytest.raises(IncompatibleDatabaseError, match="remove it explicitly"):
        with Database(path):
            pass


def test_persistence_failure_is_fatal(tmp_path):
    class FailingDatabase(Database):
        def save_investigation(self, *args, **kwargs):
            raise PersistenceError("fixture persistence failure")

    with pytest.raises(PersistenceError, match="fixture persistence failure"):
        Pipeline(Source(), Classifier(), FailingDatabase(tmp_path / "failure.sqlite3")).run(["VULN-1"], taxonomy())
