from dataclasses import replace

import pytest

from cve_agent.application import create_application
from cve_agent.budget import BudgetPreflightError
from cve_agent.config import load_settings
from cve_agent.models import CVERecord, ClassificationResult, LabelClassification, Reference
from cve_agent.persistence import Database
from cve_agent.pipeline import Pipeline
from cve_agent.taxonomy import Taxonomy, TaxonomyLabel


class Source:
    def __init__(self):
        self.calls = []
    def get_cve(self, cve_id):
        self.calls.append(cve_id)
        if cve_id == "CVE-BAD":
            raise RuntimeError("fixture failure")
        return CVERecord(cve_id, "A buffer is copied without bounds.", (Reference("https://example.test/advisory"),))


class Classifier:
    def classify(self, cve, taxonomy, state, checkpoint=None):
        assert state.evidence[0].url == "https://nvd.nist.gov/vuln/detail/CVE-OK"
        assert state.evidence[0].quote == cve.description
        assert state.tool_history[0]["tool"] == "get_cve"
        if checkpoint:
            checkpoint()
        return ClassificationResult(cve.cve_id, "classified", [LabelClassification("CWE-120", .9, ())])


class Web:
    def search(self, query): return []
    def fetch(self, url): raise AssertionError("not needed for fixture")


def test_pipeline_preserves_order_and_isolates_cve_failure(tmp_path):
    source = Source()
    taxonomy = Taxonomy((TaxonomyLabel("CWE-120", "Buffer Copy", "copy without bounds"),))
    results = Pipeline(source, Classifier(), Database(tmp_path / "results.sqlite")).run(["CVE-OK", "CVE-BAD"], taxonomy)
    assert [x.cve_id for x in results] == ["CVE-OK", "CVE-BAD"]
    assert results[0].status == "classified"
    assert results[1].status == "failed"
    run_id = results[0].operational["run_id"]
    with Database(tmp_path / "results.sqlite") as db:
        assert db.get(run_id, "CVE-OK")["status"] == "classified"
        assert db.get(run_id, "CVE-BAD")["error"] == "fixture failure"
        assert db.get_run(run_id)["status"] == "completed_with_failures"


def test_preflight_failure_happens_before_source_or_database_side_effects(tmp_path):
    class PreflightClassifier(Classifier):
        def preflight(self, taxonomy):
            raise BudgetPreflightError("fixture preflight failure")

    source = Source()
    path = tmp_path / "unused.sqlite3"
    with pytest.raises(BudgetPreflightError, match="fixture preflight failure"):
        Pipeline(source, PreflightClassifier(), Database(path)).run(["CVE-OK"], Taxonomy((TaxonomyLabel("GENERIC", "Generic", "generic"),)))
    assert source.calls == []
    assert not path.exists()


def test_application_preflight_does_not_create_database_or_web_cache(tmp_path):
    configured = replace(
        load_settings("config.example.toml"),
        token_budget=1,
        database=tmp_path / "unused.sqlite3",
        cache_dir=tmp_path / "unused-cache",
    )
    taxonomy = Taxonomy((TaxonomyLabel("GENERIC", "Generic", "generic"),))

    with pytest.raises(BudgetPreflightError):
        create_application(configured).run(["CVE-2024-1000"], taxonomy)

    assert not configured.database.exists()
    assert not configured.cache_dir.exists()
