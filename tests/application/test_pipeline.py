import logging
from dataclasses import replace

import pytest

from cve_agent.application.factory import create_application
from cve_agent.application.pipeline import Pipeline
from cve_agent.classification.budget import BudgetPreflightError
from cve_agent.core.config import load_settings
from cve_agent.core.errors import PersistenceError
from cve_agent.core.results import ClassificationResult, LabelClassification
from cve_agent.core.sources import CVERecord, Reference
from cve_agent.core.taxonomy import Taxonomy, TaxonomyLabel
from cve_agent.persistence.writer import Database


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


@pytest.mark.parametrize('fail_checkpoint', [False, True])
def test_pipeline_uses_writer_contract_and_propagates_checkpoint_failure(fail_checkpoint):
    class Writer:
        def __init__(self):
            self.events = []

        def __enter__(self):
            self.events.append('open')
            return self

        def __exit__(self, *args):
            self.events.append('close')

        def start_run(self, **snapshot):
            self.events.append('start')
            return 42

        def save_investigation(self, run_id, position, cve_id, status, state, result=None, error=None):
            assert (run_id, position, cve_id) == (42, 0, 'CVE-OK')
            self.events.append(str(status))
            if fail_checkpoint and self.events.count('investigating') == 2:
                raise PersistenceError('checkpoint unavailable')

        def finish_run(self, run_id, status):
            self.events.append(status)

    writer = Writer()
    pipeline = Pipeline(Source(), Classifier(), writer)
    taxonomy = Taxonomy((TaxonomyLabel('CWE-120', 'Buffer Copy', 'copy without bounds'),))
    if fail_checkpoint:
        with pytest.raises(PersistenceError, match='checkpoint unavailable'):
            pipeline.run(['CVE-OK'], taxonomy)
        assert writer.events == ['open', 'start', 'investigating', 'investigating', 'failed', 'close']
    else:
        result = pipeline.run(['CVE-OK'], taxonomy)[0]
        assert result.operational['run_id'] == 42
        assert writer.events == ['open', 'start', 'investigating', 'investigating', 'investigating', 'classified', 'complete', 'close']


def test_pipeline_preserves_primary_failure_when_failed_run_finalization_also_fails(caplog):
    secret = "fixture-secret-value"

    class Writer:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def start_run(self, **snapshot): return 42
        def save_investigation(self, *args, **kwargs):
            raise PersistenceError("primary checkpoint failure")
        def finish_run(self, run_id, status):
            raise PersistenceError(f"secondary failure exposed {secret}")

    taxonomy = Taxonomy((TaxonomyLabel('CWE-120', 'Buffer Copy', 'copy without bounds'),))
    with caplog.at_level(logging.ERROR, logger="cve_agent.pipeline"):
        with pytest.raises(PersistenceError, match="primary checkpoint failure"):
            Pipeline(Source(), Classifier(), Writer()).run(['CVE-OK'], taxonomy)

    assert "secondary cleanup failure" in caplog.text
    assert "cleanup_type=PersistenceError" in caplog.text
    assert secret not in caplog.text


def test_pipeline_surfaces_cleanup_only_failure():
    class Writer:
        def __enter__(self): return self
        def __exit__(self, *args): raise PersistenceError("writer close failed")
        def start_run(self, **snapshot): return 42
        def save_investigation(self, *args, **kwargs): pass
        def finish_run(self, run_id, status): pass

    taxonomy = Taxonomy((TaxonomyLabel('CWE-120', 'Buffer Copy', 'copy without bounds'),))
    with pytest.raises(PersistenceError, match="writer close failed"):
        Pipeline(Source(), Classifier(), Writer()).run(['CVE-OK'], taxonomy)


def test_pipeline_preserves_primary_failure_when_writer_close_also_fails(caplog):
    class Writer:
        def __enter__(self): return self
        def __exit__(self, *args): raise PersistenceError("secondary close failure")
        def start_run(self, **snapshot): return 42
        def save_investigation(self, *args, **kwargs):
            raise PersistenceError("primary save failure")
        def finish_run(self, run_id, status): pass

    taxonomy = Taxonomy((TaxonomyLabel('CWE-120', 'Buffer Copy', 'copy without bounds'),))
    with caplog.at_level(logging.ERROR, logger="cve_agent.pipeline"):
        with pytest.raises(PersistenceError, match="primary save failure"):
            Pipeline(Source(), Classifier(), Writer()).run(['CVE-OK'], taxonomy)

    assert "closing the analysis writer" in caplog.text
