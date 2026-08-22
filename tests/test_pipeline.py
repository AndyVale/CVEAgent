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
