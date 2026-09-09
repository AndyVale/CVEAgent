import logging

import pytest

from cve_agent.application.service import ClassificationApplication
from cve_agent.classification.evaluation import Benchmark, BenchmarkCase
from cve_agent.core.results import ClassificationResult, LabelClassification
from cve_agent.core.taxonomy import Taxonomy, TaxonomyLabel


class FixturePipeline:
    def __init__(self, results):
        self.results = results
        self.calls = []

    def run(self, cve_ids, taxonomy):
        self.calls.append((cve_ids, taxonomy))
        return self.results


def taxonomy():
    return Taxonomy((TaxonomyLabel("LABEL", "Label", "Fixture label."),))


def test_application_returns_ui_independent_results_and_evaluation():
    selected_taxonomy = taxonomy()
    pipeline = FixturePipeline([
        ClassificationResult("VULN-1", "classified", [LabelClassification("LABEL", 0.9, ())]),
    ])
    benchmark = Benchmark((BenchmarkCase("VULN-1", ("LABEL",)),))

    outcome = ClassificationApplication(pipeline).run(["VULN-1"], selected_taxonomy, benchmark)

    assert pipeline.calls == [(["VULN-1"], selected_taxonomy)]
    assert outcome.results[0].cve_id == "VULN-1"
    assert outcome.evaluation is not None
    assert outcome.evaluation.micro_f1 == 1.0
    assert outcome.complete
    assert outcome.successful_count == 1


def test_application_exposes_partial_and_failed_counts_without_terminal_policy():
    pipeline = FixturePipeline([
        ClassificationResult("VULN-1", "partial"),
        ClassificationResult("VULN-2", "failed"),
        ClassificationResult("VULN-3", "not_enough_information"),
    ])

    outcome = ClassificationApplication(pipeline).run(
        ["VULN-1", "VULN-2", "VULN-3"],
        taxonomy(),
    )

    assert outcome.partial_count == 1
    assert outcome.failed_count == 1
    assert outcome.successful_count == 1
    assert not outcome.complete


def test_application_preserves_primary_failure_and_reports_cleanup_separately(caplog):
    secret = "fixture-secret-value"

    class FailingPipeline:
        def run(self, *_):
            raise RuntimeError("primary pipeline failure")

    def cleanup():
        raise RuntimeError(f"cleanup exposed {secret}")

    with caplog.at_level(logging.ERROR, logger="cve_agent.application"):
        with pytest.raises(RuntimeError, match="primary pipeline failure"):
            ClassificationApplication(FailingPipeline(), close_resources=cleanup).run([], taxonomy())

    assert "secondary resource cleanup failure" in caplog.text
    assert "RuntimeError" in caplog.text
    assert secret not in caplog.text


def test_application_surfaces_cleanup_only_failure_and_attempts_every_resource(caplog):
    calls = []

    def first():
        calls.append("first")
        raise RuntimeError("first cleanup failure")

    def second():
        calls.append("second")
        raise ValueError("second cleanup failure")

    with caplog.at_level(logging.ERROR, logger="cve_agent.application"):
        with pytest.raises(RuntimeError, match="first cleanup failure"):
            ClassificationApplication(
                FixturePipeline([]),
                close_resources=(first, second),
            ).run([], taxonomy())

    assert calls == ["first", "second"]
    assert "cleanup_type=ValueError" in caplog.text
