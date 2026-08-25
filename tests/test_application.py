from cve_agent.application import ClassificationApplication
from cve_agent.evaluation import Benchmark, BenchmarkCase
from cve_agent.models import ClassificationResult, LabelClassification
from cve_agent.taxonomy import Taxonomy, TaxonomyLabel


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
