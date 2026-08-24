import json
from pathlib import Path

import pytest

from cve_agent.evaluation import Benchmark, BenchmarkCase, BenchmarkError, evaluate_results, format_classification_summary, format_evaluation_report, load_benchmark, taxonomy_fingerprint
from cve_agent.models import ClassificationResult, LabelClassification
from cve_agent.taxonomy import Taxonomy, TaxonomyLabel, load_taxonomy


FIXTURES = Path(__file__).parents[1] / "fixtures"


def taxonomy():
    return Taxonomy((
        TaxonomyLabel("A", "Alpha", "First class."),
        TaxonomyLabel("B", "Beta", "Second class."),
    ))


def result(cve_id, labels, status="classified"):
    return ClassificationResult(cve_id, status, [LabelClassification(label, 0.9, ()) for label in labels])


def test_load_benchmark_validates_fingerprint_membership_and_selection(tmp_path):
    selected_taxonomy = taxonomy()
    path = tmp_path / "expected.json"
    path.write_text(json.dumps({
        "taxonomy_sha256": taxonomy_fingerprint(selected_taxonomy),
        "cases": [
            {"cve_id": "CVE-2020-0001", "labels": ["A"], "rationale": "clear", "sources": ["https://source.test"]},
            {"cve_id": "CVE-2020-0002", "labels": ["B"]},
        ],
    }), encoding="utf-8")

    benchmark = load_benchmark(path, selected_taxonomy).select(["CVE-2020-0002"])
    assert benchmark.cve_ids == ["CVE-2020-0002"]

    path.write_text(json.dumps({"taxonomy_sha256": "wrong", "cases": [{"cve_id": "CVE-2020-0001", "labels": ["A"]}]}), encoding="utf-8")
    with pytest.raises(BenchmarkError, match="fingerprint"):
        load_benchmark(path, selected_taxonomy)


def test_evaluation_reports_micro_macro_exact_and_mismatches():
    benchmark = Benchmark((
        BenchmarkCase("CVE-2020-0001", ("A",)),
        BenchmarkCase("CVE-2020-0002", ("B",)),
    ))
    report = evaluate_results([
        result("CVE-2020-0001", ["A"]),
        result("CVE-2020-0002", ["A"], "partial"),
    ], benchmark, taxonomy())

    assert report.exact_matches == 1
    assert report.micro_precision == 0.5
    assert report.micro_recall == 0.5
    assert report.micro_f1 == 0.5
    assert report.macro_f1 == pytest.approx(1 / 3)
    assert report.incomplete_count == 1
    formatted = format_evaluation_report(report)
    assert "exact matches : 1/2" in formatted
    assert "A : 0.500 / 1.000 / 0.667 (TP=1, FP=1, FN=0)" in formatted
    assert "B : 0.000 / 0.000 / 0.000 (TP=0, FP=0, FN=1)" in formatted
    assert "CVE-2020-0002: expected=B; predicted=A; status=partial" in formatted


def test_compact_classification_summary_preserves_input_order_and_status():
    formatted = format_classification_summary([
        result("CVE-2020-0001", ["A", "B"]),
        result("CVE-2020-0002", [], "no_matching_label"),
        result("CVE-2020-0003", ["A"], "partial"),
    ])
    assert formatted.splitlines() == [
        "Classification summary",
        "ID            | Labels              | Precision | Recall | F1",
        "--------------+---------------------+-----------+--------+---",
        "CVE-2020-0001 | A, B                | -         | -      | -",
        "CVE-2020-0002 | [no_matching_label] | -         | -      | -",
        "CVE-2020-0003 | A [partial]         | -         | -      | -",
    ]


def test_validated_classification_summary_includes_per_case_metrics():
    selected_taxonomy = taxonomy()
    benchmark = Benchmark((
        BenchmarkCase("CVE-2020-0001", ("A", "B")),
        BenchmarkCase("CVE-2020-0002", ("B",)),
    ))
    results = [
        result("CVE-2020-0001", ["A"]),
        result("CVE-2020-0002", ["B"]),
    ]
    report = evaluate_results(results, benchmark, selected_taxonomy)
    formatted = format_classification_summary(results, report)

    assert "CVE-2020-0001 | A      | 1.000     | 0.500  | 0.667" in formatted
    assert "CVE-2020-0002 | B      | 1.000     | 1.000  | 1.000" in formatted


def test_curated_fixture_matches_and_covers_the_unchanged_example_taxonomy():
    selected_taxonomy = load_taxonomy(FIXTURES / "example_taxonomy.json")
    benchmark = load_benchmark(FIXTURES / "expected-classification.json", selected_taxonomy)
    expected_labels = {label for case in benchmark.cases for label in case.labels}

    assert len(benchmark.cases) == 14
    assert expected_labels == set(selected_taxonomy.by_id)
    assert all(case.rationale and case.sources for case in benchmark.cases)


def test_example_taxonomy_and_benchmark_ids_are_not_hard_coded_in_production():
    taxonomy_payload = json.loads((FIXTURES / "example_taxonomy.json").read_text(encoding="utf-8"))
    benchmark_payload = json.loads((FIXTURES / "expected-classification.json").read_text(encoding="utf-8"))
    fixture_values = {item["id"] for item in taxonomy_payload["labels"]}
    fixture_values.update(item["cve_id"] for item in benchmark_payload["cases"])
    production = "\n".join(path.read_text(encoding="utf-8") for path in (FIXTURES.parent / "src" / "cve_agent").glob("*.py"))

    assert all(value not in production for value in fixture_values)
