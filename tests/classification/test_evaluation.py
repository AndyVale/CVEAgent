from pathlib import Path
import json

import pytest

from cve_agent.classification.evaluation import (
    Benchmark,
    BenchmarkCase,
    BenchmarkError,
    evaluate_results,
    load_benchmark,
)
from cve_agent.cli.evaluation_format import format_classification_summary, format_evaluation_report
from cve_agent.core.results import ClassificationResult, LabelClassification
from cve_agent.core.taxonomy import Taxonomy, TaxonomyLabel, load_taxonomy
from cve_agent.core.taxonomy import taxonomy_fingerprint


FIXTURES = Path(__file__).parents[2] / "fixtures"
DEMO_NAMES = ("flat", "hierarchical", "hybrid")


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
        "schema_version": 1,
        "taxonomy_sha256": taxonomy_fingerprint(selected_taxonomy),
        "cases": [
            {"cve_id": "CVE-2020-0001", "labels": ["A"], "rationale": "clear", "sources": ["https://source.test"]},
            {"cve_id": "CVE-2020-0002", "labels": ["B"]},
        ],
    }), encoding="utf-8")

    benchmark = load_benchmark(path, selected_taxonomy).select(["CVE-2020-0002"])
    assert benchmark.cve_ids == ["CVE-2020-0002"]

    path.write_text(json.dumps({"schema_version": 1, "taxonomy_sha256": "wrong", "cases": [{"cve_id": "CVE-2020-0001", "labels": ["A"]}]}), encoding="utf-8")
    with pytest.raises(BenchmarkError, match="fingerprint"):
        load_benchmark(path, selected_taxonomy)


@pytest.mark.parametrize("version", [None, True, "1", 2])
def test_load_benchmark_requires_supported_schema_version(tmp_path, version):
    selected_taxonomy = taxonomy()
    payload = {
        "taxonomy_sha256": taxonomy_fingerprint(selected_taxonomy),
        "cases": [{"cve_id": "CVE-2020-0001", "labels": ["A"]}],
    }
    if version is not None:
        payload["schema_version"] = version
    path = tmp_path / "expected.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(BenchmarkError, match="schema_version 1"):
        load_benchmark(path, selected_taxonomy)


@pytest.mark.parametrize("fingerprint", [None, "", 123, "0" * 64])
def test_load_benchmark_requires_matching_fingerprint(tmp_path, fingerprint):
    payload = {
        "schema_version": 1,
        "cases": [{"cve_id": "CVE-2020-0001", "labels": ["A"]}],
    }
    if fingerprint is not None:
        payload["taxonomy_sha256"] = fingerprint
    path = tmp_path / "expected.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(BenchmarkError, match="fingerprint"):
        load_benchmark(path, taxonomy())


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
        "======================",
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


def _fixture_pair(name):
    selected_taxonomy = load_taxonomy(FIXTURES / name / "taxonomy.json")
    benchmark = load_benchmark(
        FIXTURES / name / "expected-classification.json",
        selected_taxonomy,
    )
    return selected_taxonomy, benchmark


def _depth(taxonomy, label_id):
    result = 1
    while taxonomy.by_id[label_id].parent:
        label_id = taxonomy.by_id[label_id].parent
        result += 1
    return result


def _root(taxonomy, label_id):
    while taxonomy.by_id[label_id].parent:
        label_id = taxonomy.by_id[label_id].parent
    return label_id


def _project(hybrid_taxonomy, labels, maximum_depth):
    projected = []
    for label_id in labels:
        while _depth(hybrid_taxonomy, label_id) > maximum_depth:
            label_id = hybrid_taxonomy.by_id[label_id].parent
        if label_id not in projected:
            projected.append(label_id)
    return tuple(projected)


def test_demo_fixtures_share_the_standard_ordered_50_case_benchmark():
    fixtures = {name: _fixture_pair(name) for name in DEMO_NAMES}
    hybrid_benchmark = fixtures["hybrid"][1]

    assert len(hybrid_benchmark.cases) == 50
    assert len(set(hybrid_benchmark.cve_ids)) == 50
    for name, (_, benchmark) in fixtures.items():
        raw = json.loads(
            (FIXTURES / name / "expected-classification.json").read_text(encoding="utf-8")
        )
        assert set(raw) == {"schema_version", "taxonomy_sha256", "cases"}
        assert benchmark.cve_ids == hybrid_benchmark.cve_ids
        assert all(case.rationale and case.sources for case in benchmark.cases)
        assert [case.sources for case in benchmark.cases] == [
            case.sources for case in hybrid_benchmark.cases
        ]

    for aligned_cases in zip(*(fixtures[name][1].cases for name in DEMO_NAMES), strict=True):
        assert len({case.rationale for case in aligned_cases}) == len(DEMO_NAMES)


def test_demo_taxonomies_are_progressively_finer_hybrid_projections():
    flat, _ = _fixture_pair("flat")
    hierarchical, _ = _fixture_pair("hierarchical")
    hybrid, _ = _fixture_pair("hybrid")

    assert all(
        taxonomy.hierarchy_policy.value == "most_specific"
        for taxonomy in (flat, hierarchical, hybrid)
    )

    hybrid_roots = tuple(label.id for label in hybrid.labels if label.parent is None)
    hybrid_two_levels = tuple(label.id for label in hybrid.labels if _depth(hybrid, label.id) <= 2)

    assert flat.name == "Flat Vulnerability Mechanisms"
    assert len(flat.labels) == 9
    assert tuple(label.id for label in flat.labels) == hybrid_roots
    assert all(label.parent is None for label in flat.labels)

    assert hierarchical.name == "Hierarchical Vulnerability Mechanisms"
    assert len(hierarchical.labels) == 39
    assert tuple(label.id for label in hierarchical.labels) == hybrid_two_levels
    assert len([label for label in hierarchical.labels if label.parent is None]) == 9
    assert max(_depth(hierarchical, label.id) for label in hierarchical.labels) == 2

    assert hybrid.name == "Adaptive Vulnerability Mechanisms"
    assert len(hybrid.labels) == 84
    assert len(hybrid_roots) == 9
    assert max(_depth(hybrid, label.id) for label in hybrid.labels) == 4

    for projection in (flat, hierarchical):
        for label in projection.labels:
            reference = hybrid.by_id[label.id]
            assert (label.name, label.description, label.parent) == (
                reference.name,
                reference.description,
                reference.parent,
            )


def test_projected_expected_labels_exactly_match_hybrid_expectations():
    flat_taxonomy, flat_benchmark = _fixture_pair("flat")
    hierarchical_taxonomy, hierarchical_benchmark = _fixture_pair("hierarchical")
    hybrid_taxonomy, hybrid_benchmark = _fixture_pair("hybrid")

    for flat_case, hierarchical_case, hybrid_case in zip(
        flat_benchmark.cases,
        hierarchical_benchmark.cases,
        hybrid_benchmark.cases,
        strict=True,
    ):
        assert flat_case.labels == _project(hybrid_taxonomy, hybrid_case.labels, 1)
        assert hierarchical_case.labels == _project(hybrid_taxonomy, hybrid_case.labels, 2)

    multi_case_ids = {
        case.cve_id for case in hybrid_benchmark.cases if len(case.labels) > 1
    }
    assert len(multi_case_ids) == 7
    for taxonomy, benchmark in (
        (flat_taxonomy, flat_benchmark),
        (hierarchical_taxonomy, hierarchical_benchmark),
        (hybrid_taxonomy, hybrid_benchmark),
    ):
        assert {case.cve_id for case in benchmark.cases if len(case.labels) > 1} == multi_case_ids
        for case in benchmark.cases:
            assert len({_root(taxonomy, label_id) for label_id in case.labels}) == len(case.labels)


def test_hybrid_fixture_has_prunable_semantic_hierarchy_and_50_curated_cases():
    selected_taxonomy = load_taxonomy(FIXTURES / "hybrid" / "taxonomy.json")
    benchmark = load_benchmark(FIXTURES / "hybrid" / "expected-classification.json", selected_taxonomy)
    roots = [label for label in selected_taxonomy.labels if label.parent is None]
    by_cve = {case.cve_id: case.labels for case in benchmark.cases}

    assert selected_taxonomy.name == "Adaptive Vulnerability Mechanisms"
    assert len(selected_taxonomy.labels) == 84
    assert len(roots) == 9
    assert max(_depth(selected_taxonomy, label.id) for label in selected_taxonomy.labels) == 4
    assert len(benchmark.cases) == 50
    assert len(set(benchmark.cve_ids)) == 50
    assert all(case.rationale and case.sources for case in benchmark.cases)
    assert sum(len(case.labels) > 1 for case in benchmark.cases) == 7
    assert selected_taxonomy.by_id["CodeInjection"].name == "General-Purpose Source Evaluation"
    assert selected_taxonomy.by_id["CodeInjection"].parent == "DynamicCodeEvaluation"
    assert selected_taxonomy.by_id["CommandInjection"].parent == "CommandConstruction"
    assert selected_taxonomy.by_id["AuthenticationBypass"].parent == "AuthenticationWeakness"
    assert selected_taxonomy.by_id["ZipSlip"].parent == "PathTraversal"
    assert selected_taxonomy.by_id["IDOR"].parent == "ImproperAuthorization"
    assert len({label.name for label in selected_taxonomy.labels}) == len(selected_taxonomy.labels)
    assert by_cve["CVE-2021-44228"] == ("InterpreterInjection", "SSRF")
    assert by_cve["CVE-2020-1472"] == ("AuthenticationBypass", "ReusedNonce")
    assert by_cve["CVE-2021-26855"] == ("SSRF", "AuthenticationBypass")
    assert by_cve["CVE-2021-41773"] == ("CommandInjection", "PathTraversal")
    assert by_cve["CVE-2018-9206"] == ("DangerousFileTypeUpload", "ImproperAuthorization")
    assert by_cve["CVE-2021-36741"] == ("FileUploadControl",)
    assert by_cve["CVE-2018-15961"] == ("DangerousFileTypeUpload",)
    assert by_cve["CVE-2024-38475"] == ("PathAndResourceSelection",)
    assert by_cve["CVE-2026-8452"] == ("SpatialMemorySafety",)


def test_hybrid_fixture_expected_labels_are_normalized_and_multi_mechanism_cases_remain_multi_label():
    selected_taxonomy = load_taxonomy(FIXTURES / "hybrid" / "taxonomy.json")
    benchmark = load_benchmark(FIXTURES / "hybrid" / "expected-classification.json", selected_taxonomy)

    def ancestors(label_id):
        result = set()
        parent = selected_taxonomy.by_id[label_id].parent
        while parent:
            result.add(parent)
            parent = selected_taxonomy.by_id[parent].parent
        return result

    multi_label_cases = 0
    for case in benchmark.cases:
        selected = set(case.labels)
        assert not any(ancestors(label_id) & selected for label_id in selected)
        multi_label_cases += len(selected) > 1

    assert multi_label_cases == 7


def test_fixture_taxonomy_and_benchmark_ids_are_not_hard_coded_in_production():
    fixture_values = set()
    for taxonomy_name, benchmark_name in (
        ("flat/taxonomy.json", "flat/expected-classification.json"),
        ("hierarchical/taxonomy.json", "hierarchical/expected-classification.json"),
        ("hybrid/taxonomy.json", "hybrid/expected-classification.json"),
    ):
        taxonomy_payload = json.loads((FIXTURES / taxonomy_name).read_text(encoding="utf-8"))
        benchmark_payload = json.loads((FIXTURES / benchmark_name).read_text(encoding="utf-8"))
        assert set(benchmark_payload) == {"schema_version", "taxonomy_sha256", "cases"}
        fixture_values.update(item["id"] for item in taxonomy_payload["labels"])
        fixture_values.update(item["cve_id"] for item in benchmark_payload["cases"])
    production = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (FIXTURES.parent / "src" / "cve_agent").glob("*.py")
    )

    assert all(value not in production for value in fixture_values)
    all_production = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (FIXTURES.parent / "src" / "cve_agent").rglob("*.py")
    )
    assert "taxonomy_readme.md" not in all_production
