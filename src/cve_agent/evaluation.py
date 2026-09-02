from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from cve_agent.models import ClassificationResult, ClassificationStatus
from cve_agent.identifiers import CVEIdentifierError, normalize_cve_id
from cve_agent.taxonomy import Taxonomy, taxonomy_fingerprint


class BenchmarkError(ValueError):
    """Raised when an expected-classification benchmark is invalid."""


@dataclass(frozen=True)
class BenchmarkCase:
    cve_id: str
    labels: tuple[str, ...]
    rationale: str = ""
    sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class Benchmark:
    cases: tuple[BenchmarkCase, ...]
    taxonomy_sha256: str | None = None

    @property
    def cve_ids(self) -> list[str]:
        return [case.cve_id for case in self.cases]

    def select(self, cve_ids: Iterable[str]) -> Benchmark:
        try:
            requested = [normalize_cve_id(cve_id) for cve_id in cve_ids]
        except CVEIdentifierError as exc:
            raise BenchmarkError(str(exc)) from exc
        if len(requested) != len(set(requested)):
            raise BenchmarkError("evaluation CVE IDs must be unique")
        by_id = {case.cve_id: case for case in self.cases}
        unknown = [cve_id for cve_id in requested if cve_id not in by_id]
        if unknown:
            raise BenchmarkError(f"CVE IDs missing from expected classifications: {unknown}")
        return Benchmark(tuple(by_id[cve_id] for cve_id in requested), self.taxonomy_sha256)


@dataclass(frozen=True)
class LabelMetrics:
    label: str
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float


@dataclass(frozen=True)
class CaseComparison:
    cve_id: str
    expected: tuple[str, ...]
    predicted: tuple[str, ...]
    status: ClassificationStatus

    @property
    def exact(self) -> bool:
        return set(self.expected) == set(self.predicted) and self.status not in {
            ClassificationStatus.PARTIAL,
            ClassificationStatus.FAILED,
        }

    @property
    def precision(self) -> float:
        expected, predicted = set(self.expected), set(self.predicted)
        if not expected and not predicted:
            return 1.0
        return _ratio(len(expected & predicted), len(predicted))

    @property
    def recall(self) -> float:
        expected, predicted = set(self.expected), set(self.predicted)
        if not expected and not predicted:
            return 1.0
        return _ratio(len(expected & predicted), len(expected))

    @property
    def f1(self) -> float:
        return _f1(self.precision, self.recall)


@dataclass(frozen=True)
class EvaluationReport:
    comparisons: tuple[CaseComparison, ...]
    per_label: tuple[LabelMetrics, ...]
    exact_matches: int
    micro_precision: float
    micro_recall: float
    micro_f1: float
    macro_f1: float

    @property
    def case_count(self) -> int:
        return len(self.comparisons)

    @property
    def incomplete_count(self) -> int:
        return sum(item.status in {ClassificationStatus.PARTIAL, ClassificationStatus.FAILED} for item in self.comparisons)


def load_benchmark(path: str | Path, taxonomy: Taxonomy) -> Benchmark:
    benchmark_path = Path(path)
    try:
        raw = json.loads(benchmark_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"cannot read expected classifications from {benchmark_path}: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("cases"), list):
        raise BenchmarkError("expected classifications must be an object with a cases array")

    expected_fingerprint = raw.get("taxonomy_sha256")
    if expected_fingerprint is not None:
        if not isinstance(expected_fingerprint, str) or expected_fingerprint != taxonomy_fingerprint(taxonomy):
            raise BenchmarkError("expected classifications do not match the supplied taxonomy fingerprint")

    cases: list[BenchmarkCase] = []
    seen_cves: set[str] = set()
    taxonomy_ids = set(taxonomy.by_id)
    for index, entry in enumerate(raw["cases"]):
        if not isinstance(entry, dict):
            raise BenchmarkError(f"expected case {index} must be an object")
        raw_cve_id = entry.get("cve_id")
        labels = entry.get("labels")
        try:
            cve_id = normalize_cve_id(raw_cve_id)
        except CVEIdentifierError as exc:
            raise BenchmarkError(f"expected case {index} has an invalid cve_id: {raw_cve_id!r}") from exc
        if cve_id in seen_cves:
            raise BenchmarkError(f"duplicate expected CVE ID: {cve_id}")
        if not isinstance(labels, list) or any(not isinstance(label, str) or not label for label in labels):
            raise BenchmarkError(f"expected case {cve_id} requires a labels array of strings")
        if len(labels) != len(set(labels)):
            raise BenchmarkError(f"expected case {cve_id} contains duplicate labels")
        unknown_labels = [label for label in labels if label not in taxonomy_ids]
        if unknown_labels:
            raise BenchmarkError(f"expected case {cve_id} uses labels outside the taxonomy: {unknown_labels}")
        rationale = entry.get("rationale", "")
        sources = entry.get("sources", [])
        if not isinstance(rationale, str) or not isinstance(sources, list) or any(not isinstance(url, str) or not url for url in sources):
            raise BenchmarkError(f"expected case {cve_id} has invalid rationale or sources")
        seen_cves.add(cve_id)
        cases.append(BenchmarkCase(cve_id, tuple(labels), rationale.strip(), tuple(sources)))

    if not cases:
        raise BenchmarkError("expected classifications must contain at least one case")
    return Benchmark(tuple(cases), expected_fingerprint)


def evaluate_results(results: list[ClassificationResult], benchmark: Benchmark, taxonomy: Taxonomy) -> EvaluationReport:
    by_cve: dict[str, ClassificationResult] = {}
    for result in results:
        if result.cve_id in by_cve:
            raise BenchmarkError(f"duplicate classification result for {result.cve_id}")
        by_cve[result.cve_id] = result
    missing = [case.cve_id for case in benchmark.cases if case.cve_id not in by_cve]
    if missing:
        raise BenchmarkError(f"missing classification results for expected CVEs: {missing}")

    taxonomy_order = {label.id: position for position, label in enumerate(taxonomy.labels)}
    comparisons: list[CaseComparison] = []
    for case in benchmark.cases:
        result = by_cve[case.cve_id]
        predicted_set = {label.label for label in result.labels}
        unknown_predictions = sorted(predicted_set - set(taxonomy_order))
        if unknown_predictions:
            raise BenchmarkError(f"classification result {case.cve_id} uses labels outside the taxonomy: {unknown_predictions}")
        predicted = tuple(sorted(predicted_set, key=taxonomy_order.__getitem__))
        comparisons.append(CaseComparison(case.cve_id, case.labels, predicted, result.status))

    per_label: list[LabelMetrics] = []
    total_tp = total_fp = total_fn = 0
    for label in taxonomy.labels:
        tp = fp = fn = 0
        for comparison in comparisons:
            expected = label.id in comparison.expected
            predicted = label.id in comparison.predicted
            tp += int(expected and predicted)
            fp += int(not expected and predicted)
            fn += int(expected and not predicted)
        precision = _ratio(tp, tp + fp)
        recall = _ratio(tp, tp + fn)
        f1 = _f1(precision, recall)
        per_label.append(LabelMetrics(label.id, tp, fp, fn, precision, recall, f1))
        total_tp += tp
        total_fp += fp
        total_fn += fn

    micro_precision = _ratio(total_tp, total_tp + total_fp)
    micro_recall = _ratio(total_tp, total_tp + total_fn)
    scored_labels = [item for item in per_label if item.true_positives + item.false_positives + item.false_negatives]
    return EvaluationReport(
        tuple(comparisons),
        tuple(per_label),
        sum(item.exact for item in comparisons),
        micro_precision,
        micro_recall,
        _f1(micro_precision, micro_recall),
        sum(item.f1 for item in scored_labels) / len(scored_labels) if scored_labels else 0.0,
    )


def format_classification_summary(results: list[ClassificationResult], report: EvaluationReport | None = None) -> str:
    comparison_by_cve = {item.cve_id: item for item in report.comparisons} if report else {}
    rows: list[tuple[str, str, str, str, str]] = []
    for result in results:
        labels = ", ".join(label.label for label in result.labels)
        if not labels:
            labels = f"[{result.status.value}]"
        elif result.status != ClassificationStatus.CLASSIFIED:
            labels = f"{labels} [{result.status.value}]"
        comparison = comparison_by_cve.get(result.cve_id)
        metrics = (
            (f"{comparison.precision:.3f}", f"{comparison.recall:.3f}", f"{comparison.f1:.3f}")
            if comparison
            else ("-", "-", "-")
        )
        rows.append((result.cve_id, labels, *metrics))
    return _format_output_section(
        "Classification summary",
        _format_table(("ID", "Labels", "Precision", "Recall", "F1"), rows),
    )


def format_evaluation_report(report: EvaluationReport) -> str:
    lines = [
        f"  exact matches : {report.exact_matches}/{report.case_count}",
        f"  micro P/R/F1  : {report.micro_precision:.3f} / {report.micro_recall:.3f} / {report.micro_f1:.3f}",
        f"  macro F1      : {report.macro_f1:.3f}",
        f"  partial/failed: {report.incomplete_count}",
    ]
    active_labels = [item for item in report.per_label if item.true_positives + item.false_positives + item.false_negatives]
    if active_labels:
        width = max(len(item.label) for item in active_labels)
        lines.append("  per-label P/R/F1")
        lines.extend(
            f"    {item.label:<{width}} : {item.precision:.3f} / {item.recall:.3f} / {item.f1:.3f} "
            f"(TP={item.true_positives}, FP={item.false_positives}, FN={item.false_negatives})"
            for item in active_labels
        )
    mismatches = [item for item in report.comparisons if not item.exact]
    if mismatches:
        lines.append("  mismatches")
        for item in mismatches:
            expected = ", ".join(item.expected) or "none"
            predicted = ", ".join(item.predicted) or "none"
            lines.append(f"    {item.cve_id}: expected={expected}; predicted={predicted}; status={item.status.value}")
    return _format_output_section("Evaluation summary", "\n".join(lines))


def format_output_header(title: str) -> str:
    return f"{title}\n{'=' * len(title)}"


def _format_output_section(title: str, content: str) -> str:
    return f"{format_output_header(title)}\n{content}"


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _f1(precision: float, recall: float) -> float:
    return 2 * precision * recall / (precision + recall) if precision + recall else 0.0


def _format_table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    widths = [
        max([len(header), *(len(row[index]) for row in rows)])
        for index, header in enumerate(headers)
    ]

    def render(row: tuple[str, ...], separator: str = " | ") -> str:
        return separator.join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip()

    divider = "-+-".join("-" * width for width in widths)
    return "\n".join((render(headers), divider, *(render(row) for row in rows)))
