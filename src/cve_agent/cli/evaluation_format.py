from __future__ import annotations

from cve_agent.classification.evaluation import EvaluationReport
from cve_agent.core.results import ClassificationResult, ClassificationStatus


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


def _format_table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    widths = [
        max([len(header), *(len(row[index]) for row in rows)])
        for index, header in enumerate(headers)
    ]

    def render(row: tuple[str, ...], separator: str = " | ") -> str:
        return separator.join(value.ljust(widths[index]) for index, value in enumerate(row)).rstrip()

    divider = "-+-".join("-" * width for width in widths)
    return "\n".join((render(headers), divider, *(render(row) for row in rows)))
