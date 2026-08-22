from __future__ import annotations

import json
from dataclasses import dataclass

from cve_agent.models import Evidence, LabelClassification
from cve_agent.taxonomy import HierarchyPolicy, Taxonomy, TaxonomyLabel


@dataclass(frozen=True)
class TaxonomyChunk:
    chunk_id: int
    labels: tuple[TaxonomyLabel, ...]


def estimate_tokens(value: object) -> int:
    """Return a conservative provider-neutral token estimate."""
    serialized = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return max(1, (len(serialized) + 2) // 3)


def chunk_taxonomy(taxonomy: Taxonomy, *, available_tokens: int) -> tuple[TaxonomyChunk, ...]:
    """Partition every label exactly once while keeping hierarchy neighbors adjacent."""
    if available_tokens <= 0:
        raise ValueError("available taxonomy tokens must be positive")
    ordered = _hierarchy_order(taxonomy)
    chunks: list[TaxonomyChunk] = []
    current: list[TaxonomyLabel] = []
    current_tokens = 0
    for label in ordered:
        label_tokens = estimate_tokens(_label_dict(label))
        if label_tokens > available_tokens:
            raise ValueError(f"taxonomy label {label.id!r} exceeds the per-request input limit")
        if current and current_tokens + label_tokens > available_tokens:
            chunks.append(TaxonomyChunk(len(chunks) + 1, tuple(current)))
            current, current_tokens = [], 0
        current.append(label)
        current_tokens += label_tokens
    if current:
        chunks.append(TaxonomyChunk(len(chunks) + 1, tuple(current)))
    return tuple(chunks)


def label_dict(label: TaxonomyLabel) -> dict[str, object]:
    return _label_dict(label)


def apply_hierarchy_policy(labels: list[LabelClassification], taxonomy: Taxonomy) -> list[LabelClassification]:
    by_id = taxonomy.by_id
    selected = {item.label: item for item in labels}
    if taxonomy.hierarchy_policy == HierarchyPolicy.MOST_SPECIFIC:
        ancestors: set[str] = set()
        for label_id in selected:
            parent = by_id[label_id].parent
            while parent:
                ancestors.add(parent)
                parent = by_id[parent].parent
        return [item for item in labels if item.label not in ancestors]

    additions: dict[str, LabelClassification] = {}
    for item in labels:
        parent = by_id[item.label].parent
        while parent:
            if parent not in selected and parent not in additions:
                evidence = tuple(Evidence(e.url, e.quote, f"Included through supported descendant {item.label}: {e.explanation}") for e in item.evidence)
                additions[parent] = LabelClassification(parent, item.confidence, evidence)
            parent = by_id[parent].parent
    return labels + [additions[label.id] for label in taxonomy.labels if label.id in additions]


def _hierarchy_order(taxonomy: Taxonomy) -> list[TaxonomyLabel]:
    by_id = taxonomy.by_id
    children: dict[str, list[str]] = {label.id: [] for label in taxonomy.labels}
    roots: list[str] = []
    for label in taxonomy.labels:
        if label.parent:
            children[label.parent].append(label.id)
        else:
            roots.append(label.id)
    ordered: list[TaxonomyLabel] = []

    def visit(label_id: str) -> None:
        ordered.append(by_id[label_id])
        for child_id in children[label_id]:
            visit(child_id)

    for root in roots:
        visit(root)
    return ordered


def _label_dict(label: TaxonomyLabel) -> dict[str, object]:
    return {
        "id": label.id,
        "name": label.name,
        "description": label.description,
        **({"parent": label.parent} if label.parent else {}),
    }
