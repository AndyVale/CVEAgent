from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

from cve_agent.models import Evidence, LabelClassification
from cve_agent.taxonomy import HierarchyPolicy, Taxonomy, TaxonomyLabel


@dataclass(frozen=True)
class TaxonomyChunk:
    chunk_id: int
    labels: tuple[TaxonomyLabel, ...]


@dataclass(frozen=True)
class TaxonomyTree:
    roots: tuple[TaxonomyLabel, ...]
    children: dict[str, tuple[TaxonomyLabel, ...]]
    by_id: dict[str, TaxonomyLabel]

    def descendants(self, label_id: str) -> tuple[TaxonomyLabel, ...]:
        result: list[TaxonomyLabel] = []

        def visit(parent_id: str) -> None:
            for child in self.children[parent_id]:
                result.append(child)
                visit(child.id)

        visit(label_id)
        return tuple(result)

    def ancestor_path(self, label_id: str) -> tuple[TaxonomyLabel, ...]:
        path: list[TaxonomyLabel] = []
        parent = self.by_id[label_id].parent
        while parent:
            path.append(self.by_id[parent])
            parent = self.by_id[parent].parent
        return tuple(reversed(path))

    def paths_from(
        self,
        labels: tuple[TaxonomyLabel, ...] | list[TaxonomyLabel],
    ) -> tuple[tuple[TaxonomyLabel, ...], ...]:
        """Return every path from the supplied frontier to its reachable leaves."""
        paths: list[tuple[TaxonomyLabel, ...]] = []

        def visit(label: TaxonomyLabel, path: tuple[TaxonomyLabel, ...]) -> None:
            current = (*path, label)
            children = self.children[label.id]
            if not children:
                paths.append(current)
                return
            for child in children:
                visit(child, current)

        for label in labels:
            visit(label, ())
        return tuple(paths)

    def root_to_leaf_paths(self) -> tuple[tuple[TaxonomyLabel, ...], ...]:
        return self.paths_from(self.roots)


def estimate_tokens(value: object) -> int:
    """Return a conservative provider-neutral token estimate."""
    serialized = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return max(1, (len(serialized) + 2) // 3)


def chunk_taxonomy(taxonomy: Taxonomy, *, available_tokens: int) -> tuple[TaxonomyChunk, ...]:
    """Partition every label exactly once while keeping hierarchy neighbors adjacent."""
    return chunk_labels(hierarchy_order(taxonomy), available_tokens=available_tokens, render=_label_dict)


def chunk_labels(
    labels: tuple[TaxonomyLabel, ...] | list[TaxonomyLabel],
    *,
    available_tokens: int,
    render: Callable[[TaxonomyLabel], object] = lambda label: _label_dict(label),
) -> tuple[TaxonomyChunk, ...]:
    """Partition an ordered label sequence into token-bounded chunks."""
    if available_tokens <= 0:
        raise ValueError("available taxonomy tokens must be positive")
    chunks: list[TaxonomyChunk] = []
    current: list[TaxonomyLabel] = []
    current_tokens = 0
    for label in labels:
        label_tokens = estimate_tokens(render(label))
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


def routing_label_dict(tree: TaxonomyTree, label: TaxonomyLabel) -> dict[str, object]:
    return {
        **_label_dict(label),
        "ancestor_path": [
            {"id": ancestor.id, "name": ancestor.name}
            for ancestor in tree.ancestor_path(label.id)
        ],
        "children": [
            {"id": child.id, "name": child.name}
            for child in tree.children[label.id]
        ],
    }


def build_taxonomy_tree(taxonomy: Taxonomy) -> TaxonomyTree:
    children: dict[str, list[TaxonomyLabel]] = {label.id: [] for label in taxonomy.labels}
    roots: list[TaxonomyLabel] = []
    for label in taxonomy.labels:
        if label.parent:
            children[label.parent].append(label)
        else:
            roots.append(label)
    return TaxonomyTree(
        tuple(roots),
        {label_id: tuple(items) for label_id, items in children.items()},
        taxonomy.by_id,
    )


def is_hierarchical(taxonomy: Taxonomy) -> bool:
    return any(label.parent is not None for label in taxonomy.labels)


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


def hierarchy_order(taxonomy: Taxonomy) -> list[TaxonomyLabel]:
    tree = build_taxonomy_tree(taxonomy)
    ordered: list[TaxonomyLabel] = []

    def visit(label_id: str) -> None:
        ordered.append(tree.by_id[label_id])
        for child in tree.children[label_id]:
            visit(child.id)

    for root in tree.roots:
        visit(root.id)
    return ordered


def _label_dict(label: TaxonomyLabel) -> dict[str, object]:
    return {
        "id": label.id,
        "name": label.name,
        "description": label.description,
        **({"parent": label.parent} if label.parent else {}),
    }
