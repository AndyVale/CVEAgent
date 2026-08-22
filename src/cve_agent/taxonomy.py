from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class TaxonomyError(ValueError):
    """Raised when a taxonomy violates the input contract."""


class HierarchyPolicy(StrEnum):
    MOST_SPECIFIC = "most_specific"
    INCLUDE_ANCESTORS = "include_ancestors"


@dataclass(frozen=True)
class TaxonomyLabel:
    id: str
    name: str
    description: str
    parent: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Taxonomy:
    labels: tuple[TaxonomyLabel, ...]
    hierarchy_policy: HierarchyPolicy = HierarchyPolicy.MOST_SPECIFIC

    @property
    def by_id(self) -> dict[str, TaxonomyLabel]:
        return {label.id: label for label in self.labels}

    def children_of(self, label_id: str) -> tuple[TaxonomyLabel, ...]:
        return tuple(label for label in self.labels if label.parent == label_id)

    def to_dict(self) -> dict[str, Any]:
        return {"hierarchy_policy": self.hierarchy_policy.value, "labels": [{"id": x.id, "name": x.name, "description": x.description, **({"parent": x.parent} if x.parent else {}), **x.extra} for x in self.labels]}


def load_taxonomy(path: str | Path) -> Taxonomy:
    with Path(path).open(encoding="utf-8") as handle:
        raw = json.load(handle)
    entries = raw.get("labels") if isinstance(raw, dict) else raw
    policy_value = raw.get("hierarchy_policy", HierarchyPolicy.MOST_SPECIFIC.value) if isinstance(raw, dict) else HierarchyPolicy.MOST_SPECIFIC.value
    try:
        hierarchy_policy = HierarchyPolicy(policy_value)
    except ValueError as exc:
        raise TaxonomyError(f"invalid hierarchy_policy: {policy_value!r}") from exc
    if not isinstance(entries, list):
        raise TaxonomyError("taxonomy must be a JSON array or an object with a labels array")
    labels: list[TaxonomyLabel] = []
    ids: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise TaxonomyError(f"label {index} must be an object")
        missing = [key for key in ("id", "name", "description") if not isinstance(entry.get(key), str) or not entry[key]]
        if missing:
            raise TaxonomyError(f"label {index} missing required fields: {', '.join(missing)}")
        label_id = entry["id"]
        if label_id in ids:
            raise TaxonomyError(f"duplicate taxonomy ID: {label_id}")
        parent = entry.get("parent")
        if parent is not None and (not isinstance(parent, str) or not parent):
            raise TaxonomyError(f"invalid parent for label: {label_id}")
        ids.add(label_id)
        labels.append(TaxonomyLabel(label_id, entry["name"], entry["description"], parent, {k: v for k, v in entry.items() if k not in {"id", "name", "description", "parent"}}))
    for label in labels:
        if label.parent is not None and label.parent not in ids:
            raise TaxonomyError(f"parent {label.parent!r} for {label.id!r} does not exist")
    by_id = {label.id: label for label in labels}
    for label in labels:
        seen: set[str] = set()
        current = label.id
        while by_id[current].parent is not None:
            if current in seen:
                raise TaxonomyError(f"cyclic taxonomy hierarchy involving {current!r}")
            seen.add(current)
            current = by_id[current].parent  # type: ignore[assignment]
    return Taxonomy(tuple(labels), hierarchy_policy)
