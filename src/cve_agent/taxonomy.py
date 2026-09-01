from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from cve_agent.serialization import json_fingerprint


MAX_TAXONOMY_DEPTH = 64


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
    extra: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "extra", MappingProxyType(dict(self.extra)))


@dataclass(frozen=True)
class Taxonomy:
    labels: tuple[TaxonomyLabel, ...]
    hierarchy_policy: HierarchyPolicy = HierarchyPolicy.MOST_SPECIFIC
    name: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)
    source_path: str | None = field(default=None, compare=False)
    _by_id: Mapping[str, TaxonomyLabel] = field(init=False, repr=False, compare=False)
    _children_by_id: Mapping[str, tuple[TaxonomyLabel, ...]] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "extra", MappingProxyType(dict(self.extra)))
        by_id = {label.id: label for label in self.labels}
        children: dict[str, list[TaxonomyLabel]] = {}
        for label in self.labels:
            if label.parent is not None:
                children.setdefault(label.parent, []).append(label)
        object.__setattr__(self, "_by_id", MappingProxyType(by_id))
        object.__setattr__(
            self,
            "_children_by_id",
            MappingProxyType({label_id: tuple(values) for label_id, values in children.items()}),
        )

    @property
    def by_id(self) -> Mapping[str, TaxonomyLabel]:
        return self._by_id

    def children_of(self, label_id: str) -> tuple[TaxonomyLabel, ...]:
        return self._children_by_id.get(label_id, ())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.extra,
            **({"name": self.name} if self.name else {}),
            "hierarchy_policy": self.hierarchy_policy.value,
            "labels": [
                {
                    "id": label.id,
                    "name": label.name,
                    "description": label.description,
                    **({"parent": label.parent} if label.parent else {}),
                    **label.extra,
                }
                for label in self.labels
            ],
        }

    @property
    def fingerprint(self) -> str:
        return json_fingerprint(self.to_dict())

    @property
    def display_name(self) -> str:
        if self.name:
            return self.name
        if self.source_path:
            return Path(self.source_path).stem
        return f"Taxonomy {self.fingerprint[:12]}"


def load_taxonomy(path: str | Path) -> Taxonomy:
    taxonomy_path = Path(path)
    try:
        with taxonomy_path.open(encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise TaxonomyError(f"cannot read taxonomy from {taxonomy_path}: {exc}") from exc
    taxonomy = parse_taxonomy(raw)
    return Taxonomy(
        taxonomy.labels,
        taxonomy.hierarchy_policy,
        taxonomy.name,
        taxonomy.extra,
        str(taxonomy_path.resolve()),
    )


def parse_taxonomy(raw: Any) -> Taxonomy:
    """Validate and materialize a taxonomy from a decoded JSON value."""
    entries = raw.get("labels") if isinstance(raw, dict) else raw
    policy_value = (
        raw.get("hierarchy_policy", HierarchyPolicy.MOST_SPECIFIC.value)
        if isinstance(raw, dict)
        else HierarchyPolicy.MOST_SPECIFIC.value
    )
    try:
        hierarchy_policy = HierarchyPolicy(policy_value)
    except (TypeError, ValueError) as exc:
        raise TaxonomyError(f"invalid hierarchy_policy: {policy_value!r}") from exc
    if not isinstance(entries, list):
        raise TaxonomyError("taxonomy must be a JSON array or an object with a labels array")
    if not entries:
        raise TaxonomyError("taxonomy must contain at least one label")
    labels: list[TaxonomyLabel] = []
    ids: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise TaxonomyError(f"label {index} must be an object")
        missing = [
            key
            for key in ("id", "name", "description")
            if not isinstance(entry.get(key), str) or not entry[key].strip()
        ]
        if missing:
            raise TaxonomyError(f"label {index} missing required fields: {', '.join(missing)}")
        label_id = entry["id"].strip()
        if label_id in ids:
            raise TaxonomyError(f"duplicate taxonomy ID: {label_id}")
        parent = entry.get("parent")
        if parent is not None and (not isinstance(parent, str) or not parent.strip()):
            raise TaxonomyError(f"invalid parent for label: {label_id}")
        parent = parent.strip() if isinstance(parent, str) else None
        ids.add(label_id)
        labels.append(
            TaxonomyLabel(
                label_id,
                entry["name"].strip(),
                entry["description"].strip(),
                parent,
                {key: value for key, value in entry.items() if key not in {"id", "name", "description", "parent"}},
            )
        )
    for label in labels:
        if label.parent is not None and label.parent not in ids:
            raise TaxonomyError(f"parent {label.parent!r} for {label.id!r} does not exist")
    by_id = {label.id: label for label in labels}
    for label in labels:
        seen: set[str] = set()
        current = label.id
        depth = 0
        while by_id[current].parent is not None:
            if current in seen:
                raise TaxonomyError(f"cyclic taxonomy hierarchy involving {current!r}")
            seen.add(current)
            current = by_id[current].parent  # type: ignore[assignment]
            depth += 1
            if depth > MAX_TAXONOMY_DEPTH:
                raise TaxonomyError(f"taxonomy hierarchy exceeds maximum depth {MAX_TAXONOMY_DEPTH}")

    name: str | None = None
    extra: dict[str, Any] = {}
    if isinstance(raw, dict):
        raw_name = raw.get("name")
        if raw_name is not None:
            if not isinstance(raw_name, str) or not raw_name.strip():
                raise TaxonomyError("taxonomy name must be a non-empty string")
            name = raw_name.strip()
        extra = {
            key: value
            for key, value in raw.items()
            if key not in {"labels", "hierarchy_policy", "name"}
        }
    return Taxonomy(tuple(labels), hierarchy_policy, name, extra)


def taxonomy_fingerprint(taxonomy: Taxonomy) -> str:
    return taxonomy.fingerprint
