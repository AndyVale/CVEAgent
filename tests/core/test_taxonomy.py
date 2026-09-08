import json

import pytest

from cve_agent.core.taxonomy import (
    MAX_TAXONOMY_DEPTH,
    HierarchyPolicy,
    TaxonomyError,
    load_taxonomy,
    parse_taxonomy,
)


def write_json(tmp_path, value):
    path = tmp_path / "taxonomy.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_loads_hierarchy_and_preserves_extra_fields(tmp_path):
    taxonomy = load_taxonomy(write_json(tmp_path, {"labels": [{"id": "CWE-1", "name": "Root", "description": "r", "x": 1}, {"id": "CWE-2", "name": "Child", "description": "c", "parent": "CWE-1"}]}))
    assert taxonomy.children_of("CWE-1")[0].id == "CWE-2"
    assert taxonomy.by_id["CWE-1"].extra == {"x": 1}
    assert taxonomy.hierarchy_policy == HierarchyPolicy.MOST_SPECIFIC


def test_loads_taxonomy_defined_hierarchy_policy(tmp_path):
    taxonomy = load_taxonomy(write_json(tmp_path, {"hierarchy_policy": "include_ancestors", "labels": [{"id": "root", "name": "Root", "description": "root"}]}))
    assert taxonomy.hierarchy_policy == HierarchyPolicy.INCLUDE_ANCESTORS


def test_rejects_invalid_hierarchy_policy(tmp_path):
    with pytest.raises(TaxonomyError, match="hierarchy_policy"):
        load_taxonomy(write_json(tmp_path, {"hierarchy_policy": "invented", "labels": []}))


@pytest.mark.parametrize("labels", [[{"id": "x", "name": "x", "description": "x"}, {"id": "x", "name": "y", "description": "y"}], [{"id": "x", "name": "x", "description": "x", "parent": "missing"}]])
def test_rejects_invalid_taxonomy(tmp_path, labels):
    with pytest.raises(TaxonomyError):
        load_taxonomy(write_json(tmp_path, labels))


def test_rejects_cycles(tmp_path):
    labels = [{"id": "a", "name": "a", "description": "a", "parent": "b"}, {"id": "b", "name": "b", "description": "b", "parent": "a"}]
    with pytest.raises(TaxonomyError, match="cyclic"):
        load_taxonomy(write_json(tmp_path, labels))


def test_preserves_trimmed_taxonomy_metadata_and_precomputes_children(tmp_path):
    taxonomy = load_taxonomy(write_json(tmp_path, {
        "name": "  Example taxonomy  ",
        "schema_version": 7,
        "labels": [
            {"id": " root ", "name": " Root ", "description": " Description "},
            {"id": "child", "name": "Child", "description": "Child description", "parent": " root "},
        ],
    }))

    assert taxonomy.name == "Example taxonomy"
    assert taxonomy.extra == {"schema_version": 7}
    assert taxonomy.children_of("root")[0].id == "child"
    assert taxonomy.to_dict()["name"] == "Example taxonomy"


@pytest.mark.parametrize("raw", [[], {"labels": []}, [{"id": "x", "name": " ", "description": "x"}]])
def test_rejects_empty_taxonomies_and_whitespace_fields(raw):
    with pytest.raises(TaxonomyError):
        parse_taxonomy(raw)


def test_rejects_taxonomies_over_the_safe_depth_limit():
    labels = [
        {
            "id": f"node-{index}",
            "name": f"Node {index}",
            "description": "Depth fixture",
            **({"parent": f"node-{index - 1}"} if index else {}),
        }
        for index in range(MAX_TAXONOMY_DEPTH + 2)
    ]

    with pytest.raises(TaxonomyError, match="maximum depth"):
        parse_taxonomy({"labels": labels})


def test_wraps_missing_and_malformed_taxonomy_files(tmp_path):
    with pytest.raises(TaxonomyError, match="cannot read taxonomy"):
        load_taxonomy(tmp_path / "missing.json")
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(TaxonomyError, match="cannot read taxonomy"):
        load_taxonomy(malformed)


def test_taxonomy_indexes_and_metadata_are_immutable(tmp_path):
    taxonomy = load_taxonomy(write_json(tmp_path, {
        "metadata": {"version": 1},
        "labels": [{"id": "root", "name": "Root", "description": "Root", "aliases": ["r"]}],
    }))

    with pytest.raises(TypeError):
        taxonomy.by_id["other"] = taxonomy.labels[0]  # type: ignore[index]
    with pytest.raises(TypeError):
        taxonomy.extra["metadata"] = {}  # type: ignore[index]
    with pytest.raises(TypeError):
        taxonomy.labels[0].extra["aliases"] = []  # type: ignore[index]
