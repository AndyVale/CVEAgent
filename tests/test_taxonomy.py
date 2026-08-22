import json

import pytest

from cve_agent.taxonomy import HierarchyPolicy, TaxonomyError, load_taxonomy


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
