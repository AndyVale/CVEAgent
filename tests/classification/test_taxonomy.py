from cve_agent.classification.taxonomy import (
    apply_hierarchy_policy,
    build_taxonomy_tree,
    chunk_taxonomy,
    routing_label_dict,
)
from cve_agent.core.results import Evidence, LabelClassification
from cve_agent.core.taxonomy import HierarchyPolicy, Taxonomy, TaxonomyLabel


def test_chunking_covers_every_arbitrary_label_once():
    taxonomy = Taxonomy(tuple(TaxonomyLabel(f"L-{index}", f"Label {index}", "A moderately long generic definition.") for index in range(20)))
    chunks = chunk_taxonomy(taxonomy, available_tokens=90)
    ids = [label.id for chunk in chunks for label in chunk.labels]
    assert len(chunks) > 1
    assert ids == [label.id for label in taxonomy.labels]


def test_most_specific_policy_removes_selected_ancestor():
    taxonomy = Taxonomy((TaxonomyLabel("ROOT", "Root", "root"), TaxonomyLabel("CHILD", "Child", "child", "ROOT")))
    evidence = (Evidence("https://source.test", "quote", "reason"),)
    result = apply_hierarchy_policy([LabelClassification("ROOT", .8, evidence), LabelClassification("CHILD", .9, evidence)], taxonomy)
    assert [item.label for item in result] == ["CHILD"]


def test_include_ancestors_policy_adds_parent():
    taxonomy = Taxonomy((TaxonomyLabel("ROOT", "Root", "root"), TaxonomyLabel("CHILD", "Child", "child", "ROOT")), HierarchyPolicy.INCLUDE_ANCESTORS)
    result = apply_hierarchy_policy([LabelClassification("CHILD", .9, (Evidence("https://source.test", "quote", "reason"),))], taxonomy)
    assert [item.label for item in result] == ["CHILD", "ROOT"]


def test_routing_label_exposes_ancestor_path_and_immediate_children():
    taxonomy = Taxonomy((
        TaxonomyLabel("ROOT", "Root", "root"),
        TaxonomyLabel("CHILD", "Child", "child", "ROOT"),
        TaxonomyLabel("LEAF", "Leaf", "leaf", "CHILD"),
    ))
    tree = build_taxonomy_tree(taxonomy)

    assert routing_label_dict(tree, taxonomy.by_id["CHILD"]) == {
        "id": "CHILD",
        "name": "Child",
        "description": "child",
        "parent": "ROOT",
        "ancestor_path": [{"id": "ROOT", "name": "Root"}],
        "children": [{"id": "LEAF", "name": "Leaf"}],
    }
