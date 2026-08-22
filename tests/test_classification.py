from cve_agent.classification import apply_hierarchy_policy, chunk_taxonomy
from cve_agent.models import Evidence, LabelClassification
from cve_agent.taxonomy import HierarchyPolicy, Taxonomy, TaxonomyLabel


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
