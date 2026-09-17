# Hierarchical demo taxonomy

## Purpose

This fixture is an illustrative demo taxonomy, not a complete or standardized vulnerability
ontology. It contains 39 mechanism labels: nine roots and their 30 immediate specializations. It
uses the `most_specific` hierarchy policy, so a supported specialization replaces its ancestor in
an expected answer.

The files in this directory are:

- `taxonomy.json`: label IDs, display names, definitions, parent relationships, and hierarchy policy.
- `expected-classification.json`: the shared 50-CVE validation set at this hierarchy's granularity.

This Markdown file documents the fixture and is not an application input.

## Relationship to the other demos

The hierarchical taxonomy is a two-level projection of the 84-label hybrid demo for the shared
families. It retains the nine shared roots and their immediate specializations. The hybrid demo
also has an independent `StaleHandleUse` root, which has no case in this benchmark. Shared IDs,
names, definitions, and parent relationships are unchanged.

Every retained child is a mechanism specialization of its parent. If the child is supported, its
parent must also be supported. The parent is omitted from the final answer under `most_specific`;
an internal label remains valid when public evidence does not justify one of its available
children.

With the documented 12,000-token per-request input limit, all 39 labels fit in one exhaustive
classification chunk. The default `auto` strategy therefore consumes this demo exhaustively in one
request. The same hierarchy could technically be consumed through a forced hybrid strategy, but
that is not this fixture's intended or automatically selected demonstration path.

## Shared validation set and projection

All three demo benchmarks contain the same 50 unique CVEs in the same order and retain the same
evidence-source lists. The hybrid expectations are the semantic reference. A hybrid expected label
at level one or two remains unchanged here; a deeper label is replaced by its nearest retained
ancestor at level two. Projections that converge are deduplicated in their original order.

The benchmark uses the standard three-field format: `schema_version`, `taxonomy_sha256`, and
`cases`. Every rationale explains the evidence and the expected label at this demo's available
depth. Ancestors are not duplicated, and seven CVEs retain multiple labels because their supported
mechanisms occupy independent root branches.

## Evidence and selection policy

The candidate pool was the 1,703-entry CISA Known Exploited Vulnerabilities catalog snapshot
version `2026.09.09`, pinned to commit
`f6fafe2585c7cc2a7568d13d08024cf142b37d3a`. Candidate IDs were sorted and shuffled with Python
`random.Random(20260910)`. Forty-five suitable cases came from that ordinary randomized research
pass. Because it produced only two multi-mechanism cases, five more were selected with the same
seed from a separately documented six-CVE multi-mechanism stratum. The selected cases were kept;
none was excluded or replaced while projecting this benchmark.

Classifications were checked against authoritative CVE records, vendor advisories, patches, and
technical analyses. CWE assignments were research leads rather than ground truth. Expectations
record supported root causes or exploitation mechanisms, not consequences such as code execution,
denial of service, disclosure, or privilege escalation. CVEAgent predictions and live model output
were not used to establish the answers.

## Coverage and limitations

The validation set covers 18 of the 39 labels. It has examples in eight of nine roots; the
availability-and-resources branch is unrepresented. Several structured-data, routing, session,
resource-management, and cryptographic specializations are also absent. These are reported gaps,
not reasons to force weakly supported cases into labels.

This demo preserves useful broad distinctions such as query injection versus process invocation,
authentication versus authorization, and spatial versus temporal memory safety. It deliberately
does not claim the leaf precision of the hybrid taxonomy.
