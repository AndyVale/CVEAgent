# Flat demo taxonomy

## Purpose

This fixture is an illustrative demo taxonomy, not a complete or standardized vulnerability
ontology. It contains nine independent mechanism families and no parent relationships. The
classification step therefore evaluates every label exhaustively; there is no hierarchy to route
or prune.

The files in this directory are:

- `taxonomy.json`: the nine label IDs, display names, and definitions.
- `expected-classification.json`: the shared 50-CVE validation set at flat granularity.

This Markdown file documents the fixture and is not an application input.

## Relationship to the other demos

The flat taxonomy is the coarsest projection used by the 50-CVE benchmark. Its labels are the
hybrid taxonomy's nine shared roots, with the same IDs, names, and definitions but without parent
relationships. The hybrid taxonomy also has an independent `StaleHandleUse` root, which has no
case in this benchmark. Each flat root represents one independent mechanism family:

| Root | Scope |
| --- | --- |
| `InterpreterInjection` | Input that changes interpreter, parser, query, command, code, template, or browser-document grammar. |
| `PathAndResourceSelection` | Attacker-controlled filesystem resolution outside the intended resource boundary. |
| `StructuredDataProcessing` | Unsafe object, reference, binding, or graph behavior while interpreting structured data. |
| `RoutingAndDestinationControl` | Attacker control over network destinations or routing authority. |
| `FileUploadControl` | Upload acceptance that violates the intended content policy or trust boundary. |
| `AccessControl` | Failures to establish identity, manage sessions, authorize actions, or validate authority-bearing requests. |
| `MemorySafety` | Invalid native-memory bounds, lifetime, initialization, pointer-validity, or object-type behavior. |
| `AvailabilityAndResources` | Violations of resource bounds, release obligations, or concurrency progress guarantees. |
| `CryptographicProtection` | Failures in primitive selection, key management, randomness, nonce handling, or certificate validation. |

With the documented 12,000-token per-request input limit, all nine labels fit in one exhaustive
classification chunk. A configured hybrid strategy is inapplicable because the fixture has no
hierarchy.

## Shared validation set and projection

All three demo benchmarks contain the same 50 unique CVEs in the same order and retain the same
evidence-source lists. The hybrid expectations are the semantic reference. For the flat benchmark,
each benchmarked hybrid label is replaced by its nearest shared root. Projections that converge on
the same root are deduplicated in their original order.

The benchmark uses the standard three-field format: `schema_version`, `taxonomy_sha256`, and
`cases`. Every rationale explains the evidence at the flat taxonomy's available granularity.
Parent and child labels are never counted as separate mechanisms. Seven CVEs retain multiple
labels because their supported mechanisms belong to different roots.

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

The validation set covers eight of nine flat labels. `AvailabilityAndResources` is unrepresented.
This is an intentional evidence-driven gap rather than a forced classification. The broad flat
families are useful for demonstrating exhaustive classification but deliberately lose distinctions
available in the hierarchical and hybrid demos. A correct flat answer therefore does not imply
that every finer mechanism within that family is supported.
