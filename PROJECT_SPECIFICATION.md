# Project specification (prompt for the classification agent)

This repository implements a CVE multi-label classification system.

The system receives one or more CVE IDs and, for each CVE, investigates available information and produces a set of classification labels selected from a user-provided taxonomy.

The taxonomy is external to the classifier: the user decides which taxonomy is used, and the classifier MUST NOT invent labels, modify the taxonomy, or output concepts that are not represented by a taxonomy entry.

The initial target use case is weakness classification (for example, CWE), but the system must support arbitrary text-based taxonomies.

## Objective

For each CVE, determine which labels from the supplied taxonomy are supported by the available evidence.

The task is multi-label classification. The classification system is intended to be evaluated primarily with micro-F1 and macro-F1, together with per-label precision and recall.

Expected-classification benchmarks are taxonomy-scoped. They must identify their taxonomy by a
deterministic fingerprint and map unique CVE IDs to sets of expected taxonomy IDs. Optional
rationales and source URLs make manual curation auditable but are never supplied to the runtime
classifier. Evaluation compares validated output labels with the expected sets, reports exact
match, micro precision/recall/F1, macro-F1, incomplete outcomes, and case-level mismatches.
Partial labels may contribute to aggregate precision and recall, but a partial or failed result
is never an exact match.

The CLI exposes validation through `--validate PATH`. Its compact classification summary is a
table with ID, predicted labels, precision, recall, and F1 columns. Metric cells are placeholders
when validation is disabled and per-CVE label-set scores when an expected-classification file is
supplied. The detailed aggregate report remains separate from the machine-readable JSON output.
Verbose diagnostics, including any ANSI presentation, are stderr-only. Stdout remains valid JSON
whether it is attached to a terminal, redirected, or piped.

The classifier should favor evidence-backed decisions and should prefer `not_enough_information` over unsupported speculation.

## Architecture

The system is coordinated by a single per-CVE classification agent with distinct evidence
investigation and taxonomy-classification phases.

The system:

- receives a CVE ID and a user-supplied taxonomy;
- queries the NVD API first;
- treats the NVD CVE description as the strongest initial evidence;
- conducts additional web research even when the NVD description initially appears sufficient;
- maintains an evolving investigation scratchpad for the current CVE;
- investigates the vulnerability mechanism without exposing the complete taxonomy to every
  research turn;
- classifies flat taxonomies exhaustively and hierarchical taxonomies with a configured
  exhaustive or conservative adaptive strategy;
- produces a structured JSON classification result.

The agent has no file-system access and must operate only through the tools exposed to it.

Application execution must remain independent of terminal presentation. The reusable application
boundary returns typed classification results and optional evaluation data; the CLI owns argument
parsing, JSON rendering, human-readable summaries, terminal logging, and exit-code policy. Other
interfaces may call the same application boundary without parsing CLI output.

The local graphical interface is an independent presentation and HTTP layer, not a mode of the
CLI. It calls the same application boundary, reads core run history from SQLite, and stores only
additive GUI chat metadata and progress events. GUI analyses preserve an immutable non-secret
configuration and taxonomy snapshot. New chats may inherit a prior snapshot, but changing draft
options must not mutate an existing chat or its result. Cached results require an exact CVE,
taxonomy-fingerprint, and effective-settings match.

## Taxonomy

The taxonomy is supplied explicitly for every run as a local JSON file.

The taxonomy defines the complete and closed set of labels that the classifier may output.

A basic taxonomy entry contains:

- `id`: stable identifier for the label;
- `name`: human-readable label name;
- `description`: textual definition of the label.

Hierarchical taxonomies may additionally represent parent/child relationships. A label may refer to a parent label by identifier. The implementation should derive child relationships rather than requiring duplicated parent and child references.

A taxonomy may define `hierarchy_policy` as `most_specific` or `include_ancestors`.
The default is `most_specific`. Hierarchy behavior belongs to the supplied taxonomy and must
not be inferred from CWE or any other particular taxonomy family.

The classifier MUST only emit label IDs that exist in the supplied taxonomy.

The classifier MUST NOT create, rename, merge, reinterpret, or otherwise invent labels.

For example, if the taxonomy contains `Buffer Overflow` and `Stack-Based Buffer Overflow` but does not contain `Heap Buffer Overflow`, the classifier MUST NOT output `Heap Buffer Overflow` as a new label.

The application should validate the taxonomy before processing CVEs. At minimum, validation should reject duplicate IDs, missing required fields, invalid parent references, and cyclic hierarchies.

The taxonomy is a required input to the CLI and should be explicit in every invocation, for example:

```text
uv run cve-agent --taxonomy path/to/taxonomy.json CVE-2026-1234 CVE-2026-5678
```

Classification strategy is runtime configuration and MUST NOT be embedded in or inferred from
taxonomy data. Supported strategies are `auto`, `hybrid`, and `exhaustive`. Flat taxonomies
always use exhaustive chunking. Hierarchical `auto` uses exhaustive evaluation when the whole
taxonomy fits one request and hybrid traversal otherwise. Forced hybrid begins with root
routing; forced exhaustive evaluates every label linearly.

## Investigation strategy

Use an investigation-first approach.

The conceptual flow is:

```text
CVE ID
  -> NVD description and metadata
  -> search, fetch, and select exact web passages
  -> build an evidence-linked vulnerability profile
  -> consult taxonomy definitions and relationships
  -> exhaustively evaluate labels or conservatively route a hierarchy
  -> resolve uncertain nodes and merge validated candidates deterministically
  -> produce final structured classification
```

Do not reduce the task to simply matching words in the taxonomy. The agent should first build an evidence-based understanding of the vulnerability and then determine which taxonomy labels are supported.

The taxonomy constrains the classification space; it does not authorize the agent to invent concepts outside that space.

Investigation behavior and tools MUST remain independent of the selected classification
strategy. `search`, `fetch`, `record_evidence`, and `finish_investigation` are available only
during investigation. Taxonomy routing and classification do not receive web tools.

## NVD and external sources

NVD MUST be the first source queried for every CVE.

The NVD CVE description is the primary and heaviest piece of evidence at the beginning of the investigation. This does not make it infallible or an absolute authority.

Additional sources may be consulted dynamically. The agent may follow relevant references exposed by NVD and may retrieve information from arbitrary web sources that are relevant to the investigation.

Use external sources to enrich, corroborate, clarify, or challenge the initial understanding.

When sources conflict, do not silently replace one interpretation with another. The agent must account for the conflict and weigh the available evidence. The NVD description should retain the greatest initial evidential weight unless stronger, more specific evidence clearly justifies another conclusion.

All external retrieval must respect the target website's rules and applicable access constraints.

## Search and retrieval behavior

The system provides search/fetch tooling for web investigation.

The investigator is directed to perform web research before finishing, including at least one
search. Beyond that direction, it may decide dynamically which queries and pages are useful.
Search and fetch limits are enforced by the application rather than being delegated to the
model. Search results are leads only; material claims require exact passages from fetched
sources. A passage cited by the finish call is promoted to application-owned evidence
automatically, so a separate recording call is optional.

NVD reference lists supplied to each research turn must be bounded and should prioritize
actionable primary material. The context must report complete and omitted reference counts so
prompt-size reduction is explicit rather than silently suggesting that all references were
provided.

Retrieved contents should be cached when appropriate so that repeated investigations and tests do not unnecessarily repeat network requests. Downloads must be bounded while streaming, restricted to supported textual content, and retain requested and resolved URL provenance.

Transient web-search failures should be retried using a bounded retry policy. A retry mechanism such as `tenacity` may be used by the implementation. The retry count and backoff are implementation concerns; the agent should not assume that unlimited retries are available.

Non-retryable errors may terminate the current investigation.

## Investigation scratchpad

Each CVE has its own temporary investigation scratchpad.

The scratchpad should evolve during the investigation and contains:

- relevant facts extracted from sources;
- structured findings grouped into a small set of high-level topics and linked to evidence IDs;
- an information-sufficiency status and concise synthesis;
- URLs already visited;
- useful quotations;
- hypotheses and conclusions;
- conflicting claims;
- unresolved questions;
- reasons for further investigation;
- other decision-relevant observations.

The high-level topics are affected system, root cause, exploitation mechanism, preconditions,
and impact. They guide investigation but are not mandatory slots: multiple findings may use
one topic and unsupported topics are omitted. Each retained finding must cite application-owned
evidence. The application derives `sufficient` only when at least one evidence-backed root-cause
or exploitation-mechanism finding exists; otherwise it derives `insufficient` without asking
the model to enumerate unknowns or correct a status field.

The scratchpad is scoped to the current CVE only. It MUST be cleared before another CVE is investigated.

Do not use the scratchpad as persistent learning across CVEs.

## Evidence requirements

Every assigned label must be supported by evidence.

Evidence must be application-owned and source-grounded. Fetched previews are divided into
stable passages. The model may select an exact passage ID, an unambiguous document-local number,
or an approximate anchor that resolves uniquely. Passage references in the finish call are
promoted automatically. Invalid references discard only the unsupported finding rather than
invalidating the complete investigation. Final label decisions reference an evidence ID; the
application materializes the exact quote and canonical resolved URL.

When available, include:

- the source URL;
- a relevant quotation or excerpt from the source;
- a concise explanation of why that evidence supports the label.

Reasoning should remain tied to observable evidence. Avoid presenting unsupported speculation as evidence.

A source may provide direct evidence, while the explanation may describe the logical connection between that evidence and the taxonomy label.

The harness must maintain a versioned provenance ledger independently of model context. It
records bounded NVD references and search results, every search and fetch attempt, requested and
resolved URLs, redirects, the complete bounded passages exposed to the model, evidence
selection methods, accepted findings, and final label/evidence associations. Search results,
fetches, documents, and provenance events receive deterministic investigation-scoped IDs.
Multiple matching discovery origins must be preserved rather than reduced to an invented
single cause. Returned label links must snapshot the exact taxonomy name, description, and
ancestor path used during classification so a later clarification does not depend on a taxonomy
file that may have changed.

The ledger computes transparent CVE-association signals from the target identifier, source URL,
title, content, NVD-reference membership, targeted searches, and other CVE identifiers found in
the document. These signals warn but do not reject evidence. Exact target mentions cannot be a
universal requirement because legitimate patches and vendor material may omit the CVE ID.

The detailed ledger is persisted but MUST NOT be included in routine research or taxonomy
requests. It is cold context: a later clarification feature may load only the sources,
passages, findings, and label links reachable from a selected label. The ledger records
observable tool activity and accepted model outputs, not hidden chain-of-thought.

## Classification behavior

The classifier must perform multi-label classification over the supplied taxonomy.

For each selected label, return:

- the taxonomy label ID;
- a confidence value;
- supporting evidence.

The classifier should not emit weakly supported labels merely because they are semantically plausible.

Every flat or exhaustive-mode label must be evaluated independently. The classifier must
distinguish a vulnerability's root cause and exploitation mechanism from its consequences.
Generic impacts such as remote code execution or information disclosure do not establish a
specific weakness class without evidence for that class's defining mechanism.

Every taxonomy request uses strict structured output and centralized validation. Exhaustive
classification merges validated chunk results directly without another model adjudication.
Hybrid classification evaluates all active nodes breadth-first using exactly one `supported`,
`uncertain`, or `unsupported` decision per supplied node. Every decision needs a concise
explanation and numeric confidence. A supported node needs canonical evidence, becomes a
candidate, and expands its children. An uncertain node expands its children. Unsupported may
prune descendants only when its confidence meets the configured threshold; lower-confidence
unsupported decisions are normalized to uncertain.

Each routed node receives its ID, name, description, ancestor path, and immediate child names.
Hybrid mode is valid only when descendants are semantic specializations of their parents. After
each routing level, the application compares exhaustive cost for unresolved active subtrees
with the next frontier, the costliest remaining route, and one adjudication batch. It switches
the active remainder to exhaustive classification when that estimate is no greater.

After traversal, uncertain leaves and uncertain internal nodes without supported descendants
receive evidence-backed binary classification in bounded batches. A failed adjudication remains
unresolved and therefore makes the result partial. `most_specific` or `include_ancestors` is
applied only after all supported candidates have been merged.

Hybrid mode can significantly reduce recall through an early routing error, guarantees budget
for only one complete branch, can return partial for multi-branch vulnerabilities, and may cost
more than exhaustive evaluation for small trees. Exhaustive mode should be used for benchmarks
and taxonomies whose parents are not true semantic supersets of every descendant.

When the available information is insufficient to justify a reliable classification, return `not_enough_information` rather than guessing.

The classifier determines which labels to emit. No external post-processing rule should be assumed to add labels that the model did not select.

## Stopping behavior

Do not impose a rigid fixed number of searches or investigation steps.

The agent should decide when to stop by considering, together:

- whether enough evidence has been collected;
- whether additional investigation is likely to change the classification;
- whether useful sources appear exhausted;
- available time, context, and tool resources;
- remaining token budget.

The goal is to stop when further investigation has diminishing expected value, without unnecessarily overengineering the investigation process.

Token usage is a staged resource constraint. Before investigation, the system reserves the
estimated cost of the effective classification strategy. Exhaustive mode reserves all chunks.
Hybrid mode reserves root routing, the most expensive sibling-aware root-to-leaf path, and one
adjudication batch. Investigation cannot consume that reserve. A configurable bounded
finalization overrun may be used only by classification. Additional active hybrid branches use
remaining classification budget and overrun. If unexpected usage prevents completion, the
agent must return a `partial` result containing validated labels, exact taxonomy coverage, and
the stop reason. Taxonomy request sizing must reserve room for the repeated profile and output
schema rather than treating the whole per-request input limit as taxonomy space.

Strategy-neutral coverage records effective strategy, total labels, directly evaluated labels,
pruned labels, unresolved labels, classification requests, routing levels, and whether coverage
is complete. A hybrid outcome is complete only when every label is directly evaluated or
pruned and no uncertain node remains unresolved.

## Output format

The final result must be structured JSON.

A successful classification should follow this conceptual shape:

```json
{
  "cve_id": "CVE-2026-1234",
  "status": "classified",
  "labels": [
    {
      "label": "CWE-79",
      "confidence": 0.93,
      "evidence": [
        {
          "url": "https://example.com/advisory",
          "quote": "...",
          "explanation": "...",
          "evidence_id": "document-id:p2"
        }
      ]
    }
  ]
}
```

A classified or partial result also contains a versioned top-level `provenance` catalog. Normal
output includes only sources and evidence reachable from returned labels. The complete audit,
including failed calls and unused sources, remains in the persisted investigation scratchpad.

When the CVE cannot be classified reliably from the available information:

```json
{
  "cve_id": "CVE-2026-1234",
  "status": "not_enough_information",
  "labels": []
}
```

The implementation may extend the schema with operational metadata needed for reproducibility and persistence, including run ID, taxonomy coverage, token usage, and stop reason, but the classification information itself must remain explicit and machine-readable.

The label field MUST contain taxonomy IDs, not newly generated label names.

Confidence is the classifier's reported confidence for the selected label and is materialized
as a number in the `[0, 1]` range. Exhaustive label output may deterministically normalize
common qualitative or percentage provider deviations, must log that normalization, and must
reject unknown forms. Hierarchy-routing confidence MUST be numeric because it controls pruning.
Confidence is not a replacement for supporting evidence.

## Failure and operational behavior

The system should checkpoint partial investigation state after NVD retrieval, evidence changes,
completed taxonomy chunks, completed hierarchy-routing chunks, and cost-based strategy switches.
Persisted JSON metadata records configured/effective strategy, threshold, routing decisions,
low-confidence normalization, pruned branch sizes, switches, and exact coverage. Persisted
records are scoped by run ID and input position so repeated classification of the same CVE does
not overwrite prior experiments.

Every research-tool checkpoint must include the updated provenance ledger. Finalization must
persist final label/evidence links. The ledger is stored in existing JSON state and does not
require a schema migration; older records may omit it.

An interrupted CVE does not need to be automatically resumed in the initial implementation.

The system should track token usage and relevant operational information so that resource-related failures can be inspected after a run.

## Independence between CVEs

Each CVE must be classified independently.

Information, assumptions, candidate labels, confidence, or conclusions from one CVE MUST NOT leak into the next CVE's investigation state.

When multiple CVEs are provided to the CLI, they may be processed sequentially, but each investigation starts with a fresh scratchpad and independent classification context.
