# Project specification (prompt for the classification agent)

This repository implements a CVE multi-label classification system.

The system receives one or more CVE IDs and, for each CVE, investigates available information and produces a set of classification labels selected from a user-provided taxonomy.

The taxonomy is external to the classifier: the user decides which taxonomy is used, and the classifier MUST NOT invent labels, modify the taxonomy, or output concepts that are not represented by a taxonomy entry.

The initial target use case is weakness classification (for example, CWE), but the system must support arbitrary text-based taxonomies.

## Objective

For each CVE, determine which labels from the supplied taxonomy are supported by the available evidence.

The task is multi-label classification. The classification system is intended to be evaluated primarily with micro-F1 and macro-F1, together with per-label precision and recall.

The classifier should favor evidence-backed decisions and should prefer `not_enough_information` over unsupported speculation.

## Initial architecture

The system is composed of a single classification agent.

The agent:

- receives a CVE ID and a user-supplied taxonomy;
- queries the NVD API first;
- treats the NVD CVE description as the strongest initial evidence;
- may dynamically investigate additional sources on the web;
- maintains an evolving investigation scratchpad for the current CVE;
- uses the taxonomy to understand the available labels and their definitions;
- produces a structured JSON classification result.

The agent has no file-system access and must operate only through the tools exposed to it.

## Taxonomy

The taxonomy is supplied explicitly for every run as a local JSON file.

The taxonomy defines the complete and closed set of labels that the classifier may output.

A basic taxonomy entry contains:

- `id`: stable identifier for the label;
- `name`: human-readable label name;
- `description`: textual definition of the label.

Hierarchical taxonomies may additionally represent parent/child relationships. A label may refer to a parent label by identifier. The implementation should derive child relationships rather than requiring duplicated parent and child references.

The classifier MUST only emit label IDs that exist in the supplied taxonomy.

The classifier MUST NOT create, rename, merge, reinterpret, or otherwise invent labels.

For example, if the taxonomy contains `Buffer Overflow` and `Stack-Based Buffer Overflow` but does not contain `Heap Buffer Overflow`, the classifier MUST NOT output `Heap Buffer Overflow` as a new label.

The application should validate the taxonomy before processing CVEs. At minimum, validation should reject duplicate IDs, missing required fields, invalid parent references, and cyclic hierarchies.

The taxonomy is a required input to the CLI and should be explicit in every invocation, for example:

```text
uv run cve-agent --taxonomy path/to/taxonomy.json CVE-2026-1234 CVE-2026-5678
```

## Investigation strategy

Use an investigation-first approach.

The conceptual flow is:

```text
CVE ID
  -> NVD description and metadata
  -> investigate and collect evidence
  -> maintain investigation scratchpad
  -> consult taxonomy definitions and relationships
  -> identify labels supported by the evidence
  -> investigate further when useful
  -> produce final structured classification
```

Do not reduce the task to simply matching words in the taxonomy. The agent should first build an evidence-based understanding of the vulnerability and then determine which taxonomy labels are supported.

The taxonomy constrains the classification space; it does not authorize the agent to invent concepts outside that space.

## NVD and external sources

NVD MUST be the first source queried for every CVE.

The NVD CVE description is the primary and heaviest piece of evidence at the beginning of the investigation. This does not make it infallible or an absolute authority.

Additional sources may be consulted dynamically. The agent may follow relevant references exposed by NVD and may retrieve information from arbitrary web sources that are relevant to the investigation.

Use external sources to enrich, corroborate, clarify, or challenge the initial understanding.

When sources conflict, do not silently replace one interpretation with another. The agent must account for the conflict and weigh the available evidence. The NVD description should retain the greatest initial evidential weight unless stronger, more specific evidence clearly justifies another conclusion.

All external retrieval must respect the target website's rules and applicable access constraints.

## Search and retrieval behavior

The system provides search/fetch tooling for web investigation.

The classifier may decide dynamically which searches or pages are useful. Do not force a rigid sequence of searches beyond the requirement that NVD is queried first.

Retrieved contents should be cached when appropriate so that repeated investigations and tests do not unnecessarily repeat network requests.

Transient web-search failures should be retried using a bounded retry policy. A retry mechanism such as `tenacity` may be used by the implementation. The retry count and backoff are implementation concerns; the agent should not assume that unlimited retries are available.

Non-retryable errors may terminate the current investigation.

## Investigation scratchpad

Each CVE has its own temporary investigation scratchpad.

The scratchpad should evolve during the investigation and may contain information such as:

- relevant facts extracted from sources;
- URLs already visited;
- useful quotations;
- hypotheses and conclusions;
- conflicting claims;
- candidate labels;
- unresolved questions;
- reasons for further investigation;
- confidence changes or other decision-relevant observations.

The scratchpad is scoped to the current CVE only. It MUST be cleared before another CVE is investigated.

Do not use the scratchpad as persistent learning across CVEs.

## Evidence requirements

Every assigned label must be supported by evidence.

Evidence should be as concrete and source-grounded as possible. When available, include:

- the source URL;
- a relevant quotation or excerpt from the source;
- a concise explanation of why that evidence supports the label.

Reasoning should remain tied to observable evidence. Avoid presenting unsupported speculation as evidence.

A source may provide direct evidence, while the explanation may describe the logical connection between that evidence and the taxonomy label.

## Classification behavior

The classifier must perform multi-label classification over the supplied taxonomy.

For each selected label, return:

- the taxonomy label ID;
- a confidence value;
- supporting evidence.

The classifier should not emit weakly supported labels merely because they are semantically plausible.

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

Token usage is a hard resource constraint. If the token limit prevents completion of a full investigation, the agent must produce the best structured answer supported by the evidence already collected. It may return `not_enough_information` when appropriate and must explicitly report that the investigation was constrained by the token limit.

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
          "explanation": "..."
        }
      ]
    }
  ]
}
```

When the CVE cannot be classified reliably from the available information:

```json
{
  "cve_id": "CVE-2026-1234",
  "status": "not_enough_information",
  "labels": []
}
```

The implementation may extend the schema with operational metadata needed for reproducibility and persistence, but the classification information itself must remain explicit and machine-readable.

The label field MUST contain taxonomy IDs, not newly generated label names.

Confidence is the classifier's reported confidence for the selected label. Confidence should not be treated as a replacement for supporting evidence.

## Failure and operational behavior

The system should preserve partial investigation state and the associated error when an investigation is aborted by an unrecoverable failure.

An interrupted CVE does not need to be automatically resumed in the initial implementation.

The system should track token usage and relevant operational information so that resource-related failures can be inspected after a run.

## Independence between CVEs

Each CVE must be classified independently.

Information, assumptions, candidate labels, confidence, or conclusions from one CVE MUST NOT leak into the next CVE's investigation state.

When multiple CVEs are provided to the CLI, they may be processed sequentially, but each investigation starts with a fresh scratchpad and independent classification context.
