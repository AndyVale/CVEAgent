# Agent Notes

## Current work

Adaptive hierarchical classification, the large hybrid benchmark, and taxonomy-name recovery
are committed through `732704b`. Terminal diagnostics and the reusable application boundary are
committed as `a6cfe8a`. The accompanying benchmark update adds two multi-label hybrid cases.

Verbose stderr now uses aligned time, semantic status, component, and message columns with
blank stage boundaries. Interactive terminals use cyan normal, green complete, magenta
incomplete, yellow warning, and red error output. Redirected/piped output is plain text,
`NO_COLOR` is honored, and stdout remains JSON-only. Semantic presentation hints use ordinary
logging records and do not change persistence or classification behavior.

`ClassificationApplication` wraps the existing pipeline and returns immutable typed results
plus optional evaluation data. Default adapter composition is reusable outside the CLI. The CLI
continues to own arguments, JSON/table rendering, terminal diagnostics, and exit-code policy.

The hybrid expected benchmark now has exactly two cross-branch multi-label cases:
`CVE-2021-26855` expects SSRF and AuthenticationBypass, while `CVE-2021-41773` expects
CommandInjection and PathTraversal under its documented CGI preconditions. The taxonomy itself
did not need to change, so its fingerprint remains stable.

The hybrid taxonomy has 126 labels, six roots, and a maximum depth of four. At the example
12,000-token request limit it needs two exhaustive chunks, so `auto` selects hybrid. Its current
hybrid preflight reserve is about 29,000 tokens; the README recommends a 50,000-token base budget
to leave useful investigation capacity. The expected benchmark reuses the existing 14 curated
CVEs and maps them to the new tree's most-specific leaves.

The complete deterministic suite now passes 120 tests. The hybrid benchmark fingerprint,
taxonomy membership, automatic strategy selection, production fixture-ID exclusion, and
curated CVE paths are validated without live services. Focused and complete tests plus bytecode
compilation, CLI import/help, and the final whitespace review pass.

An authorized post-change live run processed `CVE-2021-26855` with `--verbose`, validation, and
15-second model pacing. It completed without a runtime error in 47.1 seconds, used four model
requests and 23,130 tokens, persisted run 8, and kept stdout JSON separate from colored stderr.
The model selected SSRF but missed the expected AuthenticationBypass, producing micro-F1 0.667.
The developer chose to keep validation correctness exclusively in the classification and
evaluation tables, so the final operational log contains no exact-match or F1 assessment.
Whitespace-only continuation lines were removed, and JSON, classification, and evaluation
output now use matching plain-text section headings without decorating machine-readable stdout.
These presentation contracts have regression tests.

One authorized live run classified CVE-2023-34362 against the 126-label taxonomy with exact
precision/recall/F1 of 1.0 in four model requests and 23,226 tokens. The local 50,000-token input
limit made `auto` choose exhaustive; deterministic tests cover the same normalization in forced
hybrid routing. The live model returned IDs and selected SQLi plus its three ancestors, which
`most_specific` correctly reduced to SQLi.

## Adaptive classification design

- Flat taxonomies always use linear exhaustive chunks and log that configured strategy is
  ignored.
- Hierarchical `auto` is exhaustive when the complete taxonomy fits one request and hybrid
  otherwise. Forced hybrid always routes roots once; forced exhaustive remains linear.
- `HybridTaxonomyScanner` routes active nodes breadth-first as supported, uncertain, or
  unsupported. Supported decisions require canonical evidence. Unsupported decisions prune
  descendants only at the configured threshold; lower confidence is normalized to uncertain.
- Each routed node receives its definition, ancestor path, and immediate children. Exact
  one-decision-per-node validation gets one correction request before producing partial output.
- After every full level, hybrid estimates active-subtree exhaustive cost versus the next
  frontier, costliest remaining path, and adjudication. A cheaper exhaustive continuation is
  checkpointed before switching.
- Uncertain nodes without supported descendants receive bounded binary adjudication. Final
  hierarchy policy is applied only after all candidates merge.
- Generic coverage records effective strategy, total/evaluated/pruned/unresolved labels,
  classification request count, routing levels, and completeness. Routing history, pruning,
  normalization, and switches are stored in existing JSON metadata; schema version stays 2.

## Existing architecture and invariants

- Research is taxonomy-independent and uses five optional topics: affected system, root cause,
  exploitation mechanism, preconditions, and impact. Every retained finding cites
  application-owned evidence; final labels always require evidence.
- `InvestigationAgent` orchestrates `ResearchRunner` and a taxonomy scanner.
  `taxonomy_scan.py` owns exhaustive classification; `hierarchy_scan.py` owns adaptive routing;
  `classification.py` owns taxonomy structure/chunking/policies; `budget.py` owns staged plans.
- `ClassificationApplication` is the UI-independent execution boundary. The CLI is only a
  terminal adapter and machine-readable stdout remains separate from human stderr output.
- Research alone receives `search`, `fetch`, `record_evidence`, and `finish_investigation`.
  Classification and routing never receive web tools.
- SQLite stores run-scoped metadata, checkpoints, coverage, state, and results. Persistence
  failures remain fatal. NVD weakness assignments remain intentionally excluded.
- Fixtures are named `flat_taxonomy.json`, `flat_expected-classification.json`,
  `hierarchical_taxonomy.json`, `hierarchical_expected-classification.json`,
  `hybrid_taxonomy.json`, and `hybrid_expected-classification.json`. Production code contains
  no fixture-specific IDs or taxonomy assumptions.

## Handoff

The requested logging, application-boundary, live verification, and multi-label benchmark work
is complete. No known implementation blocker remains.
