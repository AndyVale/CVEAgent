# Agent Notes

## Current work

Adaptive hierarchical classification is implemented but not committed. The working tree adds
config-only `auto`, `hybrid`, and `exhaustive` strategies, conservative breadth-first hierarchy
routing, cost-based exhaustive fallback, uncertain-node adjudication, hybrid budget planning,
strategy-neutral coverage, persisted diagnostics, deterministic tests, and documentation.
Investigation prompts, tools, and execution are unchanged.

The complete deterministic suite passes 109 tests covering strategy selection, routing,
budgeting, configuration, orchestration, hierarchy policies, checkpoint persistence, and
fixture-driven integration. Bytecode compilation, secret/fixture-ID scans, and the Git
whitespace check also pass.

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
- Research alone receives `search`, `fetch`, `record_evidence`, and `finish_investigation`.
  Classification and routing never receive web tools.
- SQLite stores run-scoped metadata, checkpoints, coverage, state, and results. Persistence
  failures remain fatal. NVD weakness assignments remain intentionally excluded.
- Fixtures are named `flat_taxonomy.json`, `flat_expected-classification.json`,
  `hierarchical_taxonomy.json`, and `hierarchical_expected-classification.json`. Production code
  contains no fixture-specific IDs or taxonomy assumptions.

## Handoff

The implementation is ready for review. Do not commit until the developer approves a proposed
Conventional Commit.
