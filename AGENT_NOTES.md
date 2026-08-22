# Agent Notes

## Current focus

Implement the approved taxonomy-agnostic classification refactor in logical commits.
The user approved replacing the former URL-correction commit and approved the planned
commit sequence.

## Confirmed design

- Taxonomies are arbitrary user data; CWE is only an example. Production code must not
  depend on CWE identifiers, NVD weakness assignments, or fixture labels.
- Evidence is application-owned. Fetched previews contain stable passages, approximate
  model anchors may only locate a unique passage, and final labels reference evidence IDs.
- Investigation is taxonomy-independent. Classification evaluates the complete taxonomy
  in bounded exhaustive chunks and applies a taxonomy-defined hierarchy policy, defaulting
  to most-specific labels.
- Token budgeting reserves classification/finalization work before investigation and
  permits a configurable finalization-only overrun. Unexpected exhaustion returns partial
  coverage instead of discarding supported results.
- SQLite records distinct runs with taxonomy/configuration fingerprints. Current local
  database contents do not need migration.
- NVD weakness assignments remain excluded. Partial-positive dataset evaluation is deferred.

## Completed

- Mixed-reset obsolete commit `2e44957`; its changes remained available in the working tree
  while the evidence-ID design replaced them.
- Added canonical evidence records, stable passages, unique fuzzy-anchor resolution, and a
  centralized classification validator.
- Changed agent classification output to reference evidence IDs; backend materializes exact
  quotes and canonical URLs. Removed URL spelling correction logic.
- Separated taxonomy-independent investigation from exhaustive, bounded taxonomy chunk
  evaluation and final candidate adjudication. Added generic hierarchy policies and coverage.
- Removed the unused one-shot classifier and obsolete pipeline/classifier arguments.
- Added provider-neutral token estimation, exhaustive-classification preflight, a protected
  research allowance, configurable finalization overrun, and reported/estimated usage.
- Unexpected budget exhaustion preserves validated chunk labels and exact coverage as a
  partial result. Full deterministic suite passes: `29 passed`.
- Split NVD/web retry configuration, added startup validation and config-relative paths,
  streamed bounded text retrieval, and requested/resolved redirect provenance.
- Added schema-versioned run persistence with incremental run IDs, taxonomy fingerprints,
  non-secret settings, checkpoints, and fatal persistence error propagation. Removed the
  ignored legacy local database as authorized. Full deterministic suite passes: `39 passed`.
- Budget preflight now runs before NVD, database creation, or other pipeline side effects.

## Next

1. Commit run-scoped storage and checkpointing.
2. Align fixtures, broaden integration tests, update documentation, and run final checks.
