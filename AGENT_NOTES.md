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
- Focused evidence/pipeline/taxonomy tests pass: `18 passed`.

## Next

1. Commit the canonical-evidence unit.
2. Separate taxonomy-independent investigation from exhaustive chunk classification.
3. Add staged budget enforcement, hardened configuration/retrieval, and run-scoped storage.
4. Align fixtures, broaden integration tests, update documentation, and run final checks.
