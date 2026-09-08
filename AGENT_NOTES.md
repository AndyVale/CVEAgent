# Coding-agent notes

## Current work

The behavior-preserving package reorganization is complete and ready for commit review.
Work is on `main`; no files are staged and no commits have been created.
`ARCHITECTURE.md` must remain untouched, untracked and uncommitted.

## Implementation

- Source responsibilities are separated into investigation, classification, persistence, cache,
  CLI, GUI, application, core, runtime and integrations. Imports use owning modules without
  legacy forwarding modules. Stable logger names preserve displayed progress components.
- Application coordination invokes independent research and classification components. Generic
  token accounting/model calls are separate from taxonomy-specific reserve planning. Shared
  repository/model-call protocols allow deterministic adapters without SQLite or live providers.
- Web retrieval is independent of the disk-cache wrapper. Result reuse eligibility belongs to
  cache; SQL, schema-v3 writes, codecs and history queries belong to persistence.
- GUI service delegates configuration, jobs, progress capture and history presentation. Routes,
  static assets, GUI-owned configuration paths and the scratchpad event fallback are preserved.
- Prompt strings, tool descriptions/schemas, response schemas, research-context content,
  classification algorithms, budgets and provider settings are unchanged. No dependencies added;
  `uv.lock` is unchanged. README and AGENTS document the new organization and import boundaries.
- Tests mirror subsystem packages; shared doubles are under `tests/support`.

## Verification

- Original offline suite: 243 passed. Each structural unit passed the full suite before proceeding.
- Frozen regression fixtures were captured from original source, including actual request-time
  copies, result payloads, state and checkpoints: exhaustive, hybrid, malformed responses,
  finish correction, empty scans, pruning, uncertain adjudication and strategy switching.
- Full offline suite: 263 passed (all 243 original tests plus 20 regression checks). This includes
  nine frozen-contract tests, two dependency/import-cycle tests, writer-interface failure tests,
  cache eligibility/snapshot tests and GUI-job failure/logging-restoration tests. Compilation,
  annotation resolution, tracked/new-file whitespace review and credential scans passed.
- Source distribution and wheel built successfully. Both commands and module execution passed
  from an isolated wheel installation; installed GUI assets served successfully. Neither archive
  includes local configuration, credentials, data, caches, or ARCHITECTURE.md.
- `uv sync --dev --locked` refreshed the editable entry point. Both local command help checks pass.
- The original-code live benchmark completed all 14 launcher CVEs with no partial/failed runs:
  9 exact matches, micro precision 0.714286, recall 0.9375, F1 0.810811.
- New persistence/cache implementations read all 14 original-run results exactly, including
  unchanged snapshots and cache fingerprints.
- Both original and refactored live benchmarks completed all 14 launcher CVEs successfully,
  with the same taxonomy/validation pair, config settings and 15-second request pacing. Runs used
  separate databases and equivalent starting web caches. All 14 complete public results match
  exactly except elapsed duration: labels, confidence, quotes, provenance, token accounting,
  coverage and all other operational metadata are unchanged. Benchmark metrics also match.
  Sanitized comparison: `.cache/refactor-verification/comparison.json`.
- Original source/tests, sanitized results and build artifacts are in ignored
  `.cache/refactor-verification/`. Credentials were provided through non-echoing process input,
  existed only in process memory/environment, and were never written to files. Both live workers
  and their parent have exited. ARCHITECTURE.md remains untracked and the index is empty.

## Commit proposal

Proposed Conventional Commit: `refactor: separate application responsibilities`.
Developer approval is required before creating it. Stage only the intended source, tests,
README, AGENTS, AGENT_NOTES and pyproject changes; exclude ARCHITECTURE.md and local artifacts.

## Deferred work

Typed pipeline events/incremental persistence, removal of the legacy event fallback, shared HTTP
clients, hybrid scheduling changes, provider-specific retry delays, hard wall-clock cancellation,
and the separate taxonomy ambiguity pass are outside this refactor. Investigation time limits
remain admission cutoffs, and the prior full-input extraction/lazy-cache fixes are preserved.
