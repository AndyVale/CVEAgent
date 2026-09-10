# Coding-agent notes

## Hybrid taxonomy and 50-CVE validation set (2026-09-10)

- Complete on `main`; the developer approved committing the work directly.
- Fixture layout uses `fixtures/flat/`, `fixtures/hierarchical/`, and `fixtures/hybrid/`. Each
  directory contains `taxonomy.json` and `expected-classification.json`. GUI defaults, tests, and
  README commands use these paths.
- The hybrid taxonomy contains 84 mechanism labels, nine independent roots, `most_specific`
  policy, and at most three parent links. Definitions give evidence requirements and boundaries
  for nearby labels. `CodeInjection` means general-purpose source evaluation, `ZipSlip` is an
  archive-extraction specialization of `PathTraversal`, and `IDOR` is an object-level
  specialization of `ImproperAuthorization`.
- Under the example 12,000-token per-request limit, the taxonomy produces two exhaustive chunks;
  `auto` selects hybrid with the documented 50,000-token benchmark budget. The example
  12,000-token total budget is too small for hybrid preflight.
- Taxonomy fingerprint:
  `d466b8ebd065c5df63a282f657de58b9bb9ae17e743b1cfdc773fd63e431083e`.
- The hybrid benchmark uses the standard top-level format only: `schema_version`,
  `taxonomy_sha256`, and `cases`. It contains 50 unique, online-researched CVEs; every case has
  labels, a rationale, and source links. Seven cases remain multi-label after `most_specific`
  normalization, with no ancestor/descendant pair in one expected answer. CVEAgent predictions
  and live model results were not used as ground truth.
- `fixtures/hybrid/hybrid_taxonomy_readme.md` contains taxonomy-design, sampling, evidence,
  coverage, and uncertainty documentation and is not consumed by application code. Coverage is
  22 of 84 labels, leaving 62 unrepresented rather than forcing unsupported mappings.
- Verification after the fixture-path reorganization: 60 focused taxonomy, traversal,
  evaluation, and GUI path tests passed; the full offline Python suite passed with 319 tests.
  All three fixture pairs load from their new paths, and the hybrid benchmark has exactly the
  three standard top-level fields and 50 unique cases. JSON parsing and `git diff --check` passed.
  The optional GUI Node suite remains unavailable because Node is not installed.

## Current work

Reliability and maintainability follow-up is complete on `main` and awaiting review; no commits
have been created.
The working tree was clean before this work began. `ARCHITECTURE.md` remains untouched and
excluded.

Current-code reproductions completed before fixes:
- A completed pending ID for database A resolves to the overlapping `1:0` analysis in database B.
- A rejected GUI poll schedules only the toast timer and never another poll.
- Application resource cleanup and pipeline failed-run finalization both replace the primary
  exception when cleanup also fails.
- GUI events are not written during the first active run, and completed aliases grow without a
  retention bound.
- Inserting a newer history row between offset pages repeats the prior page's last row.
- The browser controller remains a single 1,031-line asset with only renderer-focused JS tests.

Implemented and verified units:
- Cleanup preserves primary pipeline/application failures, reports secondary failures with
  type-only diagnostics, surfaces cleanup-only failures, and continues independent resource
  cleanup. Focused application suite: 37 passed.
- Completed pending references carry their resolved database path. Defaults, result loading and
  progress warnings use that repository. Progress binds after an initial persisted checkpoint,
  appends idempotent sequence deltas, retries a final full flush, and uses context-local capture
  so concurrent runs cannot receive one another's diagnostics. Terminal pending state is retained
  with an LRU bound of 128 without deleting SQLite results.
- GUI history now uses criteria-bound cursor snapshots ordered by exact match, run ID and input
  position. Empty history follows the analyses primary key; substring plans still require a sort,
  so no index was added. Concurrent insert/update, boundary, exact-priority, repeated-run,
  wildcard and invalid-cursor tests pass.
- Browser code is split into request, polling, history, rendering, configuration and orchestration
  assets. Bounded retry/backoff, exhausted reconnect, stale response/timer guards, search races,
  cursor append and submission guards have executable Node coverage (7 passed).
- Full offline Python suite passed after integration: 318 passed. Frozen request/result fixtures
  were unchanged. Real browser verification used temporary database A/B instances and a mocked
  delayed classifier: overlapping `1:0` histories stayed separate, saved-row opening was read-only,
  two injected poll failures recovered the same pending run, and repeated submission created a
  new third row. A terminal helper-text ordering issue found in that pass was fixed and rechecked.
- Python compilation passed. Final source and wheel builds passed; both archives contain all six
  ordered GUI scripts and the stylesheet. An isolated import from the built wheel served every
  asset with HTTP 200 and the existing CSP. `git diff --check` passed and no schema, lockfile,
  prompt, request/result contract fixture, classification algorithm or model-setting file changed.

Proposed review units (not committed):
- `fix: preserve primary failures during cleanup`
- `feat: persist isolated analysis progress safely`
- `fix: scope analysis references and stabilize history`
- `refactor: split GUI responsibilities and recover polling`

## GUI changes (2026-09-09)

- Removed completed-result reuse from GUI submissions. Active-job keys include normalized CVE,
  database, taxonomy and settings fingerprints; registration/submission is locked against races,
  and terminal outcomes/rejected submissions release the key. Responses explicitly report
  `already_running` instead of `cached`.
- Wider history sidebar provides debounced full/partial CVE search with stale-response protection,
  exact-match priority, and additional pages. Shared HistorySearch criteria keep future filters
  separate from presentation; SQLite filters before the limit, using bound parameters and stable
  tie-breaking. No schema migration or payload loading is needed for search.
- Labels, helper text and toasts distinguish opening saved rows from starting another run.
  The history/search panel remains available at narrow widths. Existing result snapshots are
  preserved and opening history remains read-only.
- Verification: 301 offline tests pass, including concurrency, key differences, failures/retries,
  repeated fresh runs, read-only loading, exact/partial search beyond 200 rows, pagination and
  literal wildcard handling. Browser preview with temporary SQLite data and a mocked classifier
  verified searching 2889, clicking an old row, and analyzing it again creates a third matching
  row while retaining the old results. Narrow layout checked at 390px without horizontal overflow.
- Search follow-up: renderHistory now filters against the current input even when a response
  contains unrelated rows (for example from an older still-running backend). Filtering occurs
  immediately on input and applies to every rerender; server filtering/pagination remain intact.
  Added three executable JavaScript regression tests using the actual app.js renderer, including
  CVE-2021-26855 excluding CVE-2020-11022, fragments/clearing and stale query state.
- Source distribution and wheel builds passed; staged filenames remain empty and whitespace
  review passed.
- Prompts, classification behavior, dependencies and existing database/cache formats unchanged.
  No live model calls used. README documents new user behavior and the extensible search contract.
- Proposed commit: `feat: separate saved analysis search from new GUI runs`.

## Follow-up fixes (2026-09-08)

- Cache writes use a same-directory temporary file and atomic replacement. Invalid JSON,
  encoding or record structures trigger a fresh fetch; only successful retrieval replaces the
  entry. Filesystem errors, unsafe URLs and unusable cached content remain explicit failures.
- An event-save failure no longer marks a persisted analysis failed. The pending analysis view
  displays a redacted warning and the result remains available for history/cache reuse. A
  rejected executor submission removes its pending entry so settings are not blocked forever.
- Download and Tavily adapters lazily reuse separate HTTP clients within a run. Application
  cleanup closes only its owned sources on success/failure; injected clients remain caller-owned.
  Direct adapter users call close(). Cookies are cleared between logical requests, preserving
  prior isolation; authentication headers remain request-local. Redirect/response URL validation
  remains intact, with the duplicate initial uncached-fetch check removed.
- README documents recovery and ownership. No prompts, model settings, dependencies, SQLite
  schemas or valid cache formats changed. Progress still persists at completion; incremental
  event persistence is a separate deferred redesign.
- Verification: 290 offline tests pass, including the frozen request/result contracts and
  architecture checks. Added malformed-cache/recovery/write-failure, GUI completion/warning,
  queue rejection, HTTP pooling/cookie/auth isolation and resource ownership/failure tests.
  Live API benchmarks were not repeated for these follow-ups; prior results below describe
  the package reorganization. All 290 tests passed again before committing on 2026-09-09.
  Source and wheel builds and changed-file hygiene checks passed.

## Reorganization implementation

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

## Reorganization verification

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

## Approved commit units

Developer-approved follow-ups:
- `fix: recover malformed entries with atomic writes`
- `fix: preserve completed results and clean up rejected jobs`
- `perf: reuse and release owned HTTP clients`

Include the corresponding tests and documentation. Never stage ARCHITECTURE.md or local artifacts.

## Deferred work

Further typed event records, removal of the legacy event fallback, hybrid scheduling changes,
provider-specific retry delays, hard wall-clock cancellation, and the separate taxonomy ambiguity
pass are outside this refactor. Investigation time limits
remain admission cutoffs, and the prior full-input extraction/lazy-cache fixes are preserved.
