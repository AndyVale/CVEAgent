# Coding-agent notes

## Current work

The package reorganization is committed as `refactor: separate application responsibilities`.
The authorized follow-up fixes (review items 1, 3, 4 and 5) are complete on `main`.
The developer approved the three focused commits on 2026-09-09, with no parenthesized scopes.
Item 2, duplicate GUI submissions, was explicitly deferred.
`ARCHITECTURE.md` must remain untouched, untracked and uncommitted.

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

GUI duplicate-submission handling, typed pipeline events/incremental persistence, removal of the
legacy event fallback, hybrid scheduling changes, provider-specific retry delays, hard wall-clock cancellation,
and the separate taxonomy ambiguity pass are outside this refactor. Investigation time limits
remain admission cutoffs, and the prior full-input extraction/lazy-cache fixes are preserved.
