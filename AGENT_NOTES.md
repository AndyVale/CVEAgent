# Coding-agent notes

## Current state

The web-retrieval reliability repair is complete and ready for commit review.

- `CachedWebClient.fetch` now gives Trafilatura the complete decoded, byte-bounded response and
  applies `max_document_chars` only to the extracted article or raw fallback. Extraction input and
  stored output lengths retain their distinct meanings in provenance.
- Cache directories are created lazily on the first cache write. Constructing the application no
  longer creates the web-cache directory before token-budget preflight rejects a run.
- `README.md` now defines `max_investigation_seconds` as the cutoff for admitting another research
  interaction; an already-started request and its bounded retries may finish afterward.
- Provider-specific retry-delay parsing and a hard wall-clock cancellation mechanism remain
  deferred: the former is not portable enough to justify extra behavior, and the documented
  admission-cutoff semantics are sufficient for the current product.

Validation completed:

- Focused adapter/pipeline/config tests: 82 passed. Full offline suite: 243 passed.
- Bytecode compilation, `git diff --check`, secret checks, source distribution, and wheel build
  passed.
- Fresh first-chance debugger runs classified `CVE-2023-44487` as `ResourceExhaustion` and
  `CVE-2020-11022` as `XSS`, with format-v2 public/internal provenance and no credential leakage.
- All three successfully downloaded live HTML pages used Trafilatura, with full extraction inputs
  of 517,620, 55,953, and 563,055 characters. The raw fallback was not selected; a deterministic
  unit test separately covers the fallback when extraction returns no usable content.
- One reference returned HTTP 404. It was converted into an auditable research-tool error, after
  which the model selected another source. The trace otherwise contained only expected cleanup
  exceptions and final `SystemExit(0)`.

## Refactor state

Completed non-GUI units:

- `ccec8e8 refactor: centralize input validation and fingerprints`
- `5213eaf refactor: unify analysis persistence`
- `306d300 test: normalize benchmark fixture metadata`
- `1d8d12e refactor: remove redundant metadata`
- `c6b09e8 fix: gate evidence recording on fetched documents`
- `5e9388c fix: enforce public web retrieval boundaries`
- `dcd9713 fix: require coherent investigation evidence`
- `65f81f4 fix: prevent redundant web retrieval`
- `aa721c6 refactor: make vulnerability research adaptive`
- `7cdc3c7 refactor: organize gui package`

Remaining larger work:

- Reliability: provider-specific retry-delay parsing and hard wall-clock cancellation are deferred;
  current retries are bounded and `max_investigation_seconds` is documented as an admission cutoff.
- GUI behavior: typed pipeline events, incremental event persistence, and service decomposition.
- Efficiency: shared HTTP clients and deferred hybrid scheduling work.
- Cleanup: remove the scratchpad event fallback only after every run source persists typed events.
- Taxonomy: prepare and execute the separate comprehensive ambiguity pass.

`ARCHITECTURE.md` is developer-only and must remain untracked and uncommitted.
