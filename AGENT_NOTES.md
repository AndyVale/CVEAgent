 AS# Coding-agent notes

## Current work: amend adaptive research

The performance recovery and context/prompt refinements are intentionally uncommitted above
`d174d28 refactor: make vulnerability research adaptive`. After final validation, stage only the
intended files and amend that commit without changing its message.

Attribution results:

- A fresh 14-CVE debugger replay at control `c6b09e8` scored micro-F1 0.778 and 5/14 exact,
  using 425,539 tokens and 70 research turns; two cases were partial after exhausting their
  investigation allowance.
- The pre-repair current revision `d174d28` scored micro-F1 0.788 and 8/14 exact, using 203,401
  tokens and 28 research turns. The earlier 0.889 result was therefore a favorable, unstable
  sample rather than a reproducible control score.
- The midpoint `dcd9713` replay reached only seven cases before the model account quota became
  unavailable. It classified `CVE-2021-26855` with both expected labels, localizing that case's
  later failure to adaptive reference-first research combined with evidence-correction behavior,
  not passage packing alone.
- A focused pre-fix `CVE-2021-26855` replay reproduced the concrete defect: the official Microsoft
  URL yielded only `You need to enable JavaScript to run this app.`; the model submitted findings
  with invalid evidence, then made an auxiliary fetch, and the runner prematurely accepted the
  original invalid draft as `correction_not_submitted`.

Implemented repair:

- Evidence correction now remains active across no-tool responses and auxiliary search/fetch
  calls. It is consumed only by the next `finish_investigation` submission; existing time, turn,
  and token limits still materialize the valid original subset when correction cannot complete.
- Fresh and legacy-cached documents containing only a known JavaScript-enable placeholder raise
  a typed, printable `UnusableDocumentError`; newly retrieved placeholders are not cached.
- A per-investigation serializer caches immutable CVE/reference data, individual evidence and
  tool-history entries, and the available-document catalog. It re-encodes only budget counters and
  appended/changed entries, rebuilds after reorder/truncation, omits the current exchange's tool
  events until the next turn, and excludes the duplicate CVE description.
- Successful evidence results no longer repeat the quote; recorded evidence in the next context is
  canonical. Re-recording the same resolved passage is reported accurately without duplicating it.
- Prompts no longer discourage supporting research when NVD looks sufficient. They permit
  intentional session redisplay of a fetched URL while explaining that it returns the same
  passages, require immediate recording of each useful fetched passage, and preserve distinct
  mechanisms or security-boundary failures as separate findings. Search results for available
  requested/resolved URLs are omitted, one deliberate redisplay remains available, and later
  repeats return an auditable error. Convergence guidance allows further targeted research when it
  could change classification and discourages only expected restatement; it does not force an
  early stop.
- Deterministic coverage exercises rejected finish -> no tool -> search -> second fetch -> corrected
  finish, including promotion of evidence from the second document. Separate tests cover fresh and
  legacy cached JavaScript shells, cached context fragments, exchange/history deduplication,
  URL/session reuse, and ordinary short-document compatibility.

Validation completed:

- Focused `tests/test_agent.py`: 57 passed. Full offline suite: 241 passed. Compilation,
  `git diff --check`, live-secret scan, source distribution, and wheel build all passed.
- A diagnostic 14-CVE debugger run before the final prompt ordering scored micro-F1 0.875 and
  9/14 exact, but used 366,041 tokens and 63 research turns because `CVE-2023-44487` alternated
  session-reused fetches until its research budget was exhausted.
- Fresh focused debugger runs verified exact `SSRF` + `AuthenticationBypass` for
  `CVE-2021-26855`. `CVE-2021-41773` consistently remains conservative at `PathTraversal` because
  its recorded evidence states only conditional RCE and does not establish shell syntax injection.
- Final live validation was split after the provider exhausted its request quota; the first five
  valid persisted cases were combined with a clean nine-case continuation after quota recovery.
  Aggregate results were micro-F1 0.833, 10/14 exact, no partial/failed cases, 337,944 tokens, and
  55 research turns. Accuracy, exact-match, and token thresholds pass. The five-turn excess is the
  requested tradeoff for allowing additional potentially classification-changing research rather
  than forcing convergence; Shellshock used eight turns and Rapid Reset ten.
- All 14 valid results have public and internal provenance. Internal provenance is format version
  2 and contains complete extraction metadata; repeated Rapid Reset fetches are separately audited
  as session reuse/error. No credentials appear in settings, results, or provenance.
- First-chance traces contained only expected generator cleanup, handled provider 503 retries,
  intentional unusable-document rejection, and CLI exit. A separate issue remains: LLM retries do
  not honor the provider's structured retry delay, so short fixed retries can turn throttling into
  a failed CVE. Do not include that independent repair in this amendment.
- Next: review/stage only the intended files, amend `d174d28` without changing its message, then
  stop before GUI or taxonomy work.

## Refactor state

The completed non-GUI refactor units are:

- `ccec8e8 refactor: centralize input validation and fingerprints`
- `5213eaf refactor: unify analysis persistence`
- `306d300 test: normalize benchmark fixture metadata`
- `1d8d12e refactor: remove redundant metadata`
- `c6b09e8 fix: gate evidence recording on fetched documents`
- `5e9388c fix: enforce public web retrieval boundaries`
- `dcd9713 fix: require coherent investigation evidence`
- `65f81f4 fix: prevent redundant web retrieval`
- `d174d28 refactor: make vulnerability research adaptive`

`ARCHITECTURE.md` is a developer-only untracked file and must never be committed. Do not modify the
GUI, taxonomy fixtures, database schema, or public APIs in this repair. After performance recovery,
stop and prepare the separate comprehensive taxonomy-ambiguity plan; hybrid scheduling remains
deferred.
