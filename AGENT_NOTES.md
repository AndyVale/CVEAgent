# Agent Notes

## Active refactor

The approved whole-repository refactor is in progress on `main`. The first unit is committed as
`ccec8e8 refactor: centralize input validation and fingerprints`; its 189 offline tests and live
CLI/GUI checks passed. The second unit is committed as
`5213eaf refactor: unify analysis persistence`; its schema-version-3 repository provides immutable
run snapshots, lightweight analyses, checkpoint/result payloads, sequenced events, and separate
provenance records. Exact SQL cache lookup, stale-run
recovery, immutable taxonomy history, saved fresh-session defaults, and copied old-analysis
defaults are covered. The complete suite passes 196 tests plus compilation and whitespace
checks. Fresh-schema online tests exercised flat and hierarchical CVEs, successful, partial,
failed, rate-limited, retried, and unavailable-document paths; every terminal state and immutable
snapshot was stored correctly. Fixture accuracy remained diagnostic only. The third unit is
committed as `306d300 test: normalize benchmark fixture metadata`; it adds stable taxonomy names,
updates their benchmark fingerprints, and removes duplicated top-level CVE lists from expected
results. A renamed flat fixture produced a real cache miss, recovered from a transient model error,
and completed. Credentials remained process-only.

The safe-cleanup unit is committed as `1d8d12e refactor: remove redundant metadata`. It derives
`cve_agent.__version__` from project metadata, removes the unused `NO_FINISH_TOOL` value, and
removes the unused taxonomy filename from the benchmark model and expected-result fixtures. Its
197 offline tests, compilation, and whitespace checks passed. A live Heartbleed validation used
real NVD, Tavily, fetched documents, and the model; it stopped at the deliberately small
investigation budget, classified `OutOfBoundsRead` as a valid partial result, and persisted schema
version 3 correctly. Credentials remained process-only; the temporary configuration contained no
secrets.

The evidence-tool precondition fix is committed as
`c6b09e8 fix: gate evidence recording on fetched documents`. Research tool definitions are now
generated from session state: `record_evidence` is hidden before a successful fetch and its
document ID is then constrained to fetched documents. A defensive invalid call is not added to
duplicate-call tracking, so the same call can succeed after the document is fetched. Its 198-test
suite and live Heartbleed sequence passed without the earlier document-not-found warning.

The public-web trust unit is committed as
`5e9388c fix: enforce public web retrieval boundaries`. `PublicWebUrlPolicy` permits only credential-free HTTP(S) URLs
whose DNS answers are all globally routable. Search candidates now return printable rejection
reasons without exception-driven hostname detection; malformed cached URLs such as an escaped
`www\\.sentinelone.com` hostname are discarded and logged. Typed fetch failures remain visible in
the research trace. The cache revalidates search results and stored documents, and the downloader
validates every redirect before requesting it. Research instructions explicitly treat external
text as untrusted data. The complete 216-test suite, compilation, whitespace checks, secret scan,
and package build pass. A fresh controlled debugger run classified `CVE-2020-11022` and
`CVE-2014-0160` through real NVD, Tavily, public DNS, fetched advisories, the model, and
schema-version-3 persistence. Both completed successfully, the project-only first-chance tracer
observed no exceptions, temporary state was removed, and credentials remained process-only.
The coherent-evidence unit is ready. Fetched text is packed into deterministic passages around
900 characters instead of one passage per source line. Finish submissions are validated without
mutating state; unknown, ambiguous, empty, or mechanically fragmentary citations receive one
correction turn. If correction is unavailable or ignored, the valid subset is materialized and
discard reasons remain in operational metadata and provenance. The complete 225-test suite,
compilation, whitespace and secret checks, and package build pass. A fresh debugger run of
`CVE-2018-9206` and `CVE-2015-7547` completed successfully with accepted quotes between 463 and
990 characters, no unusable evidence, and no project exceptions. The second case exercised the
invalid-finish fallback after the model ignored its correction instruction. Temporary state was
removed and credentials remained process-only. Next: commit
`fix: require coherent investigation evidence`.

## Current work

The GUI now renders the public provenance catalog as a human-readable evidence chain inside
each expanded quotation. Discovery nodes (`NVD reference`, `Web search`, or `Direct source`),
the canonical hostname, and `Supporting quote` are keyboard-accessible buttons backed by one
inline detail panel. Discovery details show queries or NVD tags; source details show safe full
URLs, redirects, cache/fetch state, and humanized CVE-association diagnostics; quotation details
show exact context and accepted findings. Internal provenance IDs remain join keys only and are
never interface labels. Legacy analyses retain their existing quote/link with a quiet unavailable
notice. Focused GUI/provenance tests pass. Local browser verification against the persisted
`CVE-2020-11022` result confirmed the NVD and NVD-reference/vendor chains, node switching, full
URL tooltip, readable warning, context/findings, no console errors, and no page overflow at
1280-, 800-, and 500-pixel widths.

An evidence-provenance refactor is implemented and ready for review. A versioned, harness-owned
ledger now links the target CVE, bounded NVD/search candidates, every fetch attempt and redirect,
the complete bounded passages shown to the model, selected evidence, accepted findings, and
final label explanations. Normal model requests explicitly exclude this cold context. Normal
JSON exposes only paths reachable from returned labels, while SQLite checkpoints retain failed
and unused paths in the existing scratchpad JSON without an SQL schema migration. Deterministic
CVE-association signals warn without rejecting weakly linked sources, and adjacent passages are
stored as context rather than evidence. Evidence construction is centralized for explicit and
finish-time selection. The complete 165-test suite, bytecode compilation, whitespace review,
secret scan, and sdist/wheel build pass.

A live CLI run (not the GUI) classified `CVE-2014-0160` with the flat taxonomy and validation,
using the configured Gemini provider and a forced 15-second request interval. It exited 0 in
51.6 seconds after four model requests and 16,782 tokens, persisted run 3, and produced valid
stdout JSON separate from verbose stderr. It selected the expected `OutOfBoundsRead` plus the
broad overlapping `InputValidation` label, so benchmark precision/recall/F1 were
0.500/1.000/0.667. The additional label is evidence-backed by the fixture definition and source
text rather than a provenance failure. Public provenance contained only the three evidence
records used by final labels; the scratchpad retained all 29 discovery candidates, four evidence
records, four research events, and all 34 fetched source passages. Source origin matching and
CVE association were correct and produced no warnings.

The verbose formatter no longer constructs `LogTone` from missing or invalid third-party log
metadata. The previous exception-driven fallback worked during normal execution but caused
debuggers configured for raised exceptions to pause on every ordinary record because its absent
tone appeared as `None`. Direct value lookup now falls back to log severity without raising.
Tests cover `None`, unknown strings, and unhashable values. An offline direct CLI orchestration
run with verbose logging exercised the original startup line and completed with exit 0.

The GUI follow-up committed as `54af3eb` fixes navigation, overflow, and settings feedback. The
separate new-analysis button is removed; the home view now has the primary CVE input, stored
chats expose an explicit Back button, and the secondary input is labelled as starting another
analysis.
Analysis options moved from both composers to the Active snapshot sidebar. History, chat, and
configuration panes now have independent bounded scrolling, long evidence content cannot widen
the shared grid, stored chats reopen at the top, and stale history responses/scroll callbacks
cannot overwrite the latest selection.

Global settings submit on Enter, reject database directories and database paths whose parent
directory does not exist, and keep validation notices in the dialog's top layer as fixed
overlays so errors remain visible without changing dialog dimensions.

The GUI now owns an ignored root-level `config.gui.toml`. On first use it copies the selected
root-level initialization TOML without changing it; option saves validate the complete effective
settings, preserve comments and unknown keys with `tomlkit`, and atomically update only the
GUI-owned file. The TOML is no longer exposed as an analysis or global editable field.

All GUI file access is constrained by `GuiPathPolicy`: taxonomy reads stay below `fixtures/`,
SQLite and GUI-state files below `.data/`, web cache below `.cache/`, and TOML files at the
project root. Canonical resolution rejects traversal and symlink escapes; extensions are
restricted; persisted state is revalidated on load; state/config writes use unpredictable
same-directory temporary files. Mutating HTTP requests require JSON and same-origin headers
when an Origin is present, bodies are capped, CVE/analysis IDs are bounded, and the existing
loopback/Host/CSP protections remain. Cache paths and client-supplied config paths are no longer
editable. The UI uses server-generated taxonomy/database selectors with only `fixtures/`,
`.data/`, and `./` prefixes visible; it can create a validated new SQLite filename.

The settings form publishes numeric bounds and choices, hides hierarchy controls for flat
taxonomies, hides pruning for exhaustive scans, and hides provider-specific controls when web
research is disabled. Stored CVE snapshots remain immutable.

Loopback-only browser checks at 1280x720 verified independent scrolling, no horizontal
overflow, clean old-CVE transitions, Back navigation, the relocated options control, Enter
submission, invalid SQLite feedback, unchanged dialog geometry, flat-taxonomy filtering,
provider-dependent filtering, numeric bounds, fixed-overlay cross-field errors, project-relative
path presentation, constrained taxonomy/database choices, and safe new-database creation. A
rejected save left the temporary TOML unchanged. The complete 158-test suite passes, as do
bytecode compilation, whitespace review, and the CLI-isolation check. The temporary servers were
stopped without starting a classification.

A focused local graphical interface is implemented through `deb5e90`, `6569a62`, and `e4961d5`
and remains completely separate from `cli.py`. The Flask entry point calls
`ClassificationApplication` directly, while a GUI-facing service owns background execution,
exact configuration/taxonomy cache matching, progress capture, immutable chat snapshots, and
history payloads. GUI-only metadata and event tables are additive to the existing
schema-version-2 database.

The browser interface has the requested three-pane layout: persisted CVE history on the left,
chat/progress and evidence-backed results in the center, and the active taxonomy/effective
settings on the right. Global database/default paths and next-analysis settings use separate
dialogs. Secrets remain environment-only. New chats inherit the latest GUI snapshot, stored
chat settings never mutate, and partial/failed results are not cache hits.

Flask is the only new runtime dependency. Sixteen deterministic GUI tests currently pass,
covering configuration conversion and secret exclusion, repository compatibility, cache reuse,
progress persistence, strict CVE validation, local-only request enforcement, routes, and static
assets. The complete 136-test suite and bytecode compilation pass. A localhost-only server was
started and its health/history endpoints returned successfully without an analysis or external
call; it was then stopped. The isolated in-app browser could not reach host loopback, and a
non-loopback bind was explicitly rejected rather than exposing the GUI. The standard sdist/wheel
build passes and includes all HTML, CSS, and JavaScript assets. The GUI is hard-bound to
`127.0.0.1`, rejects non-local Host headers, and its user documentation is updated.

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

The GUI follow-up described at the top is implemented, verified, and ready for developer review
and commit approval. No known implementation blocker remains.
