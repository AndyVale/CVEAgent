# Agent Notes

## Current status

The taxonomy-agnostic refactor, diagnostics, benchmark evaluator, and curated fixtures are
complete. The evaluator implementation is committed as `97060a6`; the benchmark and its tests
are committed as `5a8ea16`. `fixtures/expected-classification.json` contains 14 source-audited
cases covering all 15 labels in the unchanged `fixtures/example_taxonomy.json`.

## Current design

- Research is taxonomy-independent and uses five optional topics: affected system, root cause,
  exploitation mechanism, preconditions, and impact. Unsupported topics are omitted.
- Every retained finding cites application-owned evidence. A fetched passage cited by
  `finish_investigation` is promoted automatically. `record_evidence` is optional, but final
  labels still require evidence.
- The application derives research sufficiency from evidence-backed root-cause or
  exploitation-mechanism findings. Invalid finish items are discarded individually.
- Every arbitrary taxonomy label is evaluated once in bounded chunks. Strict structured output
  is normalized and centrally validated, then merged without a final adjudication request.
- Complete outcomes require complete taxonomy coverage. Persistent malformed chunk output and
  unexpected classification-budget exhaustion checkpoint and return validated partial results;
  provider/infrastructure failures remain fatal.
- Classification tokens are reserved before research. Chunk sizing now reserves the repeated
  profile/schema input instead of using a fixed 2,000-token guess.
- SQLite stores run-scoped metadata, checkpoints, coverage, state, and results. Schema version 2
  remains compatible with the new JSON fields.

## Maintainability and diagnostics changes

- `InvestigationAgent` is now a small top-level orchestrator.
- `research.py` owns the bounded tool loop and tool execution; `investigation.py` normalizes the
  tolerant finish profile; `taxonomy_scan.py` owns exhaustive chunk classification.
- `research_context.py` constructs the model context and bounds NVD references to 24 unique,
  priority-ranked candidates while exposing total/omitted counts.
- Verbose stderr logs model request usage, pacing, bounded search text, sanitized fetch URLs,
  evidence IDs, finding aspects, chunk coverage/supported IDs, persistence, and stop reasons.
  Prompts and evidence passages are not logged. Query strings/fragments are stripped from URL
  diagnostics, configured credentials are redacted, and noisy provider/extraction logs are
  suppressed and restored after the CLI run.
- Empty provider responses now use the redacted diagnostic in both logs and propagated errors.
- NVD retries and web/cache activity have explicit bounded progress logs.

## Validation

- Focused refactor/diagnostics suites pass.
- Full deterministic suite: `75 passed`.
- Bytecode compilation and `git diff --check` pass.
- One authorized live run used a 15-second minimum request-start interval. For CVE-2014-0160
  against the current two-label easy taxonomy it completed all labels and correctly returned
  `no_matching_label`: four research turns, two searches, one fetch, four findings, and no
  credential prefixes in stdout/stderr.
- That run exposed 257 NVD references being resent on every turn and 88,758 total tokens. The
  bounded-reference fix was added afterward and covered deterministically; the paid live run
  was not repeated to conserve the supplied APIs.
- Final validation passes: `82 passed`, bytecode compilation, CLI help smoke test,
  `git diff --check`, fixture fingerprint/coverage checks, and a production-source scan proving
  that example label/CVE IDs are not hard-coded. `fixtures/example_taxonomy.json` is unchanged.

## Deferred and handoff

- NVD weakness assignments remain intentionally excluded.
- The evaluator accepts `--validate PATH`; without positional CVEs it runs every validation
  case, and with positional CVEs it validates and runs only that subset. The stderr summary is
  a table with ID, labels, precision, recall, and F1; metric cells are `-` without validation.
  The complete result JSON on stdout remains parseable.
- No implementation work remains for the benchmark-evaluation change.
