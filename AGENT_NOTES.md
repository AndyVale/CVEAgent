# Agent Notes

## Current status

The taxonomy-agnostic refactor is committed through `7498c9a`. The working tree contains the
approved prompt/profile simplification plus a pre-commit maintainability and diagnostics pass.
No commit has been created yet; `AGENTS.md` requires developer approval for each proposed
commit. The unrelated `x.json` observed earlier was not touched.

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

## Deferred and handoff

- NVD weakness assignments remain intentionally excluded.
- The partial-positive labelled-dataset evaluation command remains intentionally deferred.
- Review the final diff/status, then propose logical Conventional Commit boundaries. Do not
  commit until the developer explicitly approves them.
