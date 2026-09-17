# Coding-agent notes

## Review findings remediation (2026-09-16)

- Implemented public-page IP pinning for every fetch/redirect hop. The application-owned fetch
  client ignores environment proxies and does not retain idle connections; logical hostnames stay
  in HTTP Host, HTTPS verification, and document provenance.
- Benchmark files now require integer schema version 1 and a matching taxonomy fingerprint.
  NVD retries only transient HTTP statuses, timeouts, and network failures.
- Added deterministic regression tests and updated the README. The focused integration, cache,
  evaluation, and CLI suite passed: 72 tests. The final full offline suite passed: 344 tests;
  `git diff --check` passed.
- Live run requirements: first ten ordered hybrid benchmark cases, current 100,000-token per-CVE
  ceiling, isolated temporary database/cache, no-echo credential entry, and both micro/macro F1
  strictly above 0.80. If either falls short, report without tuning or rerunning. Never put key
  values in source, configuration, commands, logs, or notes. The no-echo prompt was queued but
  never became visible in the app. It was canceled before any credential entry or live call, so
  the ten-CVE run and F1 assessment remain pending.

## Classification demo alignment (2026-09-15)

- Work is on `main`. The working tree was clean before this task. No commit should be created until
  the developer explicitly approves the proposed commit.
- The three demo taxonomies are progressive projections of one mechanism model:
  - flat: nine hybrid roots, no parent relationships;
  - hierarchical: the 39 hybrid labels at levels one and two, nine roots, maximum depth two;
  - hybrid: the 84-label reference, nine roots, maximum depth four.
- Shared label IDs retain identical names and definitions. The hierarchical and hybrid fixtures use
  `most_specific`; the flat fixture also retains that default policy although it has no ancestry.
- All three expected-classification files use only `schema_version`, `taxonomy_sha256`, and `cases`.
  They contain the same 50 unique CVEs in the same order and preserve the same source lists.
- Flat expectations project each hybrid label to its nearest root. Hierarchical expectations retain
  levels one and two and project deeper labels to the nearest level-two ancestor. Converging labels
  are deduplicated without reordering. Rationales were rewritten for each taxonomy's granularity.
- The existing online evidence was rechecked and remained consistent with all 50 hybrid
  expectations. No CVE was excluded, replaced, or classified from CVEAgent output. All seven
  cross-root multi-mechanism cases remain multi-label in every projection.
- Coverage is 8/9 flat labels, 18/39 hierarchical labels, and 22/84 hybrid labels. The
  availability-and-resources root is unrepresented; other gaps are documented without forcing
  unsupported labels.
- Under the documented 12,000-token per-request input limit and 50,000-token total budget, flat and
  hierarchical each form one exhaustive chunk. Hybrid forms two exhaustive chunks, so `auto`
  selects the hybrid scanner. “Hybrid” describes its iterative routing/pruning plus exhaustive
  subtree consumption path, not a mixture of ontology types.
- Documentation-only design notes live beside each fixture. Application code does not reference
  those Markdown files. The main README describes the shared benchmark and consumption strategies.
- Current fingerprints:
  - flat: `f9c8d5199d4809a95c6773344e81d247ef41589c4cf6f40d09c6633887bcb960`
  - hierarchical: `4a270d875feea19885efea23ee86cb2ce8c5d861dfeaab721493e94b940b3b43`
  - hybrid: `d466b8ebd065c5df63a282f657de58b9bb9ae17e743b1cfdc773fd63e431083e`
- Verification: 37 focused taxonomy, evaluation, planning, and hybrid traversal tests pass. The
  full offline Python suite passes with 320 tests. All fixture JSON parses, the independent fixture
  audit passes, application source does not reference the taxonomy Markdown files, and
  `git diff --check` passes. No live model evaluation was run.

## Repository constraints

- Use `uv` and keep ordinary tests independent of live services.
- Runtime prompts, classification algorithms, model-request settings, frozen contracts, dependency
  files, and `ARCHITECTURE.md` are outside this fixture/documentation change.
- Source package boundaries and stable diagnostic logger names are documented in `AGENTS.md`.
