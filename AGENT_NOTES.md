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
- The three demo taxonomies share one mechanism model:
  - flat: nine shared hybrid roots, no parent relationships;
  - hierarchical: the 39 shared hybrid labels at levels one and two, nine roots, maximum depth two;
  - hybrid: the 84-label reference, ten roots, maximum depth four.
- Shared label IDs retain identical names and definitions. The hierarchical and hybrid fixtures use
  `most_specific`; the flat fixture also retains that default policy although it has no ancestry.
- All three expected-classification files use only `schema_version`, `taxonomy_sha256`, and `cases`.
  They contain the same 50 unique CVEs in the same order and preserve the same source lists.
- Flat expectations project each benchmarked hybrid label to its nearest shared root.
  Hierarchical expectations retain levels one and two and project deeper labels to the nearest
  level-two ancestor. Converging labels are deduplicated without reordering. Rationales were
  rewritten for each taxonomy's granularity.
- On 2026-09-17, rechecked every expected selection that directly uses or descends from a revised
  definition across the 50 aligned cases. Native use-after-free, authorization, authentication,
  routing, upload, path, and nonce cases still fit. No case uses `StaleHandleUse`, `ZipSlip`,
  `HostHeaderInjection`, or `NullPointerDereference`. Expected labels and rationales need no
  changes; only the three taxonomy fingerprint values were refreshed.
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
  - flat: `4ac8956192bee78de970b9d9db41a81e55b39bc9370aa70d170be3ed770a426b`
  - hierarchical: `13a5a7344910919dabd9763b1f6afc318e3fab936338a1f1de39af5c2c539fa1`
  - hybrid: `e12a7822d936b89d0885d5edfe202faf7ba75da13a93ae9e8e334d5a8300808e`
- Verification: 37 focused taxonomy, evaluation, planning, and hybrid traversal tests pass. The
  full offline Python suite passes with 320 tests. All fixture JSON parses, the independent fixture
  audit passes, application source does not reference the taxonomy Markdown files, and
  `git diff --check` passes. No live model evaluation was run.

## Repository constraints

- Use `uv` and keep ordinary tests independent of live services.
- Runtime prompts, classification algorithms, model-request settings, frozen contracts, dependency
  files, and `ARCHITECTURE.md` are outside this fixture/documentation change.
- Source package boundaries and stable diagnostic logger names are documented in `AGENTS.md`.
