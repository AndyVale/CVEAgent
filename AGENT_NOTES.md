# Coding-agent notes

## Current state

The GUI package organization is complete and targets the commit
`refactor: organize gui package`.

- GUI Python modules now live in `src/cve_agent/gui/`; browser assets live in
  `src/cve_agent/gui/static/`, and GUI tests mirror the boundary in `tests/gui/`.
- The `cve-agent-gui` command now enters through `cve_agent.gui.app:main`. HTTP routes,
  payloads, CLI arguments, the database schema, and GUI behavior remain unchanged.
- The ignored machine-local configuration moved to
  `src/cve_agent/gui/config.gui.toml`. GUI settings load its relative database and cache paths
  against the project root, so moving the TOML does not redirect runtime state into the package.
- `gui_repository.py`, `GuiAnalysisRepository`, and the redundant persisted-taxonomy fingerprint
  alias were removed. GUI code uses the unified persistence and fingerprint implementations
  directly. The scratchpad-to-event fallback remains for CLI and older analyses without UI events.
- Repository contract tests now live in `tests/test_analysis_repository.py`; no compatibility
  imports for the old GUI module paths remain.

Validation completed:

- Focused GUI/repository/evaluation tests: 50 passed. Full offline suite: 240 passed.
- Bytecode compilation, `git diff --check`, source distribution, and wheel build passed.
- The wheel contains all three GUI assets. A clean temporary wheel installation passed command,
  server startup, health, index, JavaScript, and stylesheet checks.
- Fresh GUI debugger runs submitted `CVE-2014-0160` and `CVE-2020-11022` through HTTP. Both
  completed as classified, stored 126-label taxonomy snapshots, sequenced events, and format-v2
  public/internal provenance. The project first-chance trace contained only expected
  `GeneratorExit` cleanup events. No process credentials were persisted.

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

Remaining larger work:

- Reliability: provider retry delays, hard wall-clock deadlines, extraction-before-truncation,
  and side-effect-free application preflight.
- GUI behavior: typed pipeline events, incremental event persistence, and service decomposition.
- Efficiency: shared HTTP clients and deferred hybrid scheduling work.
- Cleanup: remove the scratchpad event fallback only after every run source persists typed events.
- Taxonomy: prepare and execute the separate comprehensive ambiguity pass.

`ARCHITECTURE.md` is developer-only and must remain untracked and uncommitted.
