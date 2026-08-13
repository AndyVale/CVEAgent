# Agent Notes

## Current status

The initial implementation slice is present: package metadata, domain models, taxonomy
validation, TOML settings, SQLite persistence, pipeline/CLI contracts, NVD/web/vLLM
adapters, fixtures, and tests.

The vLLM adapter now uses the `openai` Python client. Tracked configuration is a safe
`config.example.toml`; the real `config.toml` is ignored, and `VLLM_API_KEY` is read only
from the environment.

The CLI now constructs the NVD, cached web, and vLLM adapters by default, so a local
`config.toml` can connect to a remote vLLM OpenAI-compatible endpoint. Deterministic tests
pass (`6 passed`); no live external service is used by the tests.

Validation performed: Python bytecode compilation and a SQLite/taxonomy smoke test pass.
The pytest suite could not start because the environment cannot download the unavailable
`hatchling` build backend from PyPI; the failure is environmental rather than a test
assertion failure.

## Current focus

Implement the initial project structure and development tooling according to `AGENTS.md` and the project specification.

## Confirmed decisions

- Use a local LLM served by vLLM on Vast.ai through its OpenAI-compatible API. Endpoint,
  model, credentials, limits, and runtime parameters are configurable; secrets must come
  from environment variables or another local secret mechanism.
- Keep explicit interfaces for `get_cve`, `search`, and `fetch`, with typed records for
  CVEs, search results, and documents. Search/fetch caching is transparent and keyed by
  query or URL. External transient failures use bounded retries; other failures propagate.
- Use local SQLite for classification results, CVE processing status/errors, token usage,
  and inspectable partial investigation state. Defer vector-database work.
- The CLI emits a JSON array to stdout, preserving input CVE order. Diagnostics and
  progress go to stderr. One CVE failure is represented in its result while other CVEs
  continue; unrecoverable persistence failures terminate the run.
- Begin with CWE-compatible JSON taxonomies while preserving a generic taxonomy model.
  Required fields are `id`, `name`, and `description`; IDs are unique, parent references
  are stored on children and must resolve, and hierarchy cycles are invalid. Names and IDs
  are case-sensitive. Extra fields may be preserved but are not part of classifier logic.
- Use distinct CLI exit codes for complete success, runs containing failed/partial CVEs,
  and fatal infrastructure failures.
- Centralize non-secret development settings in a separate configuration file, including
  vLLM, NVD/web, retry, timeout, cache, SQLite, and token-budget defaults.
- Tests use deterministic local fixtures for NVD, web, and LLM interactions. Include a
  complete example taxonomy, representative CVEs, and an expected end-to-end result.
- Evaluation accepts an explicitly supplied labelled ground-truth dataset and reports
  micro-F1, macro-F1, and per-label precision/recall/F1. `not_enough_information` is not a
  metric label unless the dataset explicitly defines it; incomplete CVEs/labels are
  reported as exclusions.

## Next steps

- Resolve the unavailable build dependency in the development environment and run the
  pytest suite.
- Expand the investigation loop so the classifier can actively use search/fetch evidence
  while preserving NVD as the first source.
- Add CLI integration tests and the labelled-dataset evaluation command.
- Harden retry/error handling and define provider-specific web search configuration.

## Open decisions

- The initial web-search provider and cache serialization mechanism need provider-level
  configuration and further tests.
- The evaluation dataset file schema needs to be specified when the evaluator is added.

The vector-database design remains intentionally deferred until the initial application
structure and retrieval/classification flow are established.
