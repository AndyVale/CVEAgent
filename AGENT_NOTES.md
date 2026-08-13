# Agent Notes

## Current status

The initial implementation slice is present: package metadata, domain models, taxonomy
validation, TOML settings, SQLite persistence, pipeline/CLI contracts, NVD/web/vLLM
adapters, fixtures, and tests.

The vLLM adapter now uses the `openai` Python client. Tracked configuration is a safe
`config.example.toml`; the real `config.toml` is ignored, and `VLLM_API_KEY` is read only
from the environment.

The classifier contract was tightened after a live Qwen3 response returned a CVE summary
instead of a classification object. Requests now include an explicit JSON schema, vLLM
guided JSON, and `enable_thinking=false` by default; `<think>` wrappers are also handled.
The deterministic suite passes (`7 passed`). A live retest reached the configured endpoint
but returned HTTP 401 because `VLLM_API_KEY` is not available in this agent process; rerun
from the shell where the key is exported.

Fixed vLLM prompt construction to recursively serialize nested dataclasses such as CVE
references. The deterministic suite passes (`6 passed`). NVD connectivity was verified
with HTTP 200, but the configured vLLM endpoint `109.134.153.217:8000` timed out during
connectivity testing; the remote port/service needs to be made reachable before a live
classification can complete.

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

- Add the labelled-dataset evaluation command.
- Define provider-specific web-search configuration.

## Open decisions

- The initial web-search provider and cache serialization mechanism need provider-level
  configuration and further tests.
- The evaluation dataset file schema needs to be specified when the evaluator is added.

## Current implementation slice

The bounded investigation agent is implemented. It uses only `search`, `fetch`, `record_evidence`, and
`finish_investigation`. NVD remains a pipeline-controlled first step. `httpx` and
`trafilatura` provide cached retrieval and bounded readable previews; full pages stay out
of the active prompt, and only explicitly recorded quotes are promoted into future context.
The agent enforces configurable turn, search, fetch, token, and wall-clock limits.

Tavily search is configured through the `TAVILY_API_KEY` environment variable. Fetch
diagnostics now report cache state, attempts, HTTP status, redirects, content type, byte
counts, extraction fallback, and typed failure messages without logging page contents or
secrets. Fetch/search exceptions are returned as recoverable tool errors so one bad URL
does not abort the entire CVE investigation. The deterministic suite passes (`13 passed`).

Verbose tool logs now include safe parameters and detailed error results. Repeated fetches
of a URL that already failed are blocked for the current investigation, and low-value
httpx/httpx2 request logs are suppressed in verbose mode. This keeps the agent trace useful
without exposing secrets or page contents.

The first live CLI attempt against the configured setup reached the service but this
environment did not expose `VLLM_API_KEY` and received HTTP 401. The developer-reported
HTTP 400 was diagnosed separately: the server was not started with vLLM auto-tool-choice
flags, so the controller now requests `tool_choice="required"`, which does not require
that optional server mode.

The follow-up refactor centralizes tool and classification schemas, removes the unused
investigation exception and execution parameters, bounds each request's completion tokens
by the remaining budget, keeps only the latest tool exchange in active context, and treats
search results as leads rather than visited URLs. Invalid finish calls now return a tool
error so the model can correct them within the remaining limits.

Verbose CLI logging is implemented with `--verbose`. It writes pipeline and agent progress
to stderr while preserving JSON output on stdout; prompts, keys, and document contents are
not logged. The logging test and full suite pass (`11 passed`).

The vector-database design remains intentionally deferred until the initial application
structure and retrieval/classification flow are established.
