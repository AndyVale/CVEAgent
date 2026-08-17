# CVEAgent

CVEAgent is an evidence-backed, multi-label CVE classification system. The initial
implementation provides the taxonomy contract, NVD/web/LLM adapter interfaces, local
SQLite persistence, and a JSON CLI foundation.

## Development

The project uses Python and `uv`:

```text
uv run cve-agent --taxonomy fixtures/example_taxonomy.json CVE-2026-0001
```

Copy [config.example.toml](config.example.toml) to `config.toml` and edit the local copy.
The real `config.toml` is ignored by Git. The default runtime targets OpenRouter at
`https://openrouter.ai/api/v1` and the configured model is
`nvidia/nemotron-3-ultra-550b-a55b:free`. You can change `[runtime].endpoint` and
`[runtime].model` for another OpenAI-compatible provider or model.

The API key value is never placed in the configuration file. Export the provider key as
`API_KEY` before running the CLI. The OpenAI Python client sends it as a bearer token.

The runtime section also controls `max_tokens`, `temperature`, `top_p`, request
`timeout_seconds`, LLM `retry_count`, and the LLM retry backoff. LLM, NVD, and web retries
are bounded; the LLM wait doubles after each failed interaction up to
`retry_max_wait_seconds`. Cache
location, SQLite location, and the investigation token budget are configured in the
remaining sections.

The CLI writes a JSON array to stdout in input order. Per-CVE diagnostics belong to the
result object; operational diagnostics are written to stderr. Exit code `0` means all CVEs
completed or were conclusively information-limited, `2` means at least one CVE is partial
or failed, `3` means invalid taxonomy input, and `4` means a fatal infrastructure error.

The local SQLite database stores each CVE's status, result, error, scratchpad, and token
usage. Its default location is `.data/cve-agent.sqlite3`.

The investigation agent uses the OpenAI-compatible chat-completions client with four bounded actions:
search, fetch, record evidence, and finish investigation. Web pages are retrieved with
`httpx`, cleaned with `trafilatura`, cached locally, and returned to the model only as
bounded previews. A page enters the retained investigation context only after the agent
records an evidence quote from it.

The NVD description is recorded as initial evidence before the first agent turn, so a clear
CVE can be classified without an unnecessary web fetch. Additional tool activity is kept
in a compact per-CVE history showing searched queries, fetched URLs, result sizes, and
errors. Evidence quotes are verified when possible; a non-verbatim quote is retained but
marked as unverified.

The agent uses standard OpenAI-compatible tool calling. It allows one tool call at a time
and enforces configurable turn, token, fetch, search, and wall-clock limits. The intended
short workflow is fetch one strong source, record one exact quote, and finish. Repeated
fetches reuse the in-memory document preview instead of making another request.

Use `--verbose` to send pipeline and agent progress to `stderr` while keeping the JSON
classification output on `stdout`:

```text
uv run cve-agent --verbose --taxonomy fixtures/example_taxonomy.json CVE-2025-6965
```

Verbose logs include NVD retrieval, agent turns, tool names, result counts, evidence
promotion, limits, provider response identifiers, and final status. Prompts, API keys, and
document contents are not logged. Empty provider completions include safe response metadata
instead of producing an opaque `NoneType` crash.

The search port remains provider-neutral. Deterministic tests inject a fixture searcher;
the default CLI uses Tavily when `[web].provider = "tavily"`. Set the API key only in the
environment:

```bash
export TAVILY_API_KEY="tvly-..."
```

The key is never read from or stored in the TOML configuration. Without the key, direct
URL fetching and NVD references still work, but an agent search request fails clearly.

With `--verbose`, fetch diagnostics include cache hits/misses, retry attempts, HTTP status,
redirect target, content type, response size, extraction fallback, and typed failure
messages. A failed source is returned to the agent as a recoverable tool error so it can
try another source or finish with the evidence already collected.
