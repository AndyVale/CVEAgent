# CVEAgent
# CVEAgent

CVEAgent is an evidence-backed, multi-label CVE classification system. The initial
implementation provides the taxonomy contract, NVD/web/vLLM adapter interfaces, local
SQLite persistence, and a JSON CLI foundation.

## Development

The project uses Python and `uv`:

```text
uv run cve-agent --taxonomy fixtures/example_taxonomy.json CVE-2026-0001
```

Copy [config.example.toml](config.example.toml) to `config.toml` and edit the local copy.
The real `config.toml` is ignored by Git. Set the remote vLLM address in
`[runtime].endpoint`, for example `https://203.0.113.10:8000/v1`, and set the served model
in `[runtime].model`.

The API key value is never placed in the configuration file. If the vLLM server requires
authentication, export it as `VLLM_API_KEY`; otherwise the client sends the placeholder key
`EMPTY`.

The runtime section also controls `max_tokens`, `temperature`, `top_p`, and request
`timeout_seconds`. NVD/web retry counts and timeouts, cache location, SQLite location, and
the investigation token budget are configured in the remaining sections.

The CLI writes a JSON array to stdout in input order. Per-CVE diagnostics belong to the
result object; operational diagnostics are written to stderr. Exit code `0` means all CVEs
completed, `2` means at least one CVE failed, `3` means invalid taxonomy input, and `4`
means a fatal infrastructure error.

The local SQLite database stores each CVE's status, result, error, scratchpad, and token
usage. Its default location is `.data/cve-agent.sqlite3`.

The investigation agent uses the OpenAI-compatible vLLM client with four bounded actions:
search, fetch, record evidence, and finish investigation. Web pages are retrieved with
`httpx`, cleaned with `trafilatura`, cached locally, and returned to the model only as
bounded previews. A page enters the retained investigation context only after the agent
records a verifiable quote from it.

The agent uses required tool calls for compatibility with vLLM servers that are not
started with `--enable-auto-tool-choice` and `--tool-call-parser`. The model still chooses
which required tool to call, including `finish_investigation` when it is done.

Use `--verbose` to send pipeline and agent progress to `stderr` while keeping the JSON
classification output on `stdout`:

```text
uv run cve-agent --verbose --taxonomy fixtures/example_taxonomy.json CVE-2025-6965
```

Verbose logs include NVD retrieval, agent turns, tool names, result counts, evidence
promotion, limits, and final status. Prompts, API keys, and document contents are not
logged.

The search port remains provider-neutral. Deterministic tests inject a fixture searcher;
the default CLI does not select a commercial search provider yet, so live investigations
must either use fetchable NVD references or provide a configured `WebSource` adapter.
