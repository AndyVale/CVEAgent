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
