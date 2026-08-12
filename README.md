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

Runtime defaults are in [config.toml](config.toml). The vLLM API key, when required, is
read from the environment variable named by `runtime.api_key_env`; secrets are not stored
in the configuration file.

The CLI writes a JSON array to stdout in input order. Per-CVE diagnostics belong to the
result object; operational diagnostics are written to stderr. Exit code `0` means all CVEs
completed, `2` means at least one CVE failed, `3` means invalid taxonomy input, and `4`
means a fatal infrastructure error.

The local SQLite database stores each CVE's status, result, error, scratchpad, and token
usage. Its default location is `.data/cve-agent.sqlite3`.
