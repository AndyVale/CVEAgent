# CVEAgent

CVEAgent investigates CVEs and performs evidence-backed, multi-label classification against
an arbitrary taxonomy supplied by the user. CWE is supported as one possible taxonomy, but
the implementation contains no CWE-specific classification rules and does not use NVD's
weakness assignments.

## Setup

The project uses Python 3.11+ and `uv`:

```bash
uv sync --dev
cp config.example.toml config.toml
export API_KEY="your-provider-key"
```

`config.toml` and local credentials are ignored by Git. `API_KEY` is sent to the configured
OpenAI-compatible endpoint. Tavily search is optional and uses `TAVILY_API_KEY`.

## Taxonomies

Every invocation requires a JSON taxonomy. Labels need only stable IDs, names, and textual
descriptions:

```json
{
  "hierarchy_policy": "most_specific",
  "labels": [
    {
      "id": "CUSTOM-ROOT",
      "name": "Generic parent concept",
      "description": "Definition supplied by the taxonomy owner."
    },
    {
      "id": "CUSTOM-CHILD",
      "name": "Specific child concept",
      "description": "A more specific definition.",
      "parent": "CUSTOM-ROOT"
    }
  ]
}
```

`hierarchy_policy` is optional and defaults to `most_specific`, which suppresses a selected
ancestor when a selected descendant exists. `include_ancestors` adds every ancestor of a
supported label. Array-only taxonomies remain supported and use the default policy.

Validation rejects missing fields, duplicate IDs, unknown parents, hierarchy cycles, and
unknown hierarchy policies. Extra label fields are preserved but do not affect classification.

## Running classifications

```bash
uv run cve-agent --taxonomy fixtures/example_taxonomy.json CVE-2025-6965
```

Multiple CVEs are processed independently and emitted in input order. Use `--verbose` for
safe progress diagnostics on stderr while stdout remains valid JSON:

```bash
uv run cve-agent --verbose --taxonomy fixtures/example_taxonomy.json CVE-2025-6965
```

`--llm-min-request-interval SECONDS` overrides model pacing for one invocation.

## Classification flow

For each CVE, the system:

1. retrieves NVD first and records its English description as exact initial evidence;
2. investigates the vulnerability mechanism without seeing or assigning taxonomy labels;
3. exposes fetched sources as stable, bounded passages;
4. records exact evidence by passage ID, with unique fuzzy-anchor resolution as a fallback;
5. evaluates every taxonomy label in bounded chunks;
6. adjudicates the supported candidates and applies the taxonomy hierarchy policy.

Final model decisions reference evidence IDs rather than writing quotes or URLs. The
application materializes the canonical resolved URL and exact stored passage into the public
JSON result. Search snippets are leads, never evidence.

Complete `classified` and `no_matching_label` results require 100% taxonomy coverage.
Operational metadata includes chunk/label coverage, token usage, stop reason, and run ID.

## Budgets

`token_budget` is the base per-CVE prompt-plus-completion budget. Before NVD or database
work begins, CVEAgent estimates the exhaustive taxonomy scan and final adjudication cost. If
that minimum cannot fit inside the base budget plus `finalization_overrun_percent`, the run
fails preflight without external side effects.

Classification tokens are reserved before investigation. Research cannot consume the
reserve or overrun allowance; only taxonomy scanning and final adjudication may enter the
configured overrun. Provider usage is used when available and conservatively estimated
otherwise. Unexpected exhaustion returns `partial` with validated labels and exact coverage.

`max_input_tokens_per_request` controls taxonomy chunk size. Large or unusually verbose
taxonomies may require raising `token_budget`; preflight reports its estimated minimum.

## Web retrieval and cache

The default search provider is Tavily. Set `[web].provider = "none"` to disable search while
retaining direct fetching of NVD references. NVD and web retries are configured independently.

Downloads are streamed, limited by `max_download_bytes`, restricted to textual content types,
and then extracted and bounded by `max_document_chars` and `max_preview_chars`. Evidence uses
the final response URL while retaining the requested URL and redirect chain.

Searches and fetched documents are cached under `[web].cache_dir`. The cache has no automatic
expiry. To reset it, delete only the configured cache directory; with the example configuration:

```bash
rm -r .cache/cve-agent/web
```

## Persistence and exit codes

SQLite stores separate runs rather than overwriting by CVE ID. Each run records an incremental
run ID, taxonomy fingerprint, model, non-secret effective settings, timestamps, status, and
per-CVE checkpoints/results. Checkpoints are written after NVD retrieval, evidence changes,
and completed taxonomy chunks.

The current schema is version 2. A legacy development database is not migrated automatically;
remove the configured database explicitly when the CLI reports an incompatible schema.

Exit codes are:

- `0`: every CVE is classified, has no matching label, or lacks sufficient information;
- `2`: at least one CVE is partial or failed;
- `3`: invalid taxonomy input;
- `4`: fatal configuration, preflight, provider-initialization, or persistence error.

## Development

Tests are deterministic and require no live web or model service:

```bash
uv run pytest -q
```
