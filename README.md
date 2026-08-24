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
OpenAI-compatible endpoint. Tavily search uses `TAVILY_API_KEY`. The investigator is directed
to perform web research, while the application derives information sufficiency from the
evidence-backed mechanism findings it actually produces.

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

The verbose trace reports research turns, bounded search queries, sanitized fetched URLs,
evidence IDs, finding aspects, taxonomy chunks and supported label IDs, token usage, coverage,
checkpoints, and stop reasons. It does not log model prompts or evidence passages. URL query
strings and fragments are removed, configured credentials are redacted from provider
diagnostics, and noisy dependency logs are suppressed.

`--llm-min-request-interval SECONDS` overrides model pacing for one invocation.

Every invocation ends with a compact mapping on stderr while stdout remains the complete valid
JSON result:

```text
Classification summary
ID             | Labels                  | Precision | Recall | F1
---------------+-------------------------+-----------+--------+---
CVE-2014-0160  | OutOfBoundsRead         | -         | -      | -
CVE-2021-41773 | PathTraversal, InfoLeak | -         | -      | -
```

Precision, recall, and F1 are `-` during an ordinary classification. Pass `--validate` to
calculate them for each CVE by comparing predicted and expected label sets.

## Evaluating classification performance

`fixtures/expected-classification.json` contains 14 conservatively selected CVEs covering every
label in the unchanged `fixtures/example_taxonomy.json`. Each case records expected label IDs,
a short mapping rationale, and the primary or NVD sources used to curate it. The benchmark also
contains a taxonomy fingerprint, so it cannot accidentally be evaluated against another
taxonomy.

Run the complete benchmark without listing CVE IDs:

```bash
uv run cve-agent \
  --taxonomy fixtures/example_taxonomy.json \
  --validate fixtures/expected-classification.json
```

Or run a cheaper subset while developing:

```bash
uv run cve-agent \
  --taxonomy fixtures/example_taxonomy.json \
  --validate fixtures/expected-classification.json \
  CVE-2014-0160 CVE-2021-41773
```

With `--validate`, the classification table contains per-CVE precision, recall, and F1. The
aggregate report that follows includes exact matches, micro precision/recall/F1, macro-F1 over
labels present in the selected evaluation, per-label precision/recall/F1 and confusion counts,
the number of partial or failed cases, and every mismatch. Partial results can contribute their
validated labels to precision/recall, but never count as exact matches. The normal JSON remains
on stdout, so it can still be redirected independently from the human-readable report.

The full benchmark can require many model and search calls. Keep the configured request pacing
and use subsets for prompt iteration before spending quota on all cases.

## Classification flow

For each CVE, the system:

1. retrieves NVD first and records its English description as exact initial evidence;
2. conducts taxonomy-independent web research focused on the affected system, root cause,
   exploitation mechanism, preconditions, and impact;
3. exposes fetched sources as stable, bounded passages;
4. builds a concise profile from any supported high-level findings; its topics are guidance,
   not mandatory fields;
5. evaluates every taxonomy label independently in bounded chunks using strict structured
   output;
6. validates and merges all chunk labels deterministically, then applies the hierarchy policy.

Final model decisions reference evidence IDs rather than writing quotes or URLs. The
application materializes the canonical resolved URL and exact stored passage into the public
JSON result. A fetched passage cited at investigation finish is promoted automatically;
`record_evidence` remains an optional way to preserve a passage across research turns. Full
passage IDs and document-local forms such as `1` or `p1` are accepted when unambiguous. Search
snippets are leads, never evidence.

NVD records can contain hundreds of references. To avoid resending an oversized record on every
turn, the model receives at most 24 unique candidates, prioritizing vendor advisories, patches,
release notes, mitigations, product pages, exploits, technical descriptions, and then
third-party advisories. The complete and omitted reference counts remain explicit in the
research context.

Classification prompts require numeric confidence in the `[0, 1]` range. As a compatibility
fallback for providers that ignore that instruction, `low`, `medium`, and `high` are normalized
to `0.35`, `0.60`, and `0.85`; percentage strings are converted to their decimal value. Each
normalization is logged. Unknown confidence words remain invalid and trigger the bounded
correction request. Taxonomy-chunk responses wrapped as a top-level JSON array are also
accepted, because the active chunk is unambiguous.

The classifier is explicitly instructed to distinguish root causes and exploitation mechanisms
from consequences: remote code execution, disclosure, denial of service, or privilege gain do
not by themselves prove a particular weakness class. There is no final model adjudication
request; a completed exhaustive scan is the classification result.

Complete `classified` and `no_matching_label` results require 100% taxonomy coverage.
Operational metadata includes chunk/label coverage, token usage, stop reason, and run ID.

## Budgets

`token_budget` is the base per-CVE prompt-plus-completion budget. Before NVD or database
work begins, CVEAgent estimates the exhaustive taxonomy-scan cost, including the repeated
profile, evidence, prompt, schema, and output allowance. If
that minimum cannot fit inside the base budget plus `finalization_overrun_percent`, the run
fails preflight without external side effects.

Classification tokens are reserved before investigation. Research cannot consume the
reserve or overrun allowance; only taxonomy scanning may enter the configured overrun.
Provider usage is used when available and conservatively estimated
otherwise. Unexpected exhaustion returns `partial` with validated labels and exact coverage.
When research stops before it can produce a profile, classification receives a bounded set of
the evidence already collected instead of silently discarding it.

`max_input_tokens_per_request` controls taxonomy chunk size. Large or unusually verbose
taxonomies may require raising `token_budget`; preflight reports its estimated minimum. Chunk
planning reserves room for the repeated vulnerability profile and structured-output schema,
so an input limit too small for that fixed context fails before research begins.

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
the structured investigation profile, and completed taxonomy chunks.

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
