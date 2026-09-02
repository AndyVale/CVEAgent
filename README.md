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

Validation rejects empty taxonomies, blank fields, duplicate IDs, unknown parents, hierarchy
cycles, hierarchies deeper than 64 parent links, and unknown hierarchy policies. Required
strings are trimmed. An optional top-level `name`, other top-level metadata, and extra label
fields are retained in the canonical taxonomy snapshot and fingerprint.

### Choosing a classification strategy

Classification strategy is operational configuration, not part of the taxonomy:

```toml
[classification]
strategy = "auto" # auto, hybrid, or exhaustive
pruning_confidence_threshold = 0.8
```

Flat taxonomies always use linear exhaustive chunking. Their configured strategy is ignored
and the override is logged. For hierarchical taxonomies:

- `auto`, the default, uses exhaustive classification when the entire taxonomy fits in one
  request and hybrid traversal otherwise;
- `hybrid` always performs at least one root-routing request, even for a small tree;
- `exhaustive` evaluates every label linearly without pruning.

Hybrid traversal routes all active nodes breadth-first. A node may be `supported`, `uncertain`,
or `unsupported`. Supported and uncertain nodes expand; an unsupported node prunes its
descendants only when its confidence meets `pruning_confidence_threshold`. Lower-confidence
unsupported decisions are treated as uncertain. The scanner may switch the remaining active
subtrees to exhaustive evaluation when its conservative cost estimate is no greater than
continued traversal. Remaining uncertain leaves and internal nodes without a supported
descendant receive a final evidence-backed binary evaluation.

> **Hybrid classification trades recall guarantees for efficiency.** An early routing error can
> prune the correct branch, the reserved budget guarantees only one complete root-to-leaf path,
> multi-branch vulnerabilities can return `partial`, and hybrid routing can cost more than
> exhaustive evaluation for small trees. Use `exhaustive` for benchmarks and whenever parent
> nodes are not true semantic supersets of all their descendants.

## Running classifications

```bash
uv run cve-agent --taxonomy fixtures/flat_taxonomy.json CVE-2025-6965
```

Multiple CVEs are processed independently and emitted in input order. Use `--verbose` for
safe progress diagnostics on stderr while stdout remains valid JSON:

```bash
uv run cve-agent --verbose --taxonomy fixtures/flat_taxonomy.json CVE-2025-6965
```

The verbose trace reports research turns, bounded search queries, sanitized fetched URLs,
evidence IDs, finding aspects, configured and effective classification strategy, taxonomy
chunks or routing levels, routing decisions, pruning normalization, branch sizes, cost-based
switches, supported label IDs, source-origin types, CVE-association warnings, token usage,
coverage, checkpoints, and stop reasons. It does
not log model prompts or evidence passages. URL query strings and fragments are removed,
configured credentials are redacted from provider diagnostics, and noisy dependency logs are
suppressed.

Interactive verbose output is grouped into stages with aligned timestamp, status, component,
and message columns. Normal progress is cyan, completed stages are green, incomplete outcomes
are magenta, warnings are yellow, and failures are red. ANSI color is used only when stderr is
an interactive terminal; redirected output and pipes remain plain text, and `NO_COLOR` disables
color explicitly. Stdout remains JSON-only in every case.

`--llm-min-request-interval SECONDS` overrides model pacing for one invocation.
CLI and GUI inputs accept CVE identifiers in the form `CVE-YYYY-NNNN`, with 4–12 sequence
digits; surrounding whitespace and letter case are normalized. Numeric configuration rejects
fractional values for integer fields and non-finite values such as `nan` and `inf`.

Every invocation ends with a compact mapping on stderr while stdout remains the complete valid
JSON result. The JSON, classification table, and optional evaluation report use matching
plain-text section headings and separators; the JSON heading itself is written to stderr so the
stdout document remains directly parseable:

```text
Classification summary
======================
ID             | Labels                  | Precision | Recall | F1
---------------+-------------------------+-----------+--------+---
CVE-2014-0160  | OutOfBoundsRead         | -         | -      | -
CVE-2021-41773 | PathTraversal, InfoLeak | -         | -      | -
```

Precision, recall, and F1 are `-` during an ordinary classification. Pass `--validate` to
calculate them for each CVE by comparing predicted and expected label sets.

## Graphical interface

The graphical interface is a separate local application; it does not invoke, wrap, or change
the CLI. Both presentation layers call the same `ClassificationApplication` and pipeline APIs.
Start it with the same environment credentials used by the CLI:

```bash
export API_KEY="your-provider-key"
export TAVILY_API_KEY="your-tavily-key"
uv run cve-agent-gui \
  --config config.toml \
  --taxonomy fixtures/hybrid_taxonomy.json
```

Run the GUI from the project root. On first use, `--config` is only the initialization source:
the GUI copies it to the ignored root-level `config.gui.toml`. Subsequent GUI edits are validated
and written atomically only to that dedicated file; the CLI's `config.toml` is never modified.
Comments and unsupported provider-specific keys are preserved. Existing GUI state that still
points at the initialization source is moved to the GUI-owned file automatically.

The command starts a server on `http://127.0.0.1:8765` and opens it in the default browser.
Use `--no-browser` or `--port` to change that startup behavior. The server is deliberately
hard-bound to loopback and rejects non-local Host headers, cross-origin mutations, non-JSON
mutations, and oversized requests: analysis history can contain exact vulnerability evidence,
and this focused interface is never intended for remote access.

The GUI has a scrollable persisted-CVE sidebar, a central chat and live investigation trace,
and a separately scrollable active-configuration sidebar. Enter a CVE ID directly on the home
screen to start the existing pipeline. Selecting a stored CVE opens its chat from the beginning;
live progress follows the latest event only while the reader remains near the bottom. When
classification finishes, each selected label shows its confidence and explanation; its exact
application-owned quotation is expandable and its canonical source URL is directly clickable.
New analyses also show a human-readable evidence chain such as `NVD reference → vendor page →
Supporting quote`. Selecting a discovery, source, or quotation node reveals the search or NVD
origin, redirects and CVE-association checks, or the exact surrounding context and supported
investigation findings. Full resolved URLs appear on the source node and in its detail panel;
internal document, evidence, fetch, and event identifiers are never presented as interface
labels. Analyses created before provenance tracking retain their quotation and source link and
report that the source chain is unavailable.

Global settings use project-scoped file selectors rather than arbitrary paths. The interface
shows only the fixed relative prefixes: taxonomies are selected below `fixtures/`, SQLite
databases below `.data/`, the GUI state stays below `.data/`, the web cache stays below
`.cache/`, and the configuration is fixed at `./config.gui.toml`. A new SQLite filename may be
created from the selector. Canonical-path checks reject parent traversal, wrong extensions,
missing parents, and symbolic-link escapes before any file is read or written.

Pressing Enter saves global settings just like the Save button, and validation errors remain
visible without resizing the open dialog. Analysis options are opened from the Active snapshot
sidebar rather than from the CVE input. Saving options first validates the complete effective
configuration and changes no file if validation fails. Numeric controls expose their supported
ranges, enumerated values use fixed choices, hierarchical strategy controls are absent for flat
taxonomies, pruning is hidden for exhaustive scans, and web-provider-specific controls are
hidden when web research is disabled.
Every analysis stores the complete canonical taxonomy JSON and non-secret effective settings,
not only their source paths. A fresh session uses `config.gui.toml` and the global taxonomy.
Selecting an old analysis copies its stored snapshot into the next draft; later draft edits
never modify that analysis. Source paths are informational, so editing or deleting the original
taxonomy file cannot change history. API keys remain environment-only and are never stored in
GUI settings or sent to the browser.

The selected SQLite database is also the history and result cache. A completed result is reused
only when its normalized CVE ID, taxonomy fingerprint, and complete non-secret effective settings
all match. Partial and failed runs are displayed but never treated as successful cache entries.
Runs created by the CLI and GUI use the same repository and appear in the same history.
Machine-local GUI defaults live in the ignored `.data/cve-agent-gui.json` file by default.

## Evaluating classification performance

`fixtures/flat_expected-classification.json` contains 14 conservatively selected CVEs covering
every label in `fixtures/flat_taxonomy.json`. Each case records expected label IDs, a short
mapping rationale, and the primary or NVD sources used to curate it. The benchmark also contains
a taxonomy fingerprint, so it cannot accidentally be evaluated against another taxonomy. The
`cases` array is the single authoritative CVE list; taxonomy files carry stable display names.

`fixtures/hierarchical_taxonomy.json` provides a 27-label, five-root tree using the
`most_specific` policy. Its corresponding
`fixtures/hierarchical_expected-classification.json` reclassifies the same CVEs against that
tree. Ancestors are omitted when a supported descendant exists; an internal node remains valid
when none of its children describes the vulnerability more precisely.

`fixtures/hybrid_taxonomy.json` is the stress fixture for adaptive traversal. It contains 126
labels, six independent roots, and paths up to four levels deep. With the example input limit it
requires two linear exhaustive chunks, so the default `auto` strategy selects hybrid routing.
Its parents are written as semantic supersets so pruning is meaningful, and
`fixtures/hybrid_expected-classification.json` maps the same 14 curated CVEs to their most
specific leaves. Two cases intentionally expect labels from multiple independent branches to
exercise multi-label traversal and evaluation. Set `token_budget = 50000` or higher before
running this benchmark; the example 12,000-token budget cannot reserve a complete hybrid branch
plus useful investigation capacity.

Run the complete benchmark without listing CVE IDs:

```bash
uv run cve-agent \
  --taxonomy fixtures/flat_taxonomy.json \
  --validate fixtures/flat_expected-classification.json
```

Or run a cheaper subset while developing:

```bash
uv run cve-agent \
  --taxonomy fixtures/hierarchical_taxonomy.json \
  --validate fixtures/hierarchical_expected-classification.json \
  CVE-2014-0160 CVE-2021-41773
```

To exercise adaptive routing rather than the smaller hierarchy, use the hybrid pair after
raising the configured token budget:

```bash
uv run cve-agent \
  --taxonomy fixtures/hybrid_taxonomy.json \
  --validate fixtures/hybrid_expected-classification.json \
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
3. packs fetched source text into stable, coherent passages bounded around 900 characters;
4. builds a concise profile from any supported high-level findings; its topics are guidance,
   not mandatory fields;
5. selects exhaustive or hybrid taxonomy scanning from the taxonomy shape and operational
   configuration;
6. validates every direct classification or routing response, resolves any required uncertain
   nodes, merges supported candidates, and only then applies the hierarchy policy.

Investigation is identical for flat, exhaustive hierarchical, and hybrid hierarchical runs.
The taxonomy and classification strategy are never exposed to research, and `search`, `fetch`,
`record_evidence`, and `finish_investigation` are research-only tools. Classification uses
structured model requests without web tools.

Final model decisions reference evidence IDs rather than writing quotes or URLs. The
application materializes the canonical resolved URL and exact stored passage into the public
JSON result and preserves the evidence ID. A fetched passage cited at investigation finish is
promoted automatically;
`record_evidence` remains an optional way to preserve a passage across research turns. Full
passage IDs and document-local forms such as `1` or `p1` are accepted when unambiguous. Search
snippets are leads, never evidence. A finish call containing unknown, ambiguous, empty, or
obviously fragmentary evidence receives one correction opportunity. If that correction is not
usable, valid findings from the original call are retained and only unsupported findings are
discarded; the reasons remain in operational metadata and persisted provenance.

Fetched documents are indexed by normalized requested and resolved URL for the duration of an
investigation. A repeated equivalent URL returns the existing document without calling the web
adapter or consuming fetch quota; paths and query strings remain significant. The repeated model
tool call is still recorded as a session reuse rather than being hidden.

Every investigation also builds a versioned, harness-owned provenance ledger. It records the
bounded NVD and search candidates shown to the model, every search and fetch attempt, URL
normalization and redirects, the complete bounded passages shown for each fetched document,
evidence selection methods, accepted findings, and final label-to-evidence links. This ledger
also snapshots each returned label's exact taxonomy definition and ancestor path. It is
checkpointed in SQLite but is deliberately excluded from research and classification
prompts, so retaining it does not consume model tokens. It is intended as cold context that a
future clarification or deep-dive feature can hydrate selectively for one label.

Normal JSON does not dump the complete audit. Provenance format version 2 additionally records
whether a fetch reused a session document and whether extraction used Trafilatura or bounded raw
content, together with input/output lengths, truncation, content type, and download size. Legacy
cache entries expose unknown extraction fields instead of being invalidated. The top-level
`provenance` catalog contains only
sources and evidence reachable from returned labels, including discovery origins, fetch
details, deterministic CVE-association signals, adjacent passage context, and the investigation
claims supported by each quotation. Failed calls and unused sources remain available only in
the persisted scratchpad. Association diagnostics warn rather than reject evidence: a vendor
patch can be relevant even when it does not repeat the CVE identifier.

The terminal is an adapter around the UI-independent `ClassificationApplication`. Application
execution returns typed classification results and an optional evaluation report; argument
parsing, colored logging, JSON serialization, summary tables, and exit-code policy stay in the
CLI. A future GUI can therefore reuse application and pipeline behavior without invoking or
parsing terminal output.

NVD records can contain hundreds of references. To avoid resending an oversized record on every
turn, the model receives at most 24 unique candidates, prioritizing vendor advisories, patches,
release notes, mitigations, product pages, exploits, technical descriptions, and then
third-party advisories. The complete and omitted reference counts remain explicit in the
research context.

Classification prompts require confidence in the `[0, 1]` range. For exhaustive label output,
`low`, `medium`, and `high` are compatibility-normalized to `0.35`, `0.60`, and `0.85`, and
percentage strings are converted to decimals. Routing decisions require an actual JSON number
because confidence controls destructive branch pruning. Invalid responses receive one bounded
correction request. Taxonomy-chunk responses wrapped as a top-level JSON array remain accepted
when the active chunk is unambiguous.

Models are instructed to copy stable taxonomy IDs into every `label` field. If a provider emits
the exact human-readable name of one uniquely identifiable label from the active chunk, the
application converts it to that label's ID and logs the recovery. Ambiguous names, invented
labels, and labels outside the active chunk remain invalid and receive the bounded correction
request.

The classifier is explicitly instructed to distinguish root causes and exploitation mechanisms
from consequences: remote code execution, disclosure, denial of service, or privilege gain do
not by themselves prove a particular weakness class. Exhaustive scanning needs no final model
adjudication request. Hybrid scanning uses binary classification only for routing decisions
that remain uncertain after traversal.

Complete `classified` and `no_matching_label` results require 100% taxonomy coverage.
Strategy-neutral coverage reports effective strategy, total labels, directly evaluated labels,
pruned labels, unresolved labels, classification requests, routing levels, and completeness.
Operational metadata also records pruning diagnostics, strategy switches, token usage, stop
reason, and run ID.

## Budgets

`token_budget` is the base per-CVE prompt-plus-completion budget. Before NVD or database work
begins, CVEAgent reserves classification capacity according to the effective strategy.
Exhaustive mode reserves every taxonomy chunk. Hybrid mode reserves root routing, the most
expensive sibling-aware root-to-leaf route, and one adjudication batch. If the relevant minimum
cannot fit inside the base budget plus `finalization_overrun_percent`, the run fails preflight
without external side effects.

Classification tokens are reserved before investigation. Research cannot consume the
reserve or overrun allowance; only taxonomy scanning may enter the configured overrun.
Provider usage is used when available and conservatively estimated
otherwise. Unexpected exhaustion returns `partial` with validated labels and exact coverage.
When research stops before it can produce a profile, classification receives a bounded set of
the evidence already collected instead of silently discarding it.

`max_input_tokens_per_request` controls exhaustive and routing request chunk sizes. Large or
unusually verbose taxonomies may require raising `token_budget`; preflight reports its estimated
minimum. Planning reserves room for the repeated vulnerability profile and structured-output
schema, so an input limit too small for that fixed context fails before research begins.

## Web retrieval and cache

The default search provider is Tavily. Set `[web].provider = "none"` to disable search while
retaining direct fetching of NVD references. NVD and web retries are configured independently.

Downloads are streamed, limited by `max_download_bytes`, restricted to textual content types,
and then extracted and bounded by `max_document_chars` and `max_preview_chars`. Evidence uses
the final response URL while retaining the requested URL and redirect chain. Fetching accepts
only HTTP(S) hosts that resolve exclusively to public IP addresses. Search results, cached
documents, and every redirect hop are checked before use; localhost, private/link-local targets,
URL credentials, and non-web schemes are rejected. External text is always treated as untrusted
source data rather than agent instructions. Verbose logs include a safe URL and concrete reason
when a search candidate or fetch is rejected.

Searches and fetched documents are cached under `[web].cache_dir`. The cache has no automatic
expiry. To reset it, delete only the configured cache directory; with the example configuration:

```bash
rm -r .cache/cve-agent/web
```

## Persistence and exit codes

SQLite schema version 3 uses one repository for the CLI and GUI:

- `runs` stores immutable canonical taxonomy and non-secret settings snapshots with fingerprints;
- `analyses` stores lightweight per-CVE lifecycle, labels, errors, and timestamps;
- `analysis_payloads` contains the current checkpoint or final result;
- `analysis_events` contains sequenced progress events;
- `provenance_records` keeps internal and public evidence audit data separately.

History queries do not load result, checkpoint, taxonomy, settings, or provenance JSON. Exact
cache lookup uses the stored CVE and snapshot fingerprints. Completion atomically replaces the
checkpoint payload with the result and keeps one authoritative token/coverage ledger. Stale
running analyses are recovered as interrupted.

Schema versions 1 and 2 are intentionally not migrated. Move or remove an incompatible database
explicitly; the application never deletes or rewrites it automatically.

Exit codes are:

- `0`: every CVE is classified, has no matching label, or lacks sufficient information;
- `2`: at least one CVE is partial or failed;
- `3`: invalid CVE, taxonomy, or evaluation input;
- `4`: fatal configuration, preflight, provider-initialization, or persistence error.

## Development

Tests are deterministic and require no live web or model service:

```bash
uv run pytest -q
```
