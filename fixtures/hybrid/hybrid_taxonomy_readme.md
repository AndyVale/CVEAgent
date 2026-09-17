# Hybrid demo taxonomy

## Purpose

This fixture is an illustrative demo taxonomy, not a complete or standardized vulnerability
ontology. It contains 84 mechanism labels under ten independent roots, uses the `most_specific`
hierarchy policy, and has paths of at most four levels.

The name **hybrid** describes how the classification step consumes this hierarchy. It does not
describe a mixture of vulnerability ontology types. Under the documented configuration, the
classifier combines iterative parent routing and conservative subtree pruning with exhaustive
scanning of an active subtree when that is cheaper or required for reliable completion.

The files in this directory are:

- `taxonomy.json`: label IDs, display names, definitions, parents, and hierarchy policy.
- `expected-classification.json`: the shared 50-CVE validation set at full demo granularity.

This Markdown file documents taxonomy design and research provenance. It is not an application
input.

## Design method

Labels describe root causes or exploitation mechanisms that can be supported from vulnerability
evidence. Consequences such as code execution, denial of service, information disclosure, and
privilege escalation are not labels by themselves.

Each label definition states:

1. the mechanism that must occur;
2. the evidence needed to support it; and
3. a boundary against nearby labels when confusion is plausible.

Every hierarchy edge follows this implication: if the child is supported, the parent must also be
supported. Internal labels remain valid expected answers when evidence establishes their mechanism
but is not detailed enough to select a child.

The ten roots are:

| Root | Scope |
| --- | --- |
| `InterpreterInjection` | Input that changes interpreter, parser, query, command, code, template, or browser-document grammar. |
| `PathAndResourceSelection` | Attacker-controlled filesystem resolution outside the intended resource boundary. |
| `StructuredDataProcessing` | Unsafe object, reference, binding, or graph behavior while interpreting structured data. |
| `RoutingAndDestinationControl` | Attacker control over network destinations or routing authority. |
| `FileUploadControl` | Upload acceptance that violates the intended content policy or trust boundary. |
| `AccessControl` | Failures to establish identity, manage sessions, authorize actions, or validate authority-bearing requests. |
| `MemorySafety` | Invalid native-memory bounds, lifetime, initialization, pointer-validity, or object-type behavior. |
| `StaleHandleUse` | Reuse of an invalidated or recycled resource handle that resolves to a different resource. |
| `AvailabilityAndResources` | Violations of resource bounds, release obligations, or concurrency progress guarantees. |
| `CryptographicProtection` | Failures in primitive selection, key management, randomness, nonce handling, or certificate validation. |

## Important boundaries

- `CodeInjection` requires evaluation of attacker-supplied general-purpose source text.
  Operating-system shell syntax is `CommandInjection`; process options without shell syntax are
  `ArgumentInjection`; expression languages and server templates use their dedicated labels.
- `AuthenticationBypass` requires creation or acceptance of an authenticated identity without the
  required proof. A caller reaching a privileged action without becoming authenticated is
  `ImproperAuthorization`.
- `IDOR` is the object-reference specialization of `ImproperAuthorization`. Filesystem paths are
  classified under `PathTraversal` instead.
- `DangerousFileTypeUpload` requires evidence that accepted content is executable, active, or
  otherwise dangerous in the deployment context. Arbitrary upload acceptance without that
  processing evidence remains `FileUploadControl`.
- `ZipSlip` is archive-extraction `PathTraversal`, because every supported Zip Slip case also
  escapes an intended filesystem directory through a crafted member path. Archive links that
  redirect extraction without such a path escape use `ImproperLinkResolution`.
- `StaleHandleUse` is independent of `MemorySafety`: a reused descriptor or numeric handle can
  select the wrong resource without an invalid native-memory operation.
- Memory labels distinguish bounds, lifetime, initialization, pointer validity, and native object
  representation. Generic memory corruption remains at the narrowest supported internal label.
- Resource-management labels are used only when an attacker-reachable resource rule fails. A crash
  caused by injection or memory corruption is not separately labeled as resource exhaustion.
- Under `most_specific`, an expected answer omits ancestors when a supported descendant is present.
  Labels from independent branches may be combined when evidence establishes multiple mechanisms.

## Why classification is hybrid

With the documented 12,000-token per-request input limit, a linear exhaustive scan of this fixture
requires two chunks. With a 50,000-token total budget, the `auto` strategy therefore selects the
hybrid scanner. It first evaluates general parents. Unsupported parents safely prune their entire
subtrees; supported or uncertain parents keep relevant children active for further traversal.

The scanner compares the remaining routing cost with an exhaustive scan of the active labels and
may switch to that exhaustive continuation when it is cheaper. It also uses bounded exhaustive
subtree scans for conservative fallback or final adjudication when routing alone cannot reliably
complete the classification.

The same taxonomy structure could technically be consumed exhaustively with a forced strategy, or
a smaller hierarchy could be forced through hybrid traversal. This fixture is called hybrid
because hybrid traversal is its intended and automatically selected classification path under the
documented configuration.

## Shared validation set and projection

All three demo benchmarks contain the same 50 unique CVEs in the same order and retain the same
evidence-source lists. This benchmark is the semantic reference. The flat benchmark projects every
benchmarked label to its nearest shared root. The hierarchical benchmark keeps benchmarked labels
at levels one and two and projects deeper labels to their nearest retained level-two ancestor.
Converging projections are deduplicated in original order.

Every benchmark uses the standard three-field format: `schema_version`, `taxonomy_sha256`, and
`cases`. Rationales are written for each taxonomy's actual granularity. Parent and child labels do
not count as distinct mechanisms. Seven CVEs retain multiple labels in all three benchmarks because
their supported mechanisms occupy independent root branches.

## Validation-set research

The candidate source was the CISA Known Exploited Vulnerabilities catalog snapshot version
`2026.09.09`, containing 1,703 entries. The snapshot is pinned to commit
`f6fafe2585c7cc2a7568d13d08024cf142b37d3a` and has SHA-256
`399e43c1b3652c76df40493e25f36e4133fca04e34a4d920f86049b141b53c93`:

<https://raw.githubusercontent.com/cisagov/kev-data/f6fafe2585c7cc2a7568d13d08024cf142b37d3a/known_exploited_vulnerabilities.json>

Candidate IDs were sorted lexicographically and shuffled with Python 3.14.6 using
`random.Random(20260910)`. Candidates were investigated online using authoritative CVE records,
vendor advisories, patches, and technical analyses. CWE assignments were treated as research leads,
not expected labels. Cases were classified from supported root causes and exploitation mechanisms,
not consequences such as remote code execution or disclosure.

The ordinary randomized research pass supplied 45 suitable cases and two genuine multi-mechanism
CVEs. To ensure that the benchmark exercises multiple independent branches, a separate
multi-mechanism stratum was formed from six independently researched candidates:

- `CVE-2018-9206`
- `CVE-2019-19781`
- `CVE-2021-26855`
- `CVE-2021-41773`
- `CVE-2022-1388`
- `CVE-2024-3400`

After sorting those IDs, five were selected with
`random.Random(20260910).sample(candidates, 5)`: `CVE-2018-9206`, `CVE-2021-26855`,
`CVE-2024-3400`, `CVE-2021-41773`, and `CVE-2019-19781`. No selected case was excluded or replaced
when producing the flat and hierarchical projections.

All 50 selected CVEs have at least one supported label, a concise rationale, and source links.
Seven cases retain labels from multiple independent branches after hierarchy normalization.
CVEAgent predictions and live model results were not used to establish expected classifications.

## Coverage and limitations

The validation set covers 22 of the 84 labels. It emphasizes mechanisms present in the randomized
known-exploited sample and does not force coverage of unsupported categories. The resource
management branch has no case, and cryptographic coverage is limited to nonce reuse. Several
query-language, structured-data, session, request-authorization, and cryptographic leaves are also
unrepresented.

When public evidence establishes only a broader mechanism, the expected answer deliberately uses
an internal label. Examples include dynamic code evaluation without a disclosed evaluator subtype,
filesystem resource selection without proven traversal syntax, and a spatial memory violation
without a disclosed read/write direction. These choices record evidence limits without asserting
that a more specific mechanism is absent.
