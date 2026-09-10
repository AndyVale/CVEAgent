# Hybrid taxonomy and validation set

## Purpose

The hybrid taxonomy is a mechanism-focused classification tree for testing adaptive traversal.
It is designed so that a classifier can reject an unsupported parent and safely prune every
descendant below it. The taxonomy contains 84 labels under nine independent roots, uses the
`most_specific` hierarchy policy, and has paths of at most four levels.

The files in this directory are:

- `taxonomy.json`: label IDs, display names, definitions, parents, and hierarchy policy.
- `expected-classification.json`: 50 researched CVEs in the standard benchmark format.

This document records design and research provenance. It is not an input to the application.

## Design method

Labels describe root causes or exploitation mechanisms that can be supported from vulnerability
evidence. Consequences such as code execution, denial of service, information disclosure, and
privilege escalation are not labels by themselves.

Each label definition states:

1. the mechanism that must occur;
2. the evidence needed to support it; and
3. a boundary against nearby labels when confusion is plausible.

Every hierarchy edge was reviewed with this implication: if the child is supported, the parent
must also be supported. Internal labels remain valid expected answers when evidence establishes
their mechanism but is not detailed enough to select a child.

The nine root families are:

| Root | Scope |
| --- | --- |
| `InterpreterInjection` | Input that changes interpreter, parser, query, command, code, template, or browser-document grammar. |
| `PathAndResourceSelection` | Attacker-controlled filesystem resolution outside the intended resource boundary. |
| `StructuredDataProcessing` | Unsafe object, reference, binding, or graph behavior while interpreting structured data. |
| `RoutingAndDestinationControl` | Attacker control over network destinations or routing authority. |
| `FileUploadControl` | Upload acceptance that violates the intended content policy or trust boundary. |
| `AccessControl` | Failures to establish identity, manage sessions, authorize actions, or validate authority-bearing requests. |
| `MemorySafety` | Invalid native-memory bounds, lifetime, initialization, pointer-validity, or object-type behavior. |
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
  escapes an intended filesystem directory.
- Memory labels distinguish bounds, lifetime, initialization, pointer validity, and native object
  representation. Generic memory corruption remains at the narrowest supported internal label.
- Resource-management labels are used only when an attacker-reachable resource rule fails. A crash
  caused by injection or memory corruption is not separately labeled as resource exhaustion.
- Under `most_specific`, an expected answer omits ancestors when a supported descendant is present.
  Labels from independent branches may be combined when the evidence establishes multiple real
  mechanisms.

## Hybrid traversal

With the project's example 12,000-token per-request input limit, the taxonomy requires two
exhaustive chunks. With a 50,000-token total budget, the `auto` strategy therefore selects hybrid
routing. The root request can prune unsupported mechanism families, while supported or uncertain
roots open their children for further classification.

## Validation-set research

The candidate source was the CISA Known Exploited Vulnerabilities catalog snapshot version
`2026.09.09`, containing 1,703 entries. The snapshot is pinned to commit
`f6fafe2585c7cc2a7568d13d08024cf142b37d3a` and has SHA-256
`399e43c1b3652c76df40493e25f36e4133fca04e34a4d920f86049b141b53c93`:

<https://raw.githubusercontent.com/cisagov/kev-data/f6fafe2585c7cc2a7568d13d08024cf142b37d3a/known_exploited_vulnerabilities.json>

Candidate IDs were sorted lexicographically and shuffled with Python 3.14.6 using
`random.Random(20260910)`. Candidates were then investigated online using authoritative CVE
records, vendor advisories, patches, and technical analyses. CWE assignments were treated as
research leads, not as expected labels. A case was classified from the mechanism demonstrated by
the sources rather than from consequences such as remote code execution or disclosure.

The ordinary research pass supplied 45 cases. It yielded two genuine multi-label CVEs, so a
separate multi-mechanism stratum was formed from six independently researched candidates:

- `CVE-2018-9206`
- `CVE-2019-19781`
- `CVE-2021-26855`
- `CVE-2021-41773`
- `CVE-2022-1388`
- `CVE-2024-3400`

After sorting those IDs, five were selected with
`random.Random(20260910).sample(candidates, 5)`: `CVE-2018-9206`, `CVE-2021-26855`,
`CVE-2024-3400`, `CVE-2021-41773`, and `CVE-2019-19781`.

All 50 selected CVEs were researched online and have at least one supported label, a concise
rationale, and source links in `expected-classification.json`. Seven cases retain labels from
multiple independent branches after hierarchy normalization. CVEAgent predictions and live model
results were not used to establish expected classifications.

## Coverage and uncertainty

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
