# AGENTS.md

## Purpose

This file contains instructions for coding agents working on this repository.

These instructions concern software development, repository maintenance, testing, documentation, Git workflow, and development tooling.

Do not place instructions for the runtime CVE classification agent in this file. The classification agent does not have file-system access, and its behavior is specified separately by the project specification.

## Working context

The repository contains a tracked project-level file named `AGENT_NOTES.md`.

`AGENT_NOTES.md` is the persistent working context for coding-agent sessions. Use it to record:

- what you are currently working on;
- what you plan to do next;
- important implementation decisions;
- relevant findings from the repository;
- tests already run and their results;
- unresolved issues or blockers;
- work that remains after the current change.

Update `AGENT_NOTES.md` as work progresses so that a new coding-agent session can understand what has already been done and what still needs to be done.

Keep `AGENT_NOTES.md` useful and concise. Remove obsolete information when it is no longer relevant.

`AGENT_NOTES.md` is tracked in Git and should normally be included in commits when it contains meaningful changes associated with the work.

## Development environment

The project uses Python and `uv`.

Use `uv` for dependency and environment management. Do not introduce a second dependency-management workflow unless there is a clear project requirement.

Use the project's managed environment for development and testing. Prefer `uv run ...` for commands so that the command executes in the project environment without relying on an activated shell.

When dependencies are added or removed:

- update the project dependency configuration using `uv`;
- keep the lockfile consistent;
- verify that the project still installs and tests correctly.

Keep the implementation in pure Python unless a project requirement explicitly justifies another language or runtime.

Do not add dependencies merely for convenience when the same behavior can be implemented cleanly with the existing stack or standard library.

## Source tree and implementation principles

Prefer small, cohesive modules with clear responsibilities.

Keep external integrations behind explicit interfaces or adapters so that business logic can be tested without live network services.

Do not tightly couple the core classification pipeline to a particular web provider, storage implementation, or model server when a small abstraction can avoid that coupling without unnecessary complexity.

Prefer straightforward implementations over premature abstraction or elaborate frameworks.

Do not overengineer features that are not required by the current project scope.

Preserve existing behavior unless the task explicitly requires a behavior change.

Before making substantial changes, inspect the existing repository structure and conventions and follow them where they do not conflict with these instructions.

## Secrets, generated files, and repository hygiene

Do not commit secrets, credentials, API keys, access tokens, or other sensitive information.

Files that contain secrets or machine-specific credentials, such as `.env` files, must be ignored through `.gitignore` where appropriate.

Ignore generated caches, virtual environments, large local artifacts, and other files that should not be versioned.

Do not add generated or machine-local files to Git merely because they exist in the working tree.

## Documentation

Maintain only the project's intended documentation files unless a task explicitly requires another document.

### README.md

`README.md` is user-facing documentation.

Update it whenever a change affects a human user's ability to use the project, including:

- adding a user-visible feature;
- changing a command or command-line argument;
- removing a command or feature;
- changing required configuration or setup;
- changing expected input or output for normal users.

Keep the README focused on how a human uses the project. Do not turn it into a record of internal coding-agent activity.

### AGENTS.md

Update this file whenever development workflow, tooling, repository conventions, testing conventions, or other coding-agent instructions change.

Do not add runtime classification-agent behavior to this file.

### AGENT_NOTES.md

Use `AGENT_NOTES.md` for persistent coding-agent working context as described above.

## Testing

Functions, modules, parsers, adapters, and tools should have unit tests appropriate to their behavior.

The end-to-end classification pipeline should have integration tests.

External APIs and websites must not be required for ordinary automated tests. Mock them or use deterministic cached/fixed fixtures so that tests are reproducible and can run without relying on live external services.

Tests should cover failure paths where practical, especially for external-service errors, retry behavior, malformed input, persistence failures, and invalid configuration.

Run the relevant test suite after meaningful changes. After a major update, run the broader applicable test suite.

When a relevant test fails:

1. investigate the cause;
2. fix the implementation when the implementation is wrong;
3. rerun the affected tests;
4. only change or remove the test when the expected behavior has intentionally changed, the feature has been removed, or the test is no longer valid for a clearly documented reason.

Do not weaken a test merely to make an implementation pass.

Legacy tests may be removed when the functionality they describe has intentionally been dropped.

If a relevant test cannot be made to pass because of a legitimate unresolved issue, do not hide the failure. Record the problem and explain it to the developer.

## External services and caching

When implementing integrations with external APIs or websites:

- isolate network access behind testable interfaces;
- respect rate limits and service policies;
- cache data when appropriate to avoid unnecessary repeated requests;
- use bounded retry behavior for transient failures;
- do not retry errors indefinitely;
- keep tests deterministic by replacing live services with mocks or fixed cached fixtures.

The LLM integration uses the OpenAI Python client against an OpenAI-compatible provider.
Keep the endpoint, model, and non-secret runtime parameters in the ignored local
`config.toml` (with `config.example.toml` as the tracked template), and read credentials
from environment variables such as `API_KEY`. Do not add provider-specific request
extensions unless they are required by the configured provider and covered by tests.

A retry library such as `tenacity` may be used when it improves clarity and correctness, but do not introduce it automatically if a small existing implementation is sufficient.

## Git workflow

Work directly on `main` unless the developer explicitly requests another workflow.

A logical unit is a focused piece of work such as:

- a bug fix;
- a new feature;
- a coherent refactor;
- a set of related tests;
- documentation corresponding to one logical change.

Do not accumulate unrelated changes into a single large commit.

Follow Conventional Commits for commit messages:

```text
<type>[optional scope]: <description>
```

Examples:

```text
feat: add CVE batch processing
fix: handle transient NVD failures
refactor: isolate taxonomy parsing
 test: add pipeline integration fixtures
```

The coding agent should propose a commit when a logical unit is complete. The developer must approve the proposed commit before the agent creates it.

Do not commit unrelated work merely because it is present in the working tree.

Before proposing a commit, inspect the diff and verify that the change contains only the intended logical unit and associated documentation/tests.

## Change discipline

Prefer incremental changes that can be understood and reviewed independently.

Do not write a large amount of uncommitted code across unrelated parts of the system when the work can be split into smaller logical units.

When a task touches several areas, keep the changes coherent and document important decisions in `AGENT_NOTES.md`.

Before making destructive changes, understand the existing behavior and verify which files are affected.

If an implementation attempt introduces an unrecoverable state, stop and report the problem rather than silently discarding work or masking the failure.

## CLI and user-visible behavior

The CLI is a first-class user interface.

When changing commands, arguments, output formats, configuration requirements, or error behavior, update the README and relevant tests in the same logical unit.

Keep command behavior explicit and predictable. Prefer clear error messages over silent fallbacks.

## Database and persisted state

Persisted application state must be treated as part of the product behavior.

Changes to schemas, stored classification results, cached investigation state, or migration behavior must be accompanied by appropriate tests and documentation where user-visible behavior is affected.

Do not silently discard persisted information during normal error handling.

## Final checks before handing work to the developer

Before declaring a logical unit complete:

1. review the diff;
2. update `AGENT_NOTES.md` with the current state and remaining work;
3. update `README.md` when user-facing behavior changed;
4. update `AGENTS.md` when coding-agent/development rules changed;
5. run the relevant tests;
6. report any remaining failures or limitations clearly;
7. propose a Conventional Commit message for developer approval.
