# Agent Notes

## Current status

Repository instructions and the initial CVE classification-agent specification have been defined.

## Current focus

Implement the initial project structure and development tooling according to `AGENTS.md` and the project specification.

## Next steps

- Decide the concrete Python/`uv` development stack.
- Implement taxonomy JSON loading and validation.
- Implement the CLI contract with an explicit taxonomy path and one or more CVE IDs.
- Implement the NVD-first investigation pipeline and tool interfaces.
- Implement persistence and deterministic tests.

## Open decisions

The vector-database design remains intentionally deferred until the initial application structure and retrieval/classification flow are established.
