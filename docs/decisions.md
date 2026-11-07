# Architecture decisions

## D001 — Ownership and implementation scope (8 November 2026)

Accepted: Medhansh is Person A. Preserve the eight three-hour packages for each of A, B and C. This change prepares plans, folder markers and repository collaboration files. Application and contract implementation remains future work.

Impact: replace the previous recommendation of Person C. No schema or database migration exists yet.

## D002 — One workspace and one service

Accepted: TypeScript pnpm workspace; Fastify, Zod and SQLite for the API; React/Vite for the dashboard; Rust/near-sdk contracts. The API calls reputation logic in-process. Use injected providers, storage, clock and signer. Pin compatible versions during A1/B1, with smoke tests before claiming compatibility.

Impact: no extra reputation microservice, graph database or package-manager lockfiles. A controls JS dependency integration; B controls Rust dependencies.

## D003 — Repository and branch conventions

Accepted: repository name `counterparty-guard`, default branch `main`, private initial visibility unless the user chooses otherwise. Use `feat/a-*`, `feat/b-*`, `feat/c-*`, `fix/*`, `docs/*` and `test/*` branches. Use contributor identity in commits; omit generated assistant attribution.

Impact: B/C account names must be supplied before automatic review assignment can be configured. Do not imply branch protection or CI is active before verification.

## D004 — Authorization is deterministic and fail-closed

Accepted: reviewed active blocks override all positive history; numeric indicators never create hard blocks; required source/storage failures issue no permit. Warnings require independent owner approval. Bind complete actions using deterministic Borsh bytes and cross-language vectors.

Impact: evidence persistence precedes permit release. Treat uncertain executions as counted and never automatically issue a replacement permit for an uncertain retry.

## Decisions to close during implementation

| Decision | Owner/review | Deadline | Required record |
| --- | --- | --- | --- |
| Exact package/toolchain pins | A / B for Rust, C for web | A1/B1 | Versions and installation/smoke-test output |
| Permit byte layout, tags, signing domain and bounds | A + B | Before A2/B2 | Byte specification and matching TS/Rust vectors |
| Fixture call method and argument schema | B + A + C | A1/B1 | Full action schema, supported target policy |
| Event schema and reconciliation rules | B + A | Before A6 | Finality evidence and state-transition fixtures |
| Reputation result and report migration interfaces | C + A | A1, finalize before A4 | Versioned schemas, bounded explanation fields |
| Exact NearBlocks authentication, routes and coverage limits | A | A3; access spike in A1 | Redacted provider captures, terms and capability matrix |
| B/C review accounts and repository protections | All | Before parallel feature work | Verified handles, available rules, real required checks |

For subsequent entries include context, decision, owner/reviewer, alternatives relevant to the tradeoff, interface or migration impact, validation evidence, and superseded decision IDs.
