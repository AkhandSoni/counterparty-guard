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

## D005 — Person A implementation and public repository (8 November 2026)

Accepted at the user's request: implement A-owned backend and make the repository public. B/C deliver their own PRs; their contracts, guard SDK, report routes/migrations, reputation package, dashboard, fixtures and demo runner are untouched. This supersedes D001's planning-only scope and D003's initial private visibility. The equal human-effort estimates in PLAN.md remain planning estimates, not measured implementation time.

Impact: source-running TypeScript workspace with exact Node26.7.0/pnpm11.25.0 pins, Fastify5.12.8, Zod4.6.7, better-sqlite3 13.0.3, TypeScript5.9.3, Vitest5.1.0 and ESLint10.14.0. Tested compatibility is established by install/native SQLite smoke, lint/typecheck and actual automated output. CI pins third-party actions by verified release commit SHA. No Rust dependencies are added by A.

## D006 — Safe partial product composition

Accepted: the standalone server is loopback, sandbox and synthetic-fixture only. Live receiver adapters can read testnet, but live permit issuance requires injected verified B policy/finality and C reputation adapters. There is no fallback empty live report state or assumed current vault policy. E2E/attack/demo entry points fail explicitly until the real B/C runners exist.

Impact: A tests and HTTP smoke exercise actual API/SQLite/Ed25519 behavior, not on-chain enforcement. Rust vector equality, owner approvals, scoped key, pending-spend checks and S1–S10 remain cross-owner gates. B/C browser consumers use the pure `@counterparty-guard/shared/browser` export; Node signing never enters a browser bundle.

## D007 — Evidence, retries and integration semantics

Accepted: canonical bounded JSON snapshots bind retained inputs to signed authorization. Mandatory account/code facts use the same concrete block with underlying freshness. Idempotency fingerprints bind authenticated identity/request, action and environment; claims persist their nonce and enforce transactional owner/invalidation checks. Authority changes during awaits cannot knowingly release the old result. Independent activity credit in live mode comes only from C's justified optional 0..15 result; raw indexed counts earn none.

Impact: fresh fetch timestamps or coverage-window/block advancement alone do not invalidate unchanged facts. Material risk/policy/code changes do; known in-flight/consumed executions cannot revalidate as reusable. Only trusted B adapters promote exact finalized operation evidence into successful history. Public golden vectors are ready for B review; no B/C owner review is fabricated.
