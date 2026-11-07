# Counterparty Guard

Repository: [medhansh-19/counterparty-guard](https://github.com/medhansh-19/counterparty-guard) · Private · Default branch: `main`.

Before an AI agent pays on NEAR, check the exact receiver and action. Return `allow`, `warn`, or `block` with evidence and freshness; enforce eligible actions through a restricted agent key and an independently checking vault.

**Status: planning and folder setup only.** There is no working API, dashboard, SDK, contract, permit implementation, or recorded attack run yet. The workspace manifests, dependency pins, lockfiles, application commands, and CI checks will be implemented in Foundation.

## Start here

- [Full product plan](PLAN.md): scope, trust boundaries, three-person split, security requirements, and S1–S10 scenarios.
- [Person A execution plan](docs/person-a-plan.md): Medhansh's eight packages, implementation targets, tests, dependencies, and handoffs.
- [Repository workflow](docs/repository-workflow.md): GitHub setup, branches, review ownership, and implementation checklist.
- [Architecture decisions](docs/decisions.md): agreed decisions and unresolved interface choices.
- [Project instructions](AGENTS.md): ownership and acceptance requirements.

## Ownership

| Contributor | Responsibility | Active effort |
| --- | --- | --- |
| A — Medhansh | API, sources, scoring, shared TS contracts/codec, core storage, JS tooling, root README | 24 hours |
| B | Rust vault and fixture contract, guarded SDK, scoped key, execution accounting, recovery | 24 hours |
| C | Reports/reputation, bounded graph features, dashboard, fixtures, demo | 24 hours |

A integrates C's report routes into the API; C owns `apps/api/src/routes/reports.ts`. A owns the root JavaScript lockfile; B owns Rust manifests and lockfiles. Each contributor tests and documents their area.

## Folder map

```text
apps/api/                   A: check service, auth, storage; C: report routes
apps/web/                   C: evidence and approval dashboard
packages/shared/            A: schemas, reason codes, permit bytes and vectors
packages/providers/         A: RPC/indexer normalization and fixture provider
packages/scoring/           A: deterministic decision rules
packages/reputation/        C: reports, dependence and bounded graphs
packages/guard/             B: guarded tools and signer boundary
contracts/vault/            B: independent execution authorization
contracts/receiver-fixture/ B: supported demonstration target
db/core/                    A: core migrations
db/reports/                 C: report migrations
fixtures/                   C: labelled accounts, reports, graphs and attacks
scripts/chain/              B: setup, deployment and recovery
scripts/demo/               C: actual scenario runs
tests/integration/          All: API and contract integration
tests/e2e/                  All: complete scenarios
docs/                       Plans, interfaces and delivery documentation
```

## Planned development commands

After Foundation is implemented, the workspace must support `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm test:integration`, `pnpm test:e2e`, `pnpm demo:attack`, and `pnpm demo:all`. They are **not available yet**. Document and pin the exact Node, pnpm, Rust, Cargo build, and sandbox versions during setup. Do not substitute empty scripts for checks.

## Security and delivery boundaries

`block` has no permit. `warn` requires the owner's approval of the exact permit hash on the vault. Missing mandatory sources produce an infrastructure failure without a permit. Reports require evidence and authenticated review before any hard-block activation. Account activity and report counts alone cannot establish safety or maliciousness.

The agent receives only a function-call key restricted to the vault's `execute` method, with zero attached deposit; the prefunded vault supplies payment value. The owner/recovery key stays outside the agent runtime. Gas allowance is separate from payment limits; it cannot be increased by topping up the account and requires key replacement when exhausted. Maintain an external recovery path and explicit method restrictions. See [NEAR access-key restrictions and caveats](https://docs.near.org/protocol/accounts-contracts/access-keys).

The vault cannot atomically check another contract's latest code or the service's latest blocklist. Short permit lifetimes, SDK revalidation and emergency pause reduce that race; they do not eliminate it. `attestation` remains `null` until real verification evidence exists.

Default to fixtures, local sandbox, and project-owned testnet accounts. Keep credentials and local databases outside version control. No contracts have been deployed and no funds have been spent by this setup.
