# Counterparty Guard

[Public repository](https://github.com/medhansh-19/counterparty-guard) · NEAR testnet/local sandbox · TypeScript/pnpm · Person A backend

Before an AI agent pays, assess the exact receiver and action. Return `allow`, `warn` or `block` with retained evidence, stable reasons and source freshness. Eligible actions receive a signed, expiring, single-use permit for B’s independently enforcing vault.

**Person A is implemented:** authenticated Fastify API, SQLite migrations/persistence, strict shared schemas and deterministic Borsh codec, provider adapters, deterministic scoring, pre-sign revalidation and trusted execution-reconciliation interfaces. B’s contracts/SDK and C’s reports/reputation/dashboard/demo remain separate PRs. No chain payment or vault enforcement is claimed by this backend alone.

## Run locally

Tested toolchain: Node 26.7.0, pnpm 11.25.0. Use `.node-version`; the native SQLite module must be rebuilt if you switch Node ABI. Native installation may need a C++ toolchain and Python. Exact dependencies and the lockfile are committed.

```sh
pnpm install --frozen-lockfile
pnpm setup:local
pnpm smoke:api
GUARD_CONFIG_FILE=artifacts/local/config.json pnpm dev:api
```

Local setup generates a random service key, bearer credential and fixture configuration under ignored `artifacts/local/`, with private file permissions. Re-running setup preserves these files and the database. The credential contents are never printed. The standalone server binds to loopback and sandbox fixture mode only; fixtures use visibly synthetic block references and timestamps. `merchant.testnet` allows; `new-receiver.testnet` warns. These names in sandbox fixtures are not claims about real testnet accounts.

The smoke command starts a temporary real HTTP service, verifies real service signatures, exercises durable retries/revalidation, and confirms no chain signing/submission. A service signature is not hardware attestation. `attestation` is always `null`.

## Validation

```sh
pnpm lint
pnpm typecheck
pnpm test
pnpm test:integration
pnpm verify:interfaces
pnpm smoke:api
pnpm audit --prod
```

`pnpm test:e2e`, `pnpm demo:attack` and `pnpm demo:all` intentionally exit nonzero with the missing B/C integration named. They do not substitute API mocks for vault, key-restriction, human-approval or real attack-demo evidence. C owns the real demo runner; B owns exact Cargo/build/sandbox commands once their Rust workspace exists. CI runs the implemented A checks without funded testnet secrets.

## Backend interfaces

- `POST /v1/checks`: authenticate a registered agent, assess an immutable exact action and persist the eligible permit before returning it.
- `GET /v1/checks/:id`: read that agent’s stored result.
- `GET /v1/checks/:id/evidence`: read the immutable retained evidence snapshot and hash.
- `POST /v1/checks/:id/revalidate`: refresh security facts without extending the original permit.
- `GET /v1/receivers/:network/:account`: inspect retained agent-scoped receiver evidence/history.
- `GET /v1/executions/:id`: read reconciled execution state from a trusted injected source.
- `GET /health`: sanitized database/configuration readiness.

Bearer credentials derive agent identity server-side. Request fields cannot grant another agent’s history/policy or reviewer authority. Amounts are canonical decimal yoctoNEAR strings with u128 bounds; revisions are u64 strings; timestamps are bounded integer milliseconds. No public endpoint accepts claimed execution success.

Use `createApp` to assemble live providers with trusted B policy/finality and C reputation/report adapters. The standalone fixture server refuses live mode, so synthetic empty reputation state cannot issue a testnet permit. Live source adapters have successful read-only testnet probes; those probes are not a payment demo.

## Security boundaries

`block` has no permit. `warn` never grants automatic signing authority; B’s vault must verify the owner’s approval of the exact permit hash. Missing mandatory current-state/reputation/policy/storage produces a typed non-success response without a permit. Reviewed active block entries override positive history; raw report counts cannot manufacture a hard block. Indexed activity earns no live independence credit until C supplies a justified result.

The agent must receive only a function-call key restricted to the vault’s `execute` method with zero attached deposit. The prefunded vault supplies payment value. The owner/recovery key stays outside the agent runtime. Gas allowance is separate from payment limits; topping up the account does not replenish it, and an existing key’s allowance cannot be edited. Replace an exhausted key through the external recovery path; retain explicit method restrictions and a finite allowance. See [NEAR access-key restrictions and caveats](https://docs.near.org/protocol/accounts-contracts/access-keys).

The vault cannot atomically inspect another contract’s latest code or the service’s latest blocklist. Short expiry, SDK revalidation and emergency pause reduce a bounded race; they do not remove it. B must independently enforce signature origin, complete action binding, expiry, nonce, policy, warning approval, budgets and conservative pending accounting. Rust/TypeScript byte equality and B/C owner review remain integration gates.

## Ownership and documentation

Medhansh is **Person A**: API (except report routes), shared TypeScript, providers, scoring, core DB, root JS tooling/lockfile and README. B owns contracts, guarded SDK and chain scripts; C owns reports/reputation, dashboard, fixtures and demo. Their directories and implementation files are left for their PRs; A provides typed seams and test doubles confined to A tests/local setup.

- [Product scope and equal-effort plan](PLAN.md)
- [Person A package plan](docs/person-a-plan.md)
- [API/auth/persistence](docs/api.md)
- [Source capabilities and read-only validation](docs/sources.md)
- [Scoring rules](docs/scoring.md)
- [Permit bytes and public golden vectors](docs/permit-v1.md)
- [B/C integration contract](docs/integration-contracts.md)
- [Security model and limitations](docs/security.md)
- [Local operations and recovery boundaries](docs/runbook.md)
- [Person A handoff](docs/person-a-handoff.md)
- [Repository workflow](docs/repository-workflow.md)
- [Architecture decisions](docs/decisions.md)
