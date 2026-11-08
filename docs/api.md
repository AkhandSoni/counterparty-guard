# Check service API and integration contract

Status: Person A service implemented. The standalone process runs labelled sandbox fixtures; it neither signs an agent transaction nor submits a payment. B's vault/SDK and C's reputation/report routes arrive through their own PRs. This document describes the A-owned boundary and the exact integration seams.

## Run locally

Run the root `pnpm setup:local` workflow, then start the API with `GUARD_CONFIG_FILE=artifacts/local/config.json pnpm dev:api` (use the actual config filename printed by setup). Run `pnpm smoke:api` against the documented local setup. The setup generates local credentials and a scorer key outside tracked files. Do not paste those files into issues or logs.

`loadConfig()` reads a bounded JSON fixture configuration from `GUARD_CONFIG_FILE`. `API_HOST` defaults to `127.0.0.1` and accepts only loopback hosts. `API_PORT` defaults to `3000`. `DATABASE_PATH` overrides the configured SQLite path. The standalone fixture server accepts only sandbox registrations/evidence and refuses a live source-mode environment setting. Fixture block timestamps are generated at fetch time and remain explicitly labelled fixture data.

Applications needing live operation use `createApp()` with verified injected providers. Do not relabel fixture policy/reputation as live state. A live deployment cannot be assembled safely until B's policy/finality adapter and C's reviewed-reputation adapter exist.

## Authentication and credentials

All A-owned `/v1` routes require `Authorization: Bearer <registered-agent-credential>`. Store SHA-256 credential hashes in registrations; load raw tokens from local secret files at the caller. The service looks up the authenticated registration and derives agent account, public key, network and vault server-side. It rejects registrations attempting authorization with the scorer signing key as their agent key; those trust roles must be separate. Requests cannot supply an `agent_id`, override another agent's policy or read another agent's assessment/execution/history. Cross-agent reads return 404.

There is no public registration, arbitrary policy-write or execution-success endpoint. `GuardStore.registerAgent()` is a trusted provisioning operation. Registration changes require an explicit provisioning migration/rotation; rerunning it with conflicting identity information fails rather than silently rewriting access.

Reviewer authentication is a separate helper and configured credential hash. It never accepts an agent credential as reviewer authority, including a reviewer hash accidentally configured to match an existing or later-registered agent credential. C's report plugin must call `context.authenticateReviewer(request)` before review writes, use that reviewer identity in its audit, validate signatures/nonces/expiry independently, and provide an actual reviewed-reputation result. Owner approval is exclusively an independent chain operation owned by B, not an API Boolean.

## Routes

| Route | Result |
| --- | --- |
| `POST /v1/checks` | Strictly validate exact action, assess retained evidence, return a durable decision and eligible permit |
| `GET /v1/checks/:id` | Return the exact original `CheckResponse`, including original expiry and permit |
| `GET /v1/checks/:id/evidence` | Return the immutable evidence/policy/reputation/history snapshot, content hash, network/mode, and local invalidation reason |
| `POST /v1/checks/:id/revalidate` | Force current-state refresh and compare security facts without editing or extending authorization |
| `GET /v1/receivers/:network/:account` | Return this agent's latest retained evidence and reconciled finalized history for the receiver |
| `GET /v1/executions/:id` | Return attempt/sign/submission/finality state and retained final receipts; optionally reconcile through the trusted execution provider |
| `GET /health` | Check SQLite liveness and report configured integration availability, without secrets |

C's report routes are not implemented by A. They are registered through an optional plugin; no synthetic report server is substituted. Health checks probe SQLite only, not live source freshness; source availability and mandatory freshness are checked during each authorization/revalidation. An unconfigured execution adapter leaves executions at their known state, never invents a finalized outcome.

### Check request

```json
{
  "schema_version": 1,
  "network": "sandbox",
  "vault_id": "vault.testnet",
  "request_id": "invoice-123",
  "action": {
    "kind": "transfer_near",
    "receiver_id": "merchant.testnet",
    "amount_yocto": "10000000000000000000000"
  }
}
```

Account names are identifiers; the `network` field determines the environment even if a sandbox fixture uses a `.testnet` suffix. Do not infer execution environment from the account suffix.

The second action is `contract_call` with `receiver_id`, `method_name`, canonical `args_base64`, decimal-string `attached_deposit_yocto` and integer `gas_tgas`. Only the configured receiver/method and bounded `memo-v1` argument schema (`{"memo":"..."}`) are eligible. Exact raw argument bytes remain bound in the permit. Unsupported methods, oversized or invalid arguments, unknown fields and integer overflow are rejected. All monetary fields preserve u128 precision; never convert them to JavaScript floating point or SQLite numeric values.

### Decision and evidence

`CheckResponse` is exported by `@counterparty-guard/shared` and includes `schema_version`, `check_id`, derived `agent_id`, decision, prototype risk indicator, stable reason codes/reasons/contributions, evidence references, coverage, source mode, evaluation/expiry timestamps, policy/blocklist revisions, permit/null and `attestation:null`.

A block stores the decision without any permit. An allow or warning may carry a signed permit. A warning is not permission to sign an agent transaction: B's vault must require the independent owner's approval for the exact permit hash. `POST /v1/checks` signs only a scorer authorization, not a chain transaction; `signed` in execution records refers to agent transaction signing and begins false.

The authenticated evidence route returns:

```text
{
  check_id, network, source_mode, evidence_snapshot_hash,
  snapshot: { evidence, reputation, policy, history },
  invalidated_reason
}
```

Snapshots retain bounded source values, hashes, real block references when live, source and fetch timestamps, coverage and the exact policy/reputation inputs used. New receiver observations never rewrite older snapshots. The service also checks each source digest against its retained canonical value. The snapshot hash is the same hash bound in the permit. Review source mode and coverage before interpreting an evidence value; fixture block references are not chain receipts.

### Idempotency and issuance

The unique key is `(authenticated agent_id, request_id)`. Its immutable fingerprint binds network, vault, full action and source mode. Repeating an unchanged request while valid returns the identical stored response and nonce. A changed action/context conflicts. Expired or locally invalidated checks require an explicit new request ID; retries do not silently renew authorization, and uncertain payments are not automatically reissued.

SQLite claims use a bounded lease and persistent nonce. Concurrent in-flight duplicates return `ISSUANCE_IN_PROGRESS` and should retry the same request ID. A crashed/stalled claim may be recovered after its lease using the original nonce. Only the current lease owner can commit a result; a superseded signer cannot return a second authorization. Network calls and asynchronous signing occur outside write transactions. The immutable evidence, policy observation, permit record, initial attempt and completed response are committed together before any permit is returned. Persistence failure produces no permit response.

The service rereads policy and reviewed blocklist state immediately before constructing authorization and recomputes the result with the latest snapshot. It captures the exact expected payload before passing an isolated clone to the signer, and verifies the returned envelope against the separately configured scorer public key and captured payload. It isolates action, registration and evidence inputs from adapter mutation, and checks that the retained snapshot still matches the signed evidence hash. It rereads policy/reputation after an asynchronous signer returns and atomically rejects any local invalidation committed before completion. It checks expiry and mandatory source freshness again after signing. This limits known stale issuance; it does not remove the off-chain/on-chain race described in PLAN.md.

### Revalidation

Revalidation accepts only the original check ID and no action or approval body. It returns `{check_id,status,reason,expires_at}` where status is `valid`, `expired`, `invalidated`, `in_flight` or `consumed`. Known signed/submitted/uncertain executions return `in_flight`; finalized success/failure returns `consumed` and cannot authorize reuse. Infrastructure failure returns a typed non-success response with `permit:null`; it is never reported as valid.

It forces current receiver state refresh and rereads policy/reputation. Changes to code, policy facts, reviewed reputation/risk facts, activity-confidence features or relevant authorization revisions invalidate the original check. Fetch timestamps, coverage-window movement and block advancement alone do not invalidate it. It rereads local invalidation and execution state after awaiting sources so a concurrent committed update cannot be reported as valid. It never extends expiry, signs a replacement permit or treats a browser-supplied Boolean as owner approval. Normal SDK callers must stop on invalidated/unavailable state and request a new assessment and, if needed, new exact owner approval.

Already signed permits retain their cryptographic validity until their original expiry unless B's independent vault policy/pause checks reject them. A local invalidation record cannot revoke a signature on-chain by itself.

## Error envelope

```json
{
  "error": { "code": "SOURCE_UNAVAILABLE", "message": "Required authorization data is unavailable" },
  "permit": null
}
```

| HTTP | Typical codes |
| --- | --- |
| 400/413 | `INVALID_REQUEST` (strict schema or input bounds) |
| 401 | `UNAUTHORIZED` |
| 403 | `FORBIDDEN`, `POLICY_REJECTED`, `UNSUPPORTED_ACTION` |
| 404 | `NOT_FOUND` |
| 409 | `REQUEST_CONFLICT`, `ISSUANCE_IN_PROGRESS`, `CHECK_EXPIRED`, `CHECK_INVALIDATED` |
| 429 | `RATE_LIMITED` |
| 503 | `SOURCE_UNAVAILABLE`, `SOURCE_STALE`, `EVIDENCE_UNAVAILABLE` |

Infrastructure messages are sanitized so authenticated source URLs, key paths and provider credentials are not echoed. HTTP bodies are capped at 16 KiB, evidence snapshots at 1 MiB and shared evidence JSON additionally has depth/node/type bounds. In-memory rate-limit buckets are bounded; distributed enforcement requires an external limit shared across API replicas. SQLite is intended for one service writer environment, not an arbitrary horizontally scaled cluster.

## Dependency injection for B and C

`createApp(options)` returns a Fastify instance. It requires:

- `store: GuardStore`, `sourceMode`, `clock?`.
- `receiverProvider: {sourceMode, assess({network,account_id,action,refresh?})}` returning validated `ReceiverEvidence`.
- `policyProvider.getPolicy(agent)` returning a fresh `PolicySnapshot` bound to the registered network/vault.
- `reputationProvider.getReputation(network,accountId,evidence)` returning a fresh available `ReputationSnapshot`; unavailability must not become an empty clean report set.
- `signPermit(payload)` plus `scorerPublicKey` from trusted configuration. The key must match B's configured scorer authority.
- Optional `executionProvider.getExecution(network,vaultId,executionId)` and C's `reportPlugin(app,context)`.

`ReportPluginContext` exposes the common SQLite store, separate auth helpers and `invalidateReceiver(network,account,reason)`. C adds SQL only under `db/reports` and appends to the ordered manifest with A coordination. Report-review/blocklist writes must invalidate affected local checks/caches as part of the reviewed change; API revision rereads remain mandatory.

The execution provider is a **trusted finality adapter**, not a JSON webhook accepting agent claims. It must verify the configured vault's actual finalized events/receipts, exact receiver/action/deposit/result and warning approval against the issued permit. `ExecutionObservation`'s permit hash binds the expected action but is not itself proof that a chain event happened. Do not instantiate this provider from model/user-supplied success data.

`GuardStore.reconcile()` validates network/vault/check/permit binding, requires finalized receipt/block references for final outcomes, requires nonexecution proof for failure, and requires an owner-approval reference for warned success. It preserves signing/submission independently, deduplicates final receipts across later polls, accepts pending→final progression, rejects conflicting final outcomes and never regresses a finalized result. Pending/uncertain/failed attempts do not earn successful-history credit. No A-owned method releases B's vault reservations.

## Persistence and migrations

The SQLite store uses WAL, foreign keys and bounded busy timeout. `db/migrations.json` orders both `core` and `reports` streams. Applied IDs, positions and SQL checksums are recorded; edited/reordered applied migrations fail startup. Add a new migration rather than editing deployed SQL. Empty-database creation and immutable-migration checks are covered by integration tests.

Core tables: agents, receiver observations, retained evidence snapshots, checks, permit records, policy observations, executions and final execution receipts. Monetary values reside inside validated JSON decimal strings; the API does not perform payment-budget arithmetic in SQLite. B independently enforces checked integer budgets and pending reservations on the vault.

## Validation and remaining gates

Run `pnpm typecheck`, `pnpm lint`, `pnpm test`, and `pnpm test:integration`. API integration coverage includes authenticated idempotency, concurrent/crashed claims, exact signed action binding, signer trust, block/no-permit, warnings without agent signatures, mandatory-source failure, persistence failure, stale data, semantic revalidation, retained immutable provenance, finality dedup and reviewer separation.

These are API/SQLite tests with explicit fixture evidence and a real Ed25519 scorer key generated in test memory. They are not sandbox transactions. TS/Rust vector matching, restricted-key enforcement, independent warning execution, actual receipt verification, supported contract operation and full S1–S10 demo gates require B/C's PRs and remain unclaimed.
