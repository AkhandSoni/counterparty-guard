# Person A handoff

Owner: Medhansh. Delivery date: 8 November 2026. Implementation branch: `feat/a-core`. Repository: [public Counterparty Guard](https://github.com/medhansh-19/counterparty-guard). Application work is limited to A-owned files; B/C-owned directories and report routes remain for their contributors' PRs.

## Delivered

| Area | Implemented behavior | Reproduction |
| --- | --- | --- |
| Workspace | Exact compatible pins, pnpm lock, strict TS, lint/test/CI setup, private local provisioning | `pnpm install --frozen-lockfile`, `pnpm setup:local` |
| Shared contract | Strict action/evidence/API/policy/reputation/event schemas, stable codes, bounded canonical JSON, browser-safe exports | `pnpm typecheck`, shared unit tests |
| Permit codec | Deterministic Borsh, bounded decoding, full action binding, SHA256/domain-separated Ed25519, four public vectors | `pnpm verify:interfaces`, shared mutation tests |
| Sources | Finalized/block-pinned RPC account/code verification; NearBlocks v3 context; bounded normalized graph; provenance/freshness/cache/deadline handling | Provider tests; actual read-only testnet probe documented in sources |
| Scoring | Deterministic capped contributions, reviewed-block precedence, independent activity seam, forced changed-code warnings and mandatory-source failures | Scoring security fixtures |
| API/storage | Agent-scoped auth, exact-action checks, durable snapshot/permit records, SQLite migrations, concurrent/restart-safe idempotency, explicit errors | `pnpm test:integration` |
| Revalidation/history | Immutable evidence lookup, material security invalidation, original expiry, in-flight/consumed status, trusted receipt progression and dedup | API integration regressions |
| Developer handoff | API/source/scoring/permit/security/runbook docs and B/C assembly interfaces | `docs/integration-contracts.md` and root README |

The HTTP smoke actually starts the standalone API, verifies service signatures, reuses stored responses, revalidates without extending expiry and confirms execution remains unsigned/unsubmitted. Its observations are synthetic sandbox fixtures, not blockchain payments. All test keys are generated in memory or in ignored private local setup files; committed vectors contain public keys/signatures only.

## Validation evidence

**Current local result: 106 tests passed** (69 shared/provider/scoring unit regressions and 37 API/storage integration regressions). Lint, strict typecheck, four golden vectors and HTTP smoke passed after the 9 November PR review fixes. The original delivery also passed frozen-lock installation and a point-in-time production dependency audit; dependency pins are unchanged.

Actual review-fix command output is archived in [the current validation transcript](validation/person-a-review-fixes.txt); [the initial delivery transcript](validation/person-a.txt) retains the earlier install/audit results. They include command exit statuses and exact test totals. They establish A's API/SQLite/cryptographic behavior, not on-chain key enforcement or demo success. GitHub CI runs the same implemented A gates on Linux; PR/run status must be verified separately before claiming that run passed.

The browser-only shared export was also bundled with the installed pinned esbuild and executed without `Buffer`, `process` or `require`; schema/public-key/base64/canonical JSON checks passed. Production dependency audit reports no known vulnerabilities at the time of validation; this is a point-in-time dependency result, not a security guarantee.

`pnpm test:e2e`, `pnpm demo:attack` and `pnpm demo:all` were executed and correctly exited1 naming the absent B/C integrations. They are unavailable gates, not passing tests. Their future real runners remain C/B work; no mocked chain/attack evidence was generated in their place.

## B/C action items before full integration

B must confirm the proposed fixture method/argument contract, compare every TS/Rust vector and rejection case, inject current deployed policy and verified finality adapters, integrate guard pre-sign revalidation/execution-state checks, and prove independent owner approval, restricted key, replay, promise accounting and spend races in a real sandbox. A will review B's actual implementation when its PR is available; that review is not claimed here.

C must implement signed reports/reviewer audit, dependent-evidence grouping/common-faucet controls, justified independent activity credit, report migrations/plugin, dashboard and actual demo runner. C reviews A's scoring/provenance after integrating its own evidence outputs. A's empty report state is a visibly synthetic local fixture, not a live moderation service.

All contributors must then run S1–S10, recovery/allowance and fresh-checkout gates, archive actual transactions/receipts/balance deltas, and disclose the code/blocklist race. OutLayer and real-model integration remain stretch; `attestation=null` throughout current output.

## Material decisions and limits

- Review fixes preserve a known code-free baseline and order approved code by finalized execution height, including u64 boundaries and conservative same-block conflicts. Completion rejects history changes during signing inside its persistence transaction. `core-002` backfills retained receipts without changing existing signed snapshots. See D008 and the runbook for migration and B/C interface impact.
- No live authority fallback: standalone runtime is loopback sandbox fixtures; use injected trusted adapters for live composition.
- Exact permit bytes/signing domains and new `independent_activity_credit`/execution/revalidation contracts are documented for B/C review. No frozen reviewed Rust compatibility is implied.
- One ordered migration manifest; append C migrations without editing/reordering applied core SQL.
- Unknown, stale or unavailable mandatory data cannot issue a permit; original expired/invalidated/uncertain authorizations are not automatically replaced.
- Scorer, agent, reviewer and owner credentials are separate. Browser schemas are pure; private service signing stays server-side.
- SQLite is a single-service MVP store; production credential lifecycle and distributed deployments need deliberate additional work.
- The equal24-hour per-person package allocations remain estimates. B/C reviews, chain integration and complete product evidence remain external gates, not silently marked complete.

## Local reproduction

```sh
pnpm install --frozen-lockfile
pnpm setup:local
pnpm lint
pnpm typecheck
pnpm test
pnpm test:integration
pnpm verify:interfaces
pnpm smoke:api
```

For interactive use, run `GUARD_CONFIG_FILE=artifacts/local/config.json pnpm dev:api`. Read [the runbook](runbook.md) before handling credentials, migrating an existing database, or integrating deployment/recovery work.
