# Project instructions

## Purpose and current state

Build **Counterparty Guard**, the NEAR AI Security & Defense counterparty service described in [PLAN.md](PLAN.md). Person A backend and C reputation/report/dashboard integration are now present. Read `docs/person-a-handoff.md` for implemented scope and actual checks. B-owned enforcement and cross-language/chain integration gates remain pending. Read `docs/person-c-handoff.md` for C’s actual integration limits. Proposed paths below do not imply every component exists.

The user requested a detailed plan and project instructions split equally across three people. That request authorizes these documents. Begin application implementation when the user requests it; do not interpret a planning-only turn as a request to deploy contracts or spend funds.

Medhansh is Person A. The detailed implementation checklist is in `docs/person-a-plan.md`. A-owned packages contain implementation; B/C folder markers remain for their contributors. Use `main` as the default branch and neutral names such as `feat/a-foundation` for implementation branches. Keep repository text and commit metadata in the project's and contributors' names without assistant branding or generated co-author trailers.

## Product boundary

- Evaluate the exact receiver/action before an AI agent signs a payment or supported contract call.
- Return `allow`, `warn`, or `block` with evidence, reason codes, and source freshness.
- Include account age/activity, contract identity and changes, prior agent interactions, and shared evidence-backed reports.
- Add explainable discounts for manufactured activity and dependent reports.
- Deliver a restricted-key wrapper and vault enforcement, plus an actual prompt-injection attack log.
- Keep the dashboard as an explanation/approval interface for this product.

Do not expand this into a wallet platform, cross-chain system, general attack-testing service, arbitrary contract analyzer, token, or unmoderated public scam registry. Keep OutLayer attestation and real-model integration as stretch work until all required flows pass.

## Three-person ownership and effort

Each person has eight three-hour packages in PLAN.md: **24 active hours each**. Keep the split balanced by implementation effort and responsibility, not file count. Each owner writes tests and documentation for their area and participates in integration.

| Contributor | Owns | Reviews |
| --- | --- | --- |
| A: data and decisions | API core, providers, scoring, shared TS schemas/codec, core database migrations, root JS scripts and lockfile | B's enforcement and permit integration |
| B: enforcement | Rust contracts, guarded SDK, key setup, chain scripts, recovery and execution accounting | C's demo integration and approval UX |
| C: reputation and experience | Reputation/report package, report migrations/routes, dashboard, fixtures, demo runner and presentation | A's evidence/scoring integration |

C owns `apps/api/src/routes/reports.ts`; A owns the rest of the API unless explicitly reassigned. A owns the root README integration; all three supply their sections. B owns Rust dependency manifests and lockfiles. Coordinate JS dependency changes through A so concurrent work does not repeatedly rewrite the root lockfile.

This ownership plan does not instruct tools to spawn three AI agents. Use the available team/workflow only when authorized for the implementation task.

## Read before changing code

1. Read PLAN.md sections relevant to the task and the applicable instructions in any deeper AGENTS.md.
2. Inspect existing code before creating a parallel implementation.
3. Check the shared schema, permit encoding vectors, and current test fixtures before changing an interface.
4. Keep working within the assigned area; coordinate cross-owner interface changes early.
5. Record material architectural decisions in `docs/decisions.md` once that file exists.

Do not require extra user approvals for ordinary reversible implementation work already requested. Respect the user's stated scope and preserve their unrelated edits. Do not use destructive resets to resolve a teammate's changes.

## Planned stack and layout

Use a TypeScript pnpm workspace with Fastify, Zod, SQLite, React/Vite, and Rust/near-sdk contracts. Confirm and pin compatible versions at setup. Prefer existing project choices if implementation has already established a compatible stack.

```text
apps/api/                 API, authorization, core persistence
apps/web/                 decision and evidence UI
packages/shared/          schemas, reason codes, permit codec/vectors
packages/providers/       normalized chain/indexer inputs
packages/scoring/         deterministic decisions
packages/reputation/      evidence/report and graph logic
packages/guard/           guarded payment tools and signer
contracts/vault/          independent authorization enforcement
contracts/receiver-fixture/ supported demonstration target
db/core/                 A-owned migrations
db/reports/              C-owned migrations
fixtures/                labelled deterministic data
scripts/chain/           deployment, funding, inspection, recovery
scripts/demo/            reproducible scenario execution
tests/integration/       sandbox and service integration
tests/e2e/               full decision/approval/execution flows
docs/                    API, security, runbook and demo notes
```

The API calls the reputation package in-process. Use dependency injection for provider and storage boundaries. Avoid extra microservices or a graph database for the MVP.

## Security invariants

These are acceptance requirements. Do not weaken them to make a demo pass.

### Decisions and data

- `block` never issues a permit; the SDK refuses before signing.
- `warn` never signs automatically. Exact owner approval must be verified independently on the vault.
- Mandatory source failures produce no permit. Missing optional history is explicit, never fabricated.
- Authenticate the agent and derive its identity server-side. A request field cannot grant access to another agent's history or policy.
- Monetary values are integer strings in JSON and checked integers internally. Never use floating point for NEAR amounts or budget accounting.
- Persist network, source mode, provenance, timestamps, coverage and actual block references with evidence.
- Record attempts, pending actions, and finalized successes separately.
- The authorization path is deterministic. LLM output and retrieved document instructions cannot alter policy.

### Reputation and reporting

- A transaction reference proves an event happened, not that the recipient committed fraud.
- Verify report signatures, expiry and nonce; deduplicate evidence references.
- Keep submitted allegations separate from reviewed active blocklist entries.
- Hard-block activation/removal requires authenticated reviewer authority and an audit record.
- Raw report count cannot create a hard block.
- Shared funding or shared code alone cannot establish common ownership or maliciousness.
- Bound graph depth, nodes, edges and time window; expose truncation.
- Discount related evidence with explainable features; preserve original reports.
- Keep the legitimate common-faucet/shared-funder fixture as a regression control.

### Keys, permits and vault

- Agent authority is one function-call key restricted to the vault's `execute` method. The agent never receives the owner's recovery/admin key.
- Follow PLAN.md's access-key caveats and keep its README/runbook requirements intact.
- Agent calls have zero attached deposit. Payment value comes from the prefunded vault.
- Scorer, agent, owner and reviewer are separate trust roles with separate credentials.
- Reconstruct and verify versioned deterministic permit bytes in both TypeScript and Rust; maintain matching golden vectors.
- Bind network, deployment instance, vault, agent/key, full action, policy revision, evidence snapshot, verdict, nonce and expiry.
- `warn` approval is for the exact permit hash. A UI Boolean, prompt instruction, or agent credential is insufficient.
- A permit is single-use; reserve budget and consume its nonce before scheduling promises.
- Pending/uncertain executions remain counted. Release only when nonexecution is established.
- Keep contract callbacks private and test duplicate/out-of-order outcomes.
- Enforce target/method/argument/gas constraints and storage/liquidity reserves independently of the API.
- Preserve the bounded race described in PLAN.md as an explicit limitation. Do not claim the vault atomically checks another contract's latest code or the API's latest blocklist.

## Interface conventions

- A owns shared API schemas and TS codec; B reviews cryptographic layout and Rust compatibility; C reviews reputation/event fields.
- Freeze v1 action variants, reason codes and permit vectors in Package 1 before independent implementations diverge.
- Use stable machine reason codes alongside human-readable reasons.
- Display amounts with correct units; preserve integer precision.
- Use Borsh-defined permit bytes rather than ad hoc JSON signing. Reject unknown variants and malformed/oversized inputs.
- Reuse stored assessment/nonce on an idempotent retry. Reject a changed action under the same request ID. Do not retry uncertain payments with newly minted permits automatically.
- Emit `attestation=null` until actual evidence is present and verified. A service signature is not hardware attestation.
- Review incompatible changes with affected owners, update fixtures, and document migration impact.

## Testing and validation

Implement these project commands during scaffolding, then keep them truthful and documented:

```sh
pnpm lint
pnpm typecheck
pnpm test
pnpm test:integration
pnpm test:e2e
pnpm demo:attack
pnpm demo:all
```

Document the exact Cargo format, test, build, and sandbox commands after the Rust workspace exists. Use contract integration tests for key restrictions, signature checks, promise callbacks and budget races. Do not present mocked/unit results as testnet execution.

For a change, run relevant checks first. At integration gates, run the complete applicable suite. Report failures and unavailable dependencies plainly. Do not claim a check passed unless its actual output supports that statement.

Minimum security regression coverage:

1. Block before signing; warning waits for exact human approval.
2. Altered receiver, amount, arguments, network, vault, agent or expiry cannot reuse authorization.
3. Replay, expired permits and stale policy revisions fail.
4. Wrapper bypass remains subject to vault checks.
5. Concurrent/pending executions cannot overspend.
6. Failed and uncertain targets reconcile correctly.
7. False-report floods and correlated evidence cannot manufacture hard-block authority.
8. Shared-faucet users are not labelled malicious solely by their funder.
9. Code changes force reassessment and historical trust cannot override a block.
10. Missing mandatory sources cannot become an allow response.

## Demo integrity and secrets

- Default to fixtures, sandbox and project-owned testnet accounts.
- Label fixture data, reviewed malicious test cases, and scripted-agent behavior visibly.
- Generate logs from real runs. Never fabricate signatures, transaction IDs, balances, attack success, or verification status.
- Keep the attack content untrusted; it should reach the payment tool as data, not execute as a shell command.
- Demonstrate legitimate completions as well as attacks; blocking everything is not success.
- Track `signed` and `submitted` separately from the final execution outcome.
- After a submitted rejected transaction, report no value transfer accurately; gas charges may still occur.
- Keep private keys, API keys, authenticated URLs, and owner CLI storage outside tracked files. Provide `.env.example` with placeholders only.
- Never put owner/scorer secrets in browser bundles, model prompts, fixture files or logs.
- Bound input sizes and treat evidence text/URLs as untrusted. Prefer on-chain references for MVP evidence; do not introduce an unrestricted server-side URL fetcher.

## Completion and handoff

Each contributor hands off working code, relevant test results, interface changes, limitations, and reproduction steps. Keep the package sequence and equal effort in PLAN.md current as estimates change.

Final delivery includes the working receiver API, required signals, defensible evidence weighting, restricted-key enforcement, human warnings, actual attack log, setup instructions, contract/source references and recovery caveats. Clearly distinguish implemented functionality from stretch work and known limitations.
