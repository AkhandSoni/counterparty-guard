# Fixture assessment demo and remaining execution gates

The scripted agent reads an untrusted fixture invoice/tool result and proposes an exact payment action. The runner calls the real A+C assessment service, stores evidence, evaluates reports and signs eligible permits with an ephemeral service key. The script does not run a model or sign/submit a NEAR transaction.

## Reproduction

```sh
pnpm install --frozen-lockfile
pnpm demo:attack -- --scenario S3 --verbose --log-file artifacts/demo/attack.jsonl
pnpm demo:all -- --scenario S1 --json --log-file artifacts/demo/allow.jsonl
pnpm demo:all -- --scenario S7 --json --log-file artifacts/demo/code-change.jsonl
```

S3 is a project-owned synthetic reviewed-malicious fixture. Reports seeded by the runner are actually signed and verified; the fixture reviewer context is explicitly synthetic, not a real moderation decision. The attack content is data inside the scripted tool-call flow, never a shell instruction. A blocked receiver has no permit, agent signature or submission.

S1 demonstrates a legitimate allow assessment with an actual Borsh/Ed25519 service permit. It records `signed=false`, `submitted=false`, zero observed value transfer and `fixture_assessment_only`; those fields describe agent transaction execution, not the scorer’s service signature. S2/S5/S7 warn and await independent owner approval. No browser Boolean supplies owner authority.

S4 deduplicates a repeated allegation across reporter identities. Shared funder/code alone does not group independent users. S6 is a common-faucet control: valid independent fixture activity may reduce uncertainty, while the faucet itself grants no trust and erases no risk. S9 returns an infrastructure-error record with no permit rather than accusing a receiver.

S10 assesses the configured `accept_memo` call using exact raw JSON arguments. Unsupported methods/arguments fail in the real scorer. The runner does not claim the call executed.

## Unavailable gates

```sh
pnpm demo:all
pnpm demo:all -- --mode sandbox
pnpm demo:all -- --mode testnet
pnpm test:e2e
```

Full `demo:all` exits nonzero because S8 mutation/replay enforcement requires B’s vault and SDK. Explicit sandbox/testnet execution adapters return `execution_unavailable`, no permit/signature/submission and no invented balances, even if a status RPC is reachable. No deterministic fallback is relabelled as chain execution. `test:e2e` also exits nonzero until B’s owner-approval, key restriction, promise accounting and real receipts exist. Passing API tests are not chain results.

## Evidence

New runs default to ignored `artifacts/demo/`. Reviewed archived logs in `docs/demo-logs/` were regenerated from actual invocations after the integration fixes. They distinguish `source_mode=fixture` from `execution_environment=not-executed`. No old counterfeit signatures, live transfer claims or mock vault rejection logs are retained as verification evidence.

Fixture JSON under `fixtures/` and the dashboard’s offline examples are labelled inputs, not chain captures. Their sample allegations/signature placeholders are never accepted as verified report intake; the runner generates real signatures at runtime. Source freshness, graph bounds/truncation and report-dependence explanations are retained in the assessment snapshot. `attestation=null` throughout.

## Dashboard

Run `pnpm setup:local`, start the API with `GUARD_CONFIG_FILE=artifacts/local/config.json pnpm dev:api`, then `pnpm dev:web`. The default Connected API view uses the local service through Vite’s same-origin proxy. It exposes actual assessment/evidence responses and a separate reviewer-credential form. The other tabs are offline presentation examples; they do not update the API and no longer manufacture signed permits. The approval command preview is disabled until B supplies its verified interface.
