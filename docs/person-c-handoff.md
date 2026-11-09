# Person C integration handoff

Contribution: reputation, signed reports, moderation, bounded graph analysis, dashboard, synthetic fixtures and scripted assessment demo. PR #2 preserves the contributor's original commit and merges current `main` before remediation. Person A's payment schema, permit vectors, API and core migrations remain authoritative.

## Implemented and verified

- Reports share the core SQLite database and ordered checksum migration manifest. Domain-separated report signatures, expiry/nonces, retained allegations, review records and append-only revisions are exercised.
- Unconfigured reviewer credentials fail closed. Production uses A's separate reviewer authenticator; caller headers do not select the audit identity. Agent credentials cannot review. Review writes are atomic; corrective dismissal/rejection revokes the report's blocks. An explicit authenticated revoke endpoint also works after report expiry.
- Account-wide blocks stay on their account; code scope requires that same account and code. A clone sharing code is not blocked by another account's report.
- Normalized evidence references are grouped across reporter identities. Shared funding alone does not establish dependence; an additional relationship (such as inter-reporter transfers or the same report signing key) is required. Original reports are retained. Common-faucet controls and independent-evidence controls remain covered.
- Cycle search collapses parallel receipt relationships, retains actual receipt provenance, aggregates their real amounts and enforces a 20,000-step limit. Incomplete analysis fails closed without a permit.
- The reputation adapter feeds A's deterministic scorer from retained graph evidence. No faucet/related-report observation creates positive trust or erases a code-change warning. Reviewed/dismissed/rejected reports do not remain unresolved risk. Live independent-activity credit is conservative zero until a justified inference is implemented.
- The default dashboard view calls the actual API for assessments, retained evidence and independently authenticated report review. Credentials stay in component memory. Offline example tabs are visibly labelled and cannot issue signed permits or execute approval commands.
- Scripted attack/allow/call scenarios use the actual A+C fixture assessment path with real ephemeral service signatures. Every agent-chain `signed`/`submitted` value remains false; no receipt or balance change is fabricated. Old misleading demo logs were replaced by actual post-fix runs.

## Validation

Local: 767 package/provider/scoring/UI/demo tests and 46 API/storage integration tests passed, plus lint, combined strict typechecks, frozen-lock installation, dashboard build, four unchanged permit vectors and real HTTP smoke. Browser checks covered API allow/warn, exact owner-warning text, unauthorized credentials, cleared stale responses, explicit offline examples and mobile layout without page errors.

Actual command summaries are retained in `docs/validation/person-c-integration.txt`. Test fixture clocks use injection; no chain submission is implied by these tests. The contributor's prior count of 698 standalone tests is superseded by the combined scope and corrected assertions. C's existing test files retain their original strict TypeScript settings; production and A code retain `noUncheckedIndexedAccess`.

## Reproduction

```sh
pnpm install --frozen-lockfile
pnpm setup:local
pnpm lint
pnpm typecheck
pnpm test
pnpm test:integration
pnpm build
pnpm verify:interfaces
pnpm smoke:api
pnpm demo:attack -- --log-file artifacts/demo/attack.jsonl
pnpm demo:all -- --scenario S1 --json --log-file artifacts/demo/allow.jsonl
```

Run `GUARD_CONFIG_FILE=artifacts/local/config.json pnpm dev:api` and `pnpm dev:web` in separate terminals for the connected dashboard. New setups provision separate private agent/reviewer credential files. Existing setup is preserved; add a distinct reviewer credential hash explicitly before enabling review.

## Remaining gates and limits

B must implement/review Rust vector equality, guarded SDK, restricted key, independent owner approval, replay/mutation enforcement, promise accounting, spending races and real finality adapters. Full `demo:all` exits 1 because S8 is unavailable; sandbox/testnet demo modes and `test:e2e` also explicitly remain unavailable. The attack runner demonstrates a scripted tool call, not a model-susceptibility measurement. No deployments or funded transactions occur.

`shared/demo` holds presentation-only compatibility formats; canonical authorization uses `shared`/`shared/browser`. C's legacy in-memory graph test helpers and isolated report-only assembly are not production services. Existing core SQL and signed snapshots are not rewritten. Production migrations only append C's four report streams.

The live code/blocklist race documented in PLAN remains. Hardware attestation and real-model integration remain stretch work; `attestation=null`. B/C human owner reviews are not fabricated by automated review. The equal 24-hour contributor allocations remain estimates, not measured completion claims.
