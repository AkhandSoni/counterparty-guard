# Receiver sources and normalization

Person A owns `packages/providers`. Providers return retained bounded observations, actual block references where supplied, source mode/network, retrieval time, source time, coverage and SHA-256 hashes. Provider errors do not become clean evidence or risk verdicts. Each `raw_hash` is SHA-256 of the shared canonical JSON encoding of the retained parsed `value`; it hashes a reproducible source snapshot rather than exact HTTP wire bytes. Derived graph snapshots use the same rule and retain source observation IDs.

## Interfaces

```ts
interface ReceiverProvider {
  readonly sourceMode: 'fixture' | 'live-testnet';
  assess(input: {
    network: 'sandbox' | 'testnet';
    account_id: string;
    action: Action;
    refresh?: boolean;
  }): Promise<ReceiverEvidence>;
}
```

`FixtureProvider(records)` accepts explicitly labelled observations and preserves supplied timestamps. `set(record)` supports deterministic tests. It never refreshes timestamps to disguise stale fixtures. Missing network/account fixtures fail.

`LiveReceiverProvider({rpc, indexer?, clock?})` is testnet-only. `NearRpcClient({url,network,...})` supplies required current facts; optional `NearBlocksClient` supplies bounded indexed context. `CachedReceiverProvider(inner,{ttlMs,maxEntries,clock})` defaults to five seconds/128 entries, scopes by source mode/network/account/full action, clones outputs, and supports `invalidate(network?,accountId?)`. `refresh:true` always calls the underlying source. Exceptions are not cached.

## Required current state

The RPC adapter verifies the node's `chain_id`, queries `view_account` at finality `final`, then queries the exact returned block to verify its hash, height and timestamp. Its source timestamp must be no more than 60 seconds old and must not be in the future. A slow/stale node is a source failure even if the HTTP fetch just completed.

For local contracts, `view_code` is queried at that same block hash. Its hash/height must match the account response; base58(SHA256(exact WASM bytes)) must match the reported code identity. Account and code evidence appear as `account_state` and `contract_code` observations. No-code accounts have `code_identity=null`. Global-code references are explicitly marked unsupported; native transfers may be assessed, while contract-call assessments fail without a supported code identity. No inferred deployment time is created from a first code observation.

Account-not-found, missing block fields, incompatible network, malformed numeric data, unsupported required code, oversized responses and stale required state throw typed `ProviderError` errors. The API must issue no permit for those errors. `NearRpcClient.viewFunction` provides bounded JSON view access for operator-configured contract integrations; a view response alone is not a verified payment outcome.

Reference: [NEAR account and contract RPC](https://docs.near.org/api/rpc/contracts).

## Indexed history: NearBlocks v3

The adapter uses the documented v3 account, receipt and deployment endpoints. It consumes `data`/`meta` envelopes and walks opaque `meta.next_page` tokens with `next` and `limit`; it does not construct or parse cursors. An optional API credential is sent in the Bearer authorization header. Credentials and authenticated URLs are never copied into observations.

Account creation age is recorded only when indexed creation metadata has a timestamp and no observed deletion ambiguity. Empty/missing creation data stays unknown. Indexed deployment references can establish a known recent deployment; missing deployment data does not establish an old deployment. Indexed observations are contextual, never execution/finality proofs.

Only successful, nonzero, pure native-transfer receipts enter the normalized transfer graph. Failed receipts, duplicate receipt IDs, function-call deposits and zero-value transfers do not earn transfer activity. Distinct receipts in one transaction remain distinct actual transfers; the adapter does not additionally count transaction rows. Receipt timestamp, hash, height, counterparties, amount and transaction reference remain attached to each normalized edge.

The `transfer_graph` observation contains normalized `edges`, `visited_accounts`, actual collection bounds and source observation IDs for C's in-process reputation module. Providers do not infer that counterparties are independent or under common control: live `independent_successful_counterparties` and `activity_manipulation_score` default to zero. C's reviewed/explainable reputation output supplies the inference. Shared faucet/funder/code by itself creates no maliciousness label.

Hard ceilings are two relationship hops, 100 accounts, 500 successful edges and seven days. The default collection budget is eight receipt pages of 25 items, configurable only within bounded limits (16 pages, at most 100 items/page). A 15-second total history-collection deadline (configurable up to 20 seconds) aborts outstanding transport work and prevents retries from extending the whole collection indefinitely. Reaching a relationship-depth boundary is explicitly marked truncated, even when all fetched pages were terminal. Returned coverage identifies page/node/edge/nested-receipt/time-window/deadline truncation and optional-source failures; it never claims full chain history. Only directly incident edges from each visited account are admitted, so nested receipt trees cannot expand graph depth implicitly.

NearBlocks attribution: **Powered by [NearBlocks.io APIs](https://nearblocks.io/)**. Public use requires attribution under the current API documentation.

References: [testnet OpenAPI](https://api-testnet.nearblocks.io/openapi.json), [v3 migration guide](https://api-testnet.nearblocks.io/api-docs/migration), [interactive reference](https://api-testnet.nearblocks.io/api-docs). Response schemas are not fully specified by the OpenAPI file; tests include the shapes observed in successful read-only probes.

## Transport and resource limits

Upstreams are operator-configured fixed HTTPS URLs; credentials, fragments and query strings are rejected in the base URL. Local HTTP RPC requires explicit opt-in for sandbox. Untrusted evidence URLs are never fetched. Redirects are rejected.

The transport defaults to a five-second per-attempt timeout, two attempts, 100ms minimum request spacing, and a two-million-byte streaming response cap. Configuration is bounded to three attempts and 30 seconds per attempt. Retries apply to transient network failures, 429 and 5xx; malformed JSON/size failures are not retried into a clean result. A cursor loop is an incomplete/truncated history, not successful pagination. Raw snapshots remain bounded by the shared evidence schema as well.

## Verification and limits

On 8 November 2026, read-only probes fetched the official NearBlocks OpenAPI/migration guide and actual public testnet account, receipt and deployment responses, plus a finalized NEAR RPC account and code response. No private credential was required for these small probes. This does not guarantee public quotas, historical completeness, or future availability; configure an appropriate API plan for sustained use.

Focused automated tests cover actual v3 envelope shapes, exact code/block binding, stale or wrong-network RPC, unsupported global code, missing optional history, receipt deduplication, failed/zero/call-deposit exclusion, opaque cursors and truncation, lifecycle ambiguity, bounded retries/body size/timeouts, total collection deadline, concurrent request spacing, graph depth boundaries, fixture network separation and forced refresh. Test captures are labelled synthetic in the test source; they are not transaction or deployment demo evidence.

Reconciliation consumes a separately injected trusted `ExecutionProvider` from B. Neither NearBlocks boolean status nor a client-submitted success claim is promoted into finalized agent history. B's event/receipt binding and C's reputation package remain separate integrations.
