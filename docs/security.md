# Security model and current limits

The implemented backend is Person A's authorization service. It does not hold an owner's recovery key, execute payments, activate reviewer judgments, or replace B's independent contract checks. C's report authenticity and dependence logic is an injected trust boundary, not implemented here.

## Enforced by A

- Agent identity derives from a stored bearer-credential hash mapped to registered account/key/network/vault; authenticated IDs scope checks, retained evidence, receiver history and execution reads. A request cannot select another agent or reviewer.
- Strict action schemas reject mainnet, unsupported variants, malformed/oversized arguments, floating point/overflow amounts and unknown fields. Yocto amounts use integer strings and checked BigInt, never floating point. DB stores signed JSON and values without SQLite numeric coercion.
- Required receiver facts, reputation and policy must be current. Fetch timestamps do not disguise stale underlying blocks. Contract account/code facts share one concrete block; unsupported code cannot issue a contract-call permit. Missing optional history is explicit.
- A reviewed active scoped block yields no permit. Warnings only issue a permit tagged `warn`; no agent/browser approval grants automatic execution. Only B's exact owner-approval check can authorize that permit.
- Deterministic bounded Borsh encoding binds network, deployment, vault, agent/key, full action/raw args, policy/review revisions, evidence snapshot, verdict, nonce and time. Verification pins the configured scorer key. JSON is display/transport, not signed serialization.
- Unique agent/request and nonce constraints plus transactional lease ownership prevent concurrent response issuance. Retried identical requests return the same stored result while valid; changed/expired/invalidated requests cannot silently mint replacements. Evidence/result/permit persistence commits before any response releases authorization. No DB write lock spans slow provider calls.
- Revalidation refreshes sources without changing the old signed bytes or expiry. Material policy/reputation/code/activity changes invalidate it. Trusted reconciliation accepts matching permit/vault/network evidence only and retains uncertainty. No public success-writing route exists.
- Retained source JSON, HTTP bodies, schemas, graph work, transport responses, retries, caches and rate-limit state are bounded. Evidence text is data. No user-provided evidence URL is fetched; redirects/authenticated base URLs are rejected.

## Required from B/C

B independently enforces exact action/key/domain/signature/time/nonce/revision, human approval and conservative spend accounting. The restricted function-call key can bypass an SDK; only vault checks constrain that path. C independently authenticates reports/reviewers, retains allegations separately from active blocks and discounts related evidence. A has no mechanism that makes raw count authoritative.

The `ExecutionProvider` is trusted server-side integration code. It must prove the exact supported operation's finalized outcome from the configured vault's event/receipts. A matching transaction ID or indexer boolean alone is insufficient; a forged in-process adapter can lie. This is an explicit trust boundary, not a public assertion API.

## Known limitations

A service signature proves origin/integrity, not correctness or hardware attestation. The scorer/owner remain trusted configured roles. B's contract cannot atomically read a receiver's latest code or the API's latest blocklist. An already issued valid permit may remain usable until expiry or a vault policy/pause change even after off-chain invalidation. SDK revalidation reduces this window; it cannot eliminate it.

The prototype indicator is not calibrated fraud probability. Graphs are bounded, historical coverage can be incomplete, shared infrastructure is not ownership evidence, and activity independence requires C's justified result. The supported call schema is deliberately narrow; downstream effects of arbitrary contracts are outside scope.

The standalone server is a loopback sandbox fixture process. Live receiver reads are implemented, but a live authorization assembly must inject verified B/C authority adapters; startup refuses to reinterpret synthetic fixtures as live state. No Rust equality, on-chain key restriction, budget race, owner approval transaction, model-driven attack, or payment execution has been verified in A-only tests.

Keep credentials, private scorer keys, owner CLI storage and authenticated URLs outside Git. Public golden vectors contain public keys/signatures only. Local setup generates random private material under ignored `artifacts/local/`, never fixture directories or browser sources. Public repository visibility is explicitly authorized by the user; it does not grant a software license automatically.
