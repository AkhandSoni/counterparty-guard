# Integration tests

A’s API/SQLite/real Ed25519 integration regressions run with `pnpm test:integration`. Source observations and chain references in these tests are explicitly synthetic. They test authentication, issuance, concurrency/restarts, invalidation, provenance and trusted receipt-state handling.

They do not prove B’s on-chain key, signature, promise/budget or callback enforcement. B adds actual sandbox tests; C adds report/reputation integration in their own PRs. See [the A handoff](../../docs/person-a-handoff.md).
