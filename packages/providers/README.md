# Receiver providers

Owner: **A**. Implemented fixture, bounded cache, NEAR RPC and NearBlocks v3 adapters.

Use `FixtureProvider` for labelled deterministic data. `LiveReceiverProvider` requires fresh finalized RPC state and makes missing optional indexed history explicit. Required failures propagate without a permit; live activity is not automatically treated as independent.

See [source interfaces, bounds, provenance and verification](../../docs/sources.md). Run provider tests from the root with `pnpm exec vitest run packages/providers/src/providers.test.ts`.
