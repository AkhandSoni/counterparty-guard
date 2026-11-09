# Shared interfaces and permit codec

Owner: **A**. B reviews cryptographic layout/Rust compatibility; C reviews reputation and event fields.

Implemented: strict Zod schemas, typed errors, evidence/policy/reputation/execution boundaries, stable reason codes, deterministic bounded Borsh permit encoding/decoding, SHA256 hashing, Ed25519 signing and trusted-key verification. Source entry point: `src/index.ts`.

Read [the exact v1 byte contract](../../docs/permit-v1.md) and [public golden vectors](vectors/permit-v1.json) before integrating. TypeScript tests are available; Rust equivalence and vault enforcement remain pending B's PR/review. No chain execution is claimed.

Run `pnpm exec vitest run packages/shared/test/codec.test.ts` from the root. Dependency changes go through A's root lockfile.

Browser consumers should import `@counterparty-guard/shared/browser` (schemas, errors and bounded canonical JSON) or `/schemas`. These entries contain no Node crypto or Buffer dependency. The root entry also exports server signing utilities and belongs in trusted server/SDK processes.

`ReputationSnapshot.independent_activity_credit` is optional, bounded to 0–15, and supplied by C's trusted in-process adapter only after graph/evidence validation. It must be justified with retained successful-transfer/graph references and explanations; a raw transfer count is insufficient. Live providers intentionally do not infer independence on their own.

Retained JSON evidence is required and bounded to 2 MiB, depth 32 and 50,000 values. Canonical serialization uses sorted keys and rejects undefined, nonfinite/unsafe integer values, cycles and non-JSON object types. Source adapters hash the same retained canonical parsed snapshot; this is distinct from a hash of exact HTTP wire bytes.
