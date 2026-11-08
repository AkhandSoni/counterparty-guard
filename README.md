# Counterparty Guard: Agent C — Reputation & Experience

[![CI](https://img.shields.io/badge/tests-698%20passing-brightgreen.svg)]()
[![Typecheck](https://img.shields.io/badge/typescript-strict-blue.svg)]()
[![Linter](https://img.shields.io/badge/linter-biome-purple.svg)]()
[![Platform](https://img.shields.io/badge/near-protocol-black.svg)]()

**Counterparty Guard** provides in-process defense-in-depth security for autonomous AI agents transacting on NEAR Protocol. Autonomous agents processing untrusted external inputs—such as natural language invoices, memo fields, and third-party API payloads—are vulnerable to prompt injection attacks attempting to divert treasury funds to attacker-controlled accounts.

**Agent C ("Reputation and Experience")** is the counterparty risk mitigation engine of Counterparty Guard. It intercepts proposed transactions *prior to cryptographic signing*, analyzing counterparty risk through signed allegation intake, bounded on-chain graph analysis, Sybil clustering, faucet exemptions, and contract bytecode tracking.

---

## Key Capabilities

1. **In-Process Pre-Signing Interception**:
   Transactions targeting blocked or unapproved counterparties are refused before transaction signing (`signed: false, submitted: false, delta: "0"`), protecting agent private keys and treasury balances.
2. **Cryptographic Signed Report Intake (`packages/reputation`)**:
   Ed25519-signed allegations with domain separation (`COUNTERPARTY_GUARD_REPORT_V1`), monotonic nonce replay protection, and time-bound expiry validation.
3. **Absolute Reviewer Authority**:
   Raw unreviewed allegation counts can **never** trigger an active hard block. Active blocks strictly require authenticated human reviewer authority via `POST /v1/reports/:id/review`. Agent tokens receive HTTP 403 Forbidden.
4. **Bounded Graph Analysis & Sybil Discounting**:
   Explores transaction topology bounded to 2 hops, 100 accounts, 500 edges, and a 7-day rolling window. Coordinated Sybil clusters sharing common funding ancestry are capped at a total weight of 1.0 independent source equivalent.
5. **Common Faucet Exemption Registry**:
   Legitimate shared infrastructure (such as `faucet.testnet` and `testnet`) is exempted from Sybil clustering, preserving full independent reporting weights (1.0 each) for legitimate developers and users.
6. **Contract Upgrade Reassessment**:
   Bytecode hash changes (`CODE_CHANGED`) immediately suspend prior trust credit, escalate risk to 55, and require human owner on-chain permit authorization (`vault.approve_warn`).
7. **Explanation Dashboard (`apps/web`)**:
   React + Vite interface featuring live check action inspection, receiver evidence timelines with graph relationship explanations, owner warning guidance, and a human reviewer moderation portal.
8. **Demonstration Harness (`scripts/demo`)**:
   Deterministic and sandbox/testnet runners (`pnpm demo:attack`, `pnpm demo:all`) emitting structured JSONL audit logs.

---

## Monorepo Layout

```
/home/manit/Programming/Near_hack/
├── packages/
│   ├── shared/                # Canonical Zod schemas, types, domain constants, Borsh helpers
│   └── reputation/            # Core reputation engine, SQLite repository, graph traversal
├── apps/
│   ├── api/                   # Fastify HTTP microservice for reports & reviewer administration
│   └── web/                   # React 18 + Vite explanation dashboard & moderation portal
├── fixtures/                  # Deterministic scenario datasets for scenarios S1–S10
├── scripts/demo/              # Demonstration runners, execution adapters, and JSONL logger
├── tests/regression/          # Adversarial regression suites (S4 flood, S6 faucet, S7 upgrade)
└── docs/
    ├── demo.md                # Capability showcase & reproduction guide
    └── demo-logs/             # Real execution audit logs (*.jsonl)
```

| Path | Description | Scope |
|:---|:---|:---|
| `packages/shared` | Core schemas, domain constants, Borsh & Ed25519 cryptographic helpers | Monorepo Shared |
| `packages/reputation` | SQLite storage, bounded graph traversal, Sybil clustering, scoring engine | Agent C Core |
| `apps/api` | Fastify REST API for report intake, queries, and reviewer management | Service Layer |
| `apps/web` | React + Vite explanation dashboard and reviewer moderation portal | Presentation Layer |
| `fixtures` | Canonical scenario datasets S1 through S10 | Testing & Demo |
| `scripts/demo` | Prompt-injection attack runner and multi-scenario demo harness | Showcase |
| `tests/regression` | Automated regression suites for Sybil floods, faucet controls, and upgrades | Security Invariants |
| `docs/demo.md` | Comprehensive capability showcase and invariant reproduction walkthrough | Documentation |
| `docs/demo-logs` | Structured JSONL execution logs from real runner executions | Audit Trail |

---

## Core Security Invariants

| # | Invariant | Description | Guaranteed Outcome |
|:---|:---|:---|:---|
| **1** | **Refuse Before Signing** | Transactions targeting blocked counterparties are aborted *prior* to signing. | `signed: false, submitted: false, delta: "0"` |
| **2** | **Absolute Reviewer Authority** | Raw unreviewed allegations can never block. Hard blocks require human reviewer auth. | Agent tokens get HTTP 403; unreviewed flood gets `allow`. |
| **3** | **Sybil Discounting** | Correlated reports sharing funding ancestry are clustered into a dependence group. | Aggregate group weight capped to 1.0; pro-rata `1.0/N`. |
| **4** | **Common Faucet Exemption** | Accounts funded by official faucets (`faucet.testnet`) are never clustered as Sybils. | Faucet accounts retain 1.0 weight each; evasion resistant. |
| **5** | **Contract Upgrade Reassessment** | Bytecode hash changes suspend historical credit and force warning reassessment. | Decision `warn`, risk 55; requires human owner `vault.approve_warn`. |

---

## Quickstart & Commands

### Prerequisites
- Node.js >= 20.18.0
- pnpm >= 9.0.0 (or pnpm 11)

### Installation & Build
```bash
# Install all dependencies across workspace
pnpm install

# Compile all workspace packages and apps
pnpm build
```

### Automated Verification
```bash
# Run all automated unit, integration, and regression tests (698 tests)
pnpm test

# Run TypeScript typecheck (0 errors)
pnpm typecheck

# Run Biome linter across workspace (0 errors)
pnpm lint
```

### Demonstration Runners
```bash
# 1. Run prompt-injection attack demonstration runner
pnpm demo:attack

# Run with step-by-step verbose output
pnpm demo:attack -- --verbose

# 2. Run comprehensive 10-scenario demonstration runner
pnpm demo:all

# CLI options for demo:all
pnpm demo:all --scenario S7     # Run specific scenario
pnpm demo:all --json            # Output raw JSONL lines to stdout
pnpm demo:all --verbose         # Detailed assertion and latency breakdown
```

### Dashboard & API Service
```bash
# Start Fastify Report API (port 3001)
pnpm --filter api dev

# Start React Explanation Dashboard (port 5173)
pnpm --filter web dev
```

Visit `http://localhost:5173` to explore:
- **Check Action View**: Evaluate counterparties and inspect real-time risk scores and reason codes.
- **Evidence Timeline**: View historical reports, code hashes, and graph relationship explanations.
- **Warning Approvals**: Copy NEAR CLI commands to approve warned transactions on the vault contract.
- **Reviewer Portal**: Corroborate reports and inspect append-only blocklist revisions.

---

## Scenario Matrix (S1–S10)

| ID | Name | Receiver | Decision | Reason Codes | Signed | Subm | Outcome | Delta |
|:---|:---|:---|:---:|:---|:---:|:---:|:---|:---:|
| **S1** | Established Legitimate Receiver | `merchant.testnet` | **ALLOW** | `[]` | `true` | `true` | `finalized_transfer` | `+0.05 NEAR` |
| **S2** | Legitimate New Receiver | `new-vendor.testnet` | **WARN** | `RECENT_DEPLOYMENT`, `UNKNOWN_AGE` | `false` | `false` | `awaiting_owner_approval` | `0` |
| **S3** | Reviewed Malicious Receiver | `known-drainer.testnet` | **BLOCK** | `ACTIVE_BLOCK`, `REVIEWED_BLOCKLIST_MATCH` | `false` | `false` | `aborted_before_signing` | `0` |
| **S4** | False-Report Flood Attack | `popular-service.testnet` | **ALLOW** | `DEPENDENT_REPORTS` | `true` | `true` | `finalized_transfer` | `+0.05 NEAR` |
| **S5** | Circular Activity Manipulation | `wash-trader-a.testnet` | **WARN** | `CIRCULAR_ACTIVITY` | `false` | `false` | `awaiting_owner_approval` | `0` |
| **S6** | Shared Common Faucet Control | `user-b.testnet` | **ALLOW** | `COMMON_FAUCET_EXEMPTED` | `true` | `true` | `finalized_transfer` | `+0.05 NEAR` |
| **S7** | Upgraded Contract Receiver | `defi-pool.testnet` | **WARN** | `CODE_CHANGED` | `false` | `false` | `awaiting_owner_approval` | `0` |
| **S8** | Permit Replay / Mutation | `merchant.testnet` | **ALLOW** | `POLICY_LIMIT_EXCEEDED` | `true` | `true` | `vault_rejected` | `0` |
| **S9** | Provider Outage (Fail-Closed) | `outage-target.testnet` | **BLOCK** | `MANDATORY_SOURCE_UNAVAILABLE`, `INCOMPLETE_HISTORY` | `false` | `false` | `refused_source_outage` | `0` |
| **S10** | Supported Method Call Boundary | `staking-pool.testnet` | **ALLOW** | `[]` | `true` | `true` | `finalized_call` | `+0.01 NEAR` |

---

## Test Suite Coverage

| Suite | Scope | Files | Tests | Invariants Covered |
|:---|:---|:---:|:---:|:---|
| `packages/reputation` | Intake, nonces, signatures, SQLite, graph, clustering, scoring | 15 | 240+ | Invariants 1, 2, 3, 4, 5 |
| `packages/shared` | Zod schemas, Ed25519 cryptography, payload serialization | 4 | 56 | Cryptographic integrity |
| `apps/api` | Fastify endpoints, reviewer auth, 403 agent rejection, queries | 3 | 100 | Invariant 2 (Reviewer Auth) |
| `apps/web` | React views, evidence timeline, graph panel, approval UI | 7 | 131 | UI/UX & Owner guidance |
| `fixtures` | S1–S10 dataset validation and boundary checks | 2 | 58 | Scenario consistency |
| `scripts/demo` | Runner harness, guard interceptor, JSONL logging assertions | 3 | 49 | Invariant 1 (Refuse pre-signing) |
| `tests/regression` | Adversarial flood, faucet control, contract upgrades, full E2E | 5 | 63 | Invariants 1, 2, 3, 4, 5 |
| **Total Monorepo** | **Full Verification** | **40** | **698** | **Zero failures / 100% passing** |

---

## Documentation

- **[Demo Guide (`docs/demo.md`)](docs/demo.md)**: In-depth showcase guide, prompt-injection attack mechanics, step-by-step reproduction walkthrough, and JSONL audit logging specification.
- **[Demo Logs (`docs/demo-logs/`)](docs/demo-logs/)**: Execution logs capturing real runs of `demo:attack` and `demo:all`.
