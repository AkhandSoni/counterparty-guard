# Repository and collaboration workflow

## Repository target

- Name: `counterparty-guard`.
- Initial owner: authenticated account `medhansh-19` unless changed by the user.
- Initial visibility: private; no license grant is assumed.
- Default branch: `main`.
- Initial content: plans, ownership markers, ignore rules and contribution templates. No working runtime or contracts yet.
- Commit identity: Medhansh's configured Git identity. Use plain project commit messages without generated attribution trailers.

Repository creation and push status must be verified directly on GitHub; these intended settings alone do not establish completion.

Verified 8 November 2026: [the private repository](https://github.com/medhansh-19/counterparty-guard) exists, the planning/folder setup is pushed, and `main` is the only remote branch and the default. Commit identity uses the contributor's configured name/email. Collaborator invitations, protections, CI and application implementation remain future work.

## Branches and reviews

| Branch pattern | Purpose | Example |
| --- | --- | --- |
| `feat/a-*` | API, sources, shared codec, scoring, root JS setup | `feat/a-foundation` |
| `feat/b-*` | Vault, SDK, keys, chain scripts | `feat/b-vault` |
| `feat/c-*` | Reports, graph features, dashboard, demo | `feat/c-reputation` |
| `fix/*`, `test/*`, `docs/*` | Focused follow-up work | `test/permit-mutations` |

Keep `main` as the integration branch. Create feature branches when work starts; avoid long-lived A/B/C integration branches. Open small pull requests after each package or coherent part of it. Synchronize before modifying shared contracts. Preserve teammate edits and resolve conflicts explicitly.

A reviews B's enforcement/permit integration, B reviews C's demo/approval work, and C reviews A's evidence/scoring. B additionally reviews shared byte layout; C reviews reputation/event fields. A owns the root lockfile and integrates JS dependency requests from B/C. B owns Rust manifests and lockfiles.

Only A's GitHub handle is known. Obtain B/C handles before adding collaborators, reviewer assignments or CODEOWNERS rules. This setup does not invite anyone or send messages. Do not publish placeholder handles or pretend automatic review assignment is configured.

## Setup sequence

1. Review the planning files and folder map; scan tracked content for credentials and unwanted attribution.
2. Initialize Git on `main` with the contributor's configured identity. Commit the reviewed planning/folder setup.
3. Create the private repository only if no matching repository exists. If it exists, inspect its contents/default branch before connecting; never overwrite or force-push it.
4. Add `origin`, push `main` and verify remote HEAD, visibility and tracked content. Do not create feature branches as part of the planning setup.
5. In A1, add workspace manifests, pinned toolchains, lockfile and real CI. Do not add a green placeholder workflow that implies unavailable checks passed.
6. Once CI check names and account capabilities are known, configure available protections for `main`: pull-request reviews, no force pushes/deletion, and required checks. Verify settings; report unavailable private-repository features without changing visibility automatically.
7. Add B/C collaborators and complete review automation after their identities and desired access are known. Document access and recovery ownership.

## GitHub work breakdown

Use the following checklist as the issue backlog. Create issues from the task template when implementation begins; do not mark planned work complete because its folder exists. Each item is a three-hour package including tests and docs.

| Package | A: data and decisions | B: enforcement | C: reputation and experience |
| --- | --- | --- | --- |
| 1 | Workspace, API factory, v1 schemas/bytes | Vault/sandbox skeleton, byte review | Labelled scenarios, report contract, web shell |
| 2 | Fixture assessment and signed permit | Verify permit, guarded sandbox transfer | Check details and visible result |
| 3 | RPC/indexer and source coverage | Restricted key and vault budgets | Signed intake, references, review states |
| 4 | Pure scoring, stable reasons | Replay/time/policy/approval | Bounded graphs and report dependence |
| 5 | Reputation routes integration, snapshots | Warning resume, supported call | Report/review UI, graph explanations |
| 6 | Reconciliation, invalidation, failures | Testnet/accounting/recovery | Injection inputs, controls, demo runner |
| 7 | Stale/missing/duplicate/auth regressions | Bypass/mutation/race/key tests | False reports/shared-funder/e2e checks |
| 8 | Source/API docs, README, review B | Key/contract docs, review C | Actual logs/presentation, review A |

Suggested labels at implementation kickoff: `owner:a`, `owner:b`, `owner:c`, `security`, `integration`, `blocked`, `documentation`. Suggested milestones: Foundation/vertical slice (1–3), Integrated flows (4–6), Validation/delivery (7–8). These are planned; no issues, labels or milestones are claimed to exist.

## Pull-request acceptance

- Describe the concrete behavior and affected owner boundary.
- Link the package/spec; show actual commands and results. Mark unavailable checks plainly.
- For interface changes, update schemas, vectors, fixtures and migration notes together; name the affected reviewer.
- Security changes preserve no block permit, independent warning approval, exact action binding, fail-closed mandatory data, bounded inputs, and conservative uncertain-execution accounting.
- Keep credentials, local databases, owner CLI storage and authenticated URLs out of commits. Review staged changes and metadata before push.
- Demo artifacts must come from a real run and identify fixture/live sources and sandbox/testnet execution. Redact secrets before deliberately committing evidence.

## CI evolution

Planning setup: no runtime CI claim. A1: install with pinned pnpm and frozen lockfile, lint, typecheck and meaningful unit tests. B adds exact Cargo format/test/build checks once contracts exist. A2 onward: add actual sandbox integration and e2e runners as they become runnable. Keep funded testnet operations manual and separate from untrusted pull requests; do not expose chain/scorer credentials to them.

When the required commands are implemented, run the applicable full suite at integration gates and record actual results. A fresh clone must reproduce local fixtures, sandbox and attack logs using documented setup without needing private owner keys from another contributor.
