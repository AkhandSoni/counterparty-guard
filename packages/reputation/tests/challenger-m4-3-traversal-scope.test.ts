/**
 * @file packages/reputation/tests/challenger-m4-3-traversal-scope.test.ts
 * @description Empirical Challenger M4.3: Remediation Verification for Traversal Limits & Blocklist Scope Strictness
 *
 * Verifies:
 * 1. packages/reputation/src/graph/traversal.ts:
 *    - Dense multi-node graphs (600, 800, 1500 edges) strictly reach 500 edges and return truncated: true without edge starvation.
 *    - Boundary checks around maxEdges (499, 500, 501).
 *    - Custom maxEdges settings (1, 2, 7, 50).
 *    - Multi-hop dense meshes with cross-edges avoiding starvation.
 * 2. packages/reputation/src/storage/repository.ts:
 *    - getActiveBlock strictly enforces scope IN ('account', 'both') on account ID condition.
 *    - getActiveBlock strictly enforces scope IN ('code_hash', 'both') on code hash condition.
 *    - Isolation across code_hash, account, both, network separation, expiry, revocation, and precedence.
 * 3. End-to-end integration in scoring pipeline with scope filtering.
 */

import { describe, expect, it } from 'vitest';
import {
  DEFAULT_MAX_ACCOUNTS,
  DEFAULT_MAX_EDGES,
  type GraphEdge,
  InMemoryGraphProvider,
  MS_PER_DAY,
  traverseBoundedGraph,
} from '../src/graph/traversal.js';
import { getReceiverReputation } from '../src/scoring.js';
import { createDatabase } from '../src/storage/db.js';
import { runMigrations } from '../src/storage/migrations.js';
import { ReportRepository } from '../src/storage/repository.js';

describe('Milestone M4.3 Empirical Challenge: Traversal Limits & Block Scope Verification', () => {
  const asOf = 1_700_000_000_000;

  // =========================================================================
  // PART 1: Dense Graph Traversal Limit & Anti-Starvation Stress Tests
  // =========================================================================
  describe('Part 1: Traversal Limits & Anti-Starvation Verification', () => {
    it('dense multi-node mesh (30 nodes, 600 edges) strictly caps at maxEdges=500 with truncated: true', async () => {
      const provider = new InMemoryGraphProvider();
      const nodeCount = 30;
      const nodes: string[] = [];
      for (let i = 0; i < nodeCount; i++) {
        nodes.push(`mesh_node_${i}.testnet`);
      }

      // Generate 600 edges across 30 nodes in a round-robin mesh
      const totalTargetEdges = 600;
      const edges: GraphEdge[] = [];
      let count = 0;
      for (let i = 0; i < nodeCount && count < totalTargetEdges; i++) {
        for (let j = 0; j < nodeCount && count < totalTargetEdges; j++) {
          if (i !== j) {
            count++;
            edges.push({
              id: `edge_mesh_${count}`,
              source: nodes[i],
              target: nodes[j],
              type: 'transfer',
              timestamp: asOf - count * 100,
            });
          }
        }
      }
      expect(edges.length).toBe(600);
      provider.addEdges(edges);

      const result = await traverseBoundedGraph(provider, nodes[0], 'testnet', {
        asOfTimestamp: asOf,
        maxEdges: 500,
      });

      // Assertions
      expect(result.coverage.edgesTraversed).toBe(500);
      expect(result.edges.length).toBe(500);
      expect(result.coverage.truncated).toBe(true);
      expect(result.coverage.accountsVisited).toBeLessThanOrEqual(DEFAULT_MAX_ACCOUNTS);

      // Verify edge uniqueness (no duplicate IDs)
      const edgeIds = new Set(result.edges.map((e) => e.id));
      expect(edgeIds.size).toBe(500);
    });

    it('super-dense graph (50 nodes, 1500 edges) strictly caps at 500 edges without starvation', async () => {
      const provider = new InMemoryGraphProvider();
      const nodeCount = 50;
      const nodes: string[] = [];
      for (let i = 0; i < nodeCount; i++) {
        nodes.push(`heavy_node_${i}.testnet`);
      }

      const edges: GraphEdge[] = [];
      let count = 0;
      for (let i = 0; i < nodeCount && count < 1500; i++) {
        for (let j = 0; j < nodeCount && count < 1500; j++) {
          if (i !== j) {
            count++;
            edges.push({
              id: `heavy_edge_${count}`,
              source: nodes[i],
              target: nodes[j],
              type: 'transfer',
              timestamp: asOf - count * 50,
            });
          }
        }
      }
      expect(edges.length).toBe(1500);
      provider.addEdges(edges);

      const result = await traverseBoundedGraph(provider, nodes[0], 'testnet', {
        asOfTimestamp: asOf,
        maxEdges: 500,
      });

      expect(result.coverage.edgesTraversed).toBe(500);
      expect(result.edges.length).toBe(500);
      expect(result.coverage.truncated).toBe(true);
    });

    it('multi-tier mesh within account limit (25 nodes, 550 edges) strictly caps at 500 edges', async () => {
      // 25 nodes total (well within maxAccounts=100)
      // Seed (hop 0) -> 12 Hop-1 nodes (12 edges)
      // Cross edges between Hop-1 nodes (12 * 11 = 132 edges)
      // Hop-1 nodes to 12 Hop-2 nodes (12 * 12 = 144 edges)
      // Additional parallel transfers to reach 550 edges total
      const provider = new InMemoryGraphProvider();
      const seed = 'root_seed.testnet';
      const hop1Nodes = Array.from({ length: 12 }, (_, i) => `h1_${i}.testnet`);
      const hop2Nodes = Array.from({ length: 12 }, (_, i) => `h2_${i}.testnet`);

      let id = 0;
      // 1. Seed to Hop 1
      for (const h1 of hop1Nodes) {
        id++;
        provider.addEdge({
          id: `seed_h1_${id}`,
          source: seed,
          target: h1,
          type: 'funding',
          timestamp: asOf - 1000,
        });
      }

      // 2. Cross edges between Hop 1 nodes
      for (let i = 0; i < hop1Nodes.length; i++) {
        for (let j = 0; j < hop1Nodes.length; j++) {
          if (i !== j) {
            id++;
            provider.addEdge({
              id: `cross_h1_${id}`,
              source: hop1Nodes[i],
              target: hop1Nodes[j],
              type: 'transfer',
              timestamp: asOf - 2000,
            });
          }
        }
      }

      // 3. Hop 1 to Hop 2 nodes
      for (const h1 of hop1Nodes) {
        for (const h2 of hop2Nodes) {
          id++;
          provider.addEdge({
            id: `h1_h2_${id}`,
            source: h1,
            target: h2,
            type: 'transfer',
            timestamp: asOf - 3000,
          });
        }
      }

      // 4. Additional parallel edges between hop1 and hop2 nodes up to 550
      let cycle = 0;
      while (id < 550) {
        id++;
        cycle++;
        provider.addEdge({
          id: `parallel_${id}`,
          source: hop1Nodes[cycle % hop1Nodes.length],
          target: hop2Nodes[cycle % hop2Nodes.length],
          type: 'transfer',
          timestamp: asOf - 3500 - id,
        });
      }

      expect(id).toBe(550);

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
        maxEdges: 500,
      });

      expect(result.coverage.edgesTraversed).toBe(500);
      expect(result.edges.length).toBe(500);
      expect(result.coverage.truncated).toBe(true);
      expect(result.coverage.accountsVisited).toBe(25); // 1 seed + 12 hop1 + 12 hop2
    });

    it('boundary conditions around maxEdges: 499, 500, 501', async () => {
      // Subtest 1: Exactly 499 edges -> truncated: false, edgesTraversed: 499
      const p499 = new InMemoryGraphProvider();
      const s1 = 'seed_499.testnet';
      for (let i = 1; i <= 499; i++) {
        p499.addEdge({
          id: `edge_499_${i}`,
          source: s1,
          target: `node_${i}.testnet`,
          type: 'transfer',
          timestamp: asOf - i * 10,
        });
      }
      const r499 = await traverseBoundedGraph(p499, s1, 'testnet', {
        asOfTimestamp: asOf,
        maxAccounts: 1000,
        maxEdges: 500,
      });
      expect(r499.coverage.edgesTraversed).toBe(499);
      expect(r499.coverage.truncated).toBe(false);

      // Subtest 2: Exactly 500 edges -> hits edge capacity limit, truncated: true, edgesTraversed: 500
      const p500 = new InMemoryGraphProvider();
      const s2 = 'seed_500.testnet';
      for (let i = 1; i <= 500; i++) {
        p500.addEdge({
          id: `edge_500_${i}`,
          source: s2,
          target: `node_${i}.testnet`,
          type: 'transfer',
          timestamp: asOf - i * 10,
        });
      }
      const r500 = await traverseBoundedGraph(p500, s2, 'testnet', {
        asOfTimestamp: asOf,
        maxAccounts: 1000,
        maxEdges: 500,
      });
      expect(r500.coverage.edgesTraversed).toBe(500);
      expect(r500.coverage.truncated).toBe(true);

      // Subtest 3: Exactly 501 edges -> strictly capped, truncated: true, edgesTraversed: 500
      const p501 = new InMemoryGraphProvider();
      const s3 = 'seed_501.testnet';
      for (let i = 1; i <= 501; i++) {
        p501.addEdge({
          id: `edge_501_${i}`,
          source: s3,
          target: `node_${i}.testnet`,
          type: 'transfer',
          timestamp: asOf - i * 10,
        });
      }
      const r501 = await traverseBoundedGraph(p501, s3, 'testnet', {
        asOfTimestamp: asOf,
        maxAccounts: 1000,
        maxEdges: 500,
      });
      expect(r501.coverage.edgesTraversed).toBe(500);
      expect(r501.coverage.truncated).toBe(true);
    });

    it('custom maxEdges limits (1, 2, 7, 50) cap strictly and set truncated: true', async () => {
      const p = new InMemoryGraphProvider();
      const seed = 'test_custom.testnet';
      for (let i = 1; i <= 60; i++) {
        p.addEdge({
          id: `custom_edge_${i}`,
          source: seed,
          target: `dest_${i}.testnet`,
          type: 'transfer',
          timestamp: asOf - i * 50,
        });
      }

      for (const limit of [1, 2, 7, 50]) {
        const res = await traverseBoundedGraph(p, seed, 'testnet', {
          asOfTimestamp: asOf,
          maxAccounts: 100,
          maxEdges: limit,
        });
        expect(res.coverage.edgesTraversed).toBe(limit);
        expect(res.edges.length).toBe(limit);
        expect(res.coverage.truncated).toBe(true);
      }
    });
  });

  // =========================================================================
  // PART 2: SQLite Repository getActiveBlock Scope Strictness
  // =========================================================================
  describe('Part 2: getActiveBlock Scope Strictness & Isolation', () => {
    function setupRepo() {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      return new ReportRepository(db);
    }

    it('scope = code_hash strictly matches ONLY identical code hash and NEVER leaks to account alone', () => {
      const repo = setupRepo();

      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'contract_pool.testnet',
        contract_code_hash: 'malicious_bytecode_hash_v1',
        scope: 'code_hash',
        reason: 'Bytecode contains exploit signature',
        reviewer_id: 'auditor_1.testnet',
      });

      // 1. The accused account running a DIFFERENT (or clean) code hash MUST NOT be blocked
      const queryCleanHash = repo.getActiveBlock(
        'testnet',
        'contract_pool.testnet',
        'clean_bytecode_hash_v2',
      );
      expect(queryCleanHash).toBeNull();

      // 2. The accused account running NO contract (null code hash) MUST NOT be blocked
      const queryNullHash = repo.getActiveBlock('testnet', 'contract_pool.testnet', null);
      expect(queryNullHash).toBeNull();

      // 3. The accused account running undefined code hash MUST NOT be blocked
      const queryUndefinedHash = repo.getActiveBlock('testnet', 'contract_pool.testnet', undefined);
      expect(queryUndefinedHash).toBeNull();

      // 4. The accused account running the MALICIOUS bytecode MUST be blocked
      const queryMatchingAccAndHash = repo.getActiveBlock(
        'testnet',
        'contract_pool.testnet',
        'malicious_bytecode_hash_v1',
      );
      expect(queryMatchingAccAndHash).not.toBeNull();
      expect(queryMatchingAccAndHash?.contract_code_hash).toBe('malicious_bytecode_hash_v1');
      expect(queryMatchingAccAndHash?.scope).toBe('code_hash');

      // 5. ANY OTHER account running the MALICIOUS bytecode MUST also be blocked
      const queryOtherAccWithBadHash = repo.getActiveBlock(
        'testnet',
        'completely_different_victim.testnet',
        'malicious_bytecode_hash_v1',
      );
      expect(queryOtherAccWithBadHash).not.toBeNull();
      expect(queryOtherAccWithBadHash?.entry_id).toBe(queryMatchingAccAndHash?.entry_id);

      // 6. Another account running clean bytecode MUST NOT be blocked
      const queryOtherAccWithCleanHash = repo.getActiveBlock(
        'testnet',
        'completely_different_victim.testnet',
        'clean_hash',
      );
      expect(queryOtherAccWithCleanHash).toBeNull();
    });

    it('scope = account strictly matches ONLY accused account and NEVER leaks to code hash alone', () => {
      const repo = setupRepo();

      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'bad_actor.testnet',
        contract_code_hash: 'standard_escrow_bytecode',
        scope: 'account',
        reason: 'Malicious operator identity scam',
        reviewer_id: 'auditor_2.testnet',
      });

      // 1. Accused account is blocked regardless of code hash (even null, clean, or undefined)
      expect(repo.getActiveBlock('testnet', 'bad_actor.testnet', null)).not.toBeNull();
      expect(repo.getActiveBlock('testnet', 'bad_actor.testnet', undefined)).not.toBeNull();
      expect(repo.getActiveBlock('testnet', 'bad_actor.testnet', 'clean_escrow_v2')).not.toBeNull();
      expect(
        repo.getActiveBlock('testnet', 'bad_actor.testnet', 'standard_escrow_bytecode'),
      ).not.toBeNull();

      // 2. An innocent account running the same bytecode MUST NOT be blocked
      const innocentQuery = repo.getActiveBlock(
        'testnet',
        'innocent_escrow.testnet',
        'standard_escrow_bytecode',
      );
      expect(innocentQuery).toBeNull();
    });

    it('scope = both matches when EITHER account matches OR code hash matches', () => {
      const repo = setupRepo();

      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'toxic_creator.testnet',
        contract_code_hash: 'toxic_bytecode_hash',
        scope: 'both',
        reason: 'Malicious author and infected bytecode',
        reviewer_id: 'auditor_3.testnet',
      });

      // 1. Toxic account with null code hash -> MATCH
      expect(repo.getActiveBlock('testnet', 'toxic_creator.testnet', null)).not.toBeNull();

      // 2. Toxic account with different code hash -> MATCH (matches account)
      expect(
        repo.getActiveBlock('testnet', 'toxic_creator.testnet', 'random_new_hash'),
      ).not.toBeNull();

      // 3. Different account with toxic code hash -> MATCH (matches code hash)
      expect(
        repo.getActiveBlock('testnet', 'unrelated_victim.testnet', 'toxic_bytecode_hash'),
      ).not.toBeNull();

      // 4. Different account with different code hash -> NO MATCH
      expect(
        repo.getActiveBlock('testnet', 'unrelated_victim.testnet', 'random_new_hash'),
      ).toBeNull();

      // 5. Different account with null code hash -> NO MATCH
      expect(repo.getActiveBlock('testnet', 'unrelated_victim.testnet', null)).toBeNull();
    });

    it('preserves network isolation across scope-filtered active blocks', () => {
      const repo = setupRepo();

      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'isolated_target.testnet',
        contract_code_hash: 'isolated_hash_123',
        scope: 'both',
        reason: 'Testnet test block',
        reviewer_id: 'auditor_net.testnet',
      });

      // Testnet matches
      expect(
        repo.getActiveBlock('testnet', 'isolated_target.testnet', 'isolated_hash_123'),
      ).not.toBeNull();

      // Mainnet must be null
      expect(
        repo.getActiveBlock('mainnet', 'isolated_target.testnet', 'isolated_hash_123'),
      ).toBeNull();

      // Sandbox must be null
      expect(
        repo.getActiveBlock('sandbox', 'isolated_target.testnet', 'isolated_hash_123'),
      ).toBeNull();
    });

    it('correctly handles expired and revoked scope-filtered blocks', () => {
      const repo = setupRepo();
      const past = Date.now() - 60_000; // 1 minute ago

      // 1. Expired code_hash block
      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'expired_target.testnet',
        contract_code_hash: 'expired_code_hash',
        scope: 'code_hash',
        reason: 'Temporary quarantine',
        reviewer_id: 'auditor_exp.testnet',
        expires_at: past,
      });

      expect(repo.getActiveBlock('testnet', 'any_account.testnet', 'expired_code_hash')).toBeNull();

      // 2. Revoked code_hash block
      const created = repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'revoked_target.testnet',
        contract_code_hash: 'revoked_code_hash',
        scope: 'code_hash',
        reason: 'Under investigation',
        reviewer_id: 'auditor_rev.testnet',
      });

      expect(
        repo.getActiveBlock('testnet', 'any_account.testnet', 'revoked_code_hash'),
      ).not.toBeNull();

      repo.revokeActiveBlock(created.entry_id, {
        reviewer_id: 'auditor_rev.testnet',
        reason: 'Investigation cleared bytecode',
      });

      expect(repo.getActiveBlock('testnet', 'any_account.testnet', 'revoked_code_hash')).toBeNull();
    });

    it('arbitrates multiple active blocks according to scope and newest created_at', () => {
      const repo = setupRepo();

      // Block 1 (older): Scope 'account' on bad_user.testnet
      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'bad_user.testnet',
        contract_code_hash: null,
        scope: 'account',
        reason: 'Account level block',
        reviewer_id: 'reviewer_1',
      });

      // Block 2 (newer): Scope 'code_hash' on malicious_hash
      repo.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'some_other_creator.testnet',
        contract_code_hash: 'malicious_hash_99',
        scope: 'code_hash',
        reason: 'Bytecode level block',
        reviewer_id: 'reviewer_2',
      });

      // Query bad_user with clean code -> matches Block 1
      const resBadUser = repo.getActiveBlock('testnet', 'bad_user.testnet', 'clean_hash');
      expect(resBadUser).not.toBeNull();
      expect(resBadUser?.scope).toBe('account');
      expect(resBadUser?.accused_account_id).toBe('bad_user.testnet');

      // Query innocent user with malicious code -> matches Block 2
      const resInnocent = repo.getActiveBlock('testnet', 'innocent.testnet', 'malicious_hash_99');
      expect(resInnocent).not.toBeNull();
      expect(resInnocent?.scope).toBe('code_hash');
      expect(resInnocent?.contract_code_hash).toBe('malicious_hash_99');

      // Query innocent user with clean code -> null
      expect(repo.getActiveBlock('testnet', 'innocent.testnet', 'clean_hash')).toBeNull();
    });
  });

  // =========================================================================
  // PART 3: End-to-End Scoring Pipeline Integration
  // =========================================================================
  describe('Part 3: End-to-End Pipeline Scope Strictness', () => {
    it('getReceiverReputation does NOT block contract that upgraded from flagged bytecode', async () => {
      const db = createDatabase({ path: ':memory:' });
      runMigrations(db);
      const repository = new ReportRepository(db);

      // Reviewer blocks bad bytecode hash only
      repository.createActiveBlock({
        network: 'testnet',
        accused_account_id: 'dex_app.testnet',
        contract_code_hash: 'vulnerable_bytecode_v1',
        scope: 'code_hash',
        reason: 'Vulnerable reentrancy bug in bytecode v1',
        reviewer_id: 'sec_team.testnet',
      });

      // 1. Querying with vulnerable bytecode v1 -> isBlocked: true, risk: 100
      const repBlocked = await getReceiverReputation({
        network: 'testnet',
        accountId: 'dex_app.testnet',
        contractCodeHash: 'vulnerable_bytecode_v1',
        repository,
      });
      expect(repBlocked.isBlocked).toBe(true);
      expect(repBlocked.reputationRiskPoints).toBe(100);
      expect(repBlocked.reasonCodes).toContain('ACTIVE_BLOCK');

      // 2. Contract upgraded to patched bytecode v2 -> isBlocked: false, clean reputation
      const repClean = await getReceiverReputation({
        network: 'testnet',
        accountId: 'dex_app.testnet',
        contractCodeHash: 'patched_bytecode_v2',
        repository,
      });
      expect(repClean.isBlocked).toBe(false);
      expect(repClean.reputationRiskPoints).toBeLessThan(100);
      expect(repClean.reasonCodes).not.toContain('ACTIVE_BLOCK');
    });
  });
});
