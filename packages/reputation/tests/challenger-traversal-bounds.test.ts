/**
 * @file packages/reputation/tests/challenger-traversal-bounds.test.ts
 * @description Empirical Challenger Stress Harness for Bounded Graph Traversal (Milestone M4)
 *
 * Verifies traversal bounds:
 * 1. Node boundary: 100, 101, 200 nodes; strictly bounds to 100 visited accounts, truncated: true.
 * 2. Edge boundary: 500, 501, 1000 edges; strictly bounds to 500 traversed edges, truncated: true.
 * 3. Hop boundary: 4-hop chain; hop 3 and 4 nodes are NEVER visited.
 * 4. Rolling window: edges outside 7-day window; expired/future edges discarded, truncated: false.
 * 5. Topologies: disconnected nodes, self-loops, multi-edges, cycles, case normalization, and async provider.
 */

import { describe, expect, it } from 'vitest';
import {
  DEFAULT_WINDOW_DAYS,
  type GraphDataProvider,
  type GraphEdge,
  InMemoryGraphProvider,
  MS_PER_DAY,
  type NetworkType,
  traverseBoundedGraph,
} from '../src/graph/traversal.js';

describe('Milestone M4 Empirical Challenge: Traversal & Bounds Stress Testing', () => {
  const asOf = 1_700_000_000_000;
  const oneDayMs = MS_PER_DAY; // 86_400_000 ms

  // =========================================================================
  // 1. Node Boundary Stress Tests (100, 101, 200 nodes, multi-tier trees)
  // =========================================================================
  describe('1. Node Boundary Stress Testing', () => {
    it('accurately admits exactly 100 nodes without truncation (boundary == 100)', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'hub_100.testnet';

      // 1 seed + 99 leaves = 100 accounts total
      const edges: GraphEdge[] = [];
      for (let i = 1; i <= 99; i++) {
        edges.push({
          id: `tx_node_${i}`,
          source: seed,
          target: `leaf_${i}.testnet`,
          type: 'transfer',
          timestamp: asOf - 1000 * i,
        });
      }
      provider.addEdges(edges);

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
        maxAccounts: 100,
      });

      expect(result.coverage.accountsVisited).toBe(100);
      expect(result.nodes.size).toBe(100);
      expect(result.coverage.truncated).toBe(false);
      expect(result.coverage.edgesTraversed).toBe(99);
      expect(result.nodes.has(seed)).toBe(true);
      expect(result.nodes.get(seed)?.hop).toBe(0);
      expect(result.nodes.has('leaf_99.testnet')).toBe(true);
      expect(result.nodes.get('leaf_99.testnet')?.hop).toBe(1);
    });

    it('strictly caps visited accounts at 100 and sets truncated: true for 101 nodes', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'hub_101.testnet';

      // 1 seed + 100 leaves = 101 accounts total
      const edges: GraphEdge[] = [];
      for (let i = 1; i <= 100; i++) {
        edges.push({
          id: `tx_node_101_${i}`,
          source: seed,
          target: `leaf_101_${i}.testnet`,
          type: 'transfer',
          timestamp: asOf - 1000 * i,
        });
      }
      provider.addEdges(edges);

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
        maxAccounts: 100,
      });

      // Strict limit: exactly 100 accounts visited
      expect(result.coverage.accountsVisited).toBe(100);
      expect(result.nodes.size).toBe(100);
      expect(result.coverage.truncated).toBe(true);
      // The 100th leaf candidate must be rejected
      expect(result.nodes.has('leaf_101_100.testnet')).toBe(false);
      // Traversal did not crash and retained seed
      expect(result.nodes.has(seed)).toBe(true);
    });

    it('strictly caps visited accounts at 100 and sets truncated: true for 200 nodes', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'hub_200.testnet';

      // 1 seed + 199 leaves = 200 accounts total
      const edges: GraphEdge[] = [];
      for (let i = 1; i <= 199; i++) {
        edges.push({
          id: `tx_node_200_${i}`,
          source: seed,
          target: `leaf_200_${i}.testnet`,
          type: 'transfer',
          timestamp: asOf - 500 * i,
        });
      }
      provider.addEdges(edges);

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
        maxAccounts: 100,
      });

      expect(result.coverage.accountsVisited).toBe(100);
      expect(result.nodes.size).toBe(100);
      expect(result.coverage.truncated).toBe(true);
      expect(result.coverage.edgesTraversed).toBe(99);
    });

    it('enforces node limit across a 2-hop hierarchy tree (1 seed + 10 hop-1 + 150 hop-2 nodes)', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'root_hierarchy.testnet';

      // 1 seed connected to 10 tier-1 accounts
      for (let i = 1; i <= 10; i++) {
        const tier1Id = `tier1_${i}.testnet`;
        provider.addEdge({
          id: `tx_root_tier1_${i}`,
          source: seed,
          target: tier1Id,
          type: 'funding',
          timestamp: asOf - 1000 * i,
        });

        // Each tier-1 account connected to 15 tier-2 accounts (150 tier-2 accounts total)
        for (let j = 1; j <= 15; j++) {
          provider.addEdge({
            id: `tx_tier1_${i}_tier2_${j}`,
            source: tier1Id,
            target: `tier2_${i}_${j}.testnet`,
            type: 'transfer',
            timestamp: asOf - 2000 * j,
          });
        }
      }

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
        maxAccounts: 100,
        maxHops: 2,
      });

      expect(result.coverage.accountsVisited).toBe(100);
      expect(result.nodes.size).toBe(100);
      expect(result.coverage.truncated).toBe(true);

      // Seed is hop 0
      expect(result.nodes.get(seed)?.hop).toBe(0);

      // All 10 tier-1 accounts must be present at hop 1
      for (let i = 1; i <= 10; i++) {
        expect(result.nodes.has(`tier1_${i}.testnet`)).toBe(true);
        expect(result.nodes.get(`tier1_${i}.testnet`)?.hop).toBe(1);
      }

      // Exactly 89 tier-2 accounts admitted (1 seed + 10 tier-1 + 89 tier-2 = 100 accounts)
      let tier2Count = 0;
      for (const node of result.nodes.values()) {
        if (node.hop === 2) {
          tier2Count++;
        }
      }
      expect(tier2Count).toBe(89);
    });

    it('respects custom maxAccounts parameter (e.g. maxAccounts: 10, maxAccounts: 1)', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'custom_node_bound.testnet';

      for (let i = 1; i <= 20; i++) {
        provider.addEdge({
          id: `tx_custom_${i}`,
          source: seed,
          target: `custom_leaf_${i}.testnet`,
          type: 'transfer',
          timestamp: asOf - 1000 * i,
        });
      }

      // Test maxAccounts: 10
      const res10 = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
        maxAccounts: 10,
      });
      expect(res10.coverage.accountsVisited).toBe(10);
      expect(res10.coverage.truncated).toBe(true);

      // Test maxAccounts: 1 (only seed allowed, 0 neighbors admitted)
      const res1 = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
        maxAccounts: 1,
      });
      expect(res1.coverage.accountsVisited).toBe(1);
      expect(res1.coverage.edgesTraversed).toBe(0);
      expect(res1.coverage.truncated).toBe(true);
    });
  });

  // =========================================================================
  // 2. Edge Boundary Stress Tests (500, 501, 1000 edges, dense mesh)
  // =========================================================================
  describe('2. Edge Boundary Stress Testing', () => {
    it('handles exactly 500 edges without exceeding limit', async () => {
      const provider = new InMemoryGraphProvider();
      const accA = 'peer_500_a.testnet';
      const accB = 'peer_500_b.testnet';

      const edges: GraphEdge[] = [];
      for (let i = 1; i <= 500; i++) {
        edges.push({
          id: `tx_500_${i}`,
          source: accA,
          target: accB,
          type: 'transfer',
          timestamp: asOf - i * 100,
        });
      }
      provider.addEdges(edges);

      const result = await traverseBoundedGraph(provider, accA, 'testnet', {
        asOfTimestamp: asOf,
        maxEdges: 500,
      });

      expect(result.coverage.edgesTraversed).toBe(500);
      expect(result.edges.length).toBe(500);
      expect(result.coverage.accountsVisited).toBe(2);
      // Because queue had accB pending expansion, hitting maxEdges halts and sets truncated
      expect(result.coverage.truncated).toBe(true);
    });

    it('strictly caps traversed edges at 500 and sets truncated: true for 501 edges', async () => {
      const provider = new InMemoryGraphProvider();
      const accA = 'peer_501_a.testnet';
      const accB = 'peer_501_b.testnet';

      const edges: GraphEdge[] = [];
      for (let i = 1; i <= 501; i++) {
        edges.push({
          id: `tx_501_${i}`,
          source: accA,
          target: accB,
          type: 'transfer',
          timestamp: asOf - i * 100,
        });
      }
      provider.addEdges(edges);

      const result = await traverseBoundedGraph(provider, accA, 'testnet', {
        asOfTimestamp: asOf,
        maxEdges: 500,
      });

      expect(result.coverage.edgesTraversed).toBe(500);
      expect(result.edges.length).toBe(500);
      expect(result.coverage.truncated).toBe(true);
      expect(result.coverage.accountsVisited).toBe(2);
      // tx_501_501 must NOT be in edges
      expect(result.edges.some((e) => e.id === 'tx_501_501')).toBe(false);
    });

    it('strictly caps traversed edges at 500 and sets truncated: true for 1000 edges', async () => {
      const provider = new InMemoryGraphProvider();
      const accA = 'peer_1000_a.testnet';
      const accB = 'peer_1000_b.testnet';

      const edges: GraphEdge[] = [];
      for (let i = 1; i <= 1000; i++) {
        edges.push({
          id: `tx_1000_${i}`,
          source: accA,
          target: accB,
          type: 'transfer',
          timestamp: asOf - i * 50,
        });
      }
      provider.addEdges(edges);

      const result = await traverseBoundedGraph(provider, accA, 'testnet', {
        asOfTimestamp: asOf,
        maxEdges: 500,
      });

      expect(result.coverage.edgesTraversed).toBe(500);
      expect(result.edges.length).toBe(500);
      expect(result.coverage.truncated).toBe(true);
    });

    it('REMEDIATED DEFECT: accurately caps K6 graph at maxEdges=12 and sets truncated: true', async () => {
      const provider = new InMemoryGraphProvider();
      const nodes = ['n0', 'n1', 'n2', 'n3', 'n4', 'n5'];

      let id = 0;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          id++;
          provider.addEdge({
            id: `edge_${id}`,
            source: nodes[i],
            target: nodes[j],
            type: 'transfer',
            timestamp: asOf - 1000 * id,
          });
        }
      }

      const result = await traverseBoundedGraph(provider, 'n0', 'testnet', {
        asOfTimestamp: asOf,
        maxEdges: 12,
      });

      // Remediated behavior:
      // K6 graph has 15 edges total in 2-hop neighborhood. maxEdges is 12.
      expect(result.coverage.edgesTraversed).toBe(12);
      expect(result.coverage.truncated).toBe(true);
    });

    it('REMEDIATED DEFECT: dense mesh (30 nodes, 600 edges) strictly traverses exactly maxEdges=500 and sets truncated: true', async () => {
      const provider = new InMemoryGraphProvider();
      const nodesList: string[] = [];
      for (let i = 0; i < 30; i++) {
        nodesList.push(`mesh_node_${i}.testnet`);
      }

      const edges: GraphEdge[] = [];
      let edgeCount = 0;
      for (let i = 0; i < 30 && edgeCount < 600; i++) {
        for (let j = 0; j < 30 && edgeCount < 600; j++) {
          if (i !== j) {
            edgeCount++;
            edges.push({
              id: `tx_mesh_${edgeCount}`,
              source: nodesList[i],
              target: nodesList[j],
              type: 'transfer',
              timestamp: asOf - edgeCount * 10,
            });
          }
        }
      }
      provider.addEdges(edges);

      const result = await traverseBoundedGraph(provider, nodesList[0], 'testnet', {
        asOfTimestamp: asOf,
        maxEdges: 500,
        maxAccounts: 100,
      });

      // Remediated behavior:
      // Graph has 600 edges. maxEdges is 500.
      expect(result.coverage.edgesTraversed).toBe(500);
      expect(result.coverage.truncated).toBe(true);
    });

    it('allows edges between already visited nodes without exceeding maxEdges', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'core_seed.testnet';
      const nodeA = 'core_a.testnet';
      const nodeB = 'core_b.testnet';

      provider.addEdge({
        id: 'tx_seed_a',
        source: seed,
        target: nodeA,
        type: 'transfer',
        timestamp: asOf - 1000,
      });
      provider.addEdge({
        id: 'tx_seed_b',
        source: seed,
        target: nodeB,
        type: 'transfer',
        timestamp: asOf - 2000,
      });

      // Add 10 parallel edges between nodeA and nodeB
      for (let i = 1; i <= 10; i++) {
        provider.addEdge({
          id: `tx_ab_cross_${i}`,
          source: nodeA,
          target: nodeB,
          type: 'transfer',
          timestamp: asOf - 3000 - i * 10,
        });
      }

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
        maxEdges: 500,
      });

      expect(result.coverage.accountsVisited).toBe(3);
      expect(result.coverage.edgesTraversed).toBe(12); // 2 from seed + 10 cross edges
      expect(result.coverage.truncated).toBe(false);
    });

    it('respects custom maxEdges parameter (e.g. maxEdges: 5)', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'custom_edge_seed.testnet';

      for (let i = 1; i <= 20; i++) {
        provider.addEdge({
          id: `tx_limit_${i}`,
          source: seed,
          target: `dest_${i}.testnet`,
          type: 'transfer',
          timestamp: asOf - 1000 * i,
        });
      }

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
        maxEdges: 5,
      });

      expect(result.coverage.edgesTraversed).toBe(5);
      expect(result.edges.length).toBe(5);
      expect(result.coverage.truncated).toBe(true);
    });
  });

  // =========================================================================
  // 3. Hop Boundary Stress Tests (4-hop chain, reverse chain, shortest hop)
  // =========================================================================
  describe('3. Hop Boundary Stress Testing', () => {
    it('strictly confines exploration to 2 hops on a 4-hop forward chain', async () => {
      const provider = new InMemoryGraphProvider();

      // 4-hop chain: Hop 0 (A) -> Hop 1 (B) -> Hop 2 (C) -> Hop 3 (D) -> Hop 4 (E) -> Hop 5 (F)
      provider.addEdges([
        {
          id: 'tx_hop_ab',
          source: 'chain_a.testnet',
          target: 'chain_b.testnet',
          type: 'funding',
          timestamp: asOf - oneDayMs,
        },
        {
          id: 'tx_hop_bc',
          source: 'chain_b.testnet',
          target: 'chain_c.testnet',
          type: 'funding',
          timestamp: asOf - oneDayMs,
        },
        {
          id: 'tx_hop_cd',
          source: 'chain_c.testnet',
          target: 'chain_d.testnet',
          type: 'funding',
          timestamp: asOf - oneDayMs,
        },
        {
          id: 'tx_hop_de',
          source: 'chain_d.testnet',
          target: 'chain_e.testnet',
          type: 'funding',
          timestamp: asOf - oneDayMs,
        },
        {
          id: 'tx_hop_ef',
          source: 'chain_e.testnet',
          target: 'chain_f.testnet',
          type: 'funding',
          timestamp: asOf - oneDayMs,
        },
      ]);

      const result = await traverseBoundedGraph(provider, 'chain_a.testnet', 'testnet', {
        asOfTimestamp: asOf,
        maxHops: 2,
      });

      // Hop 0, 1, 2 must be present
      expect(result.nodes.has('chain_a.testnet')).toBe(true);
      expect(result.nodes.get('chain_a.testnet')?.hop).toBe(0);

      expect(result.nodes.has('chain_b.testnet')).toBe(true);
      expect(result.nodes.get('chain_b.testnet')?.hop).toBe(1);

      expect(result.nodes.has('chain_c.testnet')).toBe(true);
      expect(result.nodes.get('chain_c.testnet')?.hop).toBe(2);

      // Hop 3 (D), Hop 4 (E), Hop 5 (F) must NEVER be visited
      expect(result.nodes.has('chain_d.testnet')).toBe(false);
      expect(result.nodes.has('chain_e.testnet')).toBe(false);
      expect(result.nodes.has('chain_f.testnet')).toBe(false);

      expect(result.coverage.accountsVisited).toBe(3);
      expect(result.coverage.edgesTraversed).toBe(2);
      expect(result.coverage.truncated).toBe(false);

      // Adjacency for hop 2 node (C) must NOT contain edge to D
      const cAdj = result.adjacency.get('chain_c.testnet');
      expect(cAdj).toBeDefined();
      expect(cAdj?.outEdges.some((e) => e.target === 'chain_d.testnet')).toBe(false);
    });

    it('strictly confines exploration to 2 hops on a reverse incoming chain (E -> D -> C -> B -> A)', async () => {
      const provider = new InMemoryGraphProvider();

      provider.addEdges([
        {
          id: 'tx_rev_ba',
          source: 'rev_b.testnet',
          target: 'rev_a.testnet',
          type: 'funding',
          timestamp: asOf - oneDayMs,
        },
        {
          id: 'tx_rev_cb',
          source: 'rev_c.testnet',
          target: 'rev_b.testnet',
          type: 'funding',
          timestamp: asOf - oneDayMs,
        },
        {
          id: 'tx_rev_dc',
          source: 'rev_d.testnet',
          target: 'rev_c.testnet',
          type: 'funding',
          timestamp: asOf - oneDayMs,
        },
        {
          id: 'tx_rev_ed',
          source: 'rev_e.testnet',
          target: 'rev_d.testnet',
          type: 'funding',
          timestamp: asOf - oneDayMs,
        },
      ]);

      const result = await traverseBoundedGraph(provider, 'rev_a.testnet', 'testnet', {
        asOfTimestamp: asOf,
        maxHops: 2,
      });

      expect(result.nodes.has('rev_a.testnet')).toBe(true);
      expect(result.nodes.get('rev_a.testnet')?.hop).toBe(0);

      expect(result.nodes.has('rev_b.testnet')).toBe(true);
      expect(result.nodes.get('rev_b.testnet')?.hop).toBe(1);

      expect(result.nodes.has('rev_c.testnet')).toBe(true);
      expect(result.nodes.get('rev_c.testnet')?.hop).toBe(2);

      // Upstream funders D and E at hop 3 and 4 must NOT be visited
      expect(result.nodes.has('rev_d.testnet')).toBe(false);
      expect(result.nodes.has('rev_e.testnet')).toBe(false);
    });

    it('maintains shortest-hop assignment when multi-path exists (BFS optimality)', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'seed_opt.testnet';
      const target = 'target_opt.testnet';
      const intermediate = 'inter_opt.testnet';

      // Path 1: Seed -> Intermediate -> Target (Target would be hop 2)
      // Path 2: Seed -> Target directly (Target is hop 1)
      provider.addEdges([
        {
          id: 'tx_direct',
          source: seed,
          target: target,
          type: 'transfer',
          timestamp: asOf - 1000,
        },
        {
          id: 'tx_path1_a',
          source: seed,
          target: intermediate,
          type: 'transfer',
          timestamp: asOf - 2000,
        },
        {
          id: 'tx_path1_b',
          source: intermediate,
          target: target,
          type: 'transfer',
          timestamp: asOf - 3000,
        },
      ]);

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
        maxHops: 2,
      });

      expect(result.nodes.get(target)?.hop).toBe(1);
      expect(result.nodes.get(intermediate)?.hop).toBe(1);
      expect(result.coverage.accountsVisited).toBe(3);
      expect(result.coverage.edgesTraversed).toBe(3);
    });

    it('respects custom maxHops parameter (maxHops: 1, maxHops: 3)', async () => {
      const provider = new InMemoryGraphProvider();

      // Chain 1 -> 2 -> 3 -> 4
      provider.addEdges([
        {
          id: 'tx_c1',
          source: 'n1.testnet',
          target: 'n2.testnet',
          type: 'transfer',
          timestamp: asOf - 1000,
        },
        {
          id: 'tx_c2',
          source: 'n2.testnet',
          target: 'n3.testnet',
          type: 'transfer',
          timestamp: asOf - 2000,
        },
        {
          id: 'tx_c3',
          source: 'n3.testnet',
          target: 'n4.testnet',
          type: 'transfer',
          timestamp: asOf - 3000,
        },
      ]);

      // maxHops: 1
      const resH1 = await traverseBoundedGraph(provider, 'n1.testnet', 'testnet', {
        asOfTimestamp: asOf,
        maxHops: 1,
      });
      expect(resH1.nodes.has('n1.testnet')).toBe(true);
      expect(resH1.nodes.has('n2.testnet')).toBe(true);
      expect(resH1.nodes.has('n3.testnet')).toBe(false);
      expect(resH1.coverage.accountsVisited).toBe(2);

      // maxHops: 3
      const resH3 = await traverseBoundedGraph(provider, 'n1.testnet', 'testnet', {
        asOfTimestamp: asOf,
        maxHops: 3,
      });
      expect(resH3.nodes.has('n4.testnet')).toBe(true);
      expect(resH3.nodes.get('n4.testnet')?.hop).toBe(3);
      expect(resH3.coverage.accountsVisited).toBe(4);
    });
  });

  // =========================================================================
  // 4. Rolling Window Temporal Stress Tests (7 days, future/past discard)
  // =========================================================================
  describe('4. Rolling Window Temporal Stress Testing', () => {
    it('precisely evaluates exact window boundaries [asOf - 7 days, asOf]', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'temporal_seed.testnet';
      const windowDays = 7;
      const cutoff = asOf - windowDays * oneDayMs;

      provider.addEdges([
        // Exact lower boundary (timestamp === cutoff) -> MUST BE INCLUDED
        {
          id: 'tx_exact_cutoff',
          source: seed,
          target: 'exact_cutoff.testnet',
          type: 'transfer',
          timestamp: cutoff,
        },
        // 1ms before cutoff (expired by 1ms) -> MUST BE DISCARDED
        {
          id: 'tx_expired_1ms',
          source: seed,
          target: 'expired_1ms.testnet',
          type: 'transfer',
          timestamp: cutoff - 1,
        },
        // Middle of window (3 days ago) -> MUST BE INCLUDED
        {
          id: 'tx_mid_window',
          source: seed,
          target: 'mid_window.testnet',
          type: 'transfer',
          timestamp: asOf - 3 * oneDayMs,
        },
        // Exact upper boundary (timestamp === asOf) -> MUST BE INCLUDED
        {
          id: 'tx_exact_now',
          source: seed,
          target: 'exact_now.testnet',
          type: 'transfer',
          timestamp: asOf,
        },
        // 1ms in the future (timestamp === asOf + 1) -> MUST BE DISCARDED
        {
          id: 'tx_future_1ms',
          source: seed,
          target: 'future_1ms.testnet',
          type: 'transfer',
          timestamp: asOf + 1,
        },
        // Far past (30 days ago) -> MUST BE DISCARDED
        {
          id: 'tx_ancient',
          source: seed,
          target: 'ancient.testnet',
          type: 'transfer',
          timestamp: asOf - 30 * oneDayMs,
        },
      ]);

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
        windowDays: 7,
      });

      // Valid accounts in window
      expect(result.nodes.has('exact_cutoff.testnet')).toBe(true);
      expect(result.nodes.has('mid_window.testnet')).toBe(true);
      expect(result.nodes.has('exact_now.testnet')).toBe(true);

      // Discarded accounts outside window
      expect(result.nodes.has('expired_1ms.testnet')).toBe(false);
      expect(result.nodes.has('future_1ms.testnet')).toBe(false);
      expect(result.nodes.has('ancient.testnet')).toBe(false);

      // Coverage metrics
      expect(result.coverage.accountsVisited).toBe(4); // seed + 3 valid
      expect(result.coverage.edgesTraversed).toBe(3);
      // Filtering out-of-window edges does NOT set truncated: true
      expect(result.coverage.truncated).toBe(false);
      expect(result.coverage.windowDays).toBe(7);
    });

    it('returns truncated: false when all edges are expired (empty active neighborhood)', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'stale_seed.testnet';

      for (let i = 1; i <= 10; i++) {
        provider.addEdge({
          id: `tx_stale_${i}`,
          source: seed,
          target: `stale_dest_${i}.testnet`,
          type: 'transfer',
          timestamp: asOf - (8 + i) * oneDayMs, // all > 8 days old
        });
      }

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
        windowDays: 7,
      });

      expect(result.coverage.accountsVisited).toBe(1); // seed only
      expect(result.coverage.edgesTraversed).toBe(0);
      expect(result.coverage.truncated).toBe(false);
    });

    it('respects custom windowDays parameter (windowDays: 1, windowDays: 14)', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'window_param_seed.testnet';

      provider.addEdges([
        {
          id: 'tx_half_day',
          source: seed,
          target: 'half_day.testnet',
          type: 'transfer',
          timestamp: asOf - 12 * 60 * 60 * 1000, // 12 hours ago
        },
        {
          id: 'tx_three_days',
          source: seed,
          target: 'three_days.testnet',
          type: 'transfer',
          timestamp: asOf - 3 * oneDayMs, // 3 days ago
        },
        {
          id: 'tx_ten_days',
          source: seed,
          target: 'ten_days.testnet',
          type: 'transfer',
          timestamp: asOf - 10 * oneDayMs, // 10 days ago
        },
      ]);

      // 1-day window
      const res1 = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
        windowDays: 1,
      });
      expect(res1.nodes.has('half_day.testnet')).toBe(true);
      expect(res1.nodes.has('three_days.testnet')).toBe(false);
      expect(res1.coverage.edgesTraversed).toBe(1);

      // 14-day window
      const res14 = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
        windowDays: 14,
      });
      expect(res14.nodes.has('half_day.testnet')).toBe(true);
      expect(res14.nodes.has('three_days.testnet')).toBe(true);
      expect(res14.nodes.has('ten_days.testnet')).toBe(true);
      expect(res14.coverage.edgesTraversed).toBe(3);
    });
  });

  // =========================================================================
  // 5. Topologies: Disconnected Nodes, Self-Loops, Multi-Edges & Cycles
  // =========================================================================
  describe('5. Complex Topologies: Disconnected, Self-Loops, Multi-Edges & Cycles', () => {
    it('completely ignores disconnected island components in the provider', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'connected_seed.testnet';
      const neighbor = 'connected_neighbor.testnet';

      // Component 1 (seed component)
      provider.addEdge({
        id: 'tx_connected',
        source: seed,
        target: neighbor,
        type: 'transfer',
        timestamp: asOf - oneDayMs,
      });

      // Component 2 (isolated island of 5 accounts with 10 edges)
      for (let i = 1; i <= 5; i++) {
        for (let j = 1; j <= 5; j++) {
          if (i !== j) {
            provider.addEdge({
              id: `tx_island_${i}_${j}`,
              source: `island_${i}.testnet`,
              target: `island_${j}.testnet`,
              type: 'transfer',
              timestamp: asOf - 1000,
            });
          }
        }
      }

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
      });

      expect(result.coverage.accountsVisited).toBe(2);
      expect(result.coverage.edgesTraversed).toBe(1);
      expect(result.nodes.has('island_1.testnet')).toBe(false);
      expect(result.nodes.has('island_5.testnet')).toBe(false);
      expect(result.adjacency.has('island_1.testnet')).toBe(false);
    });

    it('safely processes self-loops on seed and neighbors without infinite loops or extra nodes', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'self_loop_seed.testnet';
      const peer = 'self_loop_peer.testnet';

      provider.addEdges([
        // Seed self-loop
        {
          id: 'tx_seed_self',
          source: seed,
          target: seed,
          type: 'contract_call',
          timestamp: asOf - 1000,
        },
        // Edge between seed and peer
        {
          id: 'tx_seed_peer',
          source: seed,
          target: peer,
          type: 'transfer',
          timestamp: asOf - 2000,
        },
        // Peer self-loop
        {
          id: 'tx_peer_self',
          source: peer,
          target: peer,
          type: 'contract_call',
          timestamp: asOf - 3000,
        },
      ]);

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
      });

      // Only 2 accounts visited
      expect(result.coverage.accountsVisited).toBe(2);
      expect(result.nodes.size).toBe(2);
      expect(result.nodes.get(seed)?.hop).toBe(0);
      expect(result.nodes.get(peer)?.hop).toBe(1);

      // 3 edges traversed: seed-self, seed-peer, peer-self
      expect(result.coverage.edgesTraversed).toBe(3);
      expect(result.coverage.truncated).toBe(false);

      // Adjacency for seed: self-loop is in both inEdges and outEdges
      const seedAdj = result.adjacency.get(seed);
      expect(seedAdj).toBeDefined();
      expect(seedAdj?.outEdges.some((e) => e.id === 'tx_seed_self')).toBe(true);
      expect(seedAdj?.inEdges.some((e) => e.id === 'tx_seed_self')).toBe(true);

      // Adjacency for peer: self-loop is in both inEdges and outEdges
      const peerAdj = result.adjacency.get(peer);
      expect(peerAdj).toBeDefined();
      expect(peerAdj?.outEdges.some((e) => e.id === 'tx_peer_self')).toBe(true);
      expect(peerAdj?.inEdges.some((e) => e.id === 'tx_peer_self')).toBe(true);
    });

    it('traverses multi-edges (parallel transfers) between identical accounts cleanly', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'multi_seed.testnet';
      const merchant = 'multi_merchant.testnet';

      // 5 distinct transfer edges between seed and merchant with different amounts and timestamps
      const edges: GraphEdge[] = [
        {
          id: 'tx_multi_1',
          source: seed,
          target: merchant,
          amountYocto: '1000000000000000000000000',
          type: 'transfer',
          timestamp: asOf - 5000,
        },
        {
          id: 'tx_multi_2',
          source: seed,
          target: merchant,
          amountYocto: '2000000000000000000000000',
          type: 'transfer',
          timestamp: asOf - 4000,
        },
        {
          id: 'tx_multi_3',
          source: seed,
          target: merchant,
          amountYocto: '3000000000000000000000000',
          type: 'transfer',
          timestamp: asOf - 3000,
        },
        {
          id: 'tx_multi_4',
          source: merchant,
          target: seed,
          amountYocto: '500000000000000000000000', // refund
          type: 'transfer',
          timestamp: asOf - 2000,
        },
        {
          id: 'tx_multi_5',
          source: seed,
          target: merchant,
          amountYocto: '4000000000000000000000000',
          type: 'transfer',
          timestamp: asOf - 1000,
        },
      ];
      provider.addEdges(edges);

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
      });

      expect(result.coverage.accountsVisited).toBe(2);
      expect(result.coverage.edgesTraversed).toBe(5);
      expect(result.edges.length).toBe(5);

      const seedAdj = result.adjacency.get(seed);
      expect(seedAdj?.outEdges.length).toBe(4);
      expect(seedAdj?.inEdges.length).toBe(1);

      const merchantAdj = result.adjacency.get(merchant);
      expect(merchantAdj?.inEdges.length).toBe(4);
      expect(merchantAdj?.outEdges.length).toBe(1);
    });

    it('deduplicates identical edge IDs without double-counting', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'dedup_seed.testnet';
      const peer = 'dedup_peer.testnet';

      // Same edge ID added twice (e.g. returned during both seed and peer queries)
      const edge: GraphEdge = {
        id: 'tx_duplicate_id',
        source: seed,
        target: peer,
        type: 'transfer',
        timestamp: asOf - 1000,
      };
      provider.addEdge(edge);
      provider.addEdge(edge); // duplicate in provider

      const result = await traverseBoundedGraph(provider, seed, 'testnet', {
        asOfTimestamp: asOf,
      });

      expect(result.coverage.accountsVisited).toBe(2);
      expect(result.coverage.edgesTraversed).toBe(1);
      expect(result.edges.length).toBe(1);
      expect(result.adjacency.get(seed)?.outEdges.length).toBe(1);
      expect(result.adjacency.get(peer)?.inEdges.length).toBe(1);
    });

    it('traverses circular directed topologies (triangle ring) without looping or corruption', async () => {
      const provider = new InMemoryGraphProvider();

      // Directed ring: R1 -> R2 -> R3 -> R1
      provider.addEdges([
        {
          id: 'tx_r1_r2',
          source: 'ring_1.testnet',
          target: 'ring_2.testnet',
          type: 'transfer',
          timestamp: asOf - 1000,
        },
        {
          id: 'tx_r2_r3',
          source: 'ring_2.testnet',
          target: 'ring_3.testnet',
          type: 'transfer',
          timestamp: asOf - 2000,
        },
        {
          id: 'tx_r3_r1',
          source: 'ring_3.testnet',
          target: 'ring_1.testnet',
          type: 'transfer',
          timestamp: asOf - 3000,
        },
      ]);

      const result = await traverseBoundedGraph(provider, 'ring_1.testnet', 'testnet', {
        asOfTimestamp: asOf,
      });

      expect(result.coverage.accountsVisited).toBe(3);
      expect(result.coverage.edgesTraversed).toBe(3);
      expect(result.coverage.truncated).toBe(false);
      expect(result.nodes.get('ring_1.testnet')?.hop).toBe(0);
      expect(result.nodes.get('ring_2.testnet')?.hop).toBe(1);
      expect(result.nodes.get('ring_3.testnet')?.hop).toBe(1); // ring_3 is counterparty on tx_r3_r1 directly to ring_1!
    });
  });

  // =========================================================================
  // 6. Adversarial Robustness: Normalization & Async Providers
  // =========================================================================
  describe('6. Adversarial Robustness: Normalization & Async DataProviders', () => {
    it('normalizes seed and edge account IDs to lowercase trimmed strings', async () => {
      const provider = new InMemoryGraphProvider();
      const untrimmedSeed = '  ALICE.NEAR  ';

      provider.addEdge({
        id: 'tx_mixed_case',
        source: 'Alice.Near',
        target: 'BOB.near',
        type: 'transfer',
        timestamp: asOf - 1000,
      });

      const result = await traverseBoundedGraph(provider, untrimmedSeed, 'mainnet', {
        asOfTimestamp: asOf,
      });

      expect(result.seedAccountId).toBe('alice.near');
      expect(result.nodes.has('alice.near')).toBe(true);
      expect(result.nodes.has('bob.near')).toBe(true);
      expect(result.coverage.accountsVisited).toBe(2);
      expect(result.edges[0].source).toBe('alice.near');
      expect(result.edges[0].target).toBe('bob.near');
    });

    it('works correctly with asynchronous GraphDataProvider implementations', async () => {
      // Custom async provider returning Promises
      const asyncProvider: GraphDataProvider = {
        async getAdjacentEdges(
          accountIds: string[],
          _options: {
            network: NetworkType;
            sinceTimestamp: number;
            untilTimestamp?: number;
            limit?: number;
          },
        ): Promise<GraphEdge[]> {
          // Simulate network/RPC async latency
          await new Promise((resolve) => setTimeout(resolve, 5));

          const results: GraphEdge[] = [];
          if (accountIds.includes('async_seed.testnet')) {
            results.push({
              id: 'tx_async_1',
              source: 'async_seed.testnet',
              target: 'async_neighbor.testnet',
              type: 'funding',
              timestamp: asOf - 1000,
            });
          }
          return results;
        },
      };

      const result = await traverseBoundedGraph(asyncProvider, 'async_seed.testnet', 'testnet', {
        asOfTimestamp: asOf,
      });

      expect(result.coverage.accountsVisited).toBe(2);
      expect(result.coverage.edgesTraversed).toBe(1);
      expect(result.nodes.has('async_neighbor.testnet')).toBe(true);
    });

    it('handles empty graphs with non-existent seed gracefully without error', async () => {
      const provider = new InMemoryGraphProvider();
      const nonExistentSeed = 'ghost_account.testnet';

      const result = await traverseBoundedGraph(provider, nonExistentSeed, 'testnet', {
        asOfTimestamp: asOf,
      });

      expect(result.coverage.accountsVisited).toBe(1);
      expect(result.coverage.edgesTraversed).toBe(0);
      expect(result.coverage.truncated).toBe(false);
      expect(result.nodes.get(nonExistentSeed)?.hop).toBe(0);
      expect(result.edges).toEqual([]);
      expect(result.adjacency.get(nonExistentSeed)).toEqual({ inEdges: [], outEdges: [] });
    });

    it('preserves default constants when config is omitted', async () => {
      const provider = new InMemoryGraphProvider();
      const seed = 'defaults_test.testnet';

      const result = await traverseBoundedGraph(provider, seed, 'testnet');

      expect(result.coverage.windowDays).toBe(DEFAULT_WINDOW_DAYS);
      expect(result.coverage.truncated).toBe(false);
      expect(result.coverage.accountsVisited).toBe(1);
      expect(result.coverage.edgesTraversed).toBe(0);
    });
  });
});
