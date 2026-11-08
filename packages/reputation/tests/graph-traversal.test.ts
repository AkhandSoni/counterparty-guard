import { describe, expect, it } from 'vitest';
import {
  type GraphEdge,
  InMemoryGraphProvider,
  traverseBoundedGraph,
} from '../src/graph/traversal.js';

describe('Milestone M4: Bounded Graph Traversal (traversal.ts)', () => {
  const now = 1700000000000;
  const oneDayMs = 24 * 60 * 60 * 1000;

  it('bounds exploration strictly to 2 hops', async () => {
    const provider = new InMemoryGraphProvider();

    // Linear chain: A <-> B <-> C <-> D <-> E
    provider.addEdges([
      {
        id: 'tx_ab',
        source: 'account_a.testnet',
        target: 'account_b.testnet',
        type: 'transfer',
        timestamp: now - oneDayMs,
      },
      {
        id: 'tx_bc',
        source: 'account_b.testnet',
        target: 'account_c.testnet',
        type: 'transfer',
        timestamp: now - oneDayMs,
      },
      {
        id: 'tx_cd',
        source: 'account_c.testnet',
        target: 'account_d.testnet',
        type: 'transfer',
        timestamp: now - oneDayMs,
      },
      {
        id: 'tx_de',
        source: 'account_d.testnet',
        target: 'account_e.testnet',
        type: 'transfer',
        timestamp: now - oneDayMs,
      },
    ]);

    const result = await traverseBoundedGraph(provider, 'account_a.testnet', 'testnet', {
      asOfTimestamp: now,
      maxHops: 2,
    });

    // Accounts A (hop 0), B (hop 1), and C (hop 2) should be present
    expect(result.nodes.has('account_a.testnet')).toBe(true);
    expect(result.nodes.get('account_a.testnet')?.hop).toBe(0);

    expect(result.nodes.has('account_b.testnet')).toBe(true);
    expect(result.nodes.get('account_b.testnet')?.hop).toBe(1);

    expect(result.nodes.has('account_c.testnet')).toBe(true);
    expect(result.nodes.get('account_c.testnet')?.hop).toBe(2);

    // Accounts D (hop 3) and E (hop 4) must NOT be visited
    expect(result.nodes.has('account_d.testnet')).toBe(false);
    expect(result.nodes.get('account_d.testnet')).toBeUndefined();
    expect(result.nodes.has('account_e.testnet')).toBe(false);

    expect(result.coverage.accountsVisited).toBe(3);
    expect(result.coverage.edgesTraversed).toBe(2); // tx_ab, tx_bc
    expect(result.coverage.truncated).toBe(false);
    expect(result.coverage.windowDays).toBe(7);
  });

  it('halts gracefully and sets truncated: true when exceeding 100 accounts', async () => {
    const provider = new InMemoryGraphProvider();
    const hub = 'hub.testnet';

    // 120 leaves connected to hub
    const edges: GraphEdge[] = [];
    for (let i = 1; i <= 120; i++) {
      edges.push({
        id: `tx_leaf_${i}`,
        source: hub,
        target: `leaf_${i}.testnet`,
        type: 'transfer',
        timestamp: now - oneDayMs,
      });
    }
    provider.addEdges(edges);

    const result = await traverseBoundedGraph(provider, hub, 'testnet', {
      asOfTimestamp: now,
      maxAccounts: 100,
    });

    // Node limit strictly capped to 100
    expect(result.coverage.accountsVisited).toBe(100);
    expect(result.nodes.size).toBe(100);
    expect(result.coverage.truncated).toBe(true);
    // Traversal never throws on bounds
    expect(result.nodes.has(hub)).toBe(true);
  });

  it('halts gracefully and sets truncated: true when exceeding 500 edges', async () => {
    const provider = new InMemoryGraphProvider();
    const accA = 'pair_a.testnet';
    const accB = 'pair_b.testnet';

    // 600 parallel edges between A and B
    const edges: GraphEdge[] = [];
    for (let i = 1; i <= 600; i++) {
      edges.push({
        id: `tx_edge_${i}`,
        source: accA,
        target: accB,
        type: 'transfer',
        timestamp: now - i * 1000, // all within 7 days
      });
    }
    provider.addEdges(edges);

    const result = await traverseBoundedGraph(provider, accA, 'testnet', {
      asOfTimestamp: now,
      maxEdges: 500,
    });

    expect(result.coverage.edgesTraversed).toBe(500);
    expect(result.edges.length).toBe(500);
    expect(result.coverage.truncated).toBe(true);
    expect(result.coverage.accountsVisited).toBe(2);
  });

  it('enforces 7-day rolling window cutoff without setting truncated', async () => {
    const provider = new InMemoryGraphProvider();
    const seed = 'seed.testnet';

    provider.addEdges([
      {
        id: 'tx_valid_recent',
        source: seed,
        target: 'recent_neighbor.testnet',
        type: 'transfer',
        timestamp: now - 2 * oneDayMs, // 2 days ago (valid)
      },
      {
        id: 'tx_valid_near_cutoff',
        source: seed,
        target: 'cutoff_neighbor.testnet',
        type: 'transfer',
        timestamp: now - 6 * oneDayMs, // 6 days ago (valid)
      },
      {
        id: 'tx_expired_past',
        source: seed,
        target: 'old_neighbor.testnet',
        type: 'transfer',
        timestamp: now - 8 * oneDayMs, // 8 days ago (expired)
      },
      {
        id: 'tx_future_anomaly',
        source: seed,
        target: 'future_neighbor.testnet',
        type: 'transfer',
        timestamp: now + 1 * oneDayMs, // in the future (invalid)
      },
    ]);

    const result = await traverseBoundedGraph(provider, seed, 'testnet', {
      asOfTimestamp: now,
      windowDays: 7,
    });

    expect(result.nodes.has('recent_neighbor.testnet')).toBe(true);
    expect(result.nodes.has('cutoff_neighbor.testnet')).toBe(true);
    expect(result.nodes.has('old_neighbor.testnet')).toBe(false);
    expect(result.nodes.has('future_neighbor.testnet')).toBe(false);

    expect(result.coverage.edgesTraversed).toBe(2);
    expect(result.coverage.accountsVisited).toBe(3); // seed + 2 valid
    expect(result.coverage.truncated).toBe(false);
  });

  it('discovers bidirectional edges and segregates adjacency correctly', async () => {
    const provider = new InMemoryGraphProvider();
    const center = 'center.testnet';

    provider.addEdges([
      {
        id: 'tx_out',
        source: center,
        target: 'receiver.testnet',
        type: 'transfer',
        timestamp: now - oneDayMs,
      },
      {
        id: 'tx_in',
        source: 'funder.testnet',
        target: center,
        type: 'funding',
        timestamp: now - oneDayMs,
      },
    ]);

    const result = await traverseBoundedGraph(provider, center, 'testnet', {
      asOfTimestamp: now,
    });

    const centerAdj = result.adjacency.get(center);
    expect(centerAdj).toBeDefined();
    expect(centerAdj?.outEdges.map((e) => e.target)).toContain('receiver.testnet');
    expect(centerAdj?.inEdges.map((e) => e.source)).toContain('funder.testnet');

    expect(result.nodes.has('receiver.testnet')).toBe(true);
    expect(result.nodes.has('funder.testnet')).toBe(true);
  });

  it('handles cyclic structures cleanly without infinite loops', async () => {
    const provider = new InMemoryGraphProvider();

    // 3-node ring: A -> B -> C -> A
    provider.addEdges([
      {
        id: 'tx_ab',
        source: 'ring_a.testnet',
        target: 'ring_b.testnet',
        type: 'transfer',
        timestamp: now - oneDayMs,
      },
      {
        id: 'tx_bc',
        source: 'ring_b.testnet',
        target: 'ring_c.testnet',
        type: 'transfer',
        timestamp: now - oneDayMs,
      },
      {
        id: 'tx_ca',
        source: 'ring_c.testnet',
        target: 'ring_a.testnet',
        type: 'transfer',
        timestamp: now - oneDayMs,
      },
    ]);

    const result = await traverseBoundedGraph(provider, 'ring_a.testnet', 'testnet', {
      asOfTimestamp: now,
    });

    expect(result.coverage.accountsVisited).toBe(3);
    expect(result.coverage.edgesTraversed).toBe(3);
    expect(result.coverage.truncated).toBe(false);
  });

  it('handles empty isolated seed gracefully', async () => {
    const provider = new InMemoryGraphProvider();

    const result = await traverseBoundedGraph(provider, 'lonely.testnet', 'testnet', {
      asOfTimestamp: now,
    });

    expect(result.coverage.accountsVisited).toBe(1);
    expect(result.coverage.edgesTraversed).toBe(0);
    expect(result.coverage.truncated).toBe(false);
    expect(result.nodes.get('lonely.testnet')?.hop).toBe(0);
  });
});
