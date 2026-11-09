import { describe, expect, it } from 'vitest';
import { detectCircularFlow } from '../src/graph/circular.js';
import type {
  AccountAdjacency,
  AccountNode,
  BoundedSubgraph,
} from '../src/graph/traversal.js';

describe('Milestone M4: Circular Flow Detection (circular.ts)', () => {
  const now = 1700000000000;
  const oneDayMs = 24 * 60 * 60 * 1000;

  function createMockSubgraph(
    edges: Array<{ source: string; target: string; amountYocto?: string; timestamp?: number }>,
    seed = 'wash-trader.testnet',
  ): BoundedSubgraph {
    const nodes = new Map<string, AccountNode>();
    const adjacency = new Map<string, AccountAdjacency>();

    const graphEdges = edges.map((e, idx) => ({
      id: `edge_${idx}`,
      source: e.source,
      target: e.target,
      amountYocto: e.amountYocto ?? '1000000000000000000000000', // 1 NEAR
      timestamp: e.timestamp ?? now - oneDayMs,
      type: 'transfer' as const,
    }));

    for (const ge of graphEdges) {
      if (!nodes.has(ge.source)) {
        nodes.set(ge.source, { accountId: ge.source, hop: 1, discoveredAt: ge.timestamp });
      }
      if (!nodes.has(ge.target)) {
        nodes.set(ge.target, { accountId: ge.target, hop: 1, discoveredAt: ge.timestamp });
      }
      if (!adjacency.has(ge.source)) adjacency.set(ge.source, { inEdges: [], outEdges: [] });
      if (!adjacency.has(ge.target)) adjacency.set(ge.target, { inEdges: [], outEdges: [] });

      adjacency.get(ge.source)?.outEdges.push(ge);
      adjacency.get(ge.target)?.inEdges.push(ge);
    }

    if (!nodes.has(seed)) {
      nodes.set(seed, { accountId: seed, hop: 0, discoveredAt: now });
      adjacency.set(seed, { inEdges: [], outEdges: [] });
    }

    return {
      seedAccountId: seed,
      nodes,
      edges: graphEdges,
      adjacency,
      coverage: {
        accountsVisited: nodes.size,
        edgesTraversed: graphEdges.length,
        truncated: false,
        windowDays: 7,
      },
    };
  }

  it('S5 Scenario: detects 3-node directed cycle (wash trading ring) and calculates 65% volume', () => {
    // 3-account ring: wash-trader -> trader-b -> trader-c -> wash-trader
    // Wash trader also has an independent legitimate incoming transfer of 35 NEAR (total 100 NEAR)
    const circularAmount = '65000000000000000000000000'; // 65 NEAR
    const otherAmount = '35000000000000000000000000'; // 35 NEAR

    const subgraph = createMockSubgraph([
      { source: 'wash-trader.testnet', target: 'trader-b.testnet', amountYocto: circularAmount },
      { source: 'trader-b.testnet', target: 'trader-c.testnet', amountYocto: circularAmount },
      { source: 'trader-c.testnet', target: 'wash-trader.testnet', amountYocto: circularAmount },
      { source: 'legit-customer.testnet', target: 'wash-trader.testnet', amountYocto: otherAmount },
    ]);

    const result = detectCircularFlow({
      graph: subgraph,
      targetAccountId: 'wash-trader.testnet',
      nowMs: now,
    });

    expect(result.circularActivityDetected).toBe(true);
    expect(result.cycles.length).toBe(1);
    expect(result.cycles[0].cycleLength).toBe(3);
    expect(result.cycles[0].volumeYocto).toBe(circularAmount);

    // Total incident volume = 65 (out) + 65 (in) + 35 (in) = 165 NEAR
    // Incident circular volume = 65 NEAR
    // Ratio = 65 / (65+35) for one-way or ratio calculation
    expect(result.circularActivityScore).toBeGreaterThanOrEqual(39);
    expect(result.circularActivityScore).toBeLessThanOrEqual(100);
    expect(result.ringAccounts).toContain('wash-trader.testnet');
    expect(result.ringAccounts).toContain('trader-b.testnet');
    expect(result.ringAccounts).toContain('trader-c.testnet');
    expect(result.explanation).toBeDefined();
  });

  it('detects 2-node reciprocal transfers (reciprocal ping-pong)', () => {
    const subgraph = createMockSubgraph([
      { source: 'alice.testnet', target: 'bob.testnet', amountYocto: '5000' },
      { source: 'bob.testnet', target: 'alice.testnet', amountYocto: '4000' },
    ]);

    const result = detectCircularFlow({
      graph: subgraph,
      targetAccountId: 'alice.testnet',
      nowMs: now,
    });

    expect(result.circularActivityDetected).toBe(true);
    expect(result.cycles.length).toBe(1);
    expect(result.cycles[0].cycleLength).toBe(2);
    // Bottleneck volume is min(5000, 4000) = 4000
    expect(result.cycles[0].volumeYocto).toBe('4000');
  });

  it('detects 4-node elementary cycle', () => {
    const subgraph = createMockSubgraph([
      { source: 'n1.testnet', target: 'n2.testnet', amountYocto: '100' },
      { source: 'n2.testnet', target: 'n3.testnet', amountYocto: '200' },
      { source: 'n3.testnet', target: 'n4.testnet', amountYocto: '150' },
      { source: 'n4.testnet', target: 'n1.testnet', amountYocto: '300' },
    ]);

    const result = detectCircularFlow({
      graph: subgraph,
      targetAccountId: 'n1.testnet',
      nowMs: now,
    });

    expect(result.circularActivityDetected).toBe(true);
    expect(result.cycles.length).toBe(1);
    expect(result.cycles[0].cycleLength).toBe(4);
    // Bottleneck volume is min(100, 200, 150, 300) = 100
    expect(result.cycles[0].volumeYocto).toBe('100');
  });

  it('does not detect cycles in a directed acyclic graph (DAG)', () => {
    const subgraph = createMockSubgraph([
      { source: 'hub.testnet', target: 'leaf1.testnet', amountYocto: '100' },
      { source: 'hub.testnet', target: 'leaf2.testnet', amountYocto: '200' },
      { source: 'leaf1.testnet', target: 'sink.testnet', amountYocto: '50' },
      { source: 'leaf2.testnet', target: 'sink.testnet', amountYocto: '50' },
    ]);

    const result = detectCircularFlow({
      graph: subgraph,
      targetAccountId: 'hub.testnet',
      nowMs: now,
    });

    expect(result.circularActivityDetected).toBe(false);
    expect(result.circularActivityScore).toBe(0);
    expect(result.cycles.length).toBe(0);
    expect(result.explanation).toBeUndefined();
  });

  it('deduplicates cyclic rotations and ignores out-of-window edges', () => {
    const subgraph = createMockSubgraph([
      // In-window 3-node cycle
      { source: 'c1.testnet', target: 'c2.testnet', timestamp: now - oneDayMs },
      { source: 'c2.testnet', target: 'c3.testnet', timestamp: now - oneDayMs },
      { source: 'c3.testnet', target: 'c1.testnet', timestamp: now - oneDayMs },
      // Expired edge (10 days old)
      { source: 'c1.testnet', target: 'c3.testnet', timestamp: now - 10 * oneDayMs },
    ]);

    const result = detectCircularFlow({
      graph: subgraph,
      targetAccountId: 'c1.testnet',
      nowMs: now,
      windowDays: 7,
    });

    // Despite 3 possible cyclic starting positions, exactly 1 unique canonical cycle is retained
    expect(result.cycles.length).toBe(1);
  });

  it('does NOT flag innocent target account when cycles exist in 2-hop neighborhood without target involvement', () => {
    // 3-node cycle: ring_a -> ring_b -> ring_c -> ring_a
    // Target innocent.testnet only has a clean transfer from ring_a, but is NOT part of the cycle
    const subgraph = createMockSubgraph(
      [
        {
          source: 'ring_a.testnet',
          target: 'ring_b.testnet',
          amountYocto: '50000000000000000000000000',
        },
        {
          source: 'ring_b.testnet',
          target: 'ring_c.testnet',
          amountYocto: '50000000000000000000000000',
        },
        {
          source: 'ring_c.testnet',
          target: 'ring_a.testnet',
          amountYocto: '50000000000000000000000000',
        },
        {
          source: 'ring_a.testnet',
          target: 'innocent.testnet',
          amountYocto: '1000000000000000000000000',
        },
      ],
      'innocent.testnet',
    );

    const result = detectCircularFlow({
      graph: subgraph,
      targetAccountId: 'innocent.testnet',
      nowMs: now,
    });

    expect(result.circularActivityDetected).toBe(false);
    expect(result.circularActivityScore).toBe(0);
    expect(result.circularVolumeRatio).toBe(0);
    expect(result.cycles).toEqual([]);
    expect(result.ringAccounts).toEqual([]);
    expect(result.explanation).toBeUndefined();
  });

  it('correctly aligns rotated edges with canonical rotated nodes in directed cycles', () => {
    // 3-node cycle with asymmetric edge amounts
    // c_node -> a_node (10) -> b_node (20) -> c_node (30)
    // Canonical start node is a_node
    const subgraph = createMockSubgraph(
      [
        { source: 'c_node.testnet', target: 'a_node.testnet', amountYocto: '10' },
        { source: 'a_node.testnet', target: 'b_node.testnet', amountYocto: '20' },
        { source: 'b_node.testnet', target: 'c_node.testnet', amountYocto: '30' },
      ],
      'a_node.testnet',
    );

    const result = detectCircularFlow({
      graph: subgraph,
      targetAccountId: 'a_node.testnet',
      nowMs: now,
    });

    expect(result.circularActivityDetected).toBe(true);
    expect(result.cycles.length).toBe(1);
    const cycle = result.cycles[0];
    expect(cycle.path[0]).toBe('a_node.testnet');
    expect(cycle.edges[0].source).toBe('a_node.testnet');
    expect(cycle.edges[0].target).toBe('b_node.testnet');
    expect(cycle.edges[0].amountYocto).toBe('20');
    expect(cycle.edges[1].source).toBe('b_node.testnet');
    expect(cycle.edges[1].target).toBe('c_node.testnet');
    expect(cycle.edges[1].amountYocto).toBe('30');
    expect(cycle.edges[2].source).toBe('c_node.testnet');
    expect(cycle.edges[2].target).toBe('a_node.testnet');
    expect(cycle.edges[2].amountYocto).toBe('10');
  });
});
