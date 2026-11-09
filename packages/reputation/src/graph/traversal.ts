/**
 * @file packages/reputation/src/graph/traversal.ts
 * @description Bounded 2-hop / 100-node / 500-edge BFS graph traversal.
 */

export type NetworkType = 'testnet' | 'mainnet' | 'sandbox';
export type EdgeType = 'funding' | 'transfer' | 'contract_call';
export type AccountRole = 'seed' | 'reporter' | 'funder' | 'intermediary' | 'accused';

export interface GraphEdge {
  id: string;
  source: string; // from_account_id
  target: string; // to_account_id
  amountYocto?: string;
  timestamp: number; // in milliseconds
  type: EdgeType;
  blockHeight?: number;
  transactionHash?: string;
}

export interface AccountNode {
  accountId: string;
  hop: number; // 0 for seed, 1 for direct neighbors, 2 for 2-hop neighbors
  discoveredAt: number;
}

export interface GraphCoverage {
  accountsVisited: number;
  edgesTraversed: number;
  truncated: boolean;
  windowDays: number;
}

export interface AccountAdjacency {
  inEdges: GraphEdge[];
  outEdges: GraphEdge[];
}

export interface BoundedSubgraph {
  seedAccountId: string;
  nodes: Map<string, AccountNode>;
  edges: GraphEdge[];
  adjacency: Map<string, AccountAdjacency>;
  coverage: GraphCoverage;
}

export interface GraphDataProvider {
  getAdjacentEdges(
    accountIds: string[],
    options: {
      network: NetworkType;
      sinceTimestamp: number;
      untilTimestamp?: number;
      limit?: number;
    },
  ): Promise<GraphEdge[]> | GraphEdge[];
}

export interface TraversalConfig {
  maxHops?: number; // default: 2
  maxAccounts?: number; // default: 100
  maxEdges?: number; // default: 500
  windowDays?: number; // default: 7
  asOfTimestamp?: number; // default: Date.now()
}

export const DEFAULT_MAX_HOPS = 2;
export const DEFAULT_MAX_ACCOUNTS = 100;
export const DEFAULT_MAX_EDGES = 500;
export const DEFAULT_WINDOW_DAYS = 7;
export const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * In-memory graph data provider for fast, deterministic unit testing and scenario fixtures.
 */
export class InMemoryGraphProvider implements GraphDataProvider {
  private edges: GraphEdge[] = [];

  constructor(initialEdges?: GraphEdge[]) {
    if (initialEdges) {
      this.edges = [...initialEdges];
    }
  }

  public addEdge(edge: GraphEdge): void {
    this.edges.push(edge);
  }

  public addEdges(edges: GraphEdge[]): void {
    this.edges.push(...edges);
  }

  public getAdjacentEdges(
    accountIds: string[],
    options: {
      network: NetworkType;
      sinceTimestamp: number;
      untilTimestamp?: number;
      limit?: number;
    },
  ): GraphEdge[] {
    const accountSet = new Set(accountIds.map((a) => a.trim().toLowerCase()));
    const until = options.untilTimestamp ?? Date.now();

    const matched = this.edges.filter((e) => {
      const touches =
        accountSet.has(e.source.toLowerCase()) || accountSet.has(e.target.toLowerCase());
      const inWindow = e.timestamp >= options.sinceTimestamp && e.timestamp <= until;
      return touches && inWindow;
    });

    if (options.limit && matched.length > options.limit) {
      return matched.slice(0, options.limit);
    }
    return matched;
  }

  public clear(): void {
    this.edges = [];
  }
}

/**
 * Executes a bounded BFS graph traversal starting from seedAccountId.
 *
 * Invariants:
 * 1. Bounds exploration to maxHops (default 2).
 * 2. Bounds accounts visited to maxAccounts (default 100).
 * 3. Bounds edges traversed to maxEdges (default 500).
 * 4. Filters edges within rolling window [asOf - windowDays * 86_400_000, asOf].
 * 5. Returns truncated = true when limits are reached, never throws.
 */
export async function traverseBoundedGraph(
  dataProvider: GraphDataProvider,
  seedAccountId: string,
  network: NetworkType,
  config?: TraversalConfig,
): Promise<BoundedSubgraph> {
  const maxHops = config?.maxHops ?? DEFAULT_MAX_HOPS;
  const maxAccounts = config?.maxAccounts ?? DEFAULT_MAX_ACCOUNTS;
  const maxEdges = config?.maxEdges ?? DEFAULT_MAX_EDGES;
  const windowDays = config?.windowDays ?? DEFAULT_WINDOW_DAYS;
  const asOf = config?.asOfTimestamp ?? Date.now();
  const cutoffTimestamp = asOf - windowDays * MS_PER_DAY;

  const normalizedSeed = seedAccountId.trim().toLowerCase();

  const nodes = new Map<string, AccountNode>();
  const edgesMap = new Map<string, GraphEdge>();
  const adjacency = new Map<string, AccountAdjacency>();

  let truncated = false;

  const getOrCreateAdjacency = (accId: string): AccountAdjacency => {
    let adj = adjacency.get(accId);
    if (!adj) {
      adj = { inEdges: [], outEdges: [] };
      adjacency.set(accId, adj);
    }
    return adj;
  };

  // 1. Initialize seed
  nodes.set(normalizedSeed, {
    accountId: normalizedSeed,
    hop: 0,
    discoveredAt: asOf,
  });
  getOrCreateAdjacency(normalizedSeed);

  // 2. Queue for BFS: { accountId, hop }
  const queue: Array<{ accountId: string; hop: number }> = [{ accountId: normalizedSeed, hop: 0 }];

  while (queue.length > 0) {
    if (edgesMap.size >= maxEdges) {
      truncated = true;
      break;
    }

    const current = queue.shift();
    if (!current) {
      break;
    }

    // Hop boundary: do not expand beyond maxHops
    if (current.hop >= maxHops) {
      continue;
    }

    const rawEdges = await dataProvider.getAdjacentEdges([current.accountId], {
      network,
      sinceTimestamp: cutoffTimestamp,
      untilTimestamp: asOf,
      limit: maxEdges,
    });

    for (const rawEdge of rawEdges) {
      if (rawEdge.timestamp < cutoffTimestamp || rawEdge.timestamp > asOf) {
        continue;
      }

      const sourceId = rawEdge.source.trim().toLowerCase();
      const targetId = rawEdge.target.trim().toLowerCase();
      const edgeKey = rawEdge.id || `${sourceId}->${targetId}:${rawEdge.timestamp}:${rawEdge.type}`;

      const counterpartyId = sourceId === current.accountId ? targetId : sourceId;
      const isNewNode = !nodes.has(counterpartyId);

      // Check node limit before admitting new node or edge to that node
      if (isNewNode && nodes.size >= maxAccounts) {
        truncated = true;
        continue;
      }

      // Check edge limit before admitting edge
      if (!edgesMap.has(edgeKey)) {
        if (edgesMap.size >= maxEdges) {
          truncated = true;
          break;
        }

        const edgeObj: GraphEdge = {
          ...rawEdge,
          id: edgeKey,
          source: sourceId,
          target: targetId,
        };
        edgesMap.set(edgeKey, edgeObj);
        getOrCreateAdjacency(sourceId).outEdges.push(edgeObj);
        getOrCreateAdjacency(targetId).inEdges.push(edgeObj);
      }

      // Admit new node and queue for expansion if within hop limit
      if (isNewNode) {
        const nextHop = current.hop + 1;
        nodes.set(counterpartyId, {
          accountId: counterpartyId,
          hop: nextHop,
          discoveredAt: rawEdge.timestamp,
        });
        getOrCreateAdjacency(counterpartyId);

        if (nextHop < maxHops) {
          queue.push({ accountId: counterpartyId, hop: nextHop });
        }
      }
    }
  }

  const edges = Array.from(edgesMap.values());
  const coverage: GraphCoverage = {
    accountsVisited: nodes.size,
    edgesTraversed: edges.length,
    truncated,
    windowDays,
  };

  return {
    seedAccountId: normalizedSeed,
    nodes,
    edges,
    adjacency,
    coverage,
  };
}
