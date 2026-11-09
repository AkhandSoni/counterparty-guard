/**
 * @file packages/reputation/src/graph/circular.ts
 * @description Circular money flow detector for wash-trading rings and reciprocal transfers.
 */

import type { BoundedSubgraph, GraphEdge } from './traversal.js';

export interface DirectedCycle {
  path: string[];
  cycleLength: number;
  edges: GraphEdge[];
  volumeYocto: string;
}

export interface CircularFlowResult {
  truncated: boolean;
  searchSteps: number;
  circularActivityDetected: boolean;
  circularActivityScore: number; // 0 to 100 integer/float strictly satisfying ReceiverReputationSchema
  circularVolumeRatio: number; // 0.0 to 1.0
  circularVolumeYocto: string;
  totalVolumeYocto: string;
  cycles: DirectedCycle[];
  ringAccounts: string[];
  explanation?: string;
}

export interface CircularFlowDetectorOptions {
  graph: BoundedSubgraph;
  targetAccountId: string;
  maxCycleLength?: number; // default: 4 (lengths 2, 3, or 4)
  windowDays?: number; // default: 7
  nowMs?: number;
}

/**
 * Rotates an array of elements so that the minimum element by predicate is at index 0.
 */
function canonicalRotate<T>(arr: T[], keyFn: (item: T) => string): T[] {
  if (arr.length <= 1) return [...arr];
  let minIdx = 0;
  let minVal = keyFn(arr[0]!);
  for (let i = 1; i < arr.length; i++) {
    const val = keyFn(arr[i]!);
    if (val < minVal) {
      minVal = val;
      minIdx = i;
    }
  }
  return [...arr.slice(minIdx), ...arr.slice(0, minIdx)];
}

/**
 * Detects directed elementary cycles (lengths 2, 3, 4) in the bounded graph
 * incident to or in the neighborhood of targetAccountId.
 */
export function detectCircularFlow(options: CircularFlowDetectorOptions): CircularFlowResult {
  const { graph } = options;
  const targetAccountId = options.targetAccountId.trim().toLowerCase();
  const maxCycleLength = Math.min(4, Math.max(2, options.maxCycleLength ?? 4));
  const windowDays = options.windowDays ?? 7;
  const nowMs = options.nowMs ?? Date.now();
  const cutoffTimestamp = nowMs - windowDays * 24 * 60 * 60 * 1000;

  // 1. Build directed adjacency list from in-window transfer edges
  const adj = new Map<string, Map<string, GraphEdge>>();
  const pairVolumes = new Map<string, bigint>();
  const seenReceipts = new Set<string>();
  const eligibleEdges: GraphEdge[] = [];

  for (const edge of graph.edges) {
    if (edge.type !== 'transfer' || edge.timestamp < cutoffTimestamp || edge.timestamp > nowMs || seenReceipts.has(edge.id)) continue;
    seenReceipts.add(edge.id);
    const source = edge.source.trim().toLowerCase();
    const target = edge.target.trim().toLowerCase();
    if (source === target) continue;
    eligibleEdges.push(edge);
    const key = JSON.stringify([source, target]);
    if (edge.amountYocto && /^(0|[1-9][0-9]{0,38})$/.test(edge.amountYocto)) {
      pairVolumes.set(key, (pairVolumes.get(key) ?? 0n) + BigInt(edge.amountYocto));
    }
    let neighbors = adj.get(source);
    if (!neighbors) { neighbors = new Map(); adj.set(source, neighbors); }
    // Search one account relationship once, while retaining actual receipt values
    // separately. A representative edge remains an original receipt, not a fake aggregate.
    if (!neighbors.has(target)) neighbors.set(target, edge);
  }

  // 2. Search for directed cycles of lengths 2, 3, 4
  const detectedCycles: DirectedCycle[] = [];
  const seenCanonicalCycles = new Set<string>();

  // Explore candidate cycle start nodes from graph nodes
  // Only cycles incident to this receiver contribute to its assessment. Searching
  // from the receiver discovers all such cycles without exploring unrelated roots.
  const candidateStartNodes = [targetAccountId];
  const maxSearchSteps = 20_000;
  let searchSteps = 0;
  let truncated = false;

  for (const startNode of candidateStartNodes) {
    const dfs = (
      currentNode: string,
      pathNodes: string[],
      pathEdges: GraphEdge[],
      depth: number,
    ) => {
      const neighbors = adj.get(currentNode) ?? new Map<string, GraphEdge>();
      for (const [to, edge] of neighbors) {
        if (truncated) return;
        if (searchSteps >= maxSearchSteps) { truncated = true; return; }
        searchSteps++;
        if (to === startNode && depth >= 2 && depth <= maxCycleLength) {
          // Cycle closed!
          // Canonicalize cycle to deduplicate cyclic rotations
          const rotatedNodes = canonicalRotate(pathNodes, (n) => n);
          // Rotate edges to match the rotated nodes
          const startIdx = pathNodes.indexOf(rotatedNodes[0]!);
          const allEdges = [...pathEdges, edge];
          const rotatedEdges = [...allEdges.slice(startIdx), ...allEdges.slice(0, startIdx)];

          const canonicalKey = rotatedNodes.join('->');
          if (!seenCanonicalCycles.has(canonicalKey)) {
            seenCanonicalCycles.add(canonicalKey);

            // Compute cycle bottleneck volume using BigInt
            let minVolume = 0n;
            let hasVolume = false;
            for (const e of rotatedEdges) {
              const amount = pairVolumes.get(JSON.stringify([e.source.trim().toLowerCase(), e.target.trim().toLowerCase()])) ?? 0n;
              if (!hasVolume || amount < minVolume) { minVolume = amount; hasVolume = true; }
            }

            detectedCycles.push({
              path: [...rotatedNodes, rotatedNodes[0]!],
              cycleLength: rotatedNodes.length,
              edges: rotatedEdges,
              volumeYocto: minVolume.toString(),
            });
          }
        } else if (depth < maxCycleLength && !pathNodes.includes(to)) {
          dfs(to, [...pathNodes, to], [...pathEdges, edge], depth + 1);
        }
      }
    };

    dfs(startNode, [startNode], [], 1);
  }

  // 3. Filter cycles incident to targetAccountId
  const relevantCycles = detectedCycles.filter((c) =>
    c.path.some((node) => node.toLowerCase() === targetAccountId),
  );

  // Calculate total volume incident to targetAccountId
  let totalIncidentVolumeBigInt = 0n;
  for (const edge of eligibleEdges) {
    const s = edge.source.trim().toLowerCase();
    const t = edge.target.trim().toLowerCase();
    if (s === targetAccountId || t === targetAccountId) {
      if (edge.amountYocto) {
        try {
          totalIncidentVolumeBigInt += BigInt(edge.amountYocto);
        } catch {
          // ignore
        }
      }
    }
  }

  if (relevantCycles.length === 0) {
    return {
      truncated, searchSteps,
      circularActivityDetected: false,
      circularActivityScore: 0,
      circularVolumeRatio: 0.0,
      circularVolumeYocto: '0',
      totalVolumeYocto: totalIncidentVolumeBigInt.toString(),
      cycles: [],
      ringAccounts: [],
    };
  }

  // 4. Compute BigInt volume metrics
  let circularVolumeBigInt = 0n;
  for (const c of relevantCycles) {
    try {
      circularVolumeBigInt += BigInt(c.volumeYocto);
    } catch {
      // ignore
    }
  }

  // Circular volume ratio and score scaling
  let circularVolumeRatio = 0.0;
  if (totalIncidentVolumeBigInt > 0n) {
    const ratioBps = (circularVolumeBigInt * 10000n) / totalIncidentVolumeBigInt;
    circularVolumeRatio = Math.min(1.0, Number(ratioBps) / 10000);
  } else if (relevantCycles.length > 0) {
    circularVolumeRatio = 1.0;
  }

  const circularActivityScore = Math.min(100, Math.max(0, Math.round(circularVolumeRatio * 100)));
  const circularActivityDetected = relevantCycles.length > 0 && circularVolumeRatio > 0;

  const ringAccounts = Array.from(
    new Set(relevantCycles.flatMap((c) => c.path.map((a) => a.toLowerCase()))),
  );

  let explanation: string | undefined;
  if (circularActivityDetected) {
    explanation = `Reciprocal money flows detected in ${relevantCycles.length} cycle(s) across ${ringAccounts.length} accounts; circular volume ratio ${circularVolumeRatio.toFixed(2)}.`;
  }

  return {
    truncated, searchSteps,
    circularActivityDetected,
    circularActivityScore,
    circularVolumeRatio,
    circularVolumeYocto: circularVolumeBigInt.toString(),
    totalVolumeYocto: totalIncidentVolumeBigInt.toString(),
    cycles: relevantCycles,
    ringAccounts,
    explanation,
  };
}
