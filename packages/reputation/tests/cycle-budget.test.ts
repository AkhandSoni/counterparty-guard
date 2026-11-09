import { describe, expect, it } from 'vitest';
import { detectCircularFlow } from '../src/graph/circular.js';
import type { BoundedSubgraph, GraphEdge } from '../src/graph/traversal.js';
const now = 1800000000000;
function graph(edges: GraphEdge[]): BoundedSubgraph {
  const accounts = [...new Set(edges.flatMap(edge => [edge.source, edge.target]))];
  return { seedAccountId: accounts[0]!, nodes: new Map(accounts.map(account => [account, { accountId: account, hop: 1, discoveredAt: now }])),
    edges, adjacency: new Map(), coverage: { accountsVisited: accounts.length, edgesTraversed: edges.length, truncated: false, windowDays: 7 } };
}
describe('bounded cycle analysis', () => {
  it('handles 500 distinct receipts on a four-account ring without parallel-path explosion', () => {
    const accounts = ['a.testnet','b.testnet','c.testnet','d.testnet'];
    const edges: GraphEdge[] = Array.from({length:500}, (_,index)=>({id:`receipt:${index}`,source:accounts[index%4]!,target:accounts[(index+1)%4]!,amountYocto:'1',timestamp:now-1,type:'transfer'}));
    const result=detectCircularFlow({graph:graph(edges),targetAccountId:accounts[0]!,nowMs:now});
    expect(result.truncated).toBe(false); expect(result.searchSteps).toBe(4); expect(result.cycles).toHaveLength(1);
    expect(result.circularVolumeYocto).toBe('125'); expect(result.totalVolumeYocto).toBe('250');
    expect(result.cycles[0]!.edges.every(edge=>edges.includes(edge))).toBe(true);
  });
  it('caps dense node-path exploration deterministically and exposes truncation', () => {
    const accounts=Array.from({length:22},(_,i)=>`account-${i}.testnet`);
    const edges:GraphEdge[]=[];
    for (const source of accounts) for (const target of accounts) if(source!==target) edges.push({id:`${source}:${target}`,source,target,amountYocto:'1',timestamp:now-1,type:'transfer'});
    const result=detectCircularFlow({graph:graph(edges),targetAccountId:accounts[0]!,nowMs:now});
    expect(edges.length).toBeLessThanOrEqual(500); expect(result.searchSteps).toBe(20000); expect(result.truncated).toBe(true);
  });
  it('never counts old, future or duplicate receipts in cycle volume', () => {
    const edges:GraphEdge[]=[{id:'one',source:'a.testnet',target:'b.testnet',amountYocto:'10',timestamp:now-1,type:'transfer'}, {id:'two',source:'b.testnet',target:'a.testnet',amountYocto:'5',timestamp:now-1,type:'transfer'}];
    const duplicates=[...edges,...edges,{...edges[0]!,id:'old',timestamp:now-8*86400000},{...edges[0]!,id:'future',timestamp:now+1}];
    const result=detectCircularFlow({graph:graph(duplicates),targetAccountId:'a.testnet',nowMs:now});
    expect(result.circularVolumeYocto).toBe('5'); expect(result.totalVolumeYocto).toBe('15');
  });
});
