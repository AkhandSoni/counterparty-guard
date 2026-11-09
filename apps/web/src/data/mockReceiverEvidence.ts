/**
 * @file apps/web/src/data/mockReceiverEvidence.ts
 * @description Deterministic scenario datasets and evidence provider for Receiver Evidence Timeline & Graph UI.
 */

import type { ScenarioId } from '@counterparty-guard/shared/demo';
import type {
  Network,
  ReceiverEvidenceData,
} from '../types';

export const SCENARIO_RECEIVER_EVIDENCE: Record<ScenarioId, ReceiverEvidenceData> = {
  S1: {
    accountId: 'merchant.testnet',
    network: 'testnet',
    decision: 'allow',
    riskScore: 5,
    reasonCodes: [],
    isBlocked: false,
    historical: {
      firstSeenTimestamp: '2026-05-10T08:00:00Z',
      accountAgeDays: 182,
      isContract: false,
      currentCodeHash: null,
      codeHashChanged: false,
      deploymentTimestamp: null,
      lastInteractionTimestamp: '2026-11-06T15:20:00Z',
      interactionCount: 42,
    },
    events: [
      {
        id: 's1-e1',
        timestamp: '2026-05-10T08:00:00Z',
        type: 'creation',
        title: 'Account Genesis Activation',
        description: 'Account activated with 25.0 NEAR deposit from merchant-hq.testnet.',
        txHash: '8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c',
      },
      {
        id: 's1-e2',
        timestamp: '2026-08-14T11:30:00Z',
        type: 'interaction',
        title: 'First Guarded Vault Transfer Finalized',
        description: 'Agent transferred 0.5 NEAR for automated catalog sync services.',
        txHash: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
      },
      {
        id: 's1-e3',
        timestamp: '2026-11-06T15:20:00Z',
        type: 'interaction',
        title: 'Guarded Vault Transfer Finalized',
        description: 'Agent transferred 0.1 NEAR. Routine service execution completed on-chain.',
        txHash: '4Kz8mQp9v2x1...execute',
      },
    ],
    reports: [],
    coverage: {
      accountsVisited: 18,
      edgesTraversed: 45,
      windowDays: 7,
      truncated: false,
    },
    fundingConnections: [
      {
        source: 'merchant-hq.testnet',
        target: 'merchant.testnet',
        amountNear: '25.0',
        timestamp: '2026-05-10T08:00:00Z',
        txHash: '8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c',
        hopLevel: 1,
        isFaucet: false,
        description: 'Initial seed deposit',
      },
      {
        source: 'investor-dao.testnet',
        target: 'merchant-hq.testnet',
        amountNear: '1000.0',
        timestamp: '2026-04-01T10:00:00Z',
        txHash: '5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f',
        hopLevel: 2,
        isFaucet: false,
        description: 'Ecosystem grant funding',
      },
    ],
    circularFlow: {
      detected: false,
      score: 0,
      ringAccounts: [],
      circularVolumePercent: 0,
      discountPenalty: 'None',
      cyclePaths: [],
    },
    dependenceGroup: null,
    faucetExemption: {
      isExempted: false,
      notes: 'Direct independent funding lineage. Clean institutional origin.',
    },
  },

  S2: {
    accountId: 'new-vendor.testnet',
    network: 'testnet',
    decision: 'warn',
    riskScore: 45,
    reasonCodes: ['RECENT_DEPLOYMENT', 'UNKNOWN_AGE'],
    isBlocked: false,
    historical: {
      firstSeenTimestamp: '2026-11-07T22:30:00Z',
      accountAgeDays: 0.25,
      isContract: false,
      currentCodeHash: null,
      codeHashChanged: false,
      deploymentTimestamp: null,
      lastInteractionTimestamp: null,
      interactionCount: 0,
    },
    events: [
      {
        id: 's2-e1',
        timestamp: '2026-11-07T22:30:00Z',
        type: 'creation',
        title: 'Account Genesis Activation (< 24h ago)',
        description: 'Account created with 2.0 NEAR initial deposit from creator-wallet.testnet.',
        txHash: '2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d',
      },
    ],
    reports: [],
    coverage: {
      accountsVisited: 4,
      edgesTraversed: 3,
      windowDays: 7,
      truncated: false,
    },
    fundingConnections: [
      {
        source: 'creator-wallet.testnet',
        target: 'new-vendor.testnet',
        amountNear: '2.0',
        timestamp: '2026-11-07T22:30:00Z',
        txHash: '2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d',
        hopLevel: 1,
        isFaucet: false,
      },
    ],
    circularFlow: {
      detected: false,
      score: 0,
      ringAccounts: [],
      circularVolumePercent: 0,
      discountPenalty: 'None',
      cyclePaths: [],
    },
    dependenceGroup: null,
    faucetExemption: {
      isExempted: false,
      notes: 'No faucet connections observed in recent 1-hop lineage.',
    },
  },

  S3: {
    accountId: 'known-drainer.testnet',
    network: 'testnet',
    decision: 'block',
    riskScore: 100,
    reasonCodes: ['ACTIVE_BLOCK', 'REVIEWED_BLOCKLIST_MATCH'],
    isBlocked: true,
    blockReason:
      'Confirmed on-chain drain pattern matching exploit CVE-2026-NEAR-01; active blocklist entry added at revision #7.',
    blocklistRevision: 7,
    historical: {
      firstSeenTimestamp: '2026-10-01T10:00:00Z',
      accountAgeDays: 38,
      isContract: true,
      currentCodeHash: '7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e',
      codeHashChanged: false,
      deploymentTimestamp: '2026-10-01T10:15:00Z',
      lastInteractionTimestamp: '2026-10-25T14:00:00Z',
      interactionCount: 3,
      bytecodeSizeBytes: 52400,
    },
    events: [
      {
        id: 's3-e1',
        timestamp: '2026-10-01T10:00:00Z',
        type: 'creation',
        title: 'Account Creation',
        description: 'Created via proxy funding from mixer-gateway.testnet.',
        txHash: '9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
      },
      {
        id: 's3-e2',
        timestamp: '2026-10-01T10:15:00Z',
        type: 'deployment',
        title: 'Malicious Bytecode Deployed',
        description:
          'SHA256: 7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e (52.4 KB)',
        codeHash: '7d8e9f...7d8e',
      },
      {
        id: 's3-e3',
        timestamp: '2026-10-25T18:00:00Z',
        type: 'report',
        title: 'Critical Report Reviewed: Hard Block Activated',
        description:
          'Reviewer moderator.testnet activated hard block for confirmed unauthorized drain.',
        txHash: '3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d',
      },
    ],
    reports: [
      {
        id: 'rep_drainer_001',
        accusedAccountId: 'known-drainer.testnet',
        reporterId: 'victim-dao.testnet',
        category: 'drainer',
        description:
          'Drained 150 NEAR via unauthorized transfer after spoofing vendor invoice callback.',
        status: 'reviewed',
        evidenceHashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
        txReferences: ['9ZpQ7wK4xYz1...drain_tx'],
        issuedAt: Date.parse('2026-10-25T17:00:00Z'),
        effectiveWeight: 1.0,
      },
    ],
    coverage: {
      accountsVisited: 8,
      edgesTraversed: 14,
      windowDays: 7,
      truncated: false,
    },
    fundingConnections: [
      {
        source: 'mixer-gateway.testnet',
        target: 'known-drainer.testnet',
        amountNear: '25.0',
        timestamp: '2026-10-01T10:00:00Z',
        txHash: '9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
        hopLevel: 1,
        isFaucet: false,
        description: 'High-risk unverified mixer account funding',
      },
    ],
    circularFlow: {
      detected: false,
      score: 0,
      ringAccounts: [],
      circularVolumePercent: 0,
      discountPenalty: 'None',
      cyclePaths: [],
    },
    dependenceGroup: null,
    faucetExemption: {
      isExempted: false,
      notes: 'No faucet exemption. Target flagged on active blocklist.',
    },
  },

  S4: {
    accountId: 'popular-service.testnet',
    network: 'testnet',
    decision: 'allow',
    riskScore: 20,
    reasonCodes: ['DEPENDENT_REPORTS'],
    isBlocked: false,
    historical: {
      firstSeenTimestamp: '2026-03-15T12:00:00Z',
      accountAgeDays: 238,
      isContract: true,
      currentCodeHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      codeHashChanged: false,
      deploymentTimestamp: '2026-03-15T12:30:00Z',
      lastInteractionTimestamp: '2026-11-07T18:00:00Z',
      interactionCount: 142,
      bytecodeSizeBytes: 48200,
    },
    events: [
      {
        id: 's4-e1',
        timestamp: '2026-03-15T12:00:00Z',
        type: 'creation',
        title: 'Account Genesis Activation',
        description: 'Popular decentralized oracle service deployed on NEAR testnet.',
        txHash: '1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e',
      },
      {
        id: 's4-e2',
        timestamp: '2026-03-15T12:30:00Z',
        type: 'deployment',
        title: 'Contract Bytecode Deployed (v1.0.0)',
        description:
          'SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (48.2 KB)',
        codeHash: 'e3b0c4...855',
      },
      {
        id: 's4-e3',
        timestamp: '2026-11-07T12:00:00Z',
        type: 'report',
        title: 'Coordinated Allegation Flood Ingested',
        description:
          '20 correlated allegations submitted within 1 hour sharing common funder sybil-parent.testnet.',
      },
    ],
    reports: [
      {
        id: 'rep_sybil_01',
        accusedAccountId: 'popular-service.testnet',
        reporterId: 'sybil-1.testnet',
        category: 'phishing',
        description: 'Allegation: Service frontend redirected wallet approvals to malicious proxy.',
        status: 'corroborated',
        evidenceHashes: ['a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e'],
        txReferences: ['tx:sybil_claim_01'],
        issuedAt: Date.parse('2026-11-07T12:05:00Z'),
        dependenceGroupId: 'group_funder_sybil_parent',
        effectiveWeight: 0.05,
      },
      {
        id: 'rep_sybil_02',
        accusedAccountId: 'popular-service.testnet',
        reporterId: 'sybil-2.testnet',
        category: 'phishing',
        description: 'Allegation: Duplicate report alleging phishing signature requests.',
        status: 'corroborated',
        evidenceHashes: ['a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e'],
        txReferences: ['tx:sybil_claim_02'],
        issuedAt: Date.parse('2026-11-07T12:08:00Z'),
        dependenceGroupId: 'group_funder_sybil_parent',
        effectiveWeight: 0.05,
      },
      {
        id: 'rep_sybil_03',
        accusedAccountId: 'popular-service.testnet',
        reporterId: 'sybil-3.testnet',
        category: 'phishing',
        description: 'Allegation: Automated report flood submission.',
        status: 'corroborated',
        evidenceHashes: ['a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e'],
        txReferences: [],
        issuedAt: Date.parse('2026-11-07T12:12:00Z'),
        dependenceGroupId: 'group_funder_sybil_parent',
        effectiveWeight: 0.05,
      },
      {
        id: 'rep_sybil_04',
        accusedAccountId: 'popular-service.testnet',
        reporterId: 'sybil-4.testnet',
        category: 'drainer',
        description: 'Allegation: Coordinated flood claim 4 of 20.',
        status: 'corroborated',
        evidenceHashes: ['a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e'],
        txReferences: [],
        issuedAt: Date.parse('2026-11-07T12:15:00Z'),
        dependenceGroupId: 'group_funder_sybil_parent',
        effectiveWeight: 0.05,
      },
      {
        id: 'rep_sybil_05',
        accusedAccountId: 'popular-service.testnet',
        reporterId: 'sybil-5.testnet',
        category: 'drainer',
        description: 'Allegation: Coordinated flood claim 5 of 20.',
        status: 'corroborated',
        evidenceHashes: ['a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e'],
        txReferences: [],
        issuedAt: Date.parse('2026-11-07T12:18:00Z'),
        dependenceGroupId: 'group_funder_sybil_parent',
        effectiveWeight: 0.05,
      },
    ],
    coverage: {
      accountsVisited: 32,
      edgesTraversed: 84,
      windowDays: 7,
      truncated: false,
    },
    fundingConnections: [
      {
        source: 'sybil-parent.testnet',
        target: 'sybil-1.testnet',
        amountNear: '0.5',
        timestamp: '2026-11-07T11:00:00Z',
        txHash: '7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d',
        hopLevel: 1,
        isFaucet: false,
        description: 'Sybil cluster funding branch 1',
      },
      {
        source: 'sybil-parent.testnet',
        target: 'sybil-2.testnet',
        amountNear: '0.5',
        timestamp: '2026-11-07T11:02:00Z',
        txHash: '8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e',
        hopLevel: 1,
        isFaucet: false,
        description: 'Sybil cluster funding branch 2',
      },
    ],
    circularFlow: {
      detected: false,
      score: 0,
      ringAccounts: [],
      circularVolumePercent: 0,
      discountPenalty: 'None',
      cyclePaths: [],
    },
    dependenceGroup: {
      groupId: 'group_funder_sybil_parent',
      commonFunder: 'sybil-parent.testnet',
      memberReporters: [
        'sybil-1.testnet',
        'sybil-2.testnet',
        'sybil-3.testnet',
        'sybil-4.testnet',
        'sybil-5.testnet',
        'sybil-6.testnet',
        'sybil-7.testnet',
        'sybil-8.testnet',
        'sybil-9.testnet',
        'sybil-10.testnet',
        'sybil-11.testnet',
        'sybil-12.testnet',
        'sybil-13.testnet',
        'sybil-14.testnet',
        'sybil-15.testnet',
        'sybil-16.testnet',
        'sybil-17.testnet',
        'sybil-18.testnet',
        'sybil-19.testnet',
        'sybil-20.testnet',
      ],
      rawCount: 20,
      effectiveWeight: 1.0,
      discountFactor: 0.05,
      discountReason:
        '20 correlated allegations share common funding progenitor sybil-parent.testnet within 7-day window. Weight capped to 1.0 independent source; cannot trigger hard block.',
      faucetExempted: false,
    },
    faucetExemption: {
      isExempted: false,
      notes: 'Common progenitor sybil-parent.testnet is a private non-faucet wallet.',
    },
  },

  S5: {
    accountId: 'wash-trader.testnet',
    network: 'testnet',
    decision: 'warn',
    riskScore: 65,
    reasonCodes: ['CIRCULAR_ACTIVITY'],
    isBlocked: false,
    historical: {
      firstSeenTimestamp: '2026-09-01T00:00:00Z',
      accountAgeDays: 68,
      isContract: false,
      currentCodeHash: null,
      codeHashChanged: false,
      deploymentTimestamp: null,
      lastInteractionTimestamp: '2026-11-08T02:00:00Z',
      interactionCount: 18,
    },
    events: [
      {
        id: 's5-e1',
        timestamp: '2026-09-01T00:00:00Z',
        type: 'creation',
        title: 'Account Creation',
        description: 'Account activated with 15.0 NEAR deposit.',
        txHash: '4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b',
      },
      {
        id: 's5-e2',
        timestamp: '2026-11-08T01:30:00Z',
        type: 'interaction',
        title: 'Closed Ring Money Flow Observed',
        description:
          'Transferred 10.0 NEAR to ring-a.testnet, which transferred 9.9 NEAR to ring-b.testnet, which returned 9.8 NEAR.',
        txHash: '5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f',
      },
    ],
    reports: [
      {
        id: 'rep_wash_01',
        accusedAccountId: 'wash-trader.testnet',
        reporterId: 'indexer-sentinel.testnet',
        category: 'wash_trading',
        description:
          'Automated on-chain detector observed reciprocal 3-account ring transfer loop.',
        status: 'submitted',
        evidenceHashes: ['c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4'],
        txReferences: ['tx:ring_step1_10near', 'tx:ring_step2_99near', 'tx:ring_step3_98near'],
        issuedAt: Date.parse('2026-11-08T02:00:00Z'),
        effectiveWeight: 1.0,
      },
    ],
    coverage: {
      accountsVisited: 12,
      edgesTraversed: 28,
      windowDays: 7,
      truncated: false,
    },
    fundingConnections: [
      {
        source: 'wash-trader.testnet',
        target: 'ring-a.testnet',
        amountNear: '10.0',
        timestamp: '2026-11-08T01:30:00Z',
        txHash: 'tx_loop_hop1',
        hopLevel: 1,
        isFaucet: false,
        description: 'Cycle Hop 1: wash-trader -> ring-a',
      },
      {
        source: 'ring-a.testnet',
        target: 'ring-b.testnet',
        amountNear: '9.9',
        timestamp: '2026-11-08T01:35:00Z',
        txHash: 'tx_loop_hop2',
        hopLevel: 2,
        isFaucet: false,
        description: 'Cycle Hop 2: ring-a -> ring-b',
      },
      {
        source: 'ring-b.testnet',
        target: 'wash-trader.testnet',
        amountNear: '9.8',
        timestamp: '2026-11-08T01:40:00Z',
        txHash: 'tx_loop_hop3',
        hopLevel: 1,
        isFaucet: false,
        description: 'Cycle Hop 3: ring-b -> wash-trader (Loop Closed)',
      },
    ],
    circularFlow: {
      detected: true,
      score: 65,
      ringAccounts: ['wash-trader.testnet', 'ring-a.testnet', 'ring-b.testnet'],
      circularVolumePercent: 85,
      discountPenalty:
        'Reciprocal money flows detected in closed 3-account ring; transaction credit penalized.',
      cyclePaths: ['wash-trader.testnet → ring-a.testnet → ring-b.testnet → wash-trader.testnet'],
    },
    dependenceGroup: null,
    faucetExemption: {
      isExempted: false,
      notes: 'Ring transfers occur between private colluding wallets.',
    },
  },

  S6: {
    accountId: 'user-b.testnet',
    network: 'testnet',
    decision: 'allow',
    riskScore: 10,
    reasonCodes: ['COMMON_FAUCET_EXEMPTED'],
    isBlocked: false,
    historical: {
      firstSeenTimestamp: '2026-10-10T14:00:00Z',
      accountAgeDays: 29,
      isContract: false,
      currentCodeHash: null,
      codeHashChanged: false,
      deploymentTimestamp: null,
      lastInteractionTimestamp: '2026-11-07T16:00:00Z',
      interactionCount: 8,
    },
    events: [
      {
        id: 's6-e1',
        timestamp: '2026-10-10T14:00:00Z',
        type: 'creation',
        title: 'Account Funded via Testnet Faucet',
        description:
          'Account created and funded with 10.0 NEAR testnet tokens from faucet.testnet.',
        txHash: '6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b',
      },
      {
        id: 's6-e2',
        timestamp: '2026-11-07T16:00:00Z',
        type: 'interaction',
        title: 'Guarded Vault Transfer Finalized',
        description: '0.05 NEAR transferred without error.',
        txHash: '7b8c9d0e1f2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e',
      },
    ],
    reports: [],
    coverage: {
      accountsVisited: 15,
      edgesTraversed: 22,
      windowDays: 7,
      truncated: false,
    },
    fundingConnections: [
      {
        source: 'faucet.testnet',
        target: 'user-b.testnet',
        amountNear: '10.0',
        timestamp: '2026-10-10T14:00:00Z',
        txHash: '6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b',
        hopLevel: 1,
        isFaucet: true,
        description: 'Official testnet faucet distribution',
      },
    ],
    circularFlow: {
      detected: false,
      score: 0,
      ringAccounts: [],
      circularVolumePercent: 0,
      discountPenalty: 'None',
      cyclePaths: [],
    },
    dependenceGroup: null,
    faucetExemption: {
      isExempted: true,
      faucetAccountId: 'faucet.testnet',
      label: 'Official NEAR Testnet Faucet',
      exemptionType: 'faucet',
      notes:
        'Funding edges connected to faucet.testnet are exempted from clustering. Legitimate shared testnet infrastructure is never penalized.',
    },
  },

  S7: {
    accountId: 'contract.testnet',
    network: 'testnet',
    decision: 'warn',
    riskScore: 55,
    reasonCodes: ['CODE_CHANGED'],
    isBlocked: false,
    historical: {
      firstSeenTimestamp: '2026-06-01T00:00:00Z',
      accountAgeDays: 160,
      isContract: true,
      previousCodeHash: '3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b',
      currentCodeHash: '7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e',
      codeHashChanged: true,
      deploymentTimestamp: '2026-06-01T01:00:00Z',
      upgradeTimestamp: '2026-11-08T03:30:00Z',
      lastInteractionTimestamp: '2026-11-08T03:30:00Z',
      interactionCount: 85,
      bytecodeSizeBytes: 48200,
      upgradeReason:
        'Contract bytecode hash updated since prior interaction; requires human owner re-approval before execution.',
    },
    events: [
      {
        id: 's7-e1',
        timestamp: '2026-06-01T00:00:00Z',
        type: 'creation',
        title: 'Contract Account Genesis',
        description: 'Deployed with 50.0 NEAR initial balance.',
        txHash: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
      },
      {
        id: 's7-e2',
        timestamp: '2026-06-01T01:00:00Z',
        type: 'deployment',
        title: 'Initial Contract Bytecode Deployed (v1.0.0)',
        description:
          'Bytecode SHA256: 3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b (32.4 KB)',
        codeHash: '3a4b5c...a4b',
      },
      {
        id: 's7-e3',
        timestamp: '2026-11-08T03:30:00Z',
        type: 'deployment',
        title: 'Contract Bytecode Upgraded to v2.0.0 (CODE_CHANGED)',
        description:
          'New SHA256: 7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e (48.2 KB). Security policy requires owner warning re-approval.',
        codeHash: '7f8e9d...f8e',
      },
    ],
    reports: [],
    coverage: {
      accountsVisited: 10,
      edgesTraversed: 16,
      windowDays: 7,
      truncated: false,
    },
    fundingConnections: [
      {
        source: 'dao-deployer.testnet',
        target: 'contract.testnet',
        amountNear: '50.0',
        timestamp: '2026-06-01T00:00:00Z',
        txHash: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
        hopLevel: 1,
        isFaucet: false,
      },
    ],
    circularFlow: {
      detected: false,
      score: 0,
      ringAccounts: [],
      circularVolumePercent: 0,
      discountPenalty: 'None',
      cyclePaths: [],
    },
    dependenceGroup: null,
    faucetExemption: {
      isExempted: false,
      notes: 'Private DAO deployment funding lineage.',
    },
  },

  S8: {
    accountId: 'merchant.testnet',
    network: 'testnet',
    decision: 'error',
    riskScore: 90,
    reasonCodes: ['POLICY_LIMIT_EXCEEDED'],
    isBlocked: false,
    historical: {
      firstSeenTimestamp: '2026-05-10T08:00:00Z',
      accountAgeDays: 182,
      isContract: false,
      currentCodeHash: null,
      codeHashChanged: false,
      deploymentTimestamp: null,
      lastInteractionTimestamp: '2026-11-08T04:00:00Z',
      interactionCount: 42,
    },
    events: [
      {
        id: 's8-e1',
        timestamp: '2026-11-08T04:00:00Z',
        type: 'interaction',
        title: 'Permit Replay Rejected On-Chain',
        description:
          'Vault contract refused transaction: permit parameters mutated or exceeded max limit.',
      },
    ],
    reports: [],
    coverage: {
      accountsVisited: 5,
      edgesTraversed: 8,
      windowDays: 7,
      truncated: false,
    },
    fundingConnections: [],
    circularFlow: {
      detected: false,
      score: 0,
      ringAccounts: [],
      circularVolumePercent: 0,
      discountPenalty: 'None',
      cyclePaths: [],
    },
    dependenceGroup: null,
    faucetExemption: {
      isExempted: false,
      notes: 'No faucet connections involved.',
    },
  },

  S9: {
    accountId: 'unknown-target.testnet',
    network: 'testnet',
    decision: 'error',
    riskScore: 0,
    reasonCodes: ['INCOMPLETE_HISTORY', 'MANDATORY_SOURCE_UNAVAILABLE'],
    isBlocked: false,
    historical: {
      firstSeenTimestamp: 'Unknown',
      accountAgeDays: 0,
      isContract: false,
      currentCodeHash: null,
      codeHashChanged: false,
      deploymentTimestamp: null,
      lastInteractionTimestamp: null,
      interactionCount: 0,
    },
    events: [
      {
        id: 's9-e1',
        timestamp: '2026-11-08T04:10:00Z',
        type: 'interaction',
        title: 'Provider Timeout (Fail-Closed)',
        description:
          'Mandatory NEAR RPC provider unreachable after 60s timeout. Fail-closed without permit.',
      },
    ],
    reports: [],
    coverage: {
      accountsVisited: 0,
      edgesTraversed: 0,
      windowDays: 7,
      truncated: true,
    },
    fundingConnections: [],
    circularFlow: {
      detected: false,
      score: 0,
      ringAccounts: [],
      circularVolumePercent: 0,
      discountPenalty: 'None',
      cyclePaths: [],
    },
    dependenceGroup: null,
    faucetExemption: {
      isExempted: false,
      notes: 'Provider unreachable; historical data truncated.',
    },
  },

  S10: {
    accountId: 'fixture.testnet',
    network: 'testnet',
    decision: 'allow',
    riskScore: 5,
    reasonCodes: [],
    isBlocked: false,
    historical: {
      firstSeenTimestamp: '2026-07-20T10:00:00Z',
      accountAgeDays: 110,
      isContract: true,
      currentCodeHash: '4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b',
      codeHashChanged: false,
      deploymentTimestamp: '2026-07-20T10:30:00Z',
      lastInteractionTimestamp: '2026-11-08T01:00:00Z',
      interactionCount: 33,
      bytecodeSizeBytes: 39500,
    },
    events: [
      {
        id: 's10-e1',
        timestamp: '2026-07-20T10:00:00Z',
        type: 'creation',
        title: 'Contract Created',
        description: 'Configured allowlisted service fixture contract.',
      },
      {
        id: 's10-e2',
        timestamp: '2026-07-20T10:30:00Z',
        type: 'deployment',
        title: 'Allowlisted Bytecode Deployed',
        description:
          'SHA256: 4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b (39.5 KB)',
        codeHash: '4a5b6c...a5b',
      },
    ],
    reports: [],
    coverage: {
      accountsVisited: 6,
      edgesTraversed: 11,
      windowDays: 7,
      truncated: false,
    },
    fundingConnections: [
      {
        source: 'registrar.testnet',
        target: 'fixture.testnet',
        amountNear: '10.0',
        timestamp: '2026-07-20T10:00:00Z',
        txHash: '0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b',
        hopLevel: 1,
        isFaucet: false,
      },
    ],
    circularFlow: {
      detected: false,
      score: 0,
      ringAccounts: [],
      circularVolumePercent: 0,
      discountPenalty: 'None',
      cyclePaths: [],
    },
    dependenceGroup: null,
    faucetExemption: {
      isExempted: false,
      notes: 'Standard ecosystem contract deployer funding.',
    },
  },
};

/**
 * Generates dynamic synthetic evidence for any custom user account.
 */
export function generateCustomReceiverEvidence(
  accountId: string,
  network: Network = 'testnet',
): ReceiverEvidenceData {
  const cleanAccount = accountId.trim().toLowerCase();
  const isMalicious =
    cleanAccount.includes('drain') ||
    cleanAccount.includes('phish') ||
    cleanAccount.includes('exploit') ||
    cleanAccount.includes('scam');
  const isUpgraded = cleanAccount.includes('upgrade') || cleanAccount.includes('newcode');
  const isCircular = cleanAccount.includes('circle') || cleanAccount.includes('wash');
  const isFaucet = cleanAccount.includes('faucet');

  return {
    accountId: cleanAccount,
    network,
    decision: isMalicious ? 'block' : isUpgraded || isCircular ? 'warn' : 'allow',
    riskScore: isMalicious ? 100 : isUpgraded ? 55 : isCircular ? 65 : 15,
    reasonCodes: isMalicious
      ? ['ACTIVE_BLOCK', 'REVIEWED_BLOCKLIST_MATCH']
      : isUpgraded
        ? ['CODE_CHANGED']
        : isCircular
          ? ['CIRCULAR_ACTIVITY']
          : isFaucet
            ? ['COMMON_FAUCET_EXEMPTED']
            : [],
    isBlocked: isMalicious,
    blockReason: isMalicious
      ? 'Flagged via automated keyword heuristics in custom mode.'
      : undefined,
    historical: {
      firstSeenTimestamp: '2026-10-15T12:00:00Z',
      accountAgeDays: 24,
      isContract: isUpgraded || cleanAccount.startsWith('contract'),
      currentCodeHash: isUpgraded
        ? '7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e'
        : null,
      previousCodeHash: isUpgraded
        ? '3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b'
        : null,
      codeHashChanged: isUpgraded,
      deploymentTimestamp: isUpgraded ? '2026-10-15T12:30:00Z' : null,
      lastInteractionTimestamp: '2026-11-07T10:00:00Z',
      interactionCount: 5,
      bytecodeSizeBytes: isUpgraded ? 48200 : undefined,
      upgradeReason: isUpgraded ? 'Dynamic bytecode revision detected.' : undefined,
    },
    events: [
      {
        id: 'cust-e1',
        timestamp: '2026-10-15T12:00:00Z',
        type: 'creation',
        title: 'Custom Account Inspected',
        description: `Inspecting dynamic target: ${cleanAccount}`,
      },
    ],
    reports: isMalicious
      ? [
          {
            id: 'rep_cust_01',
            accusedAccountId: cleanAccount,
            reporterId: 'moderator.testnet',
            category: 'drainer',
            description: 'Heuristically blocked adversary account.',
            status: 'reviewed',
            evidenceHashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
            txReferences: [],
            issuedAt: Date.now() - 3600000,
            effectiveWeight: 1.0,
          },
        ]
      : [],
    coverage: {
      accountsVisited: 8,
      edgesTraversed: 15,
      windowDays: 7,
      truncated: false,
    },
    fundingConnections: [
      {
        source: isFaucet ? 'faucet.testnet' : 'funder.testnet',
        target: cleanAccount,
        amountNear: '5.0',
        timestamp: '2026-10-15T12:00:00Z',
        txHash: 'tx_custom_funder',
        hopLevel: 1,
        isFaucet,
      },
    ],
    circularFlow: {
      detected: isCircular,
      score: isCircular ? 65 : 0,
      ringAccounts: isCircular ? [cleanAccount, 'ring-a.testnet', 'ring-b.testnet'] : [],
      circularVolumePercent: isCircular ? 85 : 0,
      discountPenalty: isCircular ? 'Reciprocal loop volume penalized.' : 'None',
      cyclePaths: isCircular
        ? [`${cleanAccount} → ring-a.testnet → ring-b.testnet → ${cleanAccount}`]
        : [],
    },
    dependenceGroup: null,
    faucetExemption: {
      isExempted: isFaucet,
      faucetAccountId: isFaucet ? 'faucet.testnet' : undefined,
      label: isFaucet ? 'Official Testnet Faucet' : undefined,
      notes: isFaucet ? 'Faucet exemption active.' : 'Standard funding.',
    },
  };
}

/**
 * Returns scenario receiver evidence or resolves by account ID.
 */
export function getReceiverEvidence(
  accountId: string,
  network: Network = 'testnet',
): ReceiverEvidenceData {
  const clean = accountId.trim().toLowerCase();

  // Match canonical scenario target accounts
  if (clean === 'merchant.testnet') return SCENARIO_RECEIVER_EVIDENCE.S1;
  if (clean === 'new-vendor.testnet') return SCENARIO_RECEIVER_EVIDENCE.S2;
  if (clean === 'known-drainer.testnet') return SCENARIO_RECEIVER_EVIDENCE.S3;
  if (clean === 'popular-service.testnet') return SCENARIO_RECEIVER_EVIDENCE.S4;
  if (clean === 'wash-trader.testnet') return SCENARIO_RECEIVER_EVIDENCE.S5;
  if (clean === 'user-b.testnet') return SCENARIO_RECEIVER_EVIDENCE.S6;
  if (clean === 'contract.testnet') return SCENARIO_RECEIVER_EVIDENCE.S7;
  if (clean === 'unknown-target.testnet') return SCENARIO_RECEIVER_EVIDENCE.S9;
  if (clean === 'fixture.testnet') return SCENARIO_RECEIVER_EVIDENCE.S10;

  return generateCustomReceiverEvidence(clean, network);
}

/**
 * Returns receiver evidence for a specific scenario ID (S1–S10).
 */
export function getScenarioEvidence(scenarioId: ScenarioId): ReceiverEvidenceData {
  const match = SCENARIO_RECEIVER_EVIDENCE[scenarioId];
  if (!match) {
    throw new Error(`Scenario ID "${scenarioId}" not found in receiver evidence fixtures.`);
  }
  return match;
}
