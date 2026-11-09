import type React from 'react';
import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import {
  getReceiverEvidence,
  getScenarioEvidence,
} from '../src/data/mockReceiverEvidence';
import { EvidenceTimeline } from '../src/views/EvidenceTimeline';

describe('EvidenceTimeline Component Unit Tests (apps/web)', () => {
  describe('View Shell & Default State Rendering', () => {
    it('renders header, title, and inspect target input', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S4" />);
      expect(html).toContain('Receiver Evidence Timeline &amp; Graph Panel');
      expect(html).toContain('Inspect Target');
      expect(html).toContain('Chronological Audit Trail');
      expect(html).toContain('Bounded Graph Traversal Status');
    });

    it('renders all canonical scenario shortcut buttons (S1, S3, S4, S5, S6, S7)', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S1" />);
      expect(html).toContain('S1:');
      expect(html).toContain('merchant.testnet');
      expect(html).toContain('S3:');
      expect(html).toContain('known-drainer.testnet');
      expect(html).toContain('S4:');
      expect(html).toContain('popular-service.testnet');
      expect(html).toContain('S5:');
      expect(html).toContain('wash-trader.testnet');
      expect(html).toContain('S6:');
      expect(html).toContain('user-b.testnet');
      expect(html).toContain('S7:');
      expect(html).toContain('contract.testnet');
    });
  });

  describe('Historical Observations & Contract Code Auditing', () => {
    it('renders clean established history for S1 merchant.testnet', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S1" />);
      expect(html).toContain('merchant.testnet');
      expect(html).toContain('ALLOW');
      expect(html).toContain('182 Days');
      expect(html).toContain('42 Finalized');
      expect(html).toContain('EOA / UNCONTRACTED');
      expect(html).toContain('Account Genesis Activation');
      expect(html).toContain('Clean Report Audit Trail');
    });

    it('renders contract bytecode upgrade comparison for S7 contract.testnet (CODE_CHANGED)', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S7" />);
      expect(html).toContain('contract.testnet');
      expect(html).toContain('WARN');
      expect(html).toContain('CODE_CHANGED: BYTECODE UPGRADED');
      expect(html).toContain('Contract Bytecode Upgrade Detected (Policy Trigger: S7)');

      // Verify previous and current code hashes are both rendered
      expect(html).toContain('3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b');
      expect(html).toContain('7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e');
      expect(html).toContain('v1.0.0');
      expect(html).toContain('v2.0.0');
      expect(html).toContain('48.2 KB, +15.8 KB');
      expect(html).toContain('85 Finalized');
    });

    it('renders fresh account warning for S2 new-vendor.testnet (< 24h old)', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S2" />);
      expect(html).toContain('new-vendor.testnet');
      expect(html).toContain('WARN');
      expect(html).toContain('&lt; 24 Hours');
      expect(html).toContain('Account Genesis Activation (&lt; 24h ago)');
    });
  });

  describe('Report Audit Trails & Active Block Invariant', () => {
    it('renders active hard block banner and review record for S3 known-drainer.testnet', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S3" />);
      expect(html).toContain('known-drainer.testnet');
      expect(html).toContain('BLOCK');
      expect(html).toContain('ACTIVE HARD BLOCK IN EFFECT');
      expect(html).toContain('Revision #7');
      expect(html).toContain('drainer');
      expect(html).toContain('reviewed');
      expect(html).toContain('victim-dao.testnet');
      expect(html).toContain('Drained 150 NEAR via unauthorized transfer');
      expect(html).toContain('CVE-2026-NEAR-01');
      expect(html).toContain(
        'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
    });

    it('renders 20 Sybil allegations with categories and evidence hashes for S4 popular-service.testnet', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S4" />);
      expect(html).toContain('popular-service.testnet');
      expect(html).toContain('ALLOW');
      expect(html).toContain('20 total allegation(s) on file');
      expect(html).toContain('phishing');
      expect(html).toContain('corroborated');
      expect(html).toContain('sybil-1.testnet');
      expect(html).toContain('sybil-2.testnet');
      expect(html).toContain(
        'sha256:a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e',
      );
      expect(html).toContain('Weight: 0.05');
    });
  });

  describe('Bounded Graph Analysis Bounds & Relational Funding', () => {
    it('renders graph coverage metrics and limits (visited accounts, edges, 7-day window)', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S4" />);
      expect(html).toContain('32 / 100 max');
      expect(html).toContain('84 / 500 max');
      expect(html).toContain('7 Days (2 Hops)');
      expect(html).toContain('Truncated: FALSE');
    });

    it('renders relational funding connections breakdown (Hop 1 and Hop 2)', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S4" />);
      expect(html).toContain('Observed Inbound Funding Lineage (2 Hops)');
      expect(html).toContain('Hop 1');
      expect(html).toContain('sybil-parent.testnet');
      expect(html).toContain('sybil-1.testnet');
      expect(html).toContain('0.5 NEAR');
    });
  });

  describe('Circular Loop Flow Explanation (S5 wash-trader.testnet)', () => {
    it('renders CIRCULAR_ACTIVITY warning, score, volume ratio, and closed cycle path', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S5" />);
      expect(html).toContain('wash-trader.testnet');
      expect(html).toContain('WARN');
      expect(html).toContain('Circular Flow Detection (CIRCULAR_ACTIVITY)');
      expect(html).toContain('Score: 65/100');
      expect(html).toContain('85%');
      expect(html).toContain('Reciprocal money flows detected in closed 3-account ring');
      expect(html).toContain(
        'wash-trader.testnet → ring-a.testnet → ring-b.testnet → wash-trader.testnet',
      );
      expect(html).toContain('ring-a.testnet');
      expect(html).toContain('ring-b.testnet');
    });
  });

  describe('Sybil Clustering & Weight Capping (S4 popular-service.testnet)', () => {
    it('renders Sybil clustering panel with common progenitor and 1.0 capped weight', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S4" />);
      expect(html).toContain('Sybil Clustering &amp; Weight Capping');
      expect(html).toContain('Capped: 1.0 Max');
      expect(html).toContain('sybil-parent.testnet');
      expect(html).toContain('20 accounts');
      expect(html).toContain('1.0 (0.05 per report)');
      expect(html).toContain(
        'Coordinated Sybil floods cannot trigger a hard block without authenticated human reviewer action',
      );
    });
  });

  describe('Common Faucet Exemption Control (S6 user-b.testnet)', () => {
    it('renders Common Faucet Exemption Active banner for faucet.testnet funding', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S6" />);
      expect(html).toContain('user-b.testnet');
      expect(html).toContain('ALLOW');
      expect(html).toContain('Common Faucet Exemption Active');
      expect(html).toContain('faucet.testnet');
      expect(html).toContain(
        'Funding edges connected to faucet.testnet are exempted from clustering',
      );
      expect(html).toContain('Legitimate shared testnet infrastructure is never penalized');
    });
  });

  describe('Custom Target Account & Dynamic Evaluation Fallback', () => {
    it('renders dynamic heuristic assessment for custom target account', () => {
      const html = renderToString(
        <EvidenceTimeline initialTargetAccountId="custom-vendor.testnet" />,
      );
      expect(html).toContain('custom-vendor.testnet');
      expect(html).toContain('Inspecting dynamic target: custom-vendor.testnet');
    });

    it('dynamically flags malicious keywords with ACTIVE_BLOCK in custom mode', () => {
      const html = renderToString(
        <EvidenceTimeline initialTargetAccountId="phishing-fake.testnet" />,
      );
      expect(html).toContain('phishing-fake.testnet');
      expect(html).toContain('BLOCK');
      expect(html).toContain('ACTIVE HARD BLOCK IN EFFECT');
      expect(html).toContain('drainer');
    });
  });

  describe('Data Adapter Fixtures & Integrity', () => {
    it('provides non-null evidence fixtures for all canonical scenarios S1 through S10', () => {
      const scenarios = ['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9', 'S10'] as const;
      for (const id of scenarios) {
        const evidence = getScenarioEvidence(id);
        expect(evidence).toBeDefined();
        expect(evidence.accountId).toBeTruthy();
        expect(evidence.decision).toMatch(/allow|warn|block|error/);
        expect(evidence.coverage.windowDays).toBe(7);
        expect(evidence.historical.accountAgeDays).toBeGreaterThanOrEqual(0);
      }
    });

    it('resolves evidence by account ID accurately', () => {
      expect(getReceiverEvidence('merchant.testnet').decision).toBe('allow');
      expect(getReceiverEvidence('known-drainer.testnet').decision).toBe('block');
      expect(getReceiverEvidence('wash-trader.testnet').decision).toBe('warn');
      expect(getReceiverEvidence('user-b.testnet').faucetExemption.isExempted).toBe(true);
      expect(getReceiverEvidence('contract.testnet').historical.codeHashChanged).toBe(true);
    });
  });
});
