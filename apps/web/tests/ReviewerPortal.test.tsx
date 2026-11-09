import React from 'react';
import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { type BlocklistRevisionItem, ReviewerPortal } from '../src/views/ReviewerPortal';

describe('ReviewerPortal Component (apps/web/views/ReviewerPortal)', () => {
  describe('1. Reviewer Authentication Header & Session Management', () => {
    it('renders authenticated session by default with reviewer authority indicator', () => {
      const html = renderToString(<ReviewerPortal />);

      expect(html).toContain('Reviewer Moderation Portal');
      expect(html).toContain('Authenticated Session:');
      expect(html).toContain('moderator.testnet');
      expect(html).toContain('Security Officer / Reviewer Authority');
      expect(html).toContain('Blocklist Revision: #7');
      expect(html).toContain('✓ Reviewer Authenticated');
    });

    it('renders 403 Forbidden state when switched to automated agent session', () => {
      const html = renderToString(<ReviewerPortal initialSessionMode="unauthenticated_agent" />);

      expect(html).toContain('Autonomous Agent Session: agent.testnet');
      expect(html).toContain('Intake Only — No Review Authority');
      expect(html).toContain('✕ Unauthenticated Agent (403)');
      // Submit button must be disabled for unauthenticated agents
      expect(html).toContain('403 Forbidden (Reviewer Auth Required)');
      expect(html).toContain('disabled=""');
    });
  });

  describe('2. Moderation Queue Lifecycle Coverage (submitted, verified, corroborated)', () => {
    it('renders all reviewable report states in the moderation queue', () => {
      const html = renderToString(<ReviewerPortal />);

      // Queue Section Header
      expect(html).toContain('Pending Allegations Queue');

      // Filter tabs
      expect(html).toContain('All');
      expect(html).toContain('Submitted');
      expect(html).toContain('Verified');
      expect(html).toContain('Corroborated');

      // State 1: corroborated report
      expect(html).toContain('known-drainer.testnet');
      expect(html).toContain('drainer');
      expect(html).toContain('corroborated');
      expect(html).toContain('reporter1.testnet');
      expect(html).toContain('Group: dep_group_alpha');

      // State 2: submitted report
      expect(html).toContain('phishing-target.testnet');
      expect(html).toContain('phishing');
      expect(html).toContain('submitted');
      expect(html).toContain('reporter2.testnet');

      // State 3: references_verified report
      expect(html).toContain('exploitative-vault.testnet');
      expect(html).toContain('malicious_contract');
      expect(html).toContain('references_verified');
      expect(html).toContain('auditor.testnet');
    });

    it('renders evidence references and tx hashes for selected report', () => {
      const html = renderToString(<ReviewerPortal />);

      expect(html).toContain('Evidence References (rep_001)');
      expect(html).toContain('9ZpQ7wKmT42vNx87YkL59a12b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2');
      expect(html).toContain('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });
  });

  describe('3. Decision Actions & Scope Selection Form Controls', () => {
    it('provides decision choices: active_block, corroborated, dismissed', () => {
      const html = renderToString(<ReviewerPortal />);

      expect(html).toContain('Moderator Decision Action');
      expect(html).toContain('value="active_block"');
      expect(html).toContain('Activate Hard Block (active_block)');
      expect(html).toContain('value="corroborated"');
      expect(html).toContain('Confirm Corroboration (corroborated)');
      expect(html).toContain('value="dismissed"');
      expect(html).toContain('Dismiss Allegation (dismissed)');
    });

    it('provides scope choices: account, code_hash, both', () => {
      const html = renderToString(<ReviewerPortal />);

      expect(html).toContain('Block Enforcement Scope');
      expect(html).toContain('value="account"');
      expect(html).toContain('Account Only');
      expect(html).toContain('value="code_hash"');
      expect(html).toContain('Contract Bytecode Hash Only');
      expect(html).toContain('value="both"');
      expect(html).toContain('Both Account &amp; Bytecode');
    });

    it('renders mandatory audit reason textarea with minimum length indicator', () => {
      const html = renderToString(<ReviewerPortal />);

      expect(html).toContain('Mandatory Audit Reason (Strict)');
      expect(html).toContain('min 5');
      expect(html).toContain('data-testid="reason-textarea"');
      expect(html).toContain('Commit Moderation Record (Increment Revision)');
    });
  });

  describe('4. Immutable Blocklist Revision Log View', () => {
    it('renders append-only revision history table with revision metadata', () => {
      const html = renderToString(<ReviewerPortal />);

      expect(html).toContain('Immutable Blocklist Revision History (Append-Only Log)');
      expect(html).toContain('Total Revisions: 3');

      // Table Headers
      expect(html).toContain('Revision');
      expect(html).toContain('Action');
      expect(html).toContain('Target Account / Code Hash');
      expect(html).toContain('Scope');
      expect(html).toContain('Reviewer ID');
      expect(html).toContain('Mandatory Reason');
      expect(html).toContain('Time');

      // Initial Revision Records
      expect(html).toContain('#7');
      expect(html).toContain('drainer-v1.testnet');
      expect(html).toContain('moderator.testnet');
      expect(html).toContain('Verified drain receipt on-chain and confirmed malicious intent.');

      expect(html).toContain('#6');
      expect(html).toContain('codehash-exploit.testnet');
      expect(html).toContain('security-lead.testnet');

      expect(html).toContain('#5');
      expect(html).toContain('false-alarm.testnet');
      expect(html).toContain('REVOKED');
      expect(html).toContain(
        'Disproved phishing allegation after vendor confirmed invoice authenticity.',
      );
    });

    it('renders custom revision history properly when passed via props', () => {
      const customRevisions: BlocklistRevisionItem[] = [
        {
          revisionNumber: 42,
          entryId: 'blk_042',
          action: 'added',
          network: 'testnet',
          accusedAccountId: 'sybil-mastermind.testnet',
          scope: 'both',
          contractCodeHash: '7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d',
          reviewerId: 'lead-auditor.testnet',
          reason: 'Coordinated Sybil cluster head confirmed via forensic graph tracing.',
          createdAt: Date.now(),
        },
      ];

      const html = renderToString(<ReviewerPortal initialRevisions={customRevisions} />);

      expect(html).toContain('Blocklist Revision: #42');
      expect(html).toContain('#42');
      expect(html).toContain('sybil-mastermind.testnet');
      expect(html).toContain('lead-auditor.testnet');
      expect(html).toContain(
        'Coordinated Sybil cluster head confirmed via forensic graph tracing.',
      );
      expect(html).toContain('Total Revisions: 1');
    });
  });

  describe('5. Core Security Invariant Verification', () => {
    it('prominently displays invariant that raw unreviewed reports never block', () => {
      const html = renderToString(<ReviewerPortal />);

      expect(html).toContain('Security Invariant: Raw Unreviewed Reports Cannot Block');
      expect(html).toContain(
        'Unreviewed report intake swarms (regardless of volume, e.g. coordinated Sybil floods)',
      );
      expect(html).toContain('WARN');
      expect(html).toContain(
        'Only an explicit, authenticated human reviewer action (active_block) creates an immutable entry in the active blocklist',
      );
    });
  });
});
