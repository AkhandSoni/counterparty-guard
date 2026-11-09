import type React from 'react';
import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { DecisionBadge } from '../src/components/Badge';
import { RiskMeter } from '../src/components/RiskMeter';
import { CheckActionView } from '../src/views/CheckActionView';
import { WarningApproval } from '../src/views/WarningApproval';

describe('Web UI Component Unit Tests (apps/web)', () => {
  describe('DecisionBadge Component', () => {
    it('renders allow verdict badge with emerald styling', () => {
      const html = renderToString(<DecisionBadge decision="allow" size="md" />);
      expect(html).toContain('ALLOW');
      expect(html).toContain('emerald');
    });

    it('renders warn verdict badge with amber styling', () => {
      const html = renderToString(<DecisionBadge decision="warn" size="lg" />);
      expect(html).toContain('WARN');
      expect(html).toContain('amber');
    });

    it('renders block verdict badge with rose styling', () => {
      const html = renderToString(<DecisionBadge decision="block" size="lg" />);
      expect(html).toContain('BLOCK');
      expect(html).toContain('rose');
    });

    it('renders error badge with slate/rose styling', () => {
      const html = renderToString(<DecisionBadge decision="error" size="sm" />);
      expect(html).toContain('ERROR');
    });
  });

  describe('RiskMeter Component', () => {
    it('renders low risk score (<30) with green/emerald color styling', () => {
      const html = renderToString(<RiskMeter score={10} />);
      expect(html).toMatch(/10.*\/100/);
      expect(html).toContain('emerald');
    });

    it('renders medium risk score (30-69) with amber color styling', () => {
      const html = renderToString(<RiskMeter score={45} />);
      expect(html).toMatch(/45.*\/100/);
      expect(html).toContain('amber');
    });

    it('renders high risk score (>=70) with rose color styling', () => {
      const html = renderToString(<RiskMeter score={95} />);
      expect(html).toMatch(/95.*\/100/);
      expect(html).toContain('rose');
    });
  });

  describe('CheckActionView Component', () => {
    it('renders initial view with S1 scenario preset and ALLOW decision', () => {
      const html = renderToString(<CheckActionView />);
      expect(html).toContain('Proposed Transaction Action');
      expect(html).toContain('Deterministic Scenario Quick Selector');
      expect(html).toContain('ALLOW');
      expect(html).toContain('merchant.testnet');
      expect(html).toContain('Cryptographic Permit');
    });

    it('renders all S1 through S10 quick selector buttons', () => {
      const html = renderToString(<CheckActionView />);
      for (let i = 1; i <= 10; i++) {
        expect(html).toContain(`S${i}`);
      }
    });

    it('renders scenario context card with title and description', () => {
      const html = renderToString(<CheckActionView />);
      expect(html).toContain('Established Legitimate Receiver');
      expect(html).toContain('Receiver has 6+ months active history');
    });

    it('does not render an executable permit in offline previews', () => {
      const html = renderToString(<CheckActionView />);
      expect(html).not.toContain('Permit Digest');
      expect(html).not.toContain('Nonce:');
      expect(html).not.toContain('Revision:');
    });
  });

  describe('WarningApproval Component', () => {
    it('renders security invariant banner and CLI approval command', () => {
      const html = renderToString(<WarningApproval />);
      expect(html).toContain('Owner Warning Approval Required');
      expect(html).toContain('vault.approve_warn');
      expect(html).toContain('near contract call-function as-transaction');
    });

    it('renders custom warning context when provided', () => {
      const customContext = {
        permitHash: '5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f',
        vaultAccountId: 'custom-vault.testnet',
        receiverAccountId: 'wash-trader.testnet',
        amountNear: '1.25',
        reasonCodes: ['CIRCULAR_ACTIVITY'],
      };
      const html = renderToString(<WarningApproval context={customContext} />);
      expect(html).toContain('wash-trader.testnet');
      expect(html).toContain('custom-vault.testnet');
      expect(html).toMatch(/1\.25.*NEAR/);
      expect(html).toContain('CIRCULAR_ACTIVITY');
      expect(html).toContain('5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f');
    });
  });
});
