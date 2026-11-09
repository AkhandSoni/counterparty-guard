import type React from 'react';
import { useEffect, useState } from 'react';
import { formatDisplayPermitHash, nearToYocto} from '../adapters/mockAdapter';
import { CodeBlock } from '../components/CodeBlock';
import {
  AlertTriangleIcon,
  CheckIcon,
  CopyIcon,
} from '../components/Icons';
import type { Network, PendingWarningContext } from '../types';

export interface WarningApprovalProps {
  context?: PendingWarningContext | null;
  initialNetwork?: Network;
  initialOwnerAccount?: string;
}

/**
 * Validates NEAR account ID rules:
 * - Length between 2 and 64 characters (inclusive)
 * - Lowercase alphanumeric characters, digits, separated by _ or - or .
 * - Or 64-character lowercase hex string (implicit account ID)
 */
export function isValidNearAccountId(accountId: string): boolean {
  if (!accountId || typeof accountId !== 'string') return false;
  const trimmed = accountId.trim();
  if (trimmed.length < 2 || trimmed.length > 64) return false;
  if (/^[a-f0-9]{64}$/.test(trimmed)) return true;
  return /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/.test(trimmed);
}

/**
 * Validates and normalizes permit hash:
 * - Strips leading 0x/0X prefix
 * - Verifies exactly 64 lowercase hexadecimal characters
 */
export function validatePermitHash(hash: string): {
  isValid: boolean;
  canonicalHash: string;
  displayHash: string;
  errorMessage?: string;
} {
  if (!hash || typeof hash !== 'string' || hash.trim() === '') {
    return {
      isValid: false,
      canonicalHash: '',
      displayHash: 'None',
      errorMessage: 'Permit hash cannot be empty',
    };
  }
  const clean = hash.trim().replace(/^0x/i, '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(clean)) {
    return {
      isValid: false,
      canonicalHash: clean,
      displayHash: formatDisplayPermitHash(hash),
      errorMessage: `Invalid permit hash: expected 64 hex characters, got ${clean.length}`,
    };
  }
  return {
    isValid: true,
    canonicalHash: clean,
    displayHash: formatDisplayPermitHash(clean),
  };
}

export const WarningApproval: React.FC<WarningApprovalProps> = ({
  context,
  initialNetwork = 'testnet',
  initialOwnerAccount = 'owner.testnet',
}) => {
  const defaultPermitHash = '9b8e21a0f54318c39e2d765418b7654321908765432109876543210987654321';

  // Interactive parameter state
  const [permitHashInput, setPermitHashInput] = useState<string>(
    context?.permitHash || defaultPermitHash,
  );
  const [vaultAccount, setVaultAccount] = useState<string>(
    context?.vaultAccountId || 'vault.agent-c.testnet',
  );
  const [ownerAccount, setOwnerAccount] = useState<string>(initialOwnerAccount);
  const [network, setNetwork] = useState<Network>(initialNetwork);
  const [receiverAccount, setReceiverAccount] = useState<string>(
    context?.receiverAccountId || 'new-vendor.testnet',
  );
  const [amountNear, setAmountNear] = useState<string>(context?.amountNear || '0.05');

  // Simulation & visual copy state
  const [isSimulatedApproved, setIsSimulatedApproved] = useState(false);
  const [copied, setCopied] = useState(false);

  // Sync state if context prop updates dynamically
  useEffect(() => {
    if (context) {
      if (context.permitHash) setPermitHashInput(context.permitHash);
      if (context.vaultAccountId) setVaultAccount(context.vaultAccountId);
      if (context.receiverAccountId) setReceiverAccount(context.receiverAccountId);
      if (context.amountNear) setAmountNear(context.amountNear);
    }
  }, [context]);

  // Validation
  const hashValidation = validatePermitHash(permitHashInput);
  const isVaultValid = isValidNearAccountId(vaultAccount);
  const isOwnerValid = isValidNearAccountId(ownerAccount);
  const isAllValid = hashValidation.isValid && isVaultValid && isOwnerValid;

  const canonicalHash = hashValidation.isValid
    ? hashValidation.canonicalHash
    : '<invalid_permit_hash>';

  const displayHash = hashValidation.displayHash;

  const reasonText = context?.reasonCodes?.length
    ? context.reasonCodes.join(', ')
    : 'RECENT_DEPLOYMENT (Account created < 24h ago)';

  let yoctoAmount = '50000000000000000000000';
  try {
    yoctoAmount = nearToYocto(amountNear);
  } catch {
    yoctoAmount = '0';
  }

  // Exact NEAR CLI command format matching specification
  const nearCliCommand = `# Offline preview only. B vault interface is pending; do not execute.\nnear contract call-function as-transaction ${vaultAccount} approve_warn \\
  json-args '{"permit_hash":"${canonicalHash}"}' \\
  prepaid-gas '100.0 Tgas' \\
  attached-deposit '0 NEAR' \\
  sign-as ${ownerAccount} \\
  network-config ${network}`;

  const handleCopyCommand = async () => {
    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard) {
        await navigator.clipboard.writeText(nearCliCommand);
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* High-Level Security Invariant Banner */}
      <div className="p-4 rounded-xl bg-amber-950/40 border border-amber-800 flex items-start gap-3">
        <AlertTriangleIcon size={22} className="text-amber-400 shrink-0 mt-0.5" />
        <div className="text-xs text-amber-200 space-y-1">
          <span className="font-bold text-sm block text-amber-300">
            Owner Warning Approval Required (Human-in-the-Loop)
          </span>
          <p>
            Automated agents cannot sign value transfers under a{' '}
            <span className="font-mono font-bold">WARN</span> verdict. An independent human owner
            must approve the exact permit hash on-chain before the vault executes payment.
          </p>
          <p className="font-semibold text-amber-400">
            Security Invariant: A browser UI button or LLM prompt has ZERO authority to execute.
            Only an on-chain transaction signed by the recovery owner key authorizes execution.
          </p>
        </div>
      </div>

      {/* Warning Details Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="font-semibold text-white text-sm">Pending Warning Permit Context</h3>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 border border-amber-800 text-amber-300">
            ACTION: WARN_APPROVAL_REQUIRED
          </span>
        </div>

        {/* Action Overview Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400 block">Receiver Counterparty</span>
            <span className="font-mono text-white font-semibold break-all">{receiverAccount}</span>
          </div>
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400 block">Requested Amount</span>
            <span className="font-mono text-emerald-400 font-semibold">
              {`${amountNear} NEAR (${yoctoAmount} yoctoNEAR)`}
            </span>
          </div>
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400 block">Guarded Vault Account</span>
            <span className="font-mono text-slate-200">{vaultAccount}</span>
          </div>
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400 block">Warning Reason</span>
            <span className="font-mono text-amber-400 font-semibold">{reasonText}</span>
          </div>
        </div>

        {/* Interactive Parameter Configuration Form */}
        <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
              Approval Parameter Configuration
            </h4>
            <span
              className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                isAllValid
                  ? 'bg-emerald-950/80 border border-emerald-800 text-emerald-300'
                  : 'bg-rose-950/80 border border-rose-800 text-rose-300'
              }`}
            >
              {isAllValid ? 'Parameters Validated' : 'Validation Error'}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            {/* Vault Account Input */}
            <div>
              <label htmlFor="vault-account-input" className="block text-slate-400 mb-1">
                Vault Account
              </label>
              <input
                id="vault-account-input"
                data-testid="vault-account-input"
                type="text"
                value={vaultAccount}
                onChange={(e) => setVaultAccount(e.target.value)}
                className={`w-full bg-slate-900 border rounded-lg px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none ${
                  isVaultValid
                    ? 'border-slate-700 focus:border-cyan-500'
                    : 'border-rose-600 focus:border-rose-500 text-rose-300'
                }`}
                placeholder="vault.agent-c.testnet"
              />
              {!isVaultValid && (
                <span className="text-[10px] text-rose-400 mt-1 block">
                  Invalid NEAR account format
                </span>
              )}
            </div>

            {/* Owner Account Input */}
            <div>
              <label htmlFor="owner-account-input" className="block text-slate-400 mb-1">
                Owner Account (Signer)
              </label>
              <input
                id="owner-account-input"
                data-testid="owner-account-input"
                type="text"
                value={ownerAccount}
                onChange={(e) => setOwnerAccount(e.target.value)}
                className={`w-full bg-slate-900 border rounded-lg px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none ${
                  isOwnerValid
                    ? 'border-slate-700 focus:border-cyan-500'
                    : 'border-rose-600 focus:border-rose-500 text-rose-300'
                }`}
                placeholder="owner.testnet"
              />
              {!isOwnerValid && (
                <span className="text-[10px] text-rose-400 mt-1 block">
                  Invalid NEAR owner account
                </span>
              )}
            </div>

            {/* Network Selector */}
            <div>
              <label htmlFor="network-select" className="block text-slate-400 mb-1">
                Network Config
              </label>
              <select
                id="network-select"
                data-testid="network-select"
                value={network}
                onChange={(e) => setNetwork(e.target.value as Network)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:border-cyan-500 focus:outline-none"
              >
                <option value="testnet">testnet</option>
                <option value="mainnet">mainnet</option>
                <option value="sandbox">sandbox</option>
              </select>
            </div>
          </div>

          {/* Permit Hash Input */}
          <div>
            <label htmlFor="permit-hash-input" className="block text-slate-400 mb-1">
              Permit Hash Digest (64 Hex Characters)
            </label>
            <input
              id="permit-hash-input"
              data-testid="permit-hash-input"
              type="text"
              value={permitHashInput}
              onChange={(e) => setPermitHashInput(e.target.value)}
              className={`w-full bg-slate-900 border rounded-lg px-2.5 py-1.5 text-cyan-300 font-mono text-xs focus:outline-none ${
                hashValidation.isValid
                  ? 'border-slate-700 focus:border-cyan-500'
                  : 'border-rose-600 focus:border-rose-500 text-rose-300'
              }`}
              placeholder="e.g. 9b8e21a0f54318c39e2d765418b7654321908765432109876543210987654321"
            />
            {!hashValidation.isValid && (
              <span className="text-[10px] text-rose-400 mt-1 block">
                {hashValidation.errorMessage || 'Invalid permit hash format (must be 64-char hex)'}
              </span>
            )}
          </div>
        </div>

        {/* Canonical Hash Display */}
        <div>
          <span className="text-xs font-semibold text-slate-300 block mb-1">
            Canonical Permit Hash Digest (UI Display)
          </span>
          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-400 break-all">
            {displayHash}
          </div>
        </div>

        {/* Copyable CLI Command Card */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-300">
              Independent Owner Approval Command (NEAR CLI)
            </span>
            <button
              type="button"
              data-testid="copy-cli-command-btn"
              onClick={handleCopyCommand}
              disabled={true}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-medium transition ${
                !isAllValid
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-800'
                  : copied
                    ? 'bg-emerald-900/60 border border-emerald-700 text-emerald-300'
                    : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm'
              }`}
            >
              {copied ? (
                <>
                  <CheckIcon size={14} className="text-emerald-400" />
                  <span>Copied!</span>
                </>
              ) : (
                <>
                  <CopyIcon size={14} />
                  <span>Copy CLI Command</span>
                </>
              )}
            </button>
          </div>
          <CodeBlock code={nearCliCommand} title="Execute via Owner Terminal / Hardware Wallet" />
        </div>

        {/* Live On-Chain Poller Simulator */}
        <div className="border-t border-slate-800 pt-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <span
              className={`w-3 h-3 rounded-full ${
                isSimulatedApproved ? 'bg-emerald-400' : 'bg-amber-400 animate-pulse'
              }`}
            />
            <span className="text-xs text-slate-300">
              {isSimulatedApproved
                ? 'On-chain approval confirmed! Vault permit is unlocked for execution.'
                : 'Awaiting on-chain owner call to vault.approve_warn...'}
            </span>
          </div>

          <button
            type="button"
            data-testid="simulate-approval-btn"
            onClick={() => setIsSimulatedApproved(!isSimulatedApproved)}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 border border-slate-700 transition"
          >
            {isSimulatedApproved ? 'Reset Simulation' : 'Simulate On-Chain Approval'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default WarningApproval;
