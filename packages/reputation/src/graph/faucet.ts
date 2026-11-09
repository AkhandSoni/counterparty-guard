/**
 * @file packages/reputation/src/graph/faucet.ts
 * @description Common faucet and shared infrastructure exemption registry.
 */

import type { ReportRepository } from '../storage/repository.js';
import type { NetworkType } from './traversal.js';

export type ExemptionType = 'faucet' | 'bridge' | 'exchange' | 'system' | 'other';

export interface FaucetExemption {
  exemptionId: string;
  network: NetworkType;
  faucetAccountId: string;
  label: string;
  exemptionType: ExemptionType;
  isActive: boolean;
  createdAt: number;
  updatedAt: number;
}

/**
 * Built-in static exemptions providing fallback protection across networks.
 */
export const DEFAULT_FAUCET_EXEMPTIONS: ReadonlyArray<
  Omit<FaucetExemption, 'createdAt' | 'updatedAt'>
> = [
  // Testnet
  {
    exemptionId: 'seed-testnet-faucet',
    network: 'testnet',
    faucetAccountId: 'faucet.testnet',
    label: 'Official NEAR Testnet Faucet',
    exemptionType: 'faucet',
    isActive: true,
  },
  {
    exemptionId: 'seed-testnet-genesis',
    network: 'testnet',
    faucetAccountId: 'testnet',
    label: 'NEAR Testnet Genesis Account',
    exemptionType: 'system',
    isActive: true,
  },
  {
    exemptionId: 'seed-testnet-v2-faucet',
    network: 'testnet',
    faucetAccountId: 'v2.near-faucet.testnet',
    label: 'Community Faucet v2',
    exemptionType: 'faucet',
    isActive: true,
  },
  {
    exemptionId: 'seed-testnet-friendbot',
    network: 'testnet',
    faucetAccountId: 'friendbot.testnet',
    label: 'Friendbot Faucet',
    exemptionType: 'faucet',
    isActive: true,
  },
  // Sandbox
  {
    exemptionId: 'seed-sandbox-faucet',
    network: 'sandbox',
    faucetAccountId: 'faucet.sandbox',
    label: 'Sandbox Local Faucet',
    exemptionType: 'faucet',
    isActive: true,
  },
  {
    exemptionId: 'seed-sandbox-root',
    network: 'sandbox',
    faucetAccountId: 'sandbox',
    label: 'Sandbox Root Account',
    exemptionType: 'system',
    isActive: true,
  },
  {
    exemptionId: 'seed-sandbox-test-near',
    network: 'sandbox',
    faucetAccountId: 'test.near',
    label: 'Sandbox Test Registrar',
    exemptionType: 'system',
    isActive: true,
  },
  // Mainnet
  {
    exemptionId: 'seed-mainnet-near',
    network: 'mainnet',
    faucetAccountId: 'near',
    label: 'NEAR Mainnet Root Registrar',
    exemptionType: 'system',
    isActive: true,
  },
  {
    exemptionId: 'seed-mainnet-faucet',
    network: 'mainnet',
    faucetAccountId: 'faucet.near',
    label: 'Official NEAR Mainnet Faucet',
    exemptionType: 'faucet',
    isActive: true,
  },
  {
    exemptionId: 'seed-mainnet-fastnear',
    network: 'mainnet',
    faucetAccountId: 'faucet.fastnear.near',
    label: 'FastNear Public Faucet',
    exemptionType: 'faucet',
    isActive: true,
  },
];

/**
 * Registry of exempted faucet and system accounts.
 */
export class FaucetRegistry {
  private readonly exemptions: Map<string, FaucetExemption> = new Map();

  constructor(
    private readonly repository?: ReportRepository,
    options: { loadDefaults?: boolean } = { loadDefaults: true },
  ) {
    if (options.loadDefaults) {
      this.loadDefaults();
    }
    if (this.repository) {
      this.syncFromRepository();
    }
  }

  private getCompositeKey(network: string, accountId: string): string {
    return `${network.toLowerCase()}:${accountId.trim().toLowerCase()}`;
  }

  private loadDefaults(): void {
    const now = Date.now();
    for (const def of DEFAULT_FAUCET_EXEMPTIONS) {
      const key = this.getCompositeKey(def.network, def.faucetAccountId);
      this.exemptions.set(key, {
        ...def,
        createdAt: now,
        updatedAt: now,
      });
    }
  }

  public syncFromRepository(network?: NetworkType): void {
    if (!this.repository) return;
    const networks: NetworkType[] = network ? [network] : ['testnet', 'mainnet', 'sandbox'];

    for (const net of networks) {
      const records = this.repository.getFaucetExemptions(net);
      for (const rec of records) {
        const key = this.getCompositeKey(rec.network, rec.faucet_account_id);
        this.exemptions.set(key, {
          exemptionId: rec.exemption_id,
          network: rec.network as NetworkType,
          faucetAccountId: rec.faucet_account_id,
          label: rec.label,
          exemptionType: rec.exemption_type as ExemptionType,
          isActive: rec.is_active === 1,
          createdAt: rec.created_at,
          updatedAt: rec.updated_at,
        });
      }
    }
  }

  public isExempted(network: NetworkType, accountId: string): boolean {
    const key = this.getCompositeKey(network, accountId);
    const entry = this.exemptions.get(key);
    if (entry !== undefined) {
      return entry.isActive;
    }
    // Also check static default fallback
    const normalizedAcc = accountId.trim().toLowerCase();
    const staticMatch = DEFAULT_FAUCET_EXEMPTIONS.find(
      (f) => f.network === network && f.faucetAccountId.toLowerCase() === normalizedAcc,
    );
    if (staticMatch) {
      return staticMatch.isActive;
    }
    // If repository exists, query it
    if (this.repository) {
      return this.repository.isFaucetExempted(network, accountId);
    }
    return false;
  }

  public getExemption(network: string, accountId: string): FaucetExemption | null {
    const key = this.getCompositeKey(network, accountId);
    return this.exemptions.get(key) ?? null;
  }

  public filterNonFaucetAccounts(network: NetworkType, accountIds: string[]): string[] {
    return accountIds.filter((acc) => !this.isExempted(network, acc));
  }

  public addExemption(
    exemption: Omit<FaucetExemption, 'createdAt' | 'updatedAt'>,
  ): FaucetExemption {
    const now = Date.now();
    const entry: FaucetExemption = {
      ...exemption,
      faucetAccountId: exemption.faucetAccountId.trim().toLowerCase(),
      createdAt: now,
      updatedAt: now,
    };
    const key = this.getCompositeKey(entry.network, entry.faucetAccountId);
    this.exemptions.set(key, entry);
    return entry;
  }
}

/**
 * Checks whether an account is exempted as a known faucet or infrastructure account.
 * Checks both static defaults and the database repository if provided.
 */
export function isFaucetExempted(
  account_id: string,
  network: NetworkType,
  repository?: ReportRepository,
): boolean {
  const normalized = account_id.trim().toLowerCase();
  const staticFound = DEFAULT_FAUCET_EXEMPTIONS.some(
    (f) => f.network === network && f.faucetAccountId.toLowerCase() === normalized && f.isActive,
  );
  if (staticFound) return true;

  if (repository) {
    try {
      return repository.isFaucetExempted(network, account_id);
    } catch {
      return false;
    }
  }

  return false;
}
