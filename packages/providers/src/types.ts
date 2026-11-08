import type { Action, Coverage, Network, ReceiverEvidence, SourceMode, SourceObservation } from '@counterparty-guard/shared';
export type { Action, Coverage, Network, ReceiverEvidence, SourceMode, SourceObservation } from '@counterparty-guard/shared';

export interface AssessInput { network: Network; account_id: string; action: Action; refresh?: boolean }
export interface ReceiverProvider { readonly sourceMode: SourceMode; assess(input: AssessInput): Promise<ReceiverEvidence> }
export interface TransferEdge { receipt_id: string; transaction_hash: string; predecessor_id: string; receiver_id: string; amount_yocto: string; timestamp_ms: number; block_height: string; block_hash: string }
export interface IndexedHistory { account_age_days: number | null; recent_deployment: boolean; edges: TransferEdge[]; observations: SourceObservation[]; coverage: Coverage }
export function coverage(now: number, notes: string[] = []): Coverage {
  return { complete: false, truncated: false, pages: 0, window_start_ms: now - 7 * 86_400_000, window_end_ms: now, notes };
}
