// ─── Settlement Batcher ──────────────────────────────────────────────────────────
// Decouples request processing from payment settlement. Requests are recorded
// non-blocking in the hot path; settlements are flushed in batches during the
// alarm handler or when a batch threshold is reached.
//
// Pattern from apimarket's settler.js: record() is fast (Map increment),
// flush() is expensive (DB writes, balance updates).

import type { AccountManager } from "./wallet";
import type { ProviderRegistry } from "./provider-registry";

// ─── Configuration ──────────────────────────────────────────────────────────

const DEFAULT_BATCH_SIZE = 50;      // flush when this many entries pending
const DEFAULT_FLUSH_INTERVAL_MS = 30_000;  // or every 30s, whichever comes first

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SettlementEntry {
  buyer_address: string;
  provider_id: string;
  price_per_request: bigint;
  request_count: number;
  denom: string;
}

export interface SettlementResult {
  entries_settled: number;
  total_amount: bigint;
  failed: Array<{ key: string; error: string }>;
}

// ─── Settlement Batcher ─────────────────────────────────────────────────────

export class SettlementBatcher {
  private accounts: AccountManager;
  private providers: ProviderRegistry;
  private batchSize: number;

  // Pending settlements: "buyer:providerId" → { count, price, denom }
  private pending: Map<string, { buyer_address: string; provider_id: string; count: number; price: bigint; denom: string }> = new Map();

  constructor(
    accounts: AccountManager,
    providers: ProviderRegistry,
    batchSize: number = DEFAULT_BATCH_SIZE,
  ) {
    this.accounts = accounts;
    this.providers = providers;
    this.batchSize = batchSize;
  }

  /**
   * Record a request in the hot path. Non-blocking — just increments a counter.
   * Returns true if a flush should be triggered (batch threshold reached).
   */
  record(buyerAddress: string, providerId: string, pricePerRequest: bigint, denom: string = "PERSIST"): boolean {
    const key = `${buyerAddress}:${providerId}`;
    const existing = this.pending.get(key);

    if (existing) {
      existing.count++;
    } else {
      this.pending.set(key, {
        buyer_address: buyerAddress,
        provider_id: providerId,
        count: 1,
        price: pricePerRequest,
        denom,
      });
    }

    return this.pending.size >= this.batchSize;
  }

  /**
   * Flush all pending settlements. Debits buyers, credits providers.
   * Called from alarm handler or when batch threshold reached.
   */
  flush(): SettlementResult {
    if (this.pending.size === 0) {
      return { entries_settled: 0, total_amount: 0n, failed: [] };
    }

    let totalAmount = 0n;
    let entriesSettled = 0;
    const failed: Array<{ key: string; error: string }> = [];

    // Snapshot and clear pending (so new records during flush go to next batch)
    const batch = new Map(this.pending);
    this.pending.clear();

    for (const [key, entry] of batch) {
      const totalCost = entry.price * BigInt(entry.count);

      // Check buyer has available funds (respecting holds)
      const available = this.accounts.getAvailableBalance(entry.buyer_address, entry.denom);
      if (available < totalCost) {
        // Partial settlement: settle what we can
        const affordableCount = available > 0n ? Number(available / entry.price) : 0;
        if (affordableCount === 0) {
          failed.push({ key, error: `Insufficient balance: need ${totalCost}, available ${available}` });
          continue;
        }
        // Re-queue the remainder
        const remainder = entry.count - affordableCount;
        if (remainder > 0) {
          this.pending.set(key, { ...entry, count: remainder });
        }
        entry.count = affordableCount;
      }

      const settleAmount = entry.price * BigInt(entry.count);

      // Debit buyer
      const err = this.accounts.transfer(
        entry.buyer_address,
        "persistia1protocol_escrow",
        entry.denom,
        settleAmount,
      );
      if (err) {
        failed.push({ key, error: err });
        // Re-queue on failure
        const existing = this.pending.get(key);
        if (existing) {
          existing.count += entry.count;
        } else {
          this.pending.set(key, entry);
        }
        continue;
      }

      // Credit provider
      this.providers.recordRequest(entry.provider_id, entry.buyer_address, entry.denom);

      totalAmount += settleAmount;
      entriesSettled++;
    }

    return { entries_settled: entriesSettled, total_amount: totalAmount, failed };
  }

  /**
   * Get number of pending settlement entries.
   */
  getPendingCount(): number {
    return this.pending.size;
  }

  /**
   * Get total pending settlement amount.
   */
  getPendingAmount(): bigint {
    let total = 0n;
    for (const entry of this.pending.values()) {
      total += entry.price * BigInt(entry.count);
    }
    return total;
  }

  /**
   * Get pending entries for a specific buyer.
   */
  getPendingForBuyer(buyerAddress: string): Array<{ provider_id: string; count: number; amount: bigint }> {
    const result: Array<{ provider_id: string; count: number; amount: bigint }> = [];
    for (const [key, entry] of this.pending) {
      if (entry.buyer_address === buyerAddress) {
        result.push({
          provider_id: entry.provider_id,
          count: entry.count,
          amount: entry.price * BigInt(entry.count),
        });
      }
    }
    return result;
  }
}
