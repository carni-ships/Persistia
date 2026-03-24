// ─── Cron Triggers: Autonomous Scheduled Contract Calls ───────────────────────
// Allows contracts to schedule recurring calls without external EOAs.
// Uses DO Alarm as the execution engine.

import { sha256 } from "./consensus";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface TriggerDef {
  id: string;              // deterministic ID
  contract: string;        // contract address to call
  method: string;          // method to invoke
  args_b64: string;        // base64-encoded arguments
  interval_ms: number;     // interval between fires (min 10_000 = 10s)
  next_fire: number;       // next scheduled fire time (epoch ms)
  creator: string;         // pubkey that created the trigger
  enabled: boolean;
  created_at: number;
  last_fired: number;      // 0 if never fired
  fire_count: number;
  max_fires: number;       // 0 = unlimited
}

// ─── Constants ────────────────────────────────────────────────────────────────

export const MIN_INTERVAL_MS = 10_000;     // 10 seconds minimum
export const MAX_INTERVAL_MS = 86_400_000; // 24 hours maximum
export const MAX_TRIGGERS_PER_CONTRACT = 10;

// ─── Trigger Manager ──────────────────────────────────────────────────────────

export class TriggerManager {
  private sql: any;

  constructor(sql: any) {
    this.sql = sql;
  }

  /**
   * Create a new trigger. Returns the trigger ID.
   */
  async create(
    contract: string,
    method: string,
    argsB64: string,
    intervalMs: number,
    creator: string,
    maxFires: number = 0,
  ): Promise<string> {
    // Validate interval
    if (intervalMs < MIN_INTERVAL_MS) {
      throw new Error(`Interval too short (min ${MIN_INTERVAL_MS}ms)`);
    }
    if (intervalMs > MAX_INTERVAL_MS) {
      throw new Error(`Interval too long (max ${MAX_INTERVAL_MS}ms)`);
    }

    // Check per-contract limit
    const existing = [...this.sql.exec(
      "SELECT COUNT(*) as cnt FROM triggers WHERE contract = ? AND enabled = 1",
      contract,
    )];
    if ((existing[0]?.cnt ?? 0) >= MAX_TRIGGERS_PER_CONTRACT) {
      throw new Error(`Max ${MAX_TRIGGERS_PER_CONTRACT} triggers per contract`);
    }

    const id = await sha256(`trigger:${contract}:${method}:${creator}:${Date.now()}`);
    const now = Date.now();
    const nextFire = now + intervalMs;

    this.sql.exec(
      `INSERT INTO triggers (id, contract, method, args_b64, interval_ms, next_fire, creator, enabled, created_at, last_fired, fire_count, max_fires)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 0, 0, ?)`,
      id, contract, method, argsB64, intervalMs, nextFire, creator, now, maxFires,
    );

    return id;
  }

  /**
   * Remove a trigger. Only the creator can remove it.
   */
  remove(triggerId: string, callerPubkey: string): boolean {
    const rows = [...this.sql.exec("SELECT creator FROM triggers WHERE id = ?", triggerId)];
    if (rows.length === 0) return false;
    if ((rows[0] as any).creator !== callerPubkey) {
      throw new Error("Only the trigger creator can remove it");
    }
    this.sql.exec("DELETE FROM triggers WHERE id = ?", triggerId);
    return true;
  }

  /**
   * Get all triggers that are due to fire (next_fire <= now).
   */
  getDueTriggers(now: number = Date.now()): TriggerDef[] {
    const rows = [...this.sql.exec(
      "SELECT * FROM triggers WHERE enabled = 1 AND next_fire <= ? ORDER BY next_fire ASC",
      now,
    )];
    return rows.map(this.rowToTrigger);
  }

  /**
   * Mark a trigger as fired. Advances next_fire, increments fire_count.
   * Disables the trigger if max_fires reached.
   */
  markFired(triggerId: string, now: number = Date.now()) {
    const rows = [...this.sql.exec("SELECT * FROM triggers WHERE id = ?", triggerId)];
    if (rows.length === 0) return;

    const trigger = this.rowToTrigger(rows[0]);
    const newFireCount = trigger.fire_count + 1;
    const shouldDisable = trigger.max_fires > 0 && newFireCount >= trigger.max_fires;

    this.sql.exec(
      `UPDATE triggers SET
        last_fired = ?,
        fire_count = ?,
        next_fire = ?,
        enabled = ?
       WHERE id = ?`,
      now,
      newFireCount,
      now + trigger.interval_ms,
      shouldDisable ? 0 : 1,
      triggerId,
    );
  }

  /**
   * Get the next fire time across all enabled triggers.
   * Returns null if no triggers exist.
   */
  getNextFireTime(): number | null {
    const rows = [...this.sql.exec(
      "SELECT MIN(next_fire) as next FROM triggers WHERE enabled = 1",
    )];
    return rows[0]?.next ?? null;
  }

  /**
   * List all triggers for a contract.
   */
  listForContract(contract: string): TriggerDef[] {
    const rows = [...this.sql.exec(
      "SELECT * FROM triggers WHERE contract = ? ORDER BY created_at ASC",
      contract,
    )];
    return rows.map(this.rowToTrigger);
  }

  /**
   * Get a single trigger by ID.
   */
  get(triggerId: string): TriggerDef | null {
    const rows = [...this.sql.exec("SELECT * FROM triggers WHERE id = ?", triggerId)];
    if (rows.length === 0) return null;
    return this.rowToTrigger(rows[0]);
  }

  private rowToTrigger(row: any): TriggerDef {
    return {
      id: row.id,
      contract: row.contract,
      method: row.method,
      args_b64: row.args_b64,
      interval_ms: row.interval_ms,
      next_fire: row.next_fire,
      creator: row.creator,
      enabled: !!row.enabled,
      created_at: row.created_at,
      last_fired: row.last_fired,
      fire_count: row.fire_count,
      max_fires: row.max_fires,
    };
  }
}
