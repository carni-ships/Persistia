// ─── Fee Splitter ──────────────────────────────────────────────────────────────
// Distributes MPP payments according to protocol economics:
//
// PERSIST payments:  70% serving node, 15% validator pool, 10% burned, 5% treasury
// External tokens:   75% serving node, 15% validator pool, 10% treasury (no burn)
//
// Validator pool is distributed reputation-weighted at the end of each round.

import type { AccountManager } from "./wallet";
import type { ValidatorRegistry, ValidatorRecord } from "./validator-registry";

// ─── Configuration ──────────────────────────────────────────────────────────

export interface FeeSplitConfig {
  treasuryAddress: string;       // protocol treasury persistia1... address
  burnEnabled: boolean;          // false for external tokens
  nodePct: number;               // 0.70 for PERSIST, 0.75 for external
  validatorPct: number;          // 0.15
  burnPct: number;               // 0.10 for PERSIST, 0 for external
  treasuryPct: number;           // 0.05 for PERSIST, 0.10 for external
}

export const PERSIST_FEE_SPLIT: Omit<FeeSplitConfig, "treasuryAddress"> = {
  burnEnabled: true,
  nodePct: 0.70,
  validatorPct: 0.15,
  burnPct: 0.10,
  treasuryPct: 0.05,
};

export const EXTERNAL_FEE_SPLIT: Omit<FeeSplitConfig, "treasuryAddress"> = {
  burnEnabled: false,
  nodePct: 0.75,
  validatorPct: 0.15,
  burnPct: 0,
  treasuryPct: 0.10,
};

// ─── Split Result ───────────────────────────────────────────────────────────

export interface FeeSplitResult {
  total: bigint;
  denom: string;
  nodeShare: bigint;
  validatorPoolShare: bigint;
  burnShare: bigint;
  treasuryShare: bigint;
  remainder: bigint;            // rounding dust → goes to node
}

// ─── Fee Splitter ───────────────────────────────────────────────────────────

export class FeeSplitter {
  private sql: any;
  private accounts: AccountManager;
  private validators: ValidatorRegistry;
  private config: FeeSplitConfig;

  constructor(
    sql: any,
    accounts: AccountManager,
    validators: ValidatorRegistry,
    config: FeeSplitConfig,
  ) {
    this.sql = sql;
    this.accounts = accounts;
    this.validators = validators;
    this.config = config;
  }

  static initTables(sql: any): void {
    // Validator reward pool — accumulates until distributed each round
    sql.exec(`
      CREATE TABLE IF NOT EXISTS validator_reward_pool (
        denom TEXT PRIMARY KEY,
        amount TEXT NOT NULL DEFAULT '0'
      )
    `);
    // Fee split audit log
    sql.exec(`
      CREATE TABLE IF NOT EXISTS fee_split_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        receipt_id TEXT NOT NULL,
        denom TEXT NOT NULL,
        total TEXT NOT NULL,
        node_share TEXT NOT NULL,
        validator_share TEXT NOT NULL,
        burn_share TEXT NOT NULL,
        treasury_share TEXT NOT NULL,
        node_address TEXT NOT NULL,
        timestamp INTEGER NOT NULL
      )
    `);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_fsl_receipt ON fee_split_log(receipt_id)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_fsl_ts ON fee_split_log(timestamp)`);

    // Validator reward distribution log
    sql.exec(`
      CREATE TABLE IF NOT EXISTS validator_reward_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        round INTEGER NOT NULL,
        validator_pubkey TEXT NOT NULL,
        address TEXT NOT NULL,
        denom TEXT NOT NULL,
        amount TEXT NOT NULL,
        reputation INTEGER NOT NULL,
        timestamp INTEGER NOT NULL
      )
    `);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_vrl_round ON validator_reward_log(round)`);
  }

  /**
   * Split an incoming payment. Sends shares to node/treasury, burns PERSIST,
   * and accumulates the validator pool for later distribution.
   */
  splitPayment(params: {
    receiptId: string;
    nodeAddress: string;
    amount: bigint;
    denom: string;
    payerAddress: string;
  }): FeeSplitResult {
    const { receiptId, nodeAddress, amount, denom, payerAddress } = params;
    const isPersist = denom === "PERSIST";

    const split = isPersist ? PERSIST_FEE_SPLIT : EXTERNAL_FEE_SPLIT;

    // Calculate shares (integer math, floor each)
    const nodeShare = (amount * BigInt(Math.floor(split.nodePct * 1000))) / 1000n;
    const validatorPoolShare = (amount * BigInt(Math.floor(split.validatorPct * 1000))) / 1000n;
    const burnShare = split.burnEnabled
      ? (amount * BigInt(Math.floor(split.burnPct * 1000))) / 1000n
      : 0n;
    const treasuryShare = (amount * BigInt(Math.floor(split.treasuryPct * 1000))) / 1000n;

    // Remainder (rounding dust) goes to node
    const remainder = amount - nodeShare - validatorPoolShare - burnShare - treasuryShare;

    // Execute transfers:

    // 1. Node gets their share + remainder (funds already at recipient via MPP transfer)
    //    We need to redistribute from the MPP recipient. The payment landed at config.recipient,
    //    so we split FROM that address.
    const mppRecipient = this.config.treasuryAddress; // MPP_RECIPIENT collects first

    // Actually: the payment flow is payer → MPP_RECIPIENT (single address).
    // We redistribute from there. If MPP_RECIPIENT == treasury, treasury already has it.
    // We credit node and validator pool, burn, and leave treasury's share in place.

    // Credit node
    if (nodeShare + remainder > 0n) {
      this.accounts.mint(nodeAddress, denom, nodeShare + remainder);
    }

    // Accumulate validator pool
    if (validatorPoolShare > 0n) {
      this.addToValidatorPool(denom, validatorPoolShare);
    }

    // Burn
    if (burnShare > 0n && isPersist) {
      // Burn from the MPP recipient (who received the full payment)
      this.accounts.burn(payerAddress, denom, burnShare, `fee_burn:${receiptId}`);
    }

    // Treasury gets its share via the MPP recipient already holding funds.
    // Credit treasury explicitly if it's a different address from MPP_RECIPIENT.
    if (treasuryShare > 0n) {
      this.accounts.mint(this.config.treasuryAddress, denom, treasuryShare);
    }

    // Audit log
    this.sql.exec(
      `INSERT INTO fee_split_log
       (receipt_id, denom, total, node_share, validator_share, burn_share, treasury_share, node_address, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      receiptId, denom, amount.toString(),
      nodeShare.toString(), validatorPoolShare.toString(),
      burnShare.toString(), treasuryShare.toString(),
      nodeAddress, Date.now(),
    );

    return { total: amount, denom, nodeShare, validatorPoolShare, burnShare, treasuryShare, remainder };
  }

  // ─── Validator Pool ─────────────────────────────────────────────────────

  private addToValidatorPool(denom: string, amount: bigint): void {
    this.sql.exec(
      `INSERT INTO validator_reward_pool (denom, amount) VALUES (?, ?)
       ON CONFLICT(denom) DO UPDATE SET amount = CAST(CAST(amount AS INTEGER) + ? AS TEXT)`,
      denom, amount.toString(), amount.toString(),
    );
  }

  getValidatorPoolBalance(denom: string = "PERSIST"): bigint {
    const rows = [...this.sql.exec(
      "SELECT amount FROM validator_reward_pool WHERE denom = ?", denom,
    )];
    if (rows.length === 0) return 0n;
    return BigInt((rows[0] as any).amount || 0);
  }

  /**
   * Distribute accumulated validator rewards for a round.
   * Weights by reputation — validators with higher reputation get proportionally more.
   * Returns the number of validators paid.
   */
  distributeValidatorRewards(round: number, denom: string = "PERSIST"): number {
    const pool = this.getValidatorPoolBalance(denom);
    if (pool <= 0n) return 0;

    const activeValidators = this.validators.getActiveValidators();
    if (activeValidators.length === 0) return 0;

    const totalReputation = activeValidators.reduce((sum, v) => sum + v.reputation, 0);
    if (totalReputation <= 0) return 0;

    let distributed = 0n;
    const distributions: Array<{ validator: ValidatorRecord; share: bigint }> = [];

    for (const v of activeValidators) {
      const share = (pool * BigInt(v.reputation)) / BigInt(totalReputation);
      if (share <= 0n) continue;
      distributions.push({ validator: v, share });
      distributed += share;
    }

    // Execute distributions
    for (const { validator, share } of distributions) {
      // Derive validator's persistia address from their pubkey
      // We need to credit their account — use mint since the pool is virtual
      const addrRows = [...this.sql.exec(
        "SELECT address FROM accounts WHERE pubkey = ?", validator.pubkey,
      )];

      if (addrRows.length > 0) {
        const addr = (addrRows[0] as any).address as string;
        this.accounts.mint(addr, denom, share);

        // Log distribution
        this.sql.exec(
          `INSERT INTO validator_reward_log
           (round, validator_pubkey, address, denom, amount, reputation, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          round, validator.pubkey, addr, denom,
          share.toString(), validator.reputation, Date.now(),
        );
      }
    }

    // Deduct distributed amount from pool (remainder stays for next round)
    this.sql.exec(
      `UPDATE validator_reward_pool SET amount = CAST(CAST(amount AS INTEGER) - ? AS TEXT) WHERE denom = ?`,
      distributed.toString(), denom,
    );

    return distributions.length;
  }

  // ─── Queries ──────────────────────────────────────────────────────────

  /** Get fee split history. */
  getFeeSplitLog(limit: number = 50): Array<{
    receipt_id: string; denom: string; total: string;
    node_share: string; validator_share: string; burn_share: string; treasury_share: string;
    node_address: string; timestamp: number;
  }> {
    const rows = [...this.sql.exec(
      "SELECT * FROM fee_split_log ORDER BY timestamp DESC LIMIT ?", limit,
    )];
    return rows as any[];
  }

  /** Get validator reward history for a round. */
  getRewardLog(round: number): Array<{
    validator_pubkey: string; address: string; denom: string;
    amount: string; reputation: number; timestamp: number;
  }> {
    const rows = [...this.sql.exec(
      "SELECT * FROM validator_reward_log WHERE round = ? ORDER BY amount DESC", round,
    )];
    return rows as any[];
  }

  /** Summary stats. */
  getStats(): {
    totalSplits: number;
    totalNodeEarnings: bigint;
    totalBurned: bigint;
    totalValidatorRewards: bigint;
    totalTreasuryEarnings: bigint;
    poolBalance: bigint;
  } {
    const splits = [...this.sql.exec(
      `SELECT COUNT(*) as cnt,
              COALESCE(SUM(CAST(node_share AS INTEGER)), 0) as node_total,
              COALESCE(SUM(CAST(burn_share AS INTEGER)), 0) as burn_total,
              COALESCE(SUM(CAST(validator_share AS INTEGER)), 0) as val_total,
              COALESCE(SUM(CAST(treasury_share AS INTEGER)), 0) as treasury_total
       FROM fee_split_log WHERE denom = 'PERSIST'`
    )];
    const r = (splits[0] as any) || {};
    return {
      totalSplits: r.cnt || 0,
      totalNodeEarnings: BigInt(r.node_total || 0),
      totalBurned: BigInt(r.burn_total || 0),
      totalValidatorRewards: BigInt(r.val_total || 0),
      totalTreasuryEarnings: BigInt(r.treasury_total || 0),
      poolBalance: this.getValidatorPoolBalance("PERSIST"),
    };
  }
}
