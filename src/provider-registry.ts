// ─── External Provider Registry ──────────────────────────────────────────────────
// Permissionless marketplace: anyone can register as a service provider by posting
// a bond in PERSIST tokens. Providers declare their endpoint URL, supported service
// types/models, and price per request. The registry maintains price-sorted indexes
// for O(1) cheapest-provider routing with automatic failover.
//
// Inspired by apimarket's provider registry pattern but adapted for Persistia's
// on-DO SQLite storage (no separate smart contract needed — the DO IS the chain).

import { sha256 } from "./consensus";
import type { AccountManager } from "./wallet";

// ─── Configuration ──────────────────────────────────────────────────────────

const MIN_PROVIDER_BOND = 1000n;         // 1000 PERSIST minimum bond
const SLASH_DOWNTIME_PCT = 5;            // 5% bond slash for confirmed downtime
const SLASH_QUALITY_PCT = 20;            // 20% bond slash for bad results
const REPORTER_REWARD_PCT = 70;          // 70% of slash goes to reporter
const DOWNTIME_GRACE_MS = 10 * 60_000;   // 10 minutes before slash
const HEALTH_CHECK_TIMEOUT_MS = 5_000;    // 5s timeout for provider health checks
const MAX_PROVIDERS_PER_SERVICE = 50;     // prevent registry bloat

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ProviderRecord {
  provider_id: string;
  owner_address: string;         // persistia1... address that owns this registration
  endpoint_url: string;          // base URL (e.g. https://my-llm.example.com)
  service_type: string;          // e.g. "llm", "tts", "embed"
  model: string;                 // e.g. "@cf/meta/llama-3.3-70b-instruct-fp8-fast"
  price: bigint;                 // PERSIST per request
  bond: bigint;                  // collateral staked
  active: boolean;
  registered_at: number;
  last_seen: number;             // last successful health check
  total_requests: number;
  total_earnings: bigint;
  failures: number;              // consecutive health check failures
  down_reported_at: number | null;  // when downtime was first reported
  down_reporter: string | null;     // who reported it
}

export interface ProviderRegistration {
  owner_address: string;
  endpoint_url: string;
  service_type: string;
  model: string;
  price: bigint;
  bond_amount: bigint;
}

export interface DowntimeReport {
  provider_id: string;
  reporter_address: string;
  reported_at: number;
  grace_expires_at: number;
  resolved: boolean;
  slashed: boolean;
}

// ─── Provider Registry ──────────────────────────────────────────────────────

export class ProviderRegistry {
  private sql: any;
  private accounts: AccountManager;

  // In-memory price-sorted cache: "service:model" → ProviderRecord[] sorted by price ASC
  private cache: Map<string, ProviderRecord[]> = new Map();
  private cacheBuiltAt: number = 0;
  private static readonly CACHE_TTL = 10_000; // 10s

  constructor(sql: any, accounts: AccountManager) {
    this.sql = sql;
    this.accounts = accounts;
  }

  static initTables(sql: any): void {
    sql.exec(`
      CREATE TABLE IF NOT EXISTS service_providers (
        provider_id TEXT PRIMARY KEY,
        owner_address TEXT NOT NULL,
        endpoint_url TEXT NOT NULL,
        service_type TEXT NOT NULL,
        model TEXT NOT NULL,
        price TEXT NOT NULL DEFAULT '0',
        bond TEXT NOT NULL DEFAULT '0',
        active INTEGER NOT NULL DEFAULT 1,
        registered_at INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        total_requests INTEGER NOT NULL DEFAULT 0,
        total_earnings TEXT NOT NULL DEFAULT '0',
        failures INTEGER NOT NULL DEFAULT 0,
        down_reported_at INTEGER,
        down_reporter TEXT
      )
    `);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_sp_service ON service_providers(service_type, model)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_sp_owner ON service_providers(owner_address)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_sp_active ON service_providers(active)`);

    sql.exec(`
      CREATE TABLE IF NOT EXISTS provider_settlement_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider_id TEXT NOT NULL,
        buyer_address TEXT NOT NULL,
        request_count INTEGER NOT NULL,
        amount TEXT NOT NULL,
        denom TEXT NOT NULL,
        settled_at INTEGER NOT NULL
      )
    `);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_psl_provider ON provider_settlement_log(provider_id)`);
  }

  // ─── Registration ───────────────────────────────────────────────────────

  async register(reg: ProviderRegistration): Promise<{ ok: boolean; error?: string; provider?: ProviderRecord }> {
    if (!reg.endpoint_url || !reg.service_type || !reg.model) {
      return { ok: false, error: "Missing required fields: endpoint_url, service_type, model" };
    }
    if (reg.bond_amount < MIN_PROVIDER_BOND) {
      return { ok: false, error: `Minimum bond is ${MIN_PROVIDER_BOND} PERSIST` };
    }
    if (reg.price <= 0n) {
      return { ok: false, error: "Price must be positive" };
    }

    // Check owner has sufficient balance for bond
    const balance = this.accounts.getBalance(reg.owner_address, "PERSIST");
    if (balance < reg.bond_amount) {
      return { ok: false, error: `Insufficient balance for bond: have ${balance}, need ${reg.bond_amount}` };
    }

    // Check provider count for this service
    const countRows = [...this.sql.exec(
      "SELECT COUNT(*) as cnt FROM service_providers WHERE service_type = ? AND model = ? AND active = 1",
      reg.service_type, reg.model,
    )] as any[];
    if ((countRows[0]?.cnt || 0) >= MAX_PROVIDERS_PER_SERVICE) {
      return { ok: false, error: `Max ${MAX_PROVIDERS_PER_SERVICE} providers per service/model` };
    }

    // Lock bond (transfer to protocol escrow)
    const err = this.accounts.transfer(reg.owner_address, "persistia1protocol_escrow", "PERSIST", reg.bond_amount);
    if (err) return { ok: false, error: `Bond transfer failed: ${err}` };

    const provider_id = await sha256(`provider:${reg.owner_address}:${reg.service_type}:${reg.model}:${Date.now()}`);
    const now = Date.now();

    this.sql.exec(
      `INSERT INTO service_providers
       (provider_id, owner_address, endpoint_url, service_type, model, price, bond, active, registered_at, last_seen, total_requests, total_earnings, failures)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 0, '0', 0)`,
      provider_id, reg.owner_address, reg.endpoint_url,
      reg.service_type, reg.model, reg.price.toString(), reg.bond_amount.toString(),
      now, now,
    );

    this.invalidateCache();
    const provider = this.getProvider(provider_id)!;
    return { ok: true, provider };
  }

  // ─── Deactivation (voluntary withdrawal) ────────────────────────────────

  deactivate(providerId: string, callerAddress: string): { ok: boolean; error?: string; refunded?: bigint } {
    const provider = this.getProvider(providerId);
    if (!provider) return { ok: false, error: "Provider not found" };
    if (provider.owner_address !== callerAddress) return { ok: false, error: "Not the owner" };
    if (!provider.active) return { ok: false, error: "Already inactive" };

    // Return bond + accumulated earnings
    const refund = provider.bond + provider.total_earnings;
    if (refund > 0n) {
      this.accounts.mint(provider.owner_address, "PERSIST", refund);
    }

    this.sql.exec(
      "UPDATE service_providers SET active = 0, bond = '0', total_earnings = '0' WHERE provider_id = ?",
      providerId,
    );

    this.invalidateCache();
    return { ok: true, refunded: refund };
  }

  // ─── Price Update ──────────────────────────────────────────────────────

  updatePrice(providerId: string, callerAddress: string, newPrice: bigint): { ok: boolean; error?: string } {
    const provider = this.getProvider(providerId);
    if (!provider) return { ok: false, error: "Provider not found" };
    if (provider.owner_address !== callerAddress) return { ok: false, error: "Not the owner" };
    if (newPrice <= 0n) return { ok: false, error: "Price must be positive" };

    this.sql.exec("UPDATE service_providers SET price = ? WHERE provider_id = ?", newPrice.toString(), providerId);
    this.invalidateCache();
    return { ok: true };
  }

  // ─── Endpoint Update ──────────────────────────────────────────────────

  updateEndpoint(providerId: string, callerAddress: string, newUrl: string): { ok: boolean; error?: string } {
    const provider = this.getProvider(providerId);
    if (!provider) return { ok: false, error: "Provider not found" };
    if (provider.owner_address !== callerAddress) return { ok: false, error: "Not the owner" };

    this.sql.exec("UPDATE service_providers SET endpoint_url = ? WHERE provider_id = ?", newUrl, providerId);
    this.invalidateCache();
    return { ok: true };
  }

  // ─── Lookup ────────────────────────────────────────────────────────────

  getProvider(providerId: string): ProviderRecord | null {
    const rows = [...this.sql.exec("SELECT * FROM service_providers WHERE provider_id = ?", providerId)] as any[];
    if (rows.length === 0) return null;
    return this.rowToRecord(rows[0]);
  }

  /**
   * Get the cheapest active provider for a service+model.
   */
  getCheapest(serviceType: string, model: string): ProviderRecord | null {
    const providers = this.getActive(serviceType, model);
    return providers.length > 0 ? providers[0] : null;
  }

  /**
   * Get all active providers for a service+model, sorted by price ascending.
   */
  getActive(serviceType: string, model: string): ProviderRecord[] {
    this.ensureCache();
    return this.cache.get(`${serviceType}:${model}`) || [];
  }

  /**
   * Get all active providers across all services.
   */
  getAllActive(): ProviderRecord[] {
    const rows = [...this.sql.exec(
      "SELECT * FROM service_providers WHERE active = 1 ORDER BY service_type, model, CAST(price AS INTEGER) ASC",
    )] as any[];
    return rows.map(r => this.rowToRecord(r));
  }

  /**
   * Get providers owned by an address.
   */
  getByOwner(ownerAddress: string): ProviderRecord[] {
    const rows = [...this.sql.exec(
      "SELECT * FROM service_providers WHERE owner_address = ? ORDER BY registered_at DESC",
      ownerAddress,
    )] as any[];
    return rows.map(r => this.rowToRecord(r));
  }

  /**
   * Get available models with provider counts and price ranges.
   */
  getAvailableModels(): Array<{
    service_type: string; model: string; providers: number;
    cheapest: bigint; most_expensive: bigint;
  }> {
    const rows = [...this.sql.exec(
      `SELECT service_type, model, COUNT(*) as cnt,
              MIN(CAST(price AS INTEGER)) as min_price,
              MAX(CAST(price AS INTEGER)) as max_price
       FROM service_providers WHERE active = 1
       GROUP BY service_type, model
       ORDER BY cnt DESC`,
    )] as any[];
    return rows.map((r: any) => ({
      service_type: r.service_type,
      model: r.model,
      providers: r.cnt,
      cheapest: BigInt(r.min_price || 0),
      most_expensive: BigInt(r.max_price || 0),
    }));
  }

  // ─── Health & Downtime ──────────────────────────────────────────────────

  markHealthy(providerId: string): void {
    this.sql.exec(
      "UPDATE service_providers SET last_seen = ?, failures = 0, down_reported_at = NULL, down_reporter = NULL WHERE provider_id = ?",
      Date.now(), providerId,
    );
  }

  markFailed(providerId: string): void {
    this.sql.exec(
      "UPDATE service_providers SET failures = failures + 1 WHERE provider_id = ?",
      providerId,
    );
    this.invalidateCache();
  }

  /**
   * Report a provider as down. Starts grace period before slashing.
   */
  reportDown(providerId: string, reporterAddress: string): DowntimeReport | null {
    const provider = this.getProvider(providerId);
    if (!provider || !provider.active) return null;
    if (provider.down_reported_at) return null; // already reported

    const now = Date.now();
    this.sql.exec(
      "UPDATE service_providers SET down_reported_at = ?, down_reporter = ? WHERE provider_id = ?",
      now, reporterAddress, providerId,
    );

    return {
      provider_id: providerId,
      reporter_address: reporterAddress,
      reported_at: now,
      grace_expires_at: now + DOWNTIME_GRACE_MS,
      resolved: false,
      slashed: false,
    };
  }

  /**
   * Resolve a downtime report after grace period. Slashes bond if still down.
   */
  resolveDownReport(providerId: string): { slashed: boolean; amount?: bigint; deactivated?: boolean } {
    const provider = this.getProvider(providerId);
    if (!provider || !provider.down_reported_at) return { slashed: false };

    const elapsed = Date.now() - provider.down_reported_at;
    if (elapsed < DOWNTIME_GRACE_MS) return { slashed: false }; // still in grace

    // Slash bond
    const slashAmount = (provider.bond * BigInt(SLASH_DOWNTIME_PCT)) / 100n;
    const reporterReward = (slashAmount * BigInt(REPORTER_REWARD_PCT)) / 100n;
    const burned = slashAmount - reporterReward;

    const newBond = provider.bond - slashAmount;

    // Reward reporter
    if (reporterReward > 0n && provider.down_reporter) {
      this.accounts.mint(provider.down_reporter, "PERSIST", reporterReward);
    }

    // Burn remainder
    if (burned > 0n) {
      this.accounts.burn("persistia1protocol_escrow", "PERSIST", burned, `provider_slash:${providerId}`);
    }

    // Update bond and clear report
    const deactivated = newBond < MIN_PROVIDER_BOND;
    this.sql.exec(
      `UPDATE service_providers SET bond = ?, down_reported_at = NULL, down_reporter = NULL,
       active = ? WHERE provider_id = ?`,
      newBond.toString(), deactivated ? 0 : 1, providerId,
    );

    this.invalidateCache();
    return { slashed: true, amount: slashAmount, deactivated };
  }

  // ─── Settlement ────────────────────────────────────────────────────────

  /**
   * Record a successful request and credit the provider.
   */
  recordRequest(providerId: string, buyerAddress: string, denom: string = "PERSIST"): void {
    const provider = this.getProvider(providerId);
    if (!provider) return;

    this.sql.exec(
      `UPDATE service_providers SET total_requests = total_requests + 1,
       total_earnings = CAST(CAST(total_earnings AS INTEGER) + ? AS TEXT)
       WHERE provider_id = ?`,
      provider.price.toString(), providerId,
    );
  }

  /**
   * Claim accumulated earnings (provider withdraws).
   */
  claimEarnings(providerId: string, callerAddress: string): { ok: boolean; error?: string; amount?: bigint } {
    const provider = this.getProvider(providerId);
    if (!provider) return { ok: false, error: "Provider not found" };
    if (provider.owner_address !== callerAddress) return { ok: false, error: "Not the owner" };
    if (provider.total_earnings <= 0n) return { ok: false, error: "No earnings to claim" };

    const amount = provider.total_earnings;
    this.accounts.mint(provider.owner_address, "PERSIST", amount);
    this.sql.exec("UPDATE service_providers SET total_earnings = '0' WHERE provider_id = ?", providerId);

    return { ok: true, amount };
  }

  // ─── Cache ──────────────────────────────────────────────────────────────

  private ensureCache(): void {
    if (Date.now() - this.cacheBuiltAt < ProviderRegistry.CACHE_TTL) return;
    this.rebuildCache();
  }

  private rebuildCache(): void {
    this.cache.clear();
    const rows = [...this.sql.exec(
      "SELECT * FROM service_providers WHERE active = 1 ORDER BY CAST(price AS INTEGER) ASC",
    )] as any[];

    for (const row of rows) {
      const record = this.rowToRecord(row);
      const key = `${record.service_type}:${record.model}`;
      if (!this.cache.has(key)) this.cache.set(key, []);
      this.cache.get(key)!.push(record);
    }
    this.cacheBuiltAt = Date.now();
  }

  private invalidateCache(): void {
    this.cacheBuiltAt = 0;
  }

  private rowToRecord(row: any): ProviderRecord {
    return {
      provider_id: row.provider_id,
      owner_address: row.owner_address,
      endpoint_url: row.endpoint_url,
      service_type: row.service_type,
      model: row.model,
      price: BigInt(row.price || 0),
      bond: BigInt(row.bond || 0),
      active: row.active === 1,
      registered_at: row.registered_at,
      last_seen: row.last_seen,
      total_requests: row.total_requests || 0,
      total_earnings: BigInt(row.total_earnings || 0),
      failures: row.failures || 0,
      down_reported_at: row.down_reported_at || null,
      down_reporter: row.down_reporter || null,
    };
  }

  // ─── Stats ──────────────────────────────────────────────────────────────

  getStats(): {
    total_providers: number; active_providers: number;
    total_models: number; total_requests: number;
    total_bond_locked: bigint;
  } {
    const stats = [...this.sql.exec(
      `SELECT COUNT(*) as total,
              SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) as active_count,
              SUM(total_requests) as total_req,
              SUM(CAST(bond AS INTEGER)) as total_bond
       FROM service_providers`,
    )] as any[];
    const models = [...this.sql.exec(
      "SELECT COUNT(DISTINCT service_type || ':' || model) as cnt FROM service_providers WHERE active = 1",
    )] as any[];
    const r = stats[0] || {};
    return {
      total_providers: r.total || 0,
      active_providers: r.active_count || 0,
      total_models: models[0]?.cnt || 0,
      total_requests: r.total_req || 0,
      total_bond_locked: BigInt(r.total_bond || 0),
    };
  }
}
