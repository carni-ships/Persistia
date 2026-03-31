// ─── LLM Metering ──────────────────────────────────────────────────────────────
// Tracks token usage, cost, and latency per provider call for all AI services.
// Supports both OpenAI-compatible and Workers AI response formats.
// Cost fields use string bigints (native PERSIST token units).

// ─── Types ────────────────────────────────────────────────────────────────────

export interface LLMMeterEntry {
  id: string;
  timestamp: number;
  service: string;
  model: string;
  provider_id: string | null;
  source: "local" | "external";
  request_id: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  estimated_cost_persist: string;
  actual_cost_persist: string;
  price_per_1k_tokens: string;
  latency_ms: number;
  time_to_first_token_ms: number | null;
  tokens_per_second: number;
  http_status: number;
  error: string | null;
  attestation_id: string | null;
  buyer_address: string;
  shard: string;
}

export interface MeteringSummary {
  period: "hour" | "day" | "all";
  total_requests: number;
  total_prompt_tokens: number;
  total_completion_tokens: number;
  total_cost_persist: string;
  avg_latency_ms: number;
  avg_tokens_per_second: number;
  error_rate: number;
  by_model: Record<string, {
    requests: number;
    prompt_tokens: number;
    completion_tokens: number;
    cost: string;
    avg_latency_ms: number;
  }>;
  by_provider: Record<string, {
    requests: number;
    total_tokens: number;
    cost: string;
    avg_latency_ms: number;
    error_count: number;
  }>;
}

export interface TokenUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

type MeterEntryInput = Omit<LLMMeterEntry, "id" | "tokens_per_second">;

// ─── LLMMeteringManager ──────────────────────────────────────────────────────

export class LLMMeteringManager {
  private sql: any;

  constructor(sql: any) {
    this.sql = sql;
  }

  // ─── Schema ──────────────────────────────────────────────────────────────

  static initTables(sql: any): void {
    sql.exec(`
      CREATE TABLE IF NOT EXISTS llm_metering (
        id TEXT PRIMARY KEY,
        timestamp INTEGER NOT NULL,
        service TEXT NOT NULL,
        model TEXT NOT NULL,
        provider_id TEXT,
        source TEXT NOT NULL DEFAULT 'local',
        request_id TEXT,
        prompt_tokens INTEGER NOT NULL DEFAULT 0,
        completion_tokens INTEGER NOT NULL DEFAULT 0,
        total_tokens INTEGER NOT NULL DEFAULT 0,
        estimated_cost TEXT NOT NULL DEFAULT '0',
        actual_cost TEXT NOT NULL DEFAULT '0',
        price_per_1k_tokens TEXT NOT NULL DEFAULT '0',
        latency_ms INTEGER NOT NULL DEFAULT 0,
        time_to_first_token_ms INTEGER,
        tokens_per_second REAL NOT NULL DEFAULT 0,
        http_status INTEGER NOT NULL DEFAULT 200,
        error TEXT,
        attestation_id TEXT,
        buyer_address TEXT NOT NULL DEFAULT '',
        shard TEXT NOT NULL DEFAULT ''
      )
    `);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_llm_ts ON llm_metering(timestamp)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_llm_provider ON llm_metering(provider_id, timestamp)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_llm_model ON llm_metering(model, timestamp)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_llm_buyer ON llm_metering(buyer_address, timestamp)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_llm_service ON llm_metering(service, timestamp)`);
  }

  // ─── Record ──────────────────────────────────────────────────────────────

  record(entry: MeterEntryInput): string {
    const id = crypto.randomUUID();
    const tokens_per_second = entry.latency_ms > 0
      ? entry.completion_tokens / (entry.latency_ms / 1000)
      : 0;

    this.sql.exec(
      `INSERT INTO llm_metering
       (id, timestamp, service, model, provider_id, source, request_id,
        prompt_tokens, completion_tokens, total_tokens,
        estimated_cost, actual_cost, price_per_1k_tokens,
        latency_ms, time_to_first_token_ms, tokens_per_second,
        http_status, error, attestation_id, buyer_address, shard)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      id,
      entry.timestamp,
      entry.service,
      entry.model,
      entry.provider_id,
      entry.source,
      entry.request_id,
      entry.prompt_tokens,
      entry.completion_tokens,
      entry.total_tokens,
      entry.estimated_cost_persist,
      entry.actual_cost_persist,
      entry.price_per_1k_tokens,
      entry.latency_ms,
      entry.time_to_first_token_ms,
      tokens_per_second,
      entry.http_status,
      entry.error,
      entry.attestation_id,
      entry.buyer_address,
      entry.shard,
    );

    return id;
  }

  // ─── Extract Usage (OpenAI-compatible) ─────────────────────────────────

  static extractUsage(responseBody: any): TokenUsage | null {
    const usage = responseBody?.usage;
    if (!usage || typeof usage.prompt_tokens !== "number" || typeof usage.completion_tokens !== "number") {
      return null;
    }
    return {
      prompt_tokens: usage.prompt_tokens,
      completion_tokens: usage.completion_tokens,
      total_tokens: usage.total_tokens ?? (usage.prompt_tokens + usage.completion_tokens),
    };
  }

  // ─── Extract Usage (Workers AI) ────────────────────────────────────────

  static extractWorkersAIUsage(responseBody: any): TokenUsage | null {
    const usage = responseBody?.usage ?? responseBody?.result?.usage;
    if (!usage) return null;

    const input = usage.input_tokens ?? usage.prompt_tokens;
    const output = usage.output_tokens ?? usage.completion_tokens;
    if (typeof input !== "number" || typeof output !== "number") return null;

    return {
      prompt_tokens: input,
      completion_tokens: output,
      total_tokens: usage.total_tokens ?? (input + output),
    };
  }

  // ─── Summary ──────────────────────────────────────────────────────────────

  getSummary(period: "hour" | "day" | "all"): MeteringSummary {
    const now = Date.now();
    const cutoff = period === "hour" ? now - 3_600_000
      : period === "day" ? now - 86_400_000
      : 0;

    const whereClause = cutoff > 0 ? "WHERE timestamp >= ?" : "";
    const params = cutoff > 0 ? [cutoff] : [];

    // Aggregate totals
    const aggRows = [...this.sql.exec(
      `SELECT
         COUNT(*) as total_requests,
         COALESCE(SUM(prompt_tokens), 0) as total_prompt_tokens,
         COALESCE(SUM(completion_tokens), 0) as total_completion_tokens,
         COALESCE(SUM(CAST(actual_cost AS INTEGER)), 0) as total_cost,
         COALESCE(AVG(latency_ms), 0) as avg_latency_ms,
         COALESCE(AVG(tokens_per_second), 0) as avg_tokens_per_second,
         COALESCE(SUM(CASE WHEN http_status >= 400 THEN 1 ELSE 0 END), 0) as error_count
       FROM llm_metering ${whereClause}`,
      ...params,
    )] as any[];

    const agg = aggRows[0] || {};
    const totalRequests = agg.total_requests || 0;

    // By model breakdown
    const modelRows = [...this.sql.exec(
      `SELECT
         model,
         COUNT(*) as requests,
         COALESCE(SUM(prompt_tokens), 0) as prompt_tokens,
         COALESCE(SUM(completion_tokens), 0) as completion_tokens,
         COALESCE(SUM(CAST(actual_cost AS INTEGER)), 0) as cost,
         COALESCE(AVG(latency_ms), 0) as avg_latency_ms
       FROM llm_metering ${whereClause}
       GROUP BY model`,
      ...params,
    )] as any[];

    const by_model: MeteringSummary["by_model"] = {};
    for (const row of modelRows) {
      by_model[row.model] = {
        requests: row.requests,
        prompt_tokens: row.prompt_tokens,
        completion_tokens: row.completion_tokens,
        cost: String(row.cost),
        avg_latency_ms: row.avg_latency_ms,
      };
    }

    // By provider breakdown
    const providerRows = [...this.sql.exec(
      `SELECT
         COALESCE(provider_id, '_local') as provider,
         COUNT(*) as requests,
         COALESCE(SUM(total_tokens), 0) as total_tokens,
         COALESCE(SUM(CAST(actual_cost AS INTEGER)), 0) as cost,
         COALESCE(AVG(latency_ms), 0) as avg_latency_ms,
         COALESCE(SUM(CASE WHEN http_status >= 400 THEN 1 ELSE 0 END), 0) as error_count
       FROM llm_metering ${whereClause}
       GROUP BY provider_id`,
      ...params,
    )] as any[];

    const by_provider: MeteringSummary["by_provider"] = {};
    for (const row of providerRows) {
      by_provider[row.provider] = {
        requests: row.requests,
        total_tokens: row.total_tokens,
        cost: String(row.cost),
        avg_latency_ms: row.avg_latency_ms,
        error_count: row.error_count,
      };
    }

    return {
      period,
      total_requests: totalRequests,
      total_prompt_tokens: agg.total_prompt_tokens || 0,
      total_completion_tokens: agg.total_completion_tokens || 0,
      total_cost_persist: String(agg.total_cost || 0),
      avg_latency_ms: agg.avg_latency_ms || 0,
      avg_tokens_per_second: agg.avg_tokens_per_second || 0,
      error_rate: totalRequests > 0 ? (agg.error_count || 0) / totalRequests : 0,
      by_model,
      by_provider,
    };
  }

  // ─── Query by Buyer ──────────────────────────────────────────────────────

  getByBuyer(buyerAddress: string, limit: number = 50): LLMMeterEntry[] {
    return [...this.sql.exec(
      `SELECT * FROM llm_metering WHERE buyer_address = ? ORDER BY timestamp DESC LIMIT ?`,
      buyerAddress, limit,
    )] as LLMMeterEntry[];
  }

  // ─── Query by Provider ────────────────────────────────────────────────────

  getByProvider(providerId: string, limit: number = 50): LLMMeterEntry[] {
    return [...this.sql.exec(
      `SELECT * FROM llm_metering WHERE provider_id = ? ORDER BY timestamp DESC LIMIT ?`,
      providerId, limit,
    )] as LLMMeterEntry[];
  }

  // ─── Provider Rate Stats ──────────────────────────────────────────────────

  getProviderRate(providerId: string, model: string): {
    avg_price_per_1k: string;
    request_count: number;
    avg_latency_ms: number;
  } | null {
    const rows = [...this.sql.exec(
      `SELECT
         COALESCE(AVG(CAST(price_per_1k_tokens AS REAL)), 0) as avg_price,
         COUNT(*) as cnt,
         COALESCE(AVG(latency_ms), 0) as avg_latency
       FROM llm_metering
       WHERE provider_id = ? AND model = ?`,
      providerId, model,
    )] as any[];

    const row = rows[0];
    if (!row || row.cnt === 0) return null;

    return {
      avg_price_per_1k: String(Math.round(row.avg_price)),
      request_count: row.cnt,
      avg_latency_ms: row.avg_latency,
    };
  }

  // ─── Today's Usage ────────────────────────────────────────────────────────

  getTodayUsage(): {
    total_tokens: number;
    total_requests: number;
    by_service: Record<string, { tokens: number; requests: number }>;
  } {
    // Midnight UTC today
    const now = new Date();
    const midnight = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());

    const aggRows = [...this.sql.exec(
      `SELECT COALESCE(SUM(total_tokens), 0) as tokens, COUNT(*) as cnt
       FROM llm_metering WHERE timestamp >= ?`,
      midnight,
    )] as any[];

    const agg = aggRows[0] || {};

    const serviceRows = [...this.sql.exec(
      `SELECT service, COALESCE(SUM(total_tokens), 0) as tokens, COUNT(*) as cnt
       FROM llm_metering WHERE timestamp >= ?
       GROUP BY service`,
      midnight,
    )] as any[];

    const by_service: Record<string, { tokens: number; requests: number }> = {};
    for (const row of serviceRows) {
      by_service[row.service] = { tokens: row.tokens, requests: row.cnt };
    }

    return {
      total_tokens: agg.tokens || 0,
      total_requests: agg.cnt || 0,
      by_service,
    };
  }

  // ─── Prune ────────────────────────────────────────────────────────────────

  prune(olderThanMs: number): number {
    const cutoff = Date.now() - olderThanMs;
    const before = [...this.sql.exec(
      `SELECT COUNT(*) as cnt FROM llm_metering WHERE timestamp < ?`,
      cutoff,
    )] as any[];
    const count = before[0]?.cnt || 0;

    if (count > 0) {
      this.sql.exec(`DELETE FROM llm_metering WHERE timestamp < ?`, cutoff);
    }

    return count;
  }
}
