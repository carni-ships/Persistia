// ─── Oracle Mesh Intelligence ──────────────────────────────────────────────
// Mesh-inspired coordination layer for the oracle network.
// Patterns adapted from AnarchAI/mesh-llm:
//   1. Feed demand map — prioritize observation of hot feeds
//   2. Validator blackboard — ephemeral coordination messages
//   3. Deterministic feed leader election — reduce redundant source fetches
//   4. Two-tier feed observation sharding — all-vs-subset assignment
//   5. Observation digest sync — catch-up for new/recovering nodes
//   6. Dynamic source scoring — reliability/latency-weighted source selection

import type {
  FeedDemand, FeedDemandMap, BlackboardItem, BlackboardDigest,
  FeedLeaderAssignment, SourceStats, OracleFeedConfig,
} from "./types";

// ─── Constants ─────────────────────────────────────────────────────────────

const DEMAND_TTL_MS = 86_400_000;          // 24h expiry for demand entries
const BLACKBOARD_TTL_MS = 172_800_000;     // 48h message expiry
const BLACKBOARD_MAX_ITEMS = 500;
const BLACKBOARD_RATE_LIMIT = 10;          // posts per minute per author
const DEMAND_HOT_THRESHOLD = 5;            // reads+subs above this = "hot" feed
const SHARD_MIN_VALIDATORS = 3;            // minimum validators per feed shard
const SOURCE_SCORE_DECAY = 0.95;           // exponential decay per hour for stats
const SOURCE_SCORE_MIN_SAMPLES = 3;        // minimum samples before scoring kicks in

// ─── PII Patterns (for blackboard scrubbing) ───────────────────────────────

const PII_PATTERNS = [
  /\b[\w.-]+@[\w.-]+\.\w{2,}\b/g,                    // email
  /\b(sk-|pk-|ghp_|ghu_|ghs_|AKIA|xoxb-|xoxp-)\S+/g, // API keys
  /\b(password|passwd|secret|token|api_key)=\S+/gi,    // credential params
  /\/Users\/\w+\//g,                                    // macOS paths
  /\/home\/\w+\//g,                                     // Linux paths
  /C:\\Users\\\w+\\/g,                                  // Windows paths
  /-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/g, // PEM blocks
];

// ─── Oracle Mesh Manager ───────────────────────────────────────────────────

export class OracleMeshManager {
  private sql: any;
  private nodePubkey: string;
  private rateLimitLog: Map<string, number[]> = new Map();

  constructor(sql: any, nodePubkey: string) {
    this.sql = sql;
    this.nodePubkey = nodePubkey;
  }

  /** Update node pubkey after identity loads (loadState runs before identity init). */
  setNodePubkey(pubkey: string): void {
    this.nodePubkey = pubkey;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. FEED DEMAND MAP
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Record a consumer interaction (read or subscription) for demand tracking.
   */
  recordDemand(feedId: string, type: "read" | "subscribe"): void {
    const now = Date.now();
    this.sql.exec(
      `INSERT INTO oracle_feed_demand (feed_id, read_count, subscription_count, last_active)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(feed_id) DO UPDATE SET
         read_count = read_count + ?,
         subscription_count = subscription_count + ?,
         last_active = ?`,
      feedId,
      type === "read" ? 1 : 0,
      type === "subscribe" ? 1 : 0,
      now,
      type === "read" ? 1 : 0,
      type === "subscribe" ? 1 : 0,
      now,
    );
  }

  /**
   * Get local demand map for gossiping to peers.
   */
  getLocalDemandMap(): FeedDemandMap {
    const rows = [...this.sql.exec(
      "SELECT * FROM oracle_feed_demand WHERE last_active > ?",
      Date.now() - DEMAND_TTL_MS,
    )] as any[];

    return {
      demands: rows.map((r: any) => ({
        feed_id: r.feed_id,
        read_count: r.read_count,
        subscription_count: r.subscription_count,
        last_active: r.last_active,
      })),
      sender: this.nodePubkey,
      timestamp: Date.now(),
    };
  }

  /**
   * Merge incoming demand map from a peer (max-merge, like mesh-llm).
   */
  mergeDemandMap(incoming: FeedDemandMap): void {
    for (const d of incoming.demands) {
      if (!d.feed_id || d.last_active < Date.now() - DEMAND_TTL_MS) continue;

      this.sql.exec(
        `INSERT INTO oracle_feed_demand (feed_id, read_count, subscription_count, last_active)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(feed_id) DO UPDATE SET
           read_count = MAX(read_count, ?),
           subscription_count = MAX(subscription_count, ?),
           last_active = MAX(last_active, ?)`,
        d.feed_id, d.read_count, d.subscription_count, d.last_active,
        d.read_count, d.subscription_count, d.last_active,
      );
    }
  }

  /**
   * Get feeds sorted by demand (hottest first).
   */
  getFeedsByDemand(): FeedDemand[] {
    const rows = [...this.sql.exec(
      `SELECT * FROM oracle_feed_demand
       WHERE last_active > ?
       ORDER BY (read_count + subscription_count * 10) DESC`,
      Date.now() - DEMAND_TTL_MS,
    )] as any[];

    return rows.map((r: any) => ({
      feed_id: r.feed_id,
      read_count: r.read_count,
      subscription_count: r.subscription_count,
      last_active: r.last_active,
    }));
  }

  /**
   * Check if a feed is "hot" (high demand).
   */
  isHotFeed(feedId: string): boolean {
    const rows = [...this.sql.exec(
      "SELECT read_count, subscription_count FROM oracle_feed_demand WHERE feed_id = ?",
      feedId,
    )] as any[];
    if (rows.length === 0) return false;
    return (rows[0].read_count + rows[0].subscription_count * 10) >= DEMAND_HOT_THRESHOLD;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. VALIDATOR BLACKBOARD
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Post a message to the blackboard. Returns the item or null if rate-limited.
   */
  postMessage(
    prefix: BlackboardItem["prefix"],
    text: string,
  ): BlackboardItem | null {
    // Rate limit: 10 posts/min per author
    const now = Date.now();
    const log = this.rateLimitLog.get(this.nodePubkey) || [];
    const recent = log.filter(t => t > now - 60_000);
    if (recent.length >= BLACKBOARD_RATE_LIMIT) return null;
    recent.push(now);
    this.rateLimitLog.set(this.nodePubkey, recent);

    // PII scrub
    const scrubbed = this.scrubPII(text);

    const item: BlackboardItem = {
      id: `bb-${now}-${Math.random().toString(36).slice(2, 8)}`,
      author: this.nodePubkey,
      prefix,
      text: scrubbed,
      timestamp: now,
      expires_at: now + BLACKBOARD_TTL_MS,
    };

    this.sql.exec(
      `INSERT OR IGNORE INTO oracle_blackboard (id, author, prefix, text, timestamp, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      item.id, item.author, item.prefix, item.text, item.timestamp, item.expires_at,
    );

    return item;
  }

  /**
   * Receive a blackboard item from gossip. Returns true if new.
   */
  receiveMessage(item: BlackboardItem): boolean {
    if (!item.id || !item.text || item.expires_at < Date.now()) return false;

    // Check duplicate
    const existing = [...this.sql.exec(
      "SELECT 1 FROM oracle_blackboard WHERE id = ?", item.id,
    )];
    if (existing.length > 0) return false;

    // PII scrub incoming messages too
    item.text = this.scrubPII(item.text);

    this.sql.exec(
      `INSERT OR IGNORE INTO oracle_blackboard (id, author, prefix, text, timestamp, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      item.id, item.author, item.prefix, item.text, item.timestamp, item.expires_at,
    );
    return true;
  }

  /**
   * Get blackboard digest (list of item IDs) for sync protocol.
   */
  getDigest(): BlackboardDigest {
    const rows = [...this.sql.exec(
      "SELECT id FROM oracle_blackboard WHERE expires_at > ? ORDER BY timestamp DESC LIMIT ?",
      Date.now(), BLACKBOARD_MAX_ITEMS,
    )] as any[];

    return {
      item_ids: rows.map((r: any) => r.id),
      sender: this.nodePubkey,
    };
  }

  /**
   * Compute which IDs we're missing from a peer's digest.
   */
  getMissingIds(peerDigest: BlackboardDigest): string[] {
    const ourIds = new Set(this.getDigest().item_ids);
    return peerDigest.item_ids.filter(id => !ourIds.has(id));
  }

  /**
   * Get items by IDs (for fetch response).
   */
  getItemsByIds(ids: string[]): BlackboardItem[] {
    if (ids.length === 0) return [];
    const placeholders = ids.map(() => "?").join(",");
    const rows = [...this.sql.exec(
      `SELECT * FROM oracle_blackboard WHERE id IN (${placeholders}) AND expires_at > ?`,
      ...ids, Date.now(),
    )] as any[];
    return rows.map(this.rowToBlackboardItem);
  }

  /**
   * Search blackboard messages (multi-term OR, ranked by hit count).
   */
  searchMessages(query: string, limit: number = 20): BlackboardItem[] {
    const terms = query.toLowerCase().split(/\s+/).filter(t => t.length > 0);
    if (terms.length === 0) return [];

    const now = Date.now();
    const rows = [...this.sql.exec(
      "SELECT * FROM oracle_blackboard WHERE expires_at > ? ORDER BY timestamp DESC LIMIT 500",
      now,
    )] as any[];

    const scored = rows.map((r: any) => {
      const text = (r.text + " " + r.prefix + " " + r.author).toLowerCase();
      const hits = terms.filter(t => text.includes(t)).length;
      return { item: this.rowToBlackboardItem(r), hits };
    }).filter(s => s.hits > 0);

    scored.sort((a, b) => b.hits - a.hits || b.item.timestamp - a.item.timestamp);
    return scored.slice(0, limit).map(s => s.item);
  }

  /**
   * Get recent messages (feed view).
   */
  getRecentMessages(sinceMs: number = 86_400_000, limit: number = 50): BlackboardItem[] {
    const rows = [...this.sql.exec(
      `SELECT * FROM oracle_blackboard
       WHERE expires_at > ? AND timestamp > ?
       ORDER BY timestamp DESC LIMIT ?`,
      Date.now(), Date.now() - sinceMs, limit,
    )] as any[];
    return rows.map(this.rowToBlackboardItem);
  }

  private scrubPII(text: string): string {
    let scrubbed = text;
    for (const pattern of PII_PATTERNS) {
      scrubbed = scrubbed.replace(pattern, "[REDACTED]");
    }
    return scrubbed;
  }

  private rowToBlackboardItem(row: any): BlackboardItem {
    return {
      id: row.id,
      author: row.author,
      prefix: row.prefix,
      text: row.text,
      timestamp: row.timestamp,
      expires_at: row.expires_at,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. DETERMINISTIC FEED LEADER ELECTION
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Deterministically elect a leader for each feed.
   * Algorithm: sort active validators by reputation (desc), then pubkey (asc).
   * Feed leader = validator at index (hash(feed_id) % validator_count).
   * All nodes compute identical results from the same validator set.
   */
  electFeedLeader(feedId: string, activeValidators: { pubkey: string; reputation: number }[]): string | null {
    if (activeValidators.length === 0) return null;

    // Sort: highest reputation first, pubkey tiebreak for determinism
    const sorted = [...activeValidators].sort((a, b) => {
      if (b.reputation !== a.reputation) return b.reputation - a.reputation;
      return a.pubkey < b.pubkey ? -1 : 1;
    });

    // Hash feed_id to get a deterministic index
    const hash = this.simpleHash(feedId);
    const index = hash % sorted.length;
    return sorted[index].pubkey;
  }

  /**
   * Get all feed leader assignments for the current validator set.
   */
  getFeedLeaderAssignments(
    feeds: OracleFeedConfig[],
    activeValidators: { pubkey: string; reputation: number }[],
    epoch: number,
  ): FeedLeaderAssignment[] {
    return feeds.map(feed => ({
      feed_id: feed.id,
      leader_pubkey: this.electFeedLeader(feed.id, activeValidators) || "",
      epoch,
    }));
  }

  /**
   * Check if this node is the leader for a given feed.
   */
  isLeaderForFeed(feedId: string, activeValidators: { pubkey: string; reputation: number }[]): boolean {
    return this.electFeedLeader(feedId, activeValidators) === this.nodePubkey;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. TWO-TIER FEED OBSERVATION SHARDING
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Determine which feeds this validator should observe.
   * Tier 1 (all observe): hot feeds + feeds with subscriptions
   * Tier 2 (shard): niche feeds assigned via consistent hashing
   *
   * Returns the list of feed IDs this node should observe.
   */
  getAssignedFeeds(
    allFeeds: OracleFeedConfig[],
    activeValidators: string[],
  ): { tier1: string[]; tier2: string[] } {
    if (activeValidators.length === 0) {
      return { tier1: allFeeds.map(f => f.id), tier2: [] };
    }

    const tier1: string[] = [];
    const tier2: string[] = [];

    for (const feed of allFeeds) {
      if (feed.status !== "active") continue;

      // Tier 1: hot feeds — all validators observe
      if (this.isHotFeed(feed.id)) {
        tier1.push(feed.id);
        continue;
      }

      // Tier 2: shard assignment via consistent hashing
      const assignedValidators = this.getShardValidators(
        feed.id,
        activeValidators,
        Math.max(SHARD_MIN_VALIDATORS, Math.ceil(activeValidators.length * 0.4)),
      );

      if (assignedValidators.includes(this.nodePubkey)) {
        tier2.push(feed.id);
      }
    }

    return { tier1, tier2 };
  }

  /**
   * Consistent hashing to assign a subset of validators to a feed.
   * Each validator gets a deterministic score for each feed.
   * Top N validators by score are assigned.
   */
  private getShardValidators(
    feedId: string,
    validators: string[],
    count: number,
  ): string[] {
    const scored = validators.map(pubkey => ({
      pubkey,
      score: this.simpleHash(`${feedId}:${pubkey}`),
    }));
    scored.sort((a, b) => a.score - b.score);
    return scored.slice(0, Math.min(count, validators.length)).map(s => s.pubkey);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. OBSERVATION DIGEST SYNC
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get a digest of recent observation rounds for sync protocol.
   * Returns {feed_id, round, committed_at} for rounds committed in the last hour.
   */
  getObservationDigest(): { feed_id: string; round: number; committed_at: number }[] {
    const rows = [...this.sql.exec(
      `SELECT feed_id, round, committed_at FROM oracle_feed_rounds
       WHERE committed_at > ?
       ORDER BY committed_at DESC LIMIT 500`,
      Date.now() - 3_600_000,
    )] as any[];

    return rows.map((r: any) => ({
      feed_id: r.feed_id,
      round: r.round,
      committed_at: r.committed_at,
    }));
  }

  /**
   * Compute which rounds we're missing compared to a peer's digest.
   */
  getMissingRounds(
    peerDigest: { feed_id: string; round: number; committed_at: number }[],
  ): { feed_id: string; round: number }[] {
    const missing: { feed_id: string; round: number }[] = [];

    for (const entry of peerDigest) {
      const exists = [...this.sql.exec(
        "SELECT 1 FROM oracle_feed_rounds WHERE feed_id = ? AND round = ?",
        entry.feed_id, entry.round,
      )];
      if (exists.length === 0) {
        missing.push({ feed_id: entry.feed_id, round: entry.round });
      }
    }

    return missing;
  }

  /**
   * Get full round data for specific rounds (for fetch response).
   */
  getRoundData(
    requests: { feed_id: string; round: number }[],
  ): { feed_id: string; round: number; value: string; value_num: number | null; observers: number; observations_hash: string; committed_at: number }[] {
    const results: any[] = [];

    for (const req of requests.slice(0, 100)) { // cap at 100 per request
      const rows = [...this.sql.exec(
        "SELECT * FROM oracle_feed_rounds WHERE feed_id = ? AND round = ?",
        req.feed_id, req.round,
      )] as any[];
      if (rows.length > 0) {
        results.push({
          feed_id: rows[0].feed_id,
          round: rows[0].round,
          value: rows[0].value,
          value_num: rows[0].value_num,
          observers: rows[0].observers,
          observations_hash: rows[0].observations_hash,
          committed_at: rows[0].committed_at,
        });
      }
    }

    return results;
  }

  /**
   * Ingest rounds received from a peer's sync response.
   */
  ingestSyncedRounds(
    rounds: { feed_id: string; round: number; value: string; value_num: number | null; observers: number; observations_hash: string; committed_at: number }[],
  ): number {
    let ingested = 0;
    for (const r of rounds) {
      try {
        this.sql.exec(
          `INSERT OR IGNORE INTO oracle_feed_rounds (feed_id, round, value, value_num, observers, observations_hash, committed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          r.feed_id, r.round, r.value, r.value_num, r.observers, r.observations_hash, r.committed_at,
        );

        // Also update latest if this round is newer
        const latest = [...this.sql.exec(
          "SELECT round FROM oracle_feed_latest WHERE feed_id = ?", r.feed_id,
        )] as any[];
        if (latest.length === 0 || latest[0].round < r.round) {
          const feed = [...this.sql.exec(
            "SELECT heartbeat_ms FROM oracle_feeds WHERE id = ?", r.feed_id,
          )] as any[];
          const heartbeat = feed[0]?.heartbeat_ms || 60_000;
          this.sql.exec(
            `INSERT OR REPLACE INTO oracle_feed_latest (feed_id, value, value_num, round, observers, committed_at, stale_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            r.feed_id, r.value, r.value_num, r.round, r.observers, r.committed_at,
            r.committed_at + heartbeat * 3,
          );
        }

        ingested++;
      } catch { /* ignore conflicts */ }
    }
    return ingested;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. DYNAMIC SOURCE SCORING
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Record the outcome of a source fetch for scoring.
   */
  recordSourceResult(
    feedId: string,
    sourceIndex: number,
    sourceType: string,
    success: boolean,
    latencyMs: number,
    freshnessMs: number,
  ): void {
    this.sql.exec(
      `INSERT INTO oracle_source_stats (feed_id, source_index, source_type, success_count, failure_count, total_latency_ms, last_success, last_failure, avg_freshness_ms)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(feed_id, source_index) DO UPDATE SET
         success_count = success_count + ?,
         failure_count = failure_count + ?,
         total_latency_ms = total_latency_ms + ?,
         last_success = MAX(last_success, ?),
         last_failure = MAX(last_failure, ?),
         avg_freshness_ms = CASE WHEN ? > 0
           THEN (avg_freshness_ms * 0.8 + ? * 0.2)
           ELSE avg_freshness_ms END`,
      feedId, sourceIndex, sourceType,
      success ? 1 : 0, success ? 0 : 1,
      success ? latencyMs : 0,
      success ? Date.now() : 0,
      success ? 0 : Date.now(),
      success ? freshnessMs : 0,
      // update params
      success ? 1 : 0, success ? 0 : 1,
      success ? latencyMs : 0,
      success ? Date.now() : 0,
      success ? 0 : Date.now(),
      success ? 1 : 0,
      freshnessMs,
    );
  }

  /**
   * Get source stats for a feed.
   */
  getSourceStats(feedId: string): SourceStats[] {
    const rows = [...this.sql.exec(
      "SELECT * FROM oracle_source_stats WHERE feed_id = ? ORDER BY source_index",
      feedId,
    )] as any[];
    return rows.map((r: any) => ({
      feed_id: r.feed_id,
      source_index: r.source_index,
      source_type: r.source_type,
      success_count: r.success_count,
      failure_count: r.failure_count,
      total_latency_ms: r.total_latency_ms,
      last_success: r.last_success,
      last_failure: r.last_failure,
      avg_freshness_ms: r.avg_freshness_ms,
    }));
  }

  /**
   * Compute a dynamic weight multiplier for each source based on its stats.
   * Returns a map of source_index → weight_multiplier (0.1 to 3.0).
   *
   * Score = reliability_score * (1 / latency_score) * freshness_score
   *   reliability = success_rate ^ 2 (penalize unreliable sources quadratically)
   *   latency = normalized avg latency (lower is better)
   *   freshness = normalized avg freshness (lower is better)
   */
  computeSourceWeights(feedId: string): Map<number, number> {
    const stats = this.getSourceStats(feedId);
    const weights = new Map<number, number>();

    if (stats.length === 0) return weights;

    // Compute per-source scores
    const scores: { index: number; score: number }[] = [];
    for (const s of stats) {
      const total = s.success_count + s.failure_count;
      if (total < SOURCE_SCORE_MIN_SAMPLES) {
        weights.set(s.source_index, 1.0); // not enough data, use default
        continue;
      }

      const reliability = Math.pow(s.success_count / total, 2);
      const avgLatency = s.success_count > 0 ? s.total_latency_ms / s.success_count : 10_000;
      const latencyScore = 1000 / (avgLatency + 100); // inverse, normalized
      const freshnessScore = 1000 / (s.avg_freshness_ms + 100);

      const score = reliability * latencyScore * freshnessScore;
      scores.push({ index: s.source_index, score });
    }

    if (scores.length === 0) return weights;

    // Normalize scores to [0.1, 3.0] range
    const maxScore = Math.max(...scores.map(s => s.score));
    if (maxScore <= 0) return weights;

    for (const s of scores) {
      const normalized = (s.score / maxScore) * 2.9 + 0.1; // map [0,1] → [0.1, 3.0]
      weights.set(s.index, Math.round(normalized * 100) / 100);
    }

    return weights;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRUNING
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Prune expired data across all mesh subsystems.
   */
  prune(): void {
    const now = Date.now();

    // Blackboard: remove expired messages, cap at MAX_ITEMS
    this.sql.exec("DELETE FROM oracle_blackboard WHERE expires_at < ?", now);
    this.sql.exec(
      `DELETE FROM oracle_blackboard WHERE id NOT IN (
        SELECT id FROM oracle_blackboard ORDER BY timestamp DESC LIMIT ?
      )`,
      BLACKBOARD_MAX_ITEMS,
    );

    // Demand map: remove stale entries
    this.sql.exec(
      "DELETE FROM oracle_feed_demand WHERE last_active < ?",
      now - DEMAND_TTL_MS,
    );

    // Source stats: decay old stats (reduce counts to prevent unbounded growth)
    this.sql.exec(
      `UPDATE oracle_source_stats SET
         success_count = CAST(success_count * 0.9 AS INTEGER),
         failure_count = CAST(failure_count * 0.9 AS INTEGER),
         total_latency_ms = CAST(total_latency_ms * 0.9 AS INTEGER)
       WHERE success_count + failure_count > 100`,
    );

    // Clear rate limit log
    this.rateLimitLog.clear();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Simple deterministic hash for consistent sharding/election.
   * Not cryptographic — just needs to be uniform and deterministic.
   */
  private simpleHash(input: string): number {
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
      const chr = input.charCodeAt(i);
      hash = ((hash << 5) - hash) + chr;
      hash |= 0;
    }
    return Math.abs(hash);
  }
}
