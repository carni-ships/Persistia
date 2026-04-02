// ─── Persistia Oracle Network (PON) ─────────────────────────────────────────
// Proactive feed-based oracle with sub-round delivery via gossip.
// Validators observe → gossip observations → aggregate at quorum → commit.
// Inspired by Chainlink DON OCR and Pyth Network.

import { sha256 } from "./consensus";
import {
  fetchChainlinkBatch, fetchRedstoneBoltBatch,
  fetchSource, type SourceFetchResult,
} from "./oracle-mirrors";
import type {
  MirrorResult, OracleFeedConfig, FeedSource, FeedRound, OracleObservation,
  OracleObservationBatch, OracleSubscription, VRFRequest, VRFPartial,
  FeedLatest, OracleAggregation, OraclePushSubscription, OraclePushAttestation,
  OraclePushDepositor,
} from "./types";
import {
  keccak256, toBytes, toHex, encodeAbiParameters, encodePacked,
  getContractAddress, parseAbiParameters,
} from "viem";

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_FEEDS = 200;
const MAX_SUBSCRIPTIONS_PER_CONTRACT = 20;
const MAX_PUSH_DEPOSITS_PER_DEPOSITOR = 10;

// ─── Chainlink-Compatible Push Constants ──────────────────────────────────
// transmit(int256,uint80,uint256,uint256,bytes32,bytes) selector
const TRANSMIT_SELECTOR = keccak256(toBytes("transmit(int256,uint80,uint256,uint256,bytes32,bytes)")).slice(0, 10);

// Factory addresses per destination chain (deployed via Nick's factory for deterministic addresses)
// These are placeholders until the PersistiaOracleFactory is deployed on each chain
const FACTORY_ADDRESSES: Record<number, `0x${string}`> = {
  42161: "0x0000000000000000000000000000000000000000" as `0x${string}`, // Arbitrum One — TBD
  6342:  "0x0000000000000000000000000000000000000000" as `0x${string}`, // MegaETH — TBD
};

// keccak256 of PersistiaOracleReceiver creation bytecode — TBD after compilation
const RECEIVER_INIT_CODE_HASH = "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;
const MAX_OBSERVATIONS_PER_BATCH = 200;
const STALE_MULTIPLIER = 3; // feed goes stale after 3x heartbeat
const DEFAULT_HEARTBEAT_MS = 60_000;
const DEFAULT_DEVIATION_BPS = 50; // 0.5%
const MIN_HEARTBEAT_MS = 10_000;
const MAX_HEARTBEAT_MS = 86_400_000;

// ─── Graduated Oracle Slashing ─────────────────────────────────────────────
// Severity tiers for oracle misbehavior, applied as reputation adjustments
// via the validators table (shared with ValidatorRegistry).

const SLASH_MISSED_OBSERVATION = -2;        // mild: didn't observe when expected
const SLASH_MODERATE_DEVIATION = -5;        // moderate: observation > 2% from consensus
const SLASH_LARGE_DEVIATION = -15;          // severe: observation > 10% from consensus
const SLASH_CONTRADICTORY_OBSERVATION = -50; // critical: two different values same round
const SLASH_DEVIATION_MODERATE_BPS = 200;   // 2% threshold
const SLASH_DEVIATION_LARGE_BPS = 1000;     // 10% threshold
const REWARD_ACCURATE_OBSERVATION = 1;      // small reward for on-consensus observation

// ─── Oracle Network Class ───────────────────────────────────────────────────

export class OracleNetwork {
  private sql: any;
  private stateTree: any;
  private nodePubkey: string;
  private getActiveNodeCount: () => number;
  private getQuorumSize: (n: number) => number;
  private signPayload: (data: string) => Promise<string>;
  private observeCycle: number = 0;
  onSourceStats?: (feedId: string, results: SourceFetchResult[]) => void;

  constructor(opts: {
    sql: any;
    stateTree: any;
    nodePubkey: string;
    getActiveNodeCount: () => number;
    getQuorumSize: (n: number) => number;
    signPayload: (data: string) => Promise<string>;
  }) {
    this.sql = opts.sql;
    this.stateTree = opts.stateTree;
    this.nodePubkey = opts.nodePubkey;
    this.getActiveNodeCount = opts.getActiveNodeCount;
    this.getQuorumSize = opts.getQuorumSize;
    this.signPayload = opts.signPayload;
  }

  // ─── Feed Management ────────────────────────────────────────────────────

  registerFeed(config: {
    id: string;
    description?: string;
    decimals?: number;
    heartbeat_ms?: number;
    deviation_bps?: number;
    aggregation?: OracleAggregation;
    sources: FeedSource[];
    category?: OracleFeedConfig["category"];
  }): string {
    const existing = this.getFeedConfig(config.id);
    const now = Date.now();

    if (existing) {
      // Update existing feed
      this.sql.exec(
        `UPDATE oracle_feeds SET description = ?, decimals = ?, heartbeat_ms = ?, deviation_bps = ?,
         aggregation = ?, sources = ?, category = ?, updated_at = ? WHERE id = ?`,
        config.description || existing.description,
        config.decimals ?? existing.decimals,
        Math.max(MIN_HEARTBEAT_MS, Math.min(MAX_HEARTBEAT_MS, config.heartbeat_ms ?? existing.heartbeat_ms)),
        config.deviation_bps ?? existing.deviation_bps,
        config.aggregation || existing.aggregation,
        JSON.stringify(config.sources),
        config.category || existing.category,
        now,
        config.id,
      );
      return config.id;
    }

    // Check limit
    const count = [...this.sql.exec("SELECT COUNT(*) as cnt FROM oracle_feeds")][0]?.cnt ?? 0;
    if (count >= MAX_FEEDS) throw new Error(`Max ${MAX_FEEDS} feeds reached`);

    this.sql.exec(
      `INSERT INTO oracle_feeds (id, description, decimals, heartbeat_ms, deviation_bps, aggregation, sources, status, category, created_at, updated_at, current_round)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, 0)`,
      config.id,
      config.description || config.id,
      config.decimals ?? 8,
      Math.max(MIN_HEARTBEAT_MS, Math.min(MAX_HEARTBEAT_MS, config.heartbeat_ms ?? DEFAULT_HEARTBEAT_MS)),
      config.deviation_bps ?? DEFAULT_DEVIATION_BPS,
      config.aggregation || "weighted_median",
      JSON.stringify(config.sources),
      config.category || "price",
      now, now,
    );
    return config.id;
  }

  removeFeed(feedId: string): void {
    this.sql.exec("UPDATE oracle_feeds SET status = 'paused' WHERE id = ?", feedId);
  }

  getFeedConfig(feedId: string): OracleFeedConfig | null {
    const rows = [...this.sql.exec("SELECT * FROM oracle_feeds WHERE id = ?", feedId)];
    if (rows.length === 0) return null;
    return this.rowToFeedConfig(rows[0]);
  }

  getActiveFeedConfigs(): OracleFeedConfig[] {
    const rows = [...this.sql.exec("SELECT * FROM oracle_feeds WHERE status = 'active' ORDER BY id")];
    return rows.map(this.rowToFeedConfig);
  }

  getFeedLatest(feedId: string): FeedLatest | null {
    const rows = [...this.sql.exec("SELECT * FROM oracle_feed_latest WHERE feed_id = ?", feedId)];
    if (rows.length === 0) return null;
    const r = rows[0] as any;
    return {
      feed_id: r.feed_id,
      value: r.value,
      value_num: r.value_num,
      round: r.round,
      observers: r.observers,
      committed_at: r.committed_at,
      stale: Date.now() > r.stale_at,
    };
  }

  getFeedRound(feedId: string, round: number): FeedRound | null {
    const rows = [...this.sql.exec(
      "SELECT * FROM oracle_feed_rounds WHERE feed_id = ? AND round = ?", feedId, round,
    )];
    if (rows.length === 0) return null;
    return this.rowToFeedRound(rows[0]);
  }

  getFeedHistory(feedId: string, limit: number = 50): FeedRound[] {
    const rows = [...this.sql.exec(
      "SELECT * FROM oracle_feed_rounds WHERE feed_id = ? ORDER BY round DESC LIMIT ?",
      feedId, Math.min(limit, 500),
    )];
    return rows.map(this.rowToFeedRound);
  }

  getAllFeedLatest(): FeedLatest[] {
    const rows = [...this.sql.exec("SELECT * FROM oracle_feed_latest ORDER BY feed_id")];
    const now = Date.now();
    return rows.map((r: any) => ({
      feed_id: r.feed_id,
      value: r.value,
      value_num: r.value_num,
      round: r.round,
      observers: r.observers,
      committed_at: r.committed_at,
      stale: now > r.stale_at,
    }));
  }

  // ─── Observation-Report-Transmit (ORT) ──────────────────────────────────

  /**
   * Phase 1: OBSERVE — Fetch all active feeds concurrently, return signed batch.
   * Called every alarm cycle by the local validator.
   */
  async observe(assignedFeedIds?: Set<string>): Promise<OracleObservationBatch> {
    this.observeCycle++;
    const feeds = this.getActiveFeedConfigs();
    const now = Date.now();
    const observations: OracleObservation[] = [];

    // Determine which feeds need observation this cycle
    const feedsToObserve = feeds.filter(feed =>
      (!assignedFeedIds || assignedFeedIds.has(feed.id)) && this.shouldObserveFeed(feed, now),
    );

    // ── RPC batching: group Chainlink/Bolt feeds by RPC URL ──
    // Each feed has exactly one source. Batch EVM calls sharing the same RPC.
    const chainlinkByRpc = new Map<string, Set<string>>();
    const boltByRpc = new Map<string, Set<string>>();

    for (const feed of feedsToObserve) {
      const src = feed.sources[0];
      if (!src) continue;
      if (src.type === "chainlink" && src.rpc_url) {
        const set = chainlinkByRpc.get(src.rpc_url) || new Set();
        set.add(src.endpoint);
        chainlinkByRpc.set(src.rpc_url, set);
      } else if (src.type === "redstone_bolt") {
        const rpc = src.rpc_url || "https://mainnet.megaeth.com/rpc";
        const set = boltByRpc.get(rpc) || new Set();
        set.add(src.endpoint);
        boltByRpc.set(rpc, set);
      }
    }

    // Batch-fetch all EVM sources in parallel (one RPC call per unique URL)
    const batchPromises: Promise<any>[] = [];
    const chainlinkRpcKeys: string[] = [];
    for (const [rpcUrl, addrs] of Array.from(chainlinkByRpc.entries())) {
      chainlinkRpcKeys.push(rpcUrl);
      batchPromises.push(fetchChainlinkBatch(Array.from(addrs).map(a => ({ address: a })), rpcUrl));
    }
    const boltRpcKeys: string[] = [];
    for (const [rpcUrl, addrs] of Array.from(boltByRpc.entries())) {
      boltRpcKeys.push(rpcUrl);
      batchPromises.push(fetchRedstoneBoltBatch(Array.from(addrs).map(a => ({ address: a })), rpcUrl));
    }

    const batchResults = batchPromises.length > 0 ? await Promise.all(batchPromises) : [];
    // Merge Chainlink batch results
    const clBatch = new Map<string, MirrorResult>();
    for (let i = 0; i < chainlinkRpcKeys.length; i++) {
      const m = batchResults[i] as Map<string, MirrorResult>;
      Array.from(m.entries()).forEach(([k, v]) => clBatch.set(k, v));
    }
    // Merge Bolt batch results
    const boltBatch = new Map<string, MirrorResult>();
    for (let i = 0; i < boltRpcKeys.length; i++) {
      const m = batchResults[chainlinkRpcKeys.length + i] as Map<string, MirrorResult>;
      Array.from(m.entries()).forEach(([k, v]) => boltBatch.set(k, v));
    }

    // ── Per-feed observation: each feed has exactly one source ──
    const fetchPromises = feedsToObserve.map(async (feed) => {
      try {
        const src = feed.sources[0];
        if (!src) return null;

        const fetchStart = Date.now();
        let result: MirrorResult | null = null;

        // Use batched result for EVM sources, fall back to individual fetch
        if (src.type === "chainlink" && clBatch.has(src.endpoint)) {
          result = clBatch.get(src.endpoint) || null;
        } else if (src.type === "redstone_bolt" && boltBatch.size > 0 && boltBatch.has(src.endpoint)) {
          result = boltBatch.get(src.endpoint) || null;
        } else {
          result = await fetchSource(src);
        }

        const latency = Date.now() - fetchStart;

        // Report stats for source scoring
        if (this.onSourceStats) {
          const stat: SourceFetchResult = result
            ? { source_index: 0, source_type: src.type, success: true, value: result.value,
                weight: src.weight, source_ts: result.source_ts, latency_ms: latency,
                freshness_ms: Math.max(0, now - result.source_ts) }
            : { source_index: 0, source_type: src.type, success: false, weight: src.weight,
                latency_ms: latency, freshness_ms: 0 };
          this.onSourceStats(feed.id, [stat]);
        }

        if (!result) return null;

        return {
          feed_id: feed.id,
          round: feed.current_round + 1,
          observer: this.nodePubkey,
          value: String(result.value),
          value_num: result.value,
          observed_at: now,
        } as OracleObservation;
      } catch {
        return null;
      }
    });

    const results = await Promise.allSettled(fetchPromises);
    for (const r of results) {
      if (r.status === "fulfilled" && r.value !== null) {
        observations.push(r.value);
      }
    }

    // Sign the batch
    const batchData = JSON.stringify({
      observer: this.nodePubkey,
      round_timestamp: now,
      observations: observations.map(o => ({ f: o.feed_id, v: o.value })),
    });
    const signature = await this.signPayload(batchData);

    return {
      observer: this.nodePubkey,
      round_timestamp: now,
      observations,
      signature,
    };
  }

  /**
   * Phase 2: RECEIVE — Store observations and check quorum for each feed.
   * Called when receiving gossip from peers OR processing own observations.
   * Returns list of feed rounds that were committed (quorum reached).
   */
  receiveObservations(batch: OracleObservationBatch): FeedRound[] {
    const committed: FeedRound[] = [];
    const activeCount = this.getActiveNodeCount();
    const quorum = this.getQuorumSize(activeCount);

    for (const obs of batch.observations) {
      if (!obs.feed_id || obs.value === undefined) continue;

      // Check for contradictory observations (different value for same feed+round+observer)
      this.checkContradiction(obs.feed_id, obs.round, obs.observer, obs.value);

      // Store observation
      this.sql.exec(
        `INSERT OR REPLACE INTO oracle_observations (feed_id, round, observer, value, value_num, source_count, observed_at)
         VALUES (?, ?, ?, ?, ?, 1, ?)`,
        obs.feed_id, obs.round, obs.observer, obs.value, obs.value_num, obs.observed_at,
      );

      // Check if quorum reached for this feed+round
      const count = [...this.sql.exec(
        "SELECT COUNT(*) as cnt FROM oracle_observations WHERE feed_id = ? AND round = ?",
        obs.feed_id, obs.round,
      )][0]?.cnt ?? 0;

      if (count >= quorum) {
        // Check if already committed
        const existing = [...this.sql.exec(
          "SELECT 1 FROM oracle_feed_rounds WHERE feed_id = ? AND round = ?",
          obs.feed_id, obs.round,
        )];
        if (existing.length > 0) continue;

        // Aggregate and commit
        const round = this.aggregateAndCommit(obs.feed_id, obs.round, quorum);
        if (round) committed.push(round);
      }
    }

    return committed;
  }

  /**
   * Phase 3: AGGREGATE & COMMIT — Compute consensus value from quorum observations.
   */
  private aggregateAndCommit(feedId: string, round: number, quorum: number): FeedRound | null {
    const feed = this.getFeedConfig(feedId);
    if (!feed) return null;

    const observations = [...this.sql.exec(
      "SELECT * FROM oracle_observations WHERE feed_id = ? AND round = ? ORDER BY observer",
      feedId, round,
    )] as any[];

    if (observations.length < quorum) return null;

    // Aggregate based on feed's strategy
    let value: string;
    let valueNum: number | null = null;

    switch (feed.aggregation) {
      case "weighted_median":
      case "median": {
        const nums = observations
          .map((o: any) => parseFloat(o.value))
          .filter((n: number) => !isNaN(n) && isFinite(n));
        if (nums.length < quorum) return null;
        nums.sort((a: number, b: number) => a - b);
        const mid = Math.floor(nums.length / 2);
        valueNum = nums.length % 2 === 0
          ? (nums[mid - 1] + nums[mid]) / 2
          : nums[mid];
        value = String(valueNum);
        break;
      }
      case "identical": {
        const first = observations[0].value;
        const allSame = observations.every((o: any) => o.value === first);
        if (!allSame) return null; // no consensus
        value = first;
        valueNum = parseFloat(first);
        if (isNaN(valueNum)) valueNum = null;
        break;
      }
      case "majority": {
        const counts = new Map<string, number>();
        for (const o of observations) {
          counts.set(o.value, (counts.get(o.value) || 0) + 1);
        }
        let best = ""; let bestCount = 0;
        for (const [v, c] of counts) {
          if (c > bestCount) { best = v; bestCount = c; }
        }
        if (bestCount < quorum) return null;
        value = best;
        valueNum = parseFloat(best);
        if (isNaN(valueNum)) valueNum = null;
        break;
      }
      default:
        return null;
    }

    // Check deviation threshold — skip commit if value hasn't moved enough
    // (unless heartbeat forces it)
    const latest = this.getFeedLatest(feedId);
    if (latest && latest.value_num !== null && valueNum !== null) {
      const deviationBps = Math.abs((valueNum - latest.value_num) / latest.value_num) * 10_000;
      const timeSinceLastCommit = Date.now() - latest.committed_at;
      if (deviationBps < feed.deviation_bps && timeSinceLastCommit < feed.heartbeat_ms) {
        // Not enough deviation and heartbeat not expired — skip
        return null;
      }
    }

    // Compute observations hash for cross-verification
    const sortedObs = observations.map((o: any) => `${o.observer}:${o.value}`).sort();
    // Use synchronous hash since we're in a hot path
    const obsHashInput = sortedObs.join("|");
    const obsHash = this.syncHash(obsHashInput);

    const now = Date.now();

    // Commit the round
    this.sql.exec(
      `INSERT OR IGNORE INTO oracle_feed_rounds (feed_id, round, value, value_num, observers, observations_hash, committed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      feedId, round, value, valueNum, observations.length, obsHash, now,
    );

    // Update feed's current_round
    this.sql.exec(
      "UPDATE oracle_feeds SET current_round = ?, updated_at = ? WHERE id = ?",
      round, now, feedId,
    );

    // Update denormalized latest
    const staleAt = now + (feed.heartbeat_ms * STALE_MULTIPLIER);
    this.sql.exec(
      `INSERT OR REPLACE INTO oracle_feed_latest (feed_id, value, value_num, round, observers, committed_at, stale_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      feedId, value, valueNum, round, observations.length, now, staleAt,
    );

    // Mark dirty in state tree for Merkle proofs
    if (this.stateTree) {
      this.stateTree.markDirty(`oracle:${feedId}:latest`, `${value}:${round}:${now}`);
    }

    const feedRound: FeedRound = {
      feed_id: feedId, round, value, value_num: valueNum,
      observers: observations.length, observations_hash: obsHash, committed_at: now,
    };

    // Graduated slashing: evaluate observers against consensus
    if (valueNum !== null) {
      this.evaluateObservers(feedId, round, valueNum);
    }

    return feedRound;
  }

  /**
   * Check whether a feed needs observation this alarm cycle.
   * Uses staggered scheduling to spread observations across cycles,
   * reducing subrequest burst and staying within CF Workers limits.
   *
   * Stagger slots based on heartbeat:
   *   heartbeat < 30s  → observe every cycle (high-frequency)
   *   heartbeat 30-59s → observe every 2nd cycle (stagger into 2 slots)
   *   heartbeat 60s+   → observe every 3rd cycle (stagger into 3 slots)
   *
   * Feed's slot = hash(feed_id) % slotCount, so feeds are evenly distributed.
   * Always observe if: never committed, heartbeat approaching, or first cycle.
   */
  private shouldObserveFeed(feed: OracleFeedConfig, now: number): boolean {
    // Always observe on first cycle (cold start)
    if (this.observeCycle <= 1) return true;

    const latest = this.getFeedLatest(feed.id);
    // Never committed — must observe
    if (!latest) return true;

    const timeSinceCommit = now - latest.committed_at;
    // Heartbeat approaching (within 80%) — always observe regardless of stagger
    if (timeSinceCommit >= feed.heartbeat_ms * 0.8) return true;

    // High-frequency feeds: every cycle
    if (feed.heartbeat_ms < 30_000) return true;

    // Stagger: determine slot count and this feed's assigned slot
    const slotCount = feed.heartbeat_ms < 60_000 ? 2 : 3;
    const feedSlot = this.feedHash(feed.id) % slotCount;
    return (this.observeCycle % slotCount) === feedSlot;
  }

  /**
   * Simple deterministic hash for feed staggering. Must be consistent.
   */
  private feedHash(feedId: string): number {
    let h = 0;
    for (let i = 0; i < feedId.length; i++) {
      h = ((h << 5) - h) + feedId.charCodeAt(i);
      h |= 0;
    }
    return Math.abs(h);
  }

  // ─── Subscription Management ────────────────────────────────────────────

  async addSubscription(
    feedId: string,
    contract: string,
    callbackMethod: string,
    deviationBps: number = 0,
    minIntervalMs: number = 0,
  ): Promise<string> {
    // Check feed exists
    if (!this.getFeedConfig(feedId)) {
      throw new Error(`Feed ${feedId} not found`);
    }

    // Check per-contract limit
    const count = [...this.sql.exec(
      "SELECT COUNT(*) as cnt FROM oracle_subscriptions WHERE contract = ? AND enabled = 1",
      contract,
    )][0]?.cnt ?? 0;
    if (count >= MAX_SUBSCRIPTIONS_PER_CONTRACT) {
      throw new Error(`Max ${MAX_SUBSCRIPTIONS_PER_CONTRACT} subscriptions per contract`);
    }

    const id = await sha256(`oracle_sub:${contract}:${feedId}:${callbackMethod}:${Date.now()}`);
    this.sql.exec(
      `INSERT INTO oracle_subscriptions (id, feed_id, contract, callback_method, deviation_bps, min_interval_ms, last_delivered_at, last_delivered_value, enabled, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 0, NULL, 1, ?)`,
      id, feedId, contract, callbackMethod, deviationBps, minIntervalMs, Date.now(),
    );
    return id;
  }

  removeSubscription(subId: string): void {
    this.sql.exec("UPDATE oracle_subscriptions SET enabled = 0 WHERE id = ?", subId);
  }

  /**
   * Get subscriptions that should fire given a new feed value.
   */
  getTriggeredSubscriptions(feedId: string, newValue: string, newValueNum: number | null): OracleSubscription[] {
    const now = Date.now();
    const rows = [...this.sql.exec(
      "SELECT * FROM oracle_subscriptions WHERE feed_id = ? AND enabled = 1",
      feedId,
    )] as any[];

    const triggered: OracleSubscription[] = [];
    for (const row of rows) {
      const sub = this.rowToSubscription(row);

      // Check min interval
      if (sub.min_interval_ms > 0 && (now - sub.last_delivered_at) < sub.min_interval_ms) {
        continue;
      }

      // Check deviation threshold
      if (sub.deviation_bps > 0 && sub.last_delivered_value !== null && newValueNum !== null) {
        const lastNum = parseFloat(sub.last_delivered_value);
        if (!isNaN(lastNum) && lastNum !== 0) {
          const devBps = Math.abs((newValueNum - lastNum) / lastNum) * 10_000;
          if (devBps < sub.deviation_bps) continue;
        }
      }

      triggered.push(sub);
    }
    return triggered;
  }

  /**
   * Mark a subscription as delivered.
   */
  markSubscriptionDelivered(subId: string, value: string): void {
    this.sql.exec(
      "UPDATE oracle_subscriptions SET last_delivered_at = ?, last_delivered_value = ? WHERE id = ?",
      Date.now(), value, subId,
    );
  }

  getSubscriptionsForContract(contract: string): OracleSubscription[] {
    const rows = [...this.sql.exec(
      "SELECT * FROM oracle_subscriptions WHERE contract = ? ORDER BY created_at",
      contract,
    )];
    return rows.map(this.rowToSubscription);
  }

  // ─── Cross-Chain Push Subscriptions (Chainlink-Compatible) ──────────────
  // Subscriptions are keyed by (feed_id, dest_chain_id) — deterministic.
  // Same oracle config = same subscription and same receiver contract address.
  // Multiple depositors can fund a shared subscription.

  static getTransmitSelector(): string { return TRANSMIT_SELECTOR; }

  computeReceiverAddress(feedId: string, decimals: number, destChainId: number): string {
    const factoryAddr = FACTORY_ADDRESSES[destChainId];
    if (!factoryAddr || factoryAddr === "0x0000000000000000000000000000000000000000") {
      // Deterministic address from feed params even without deployed factory
      const hash = keccak256(encodePacked(["string", "uint8", "uint256"], [feedId, decimals, BigInt(destChainId)]));
      return ("0x" + hash.slice(26)) as string; // last 20 bytes as address
    }
    const salt = keccak256(encodePacked(["string", "uint8"], [feedId, decimals]));
    return getContractAddress({ from: factoryAddr, salt, bytecodeHash: RECEIVER_INIT_CODE_HASH, opcode: "CREATE2" });
  }

  async addPushSubscription(opts: {
    feed_id: string;
    depositor: string;
    dest_chain_id: number;
    dest_rpc_url: string;
    deviation_bps?: number;
    heartbeat_ms?: number;
    deposit_wei?: string;
  }): Promise<{ subscription_id: string; receiver_address: string }> {
    const feedConfig = this.getFeedConfig(opts.feed_id);
    if (!feedConfig) throw new Error(`Feed ${opts.feed_id} not found`);
    if (!/^0x[0-9a-fA-F]{40}$/.test(opts.depositor)) throw new Error("Invalid depositor address");

    // Deterministic subscription ID
    const subId = await sha256(`${opts.feed_id}:${opts.dest_chain_id}`);
    const receiverAddress = this.computeReceiverAddress(opts.feed_id, feedConfig.decimals, opts.dest_chain_id);

    // Check depositor limit
    const depCount = [...this.sql.exec(
      "SELECT COUNT(*) as cnt FROM oracle_push_depositors WHERE depositor = ?",
      opts.depositor.toLowerCase(),
    )][0]?.cnt ?? 0;
    if (depCount >= MAX_PUSH_DEPOSITS_PER_DEPOSITOR) {
      throw new Error(`Max ${MAX_PUSH_DEPOSITS_PER_DEPOSITOR} push subscriptions per depositor`);
    }

    const heartbeat = Math.max(MIN_HEARTBEAT_MS, Math.min(MAX_HEARTBEAT_MS, opts.heartbeat_ms || DEFAULT_HEARTBEAT_MS));
    const deviation = Math.max(0, opts.deviation_bps ?? DEFAULT_DEVIATION_BPS);
    const depositWei = opts.deposit_wei || "0";

    // Upsert subscription
    const existing = [...this.sql.exec(
      "SELECT id FROM oracle_push_subscriptions_v2 WHERE id = ?", subId,
    )] as any[];

    if (existing.length === 0) {
      this.sql.exec(
        `INSERT INTO oracle_push_subscriptions_v2 (id, feed_id, dest_chain_id, dest_rpc_url, receiver_address, deviation_bps, heartbeat_ms, last_pushed_at, last_pushed_value, last_pushed_round, total_deposit_wei, enabled, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, 0, ?, 1, ?)`,
        subId, opts.feed_id, opts.dest_chain_id, opts.dest_rpc_url,
        receiverAddress, deviation, heartbeat, depositWei, Date.now(),
      );
    } else {
      // Update thresholds to tightest values
      this.sql.exec(
        `UPDATE oracle_push_subscriptions_v2 SET
         deviation_bps = MIN(deviation_bps, ?),
         heartbeat_ms = MIN(heartbeat_ms, ?),
         total_deposit_wei = CAST((CAST(total_deposit_wei AS INTEGER) + CAST(? AS INTEGER)) AS TEXT),
         enabled = 1
         WHERE id = ?`,
        deviation, heartbeat, depositWei, subId,
      );
    }

    // Upsert depositor
    const existingDep = [...this.sql.exec(
      "SELECT depositor FROM oracle_push_depositors WHERE subscription_id = ? AND depositor = ?",
      subId, opts.depositor.toLowerCase(),
    )] as any[];

    if (existingDep.length === 0) {
      this.sql.exec(
        "INSERT INTO oracle_push_depositors (subscription_id, depositor, deposit_wei, created_at) VALUES (?, ?, ?, ?)",
        subId, opts.depositor.toLowerCase(), depositWei, Date.now(),
      );
    } else {
      this.sql.exec(
        "UPDATE oracle_push_depositors SET deposit_wei = CAST((CAST(deposit_wei AS INTEGER) + CAST(? AS INTEGER)) AS TEXT) WHERE subscription_id = ? AND depositor = ?",
        depositWei, subId, opts.depositor.toLowerCase(),
      );
    }

    return { subscription_id: subId, receiver_address: receiverAddress };
  }

  disablePushSubscription(subId: string): void {
    this.sql.exec("UPDATE oracle_push_subscriptions_v2 SET enabled = 0 WHERE id = ?", subId);
  }

  getPushSubscriptionsForDepositor(depositor: string): OraclePushSubscription[] {
    const rows = [...this.sql.exec(
      `SELECT s.* FROM oracle_push_subscriptions_v2 s
       INNER JOIN oracle_push_depositors d ON d.subscription_id = s.id
       WHERE d.depositor = ? ORDER BY s.created_at DESC`,
      depositor.toLowerCase(),
    )] as any[];
    return rows.map(this.rowToPushSubscription);
  }

  getAllPushSubscriptions(): OraclePushSubscription[] {
    const rows = [...this.sql.exec(
      "SELECT * FROM oracle_push_subscriptions_v2 WHERE enabled = 1 ORDER BY created_at DESC",
    )] as any[];
    return rows.map(this.rowToPushSubscription);
  }

  getPushSubscription(subId: string): OraclePushSubscription | null {
    const rows = [...this.sql.exec(
      "SELECT * FROM oracle_push_subscriptions_v2 WHERE id = ?", subId,
    )] as any[];
    return rows.length > 0 ? this.rowToPushSubscription(rows[0]) : null;
  }

  getPushDepositors(subId: string): OraclePushDepositor[] {
    const rows = [...this.sql.exec(
      "SELECT * FROM oracle_push_depositors WHERE subscription_id = ? ORDER BY created_at",
      subId,
    )] as any[];
    return rows.map((r: any) => ({
      subscription_id: r.subscription_id,
      depositor: r.depositor,
      deposit_wei: r.deposit_wei,
      created_at: r.created_at,
    }));
  }

  getTriggeredPushSubscriptions(feedId: string, newValue: string, newValueNum: number | null): OraclePushSubscription[] {
    const now = Date.now();
    const rows = [...this.sql.exec(
      "SELECT * FROM oracle_push_subscriptions_v2 WHERE feed_id = ? AND enabled = 1",
      feedId,
    )] as any[];

    const triggered: OraclePushSubscription[] = [];
    for (const row of rows) {
      const sub = this.rowToPushSubscription(row);

      // Check heartbeat interval
      if (sub.last_pushed_at > 0 && (now - sub.last_pushed_at) < sub.heartbeat_ms) {
        if (sub.deviation_bps > 0 && sub.last_pushed_value !== null && newValueNum !== null) {
          const lastNum = parseFloat(sub.last_pushed_value);
          if (!isNaN(lastNum) && lastNum !== 0) {
            const devBps = Math.abs((newValueNum - lastNum) / lastNum) * 10_000;
            if (devBps < sub.deviation_bps) continue;
          }
        } else {
          continue;
        }
      }

      triggered.push(sub);
    }
    return triggered;
  }

  async generatePushAttestation(sub: OraclePushSubscription, round: FeedRound): Promise<OraclePushAttestation> {
    const payloadStr = JSON.stringify({
      feed_id: round.feed_id,
      round: round.round,
      value: round.value,
      value_num: round.value_num,
      observers: round.observers,
      committed_at: round.committed_at,
      dest_chain_id: sub.dest_chain_id,
      receiver_address: sub.receiver_address,
    });
    const attestationHash = await sha256(payloadStr);
    const signature = await this.signPayload(attestationHash);
    const signatures = JSON.stringify([{ pubkey: this.nodePubkey, sig: signature }]);

    const feedConfig = this.getFeedConfig(round.feed_id);
    const decimals = feedConfig?.decimals ?? 8;
    const calldata = this.abiEncodePushCalldata(
      round.round, round.value, round.value_num, decimals,
      round.observers, round.committed_at, attestationHash, signatures,
    );

    const id = await sha256(`push_att:${sub.id}:${round.round}:${Date.now()}`);
    const now = Date.now();

    this.sql.exec(
      `INSERT INTO oracle_push_attestations (id, subscription_id, feed_id, round, value, value_num, observers, committed_at, attestation_hash, signatures, calldata, created_at, relayed_at, relay_tx_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`,
      id, sub.id, round.feed_id, round.round, round.value, round.value_num,
      round.observers, round.committed_at, attestationHash, signatures, calldata, now,
    );

    this.sql.exec(
      "UPDATE oracle_push_subscriptions_v2 SET last_pushed_at = ?, last_pushed_value = ?, last_pushed_round = ? WHERE id = ?",
      now, round.value, round.round, sub.id,
    );

    return {
      id, subscription_id: sub.id, feed_id: round.feed_id, round: round.round,
      value: round.value, value_num: round.value_num, observers: round.observers,
      committed_at: round.committed_at, attestation_hash: attestationHash,
      signatures, calldata, created_at: now, relayed_at: null, relay_tx_hash: null,
    };
  }

  getPushAttestations(subId: string, limit: number = 20): OraclePushAttestation[] {
    const rows = [...this.sql.exec(
      "SELECT * FROM oracle_push_attestations WHERE subscription_id = ? ORDER BY created_at DESC LIMIT ?",
      subId, limit,
    )] as any[];
    return rows.map(this.rowToPushAttestation);
  }

  getLatestPendingAttestation(subId: string): OraclePushAttestation | null {
    const rows = [...this.sql.exec(
      "SELECT * FROM oracle_push_attestations WHERE subscription_id = ? AND relayed_at IS NULL ORDER BY created_at DESC LIMIT 1",
      subId,
    )] as any[];
    return rows.length > 0 ? this.rowToPushAttestation(rows[0]) : null;
  }

  markPushRelayed(attestationId: string, txHash: string): void {
    this.sql.exec(
      "UPDATE oracle_push_attestations SET relayed_at = ?, relay_tx_hash = ? WHERE id = ?",
      Date.now(), txHash, attestationId,
    );
  }

  depositPushFunds(subId: string, depositor: string, amountWei: string): void {
    const sub = this.getPushSubscription(subId);
    if (!sub) throw new Error("Push subscription not found");
    if (!/^0x[0-9a-fA-F]{40}$/.test(depositor)) throw new Error("Invalid depositor address");
    const deposit = BigInt(amountWei);
    if (deposit <= 0n) throw new Error("Amount must be positive");

    // Update total
    this.sql.exec(
      "UPDATE oracle_push_subscriptions_v2 SET total_deposit_wei = CAST((CAST(total_deposit_wei AS INTEGER) + ?) AS TEXT) WHERE id = ?",
      amountWei, subId,
    );

    // Upsert depositor
    const existing = [...this.sql.exec(
      "SELECT depositor FROM oracle_push_depositors WHERE subscription_id = ? AND depositor = ?",
      subId, depositor.toLowerCase(),
    )] as any[];

    if (existing.length === 0) {
      this.sql.exec(
        "INSERT INTO oracle_push_depositors (subscription_id, depositor, deposit_wei, created_at) VALUES (?, ?, ?, ?)",
        subId, depositor.toLowerCase(), amountWei, Date.now(),
      );
    } else {
      this.sql.exec(
        "UPDATE oracle_push_depositors SET deposit_wei = CAST((CAST(deposit_wei AS INTEGER) + ?) AS TEXT) WHERE subscription_id = ? AND depositor = ?",
        amountWei, subId, depositor.toLowerCase(),
      );
    }
  }

  withdrawPushFunds(subId: string, depositor: string, amountWei: string): void {
    const sub = this.getPushSubscription(subId);
    if (!sub) throw new Error("Push subscription not found");
    const withdrawal = BigInt(amountWei);
    if (withdrawal <= 0n) throw new Error("Amount must be positive");

    // Check depositor balance
    const depRow = [...this.sql.exec(
      "SELECT deposit_wei FROM oracle_push_depositors WHERE subscription_id = ? AND depositor = ?",
      subId, depositor.toLowerCase(),
    )] as any[];
    if (depRow.length === 0) throw new Error("Not a depositor");
    if (BigInt(depRow[0].deposit_wei) < withdrawal) throw new Error("Insufficient deposit balance");

    this.sql.exec(
      "UPDATE oracle_push_depositors SET deposit_wei = CAST((CAST(deposit_wei AS INTEGER) - ?) AS TEXT) WHERE subscription_id = ? AND depositor = ?",
      amountWei, subId, depositor.toLowerCase(),
    );
    this.sql.exec(
      "UPDATE oracle_push_subscriptions_v2 SET total_deposit_wei = CAST((CAST(total_deposit_wei AS INTEGER) - ?) AS TEXT) WHERE id = ?",
      amountWei, subId,
    );
  }

  // ─── Push Subscription Helpers ─────────────────────────────────────────

  private rowToPushSubscription(row: any): OraclePushSubscription {
    return {
      id: row.id,
      feed_id: row.feed_id,
      dest_chain_id: row.dest_chain_id,
      dest_rpc_url: row.dest_rpc_url,
      receiver_address: row.receiver_address,
      deviation_bps: row.deviation_bps,
      heartbeat_ms: row.heartbeat_ms,
      last_pushed_at: row.last_pushed_at,
      last_pushed_value: row.last_pushed_value,
      last_pushed_round: row.last_pushed_round,
      total_deposit_wei: row.total_deposit_wei,
      enabled: !!row.enabled,
      created_at: row.created_at,
    };
  }

  private rowToPushAttestation(row: any): OraclePushAttestation {
    return {
      id: row.id,
      subscription_id: row.subscription_id,
      feed_id: row.feed_id,
      round: row.round,
      value: row.value,
      value_num: row.value_num,
      observers: row.observers,
      committed_at: row.committed_at,
      attestation_hash: row.attestation_hash,
      signatures: row.signatures,
      calldata: row.calldata,
      created_at: row.created_at,
      relayed_at: row.relayed_at,
      relay_tx_hash: row.relay_tx_hash,
    };
  }

  /**
   * ABI encoder for Chainlink-compatible transmit() calldata.
   * transmit(int256 answer, uint80 roundId, uint256 updatedAt, uint256 observers, bytes32 attestationHash, bytes signatures)
   */
  private abiEncodePushCalldata(
    round: number, value: string, valueNum: number | null, decimals: number,
    observers: number, committedAt: number, attestationHash: string, signatures: string,
  ): string {
    const scaledValue = BigInt(Math.round((valueNum ?? parseFloat(value) ?? 0) * (10 ** decimals)));
    const attHashHex = ("0x" + attestationHash.padStart(64, "0")) as `0x${string}`;
    const sigBytes = toHex(toBytes(signatures));

    const encoded = encodeAbiParameters(
      parseAbiParameters("int256, uint80, uint256, uint256, bytes32, bytes"),
      [
        scaledValue,
        round,
        BigInt(Math.floor(committedAt / 1000)),
        BigInt(observers),
        attHashHex,
        sigBytes,
      ],
    );

    return TRANSMIT_SELECTOR.slice(2) + encoded.slice(2);
  }

  // ─── VRF (Verifiable Random Function) ──────────────────────────────────

  async createVRFRequest(
    seed: string,
    contract: string,
    callbackMethod: string,
  ): Promise<string> {
    const round = this.getCurrentMaxRound() + 1;
    const id = await sha256(`vrf:${contract}:${seed}:${round}:${Date.now()}`);

    this.sql.exec(
      `INSERT INTO oracle_vrf_requests (id, seed, contract, callback_method, round, status, result, created_at, delivered_at)
       VALUES (?, ?, ?, ?, ?, 'pending', NULL, ?, NULL)`,
      id, seed, contract, callbackMethod, round, Date.now(),
    );
    return id;
  }

  /**
   * Generate this validator's VRF partial for a request.
   * Uses Schnorr signature over SHA256("vrf:" + round + ":" + seed) as the partial.
   */
  async generateVRFPartial(requestId: string): Promise<VRFPartial | null> {
    const rows = [...this.sql.exec(
      "SELECT * FROM oracle_vrf_requests WHERE id = ? AND status IN ('pending', 'collecting')",
      requestId,
    )] as any[];
    if (rows.length === 0) return null;

    const req = rows[0];
    const message = `vrf:${req.round}:${req.seed}`;
    const partialSig = await this.signPayload(message);

    const partial: VRFPartial = {
      request_id: requestId,
      validator: this.nodePubkey,
      partial_sig: partialSig,
      created_at: Date.now(),
    };

    // Store partial
    this.sql.exec(
      `INSERT OR REPLACE INTO oracle_vrf_partials (request_id, validator, partial_sig, created_at)
       VALUES (?, ?, ?, ?)`,
      requestId, this.nodePubkey, partialSig, Date.now(),
    );

    // Update status
    this.sql.exec(
      "UPDATE oracle_vrf_requests SET status = 'collecting' WHERE id = ? AND status = 'pending'",
      requestId,
    );

    // Check quorum
    return partial;
  }

  /**
   * Try to combine VRF partials if quorum reached. Returns the random value or null.
   */
  async tryFinalizeVRF(requestId: string): Promise<string | null> {
    const activeCount = this.getActiveNodeCount();
    const quorum = this.getQuorumSize(activeCount);

    const partials = [...this.sql.exec(
      "SELECT * FROM oracle_vrf_partials WHERE request_id = ? ORDER BY validator",
      requestId,
    )] as any[];

    if (partials.length < quorum) return null;

    // Combine: SHA256 of sorted partial signatures
    const sortedSigs = partials.map((p: any) => p.partial_sig).sort();
    const combined = await sha256(sortedSigs.join(":"));

    // Commit
    this.sql.exec(
      "UPDATE oracle_vrf_requests SET status = 'delivered', result = ?, delivered_at = ? WHERE id = ?",
      combined, Date.now(), requestId,
    );

    return combined;
  }

  getVRFRequest(requestId: string): VRFRequest | null {
    const rows = [...this.sql.exec("SELECT * FROM oracle_vrf_requests WHERE id = ?", requestId)];
    if (rows.length === 0) return null;
    const r = rows[0] as any;
    return {
      id: r.id, seed: r.seed, contract: r.contract, callback_method: r.callback_method,
      round: r.round, status: r.status, result: r.result,
      created_at: r.created_at, delivered_at: r.delivered_at,
    };
  }

  getPendingVRFRequests(): VRFRequest[] {
    const rows = [...this.sql.exec(
      "SELECT * FROM oracle_vrf_requests WHERE status IN ('pending', 'collecting') ORDER BY created_at LIMIT 20",
    )];
    return rows.map((r: any) => ({
      id: r.id, seed: r.seed, contract: r.contract, callback_method: r.callback_method,
      round: r.round, status: r.status, result: r.result,
      created_at: r.created_at, delivered_at: r.delivered_at,
    }));
  }

  // ─── Staleness Detection ────────────────────────────────────────────────

  /**
   * Mark feeds as stale if they haven't been updated within 3x heartbeat.
   */
  updateStaleness(): void {
    const now = Date.now();
    // Mark stale feeds
    this.sql.exec(
      `UPDATE oracle_feeds SET status = 'stale'
       WHERE status = 'active' AND id IN (
         SELECT feed_id FROM oracle_feed_latest WHERE stale_at < ?
       )`,
      now,
    );
    // Recover previously stale feeds that got updated
    this.sql.exec(
      `UPDATE oracle_feeds SET status = 'active'
       WHERE status = 'stale' AND id IN (
         SELECT feed_id FROM oracle_feed_latest WHERE stale_at >= ?
       )`,
      now,
    );
  }

  // ─── Pruning ────────────────────────────────────────────────────────────

  prune(): void {
    const now = Date.now();
    // Prune observations older than 1 hour
    this.sql.exec("DELETE FROM oracle_observations WHERE observed_at < ?", now - 3_600_000);
    // Prune old feed rounds (keep latest 1000 per feed, older than 7 days)
    this.sql.exec(
      `DELETE FROM oracle_feed_rounds WHERE committed_at < ? AND rowid NOT IN (
        SELECT rowid FROM oracle_feed_rounds ORDER BY committed_at DESC LIMIT 5000
      )`,
      now - 7 * 86_400_000,
    );
    // Prune delivered VRF requests older than 1 hour
    this.sql.exec("DELETE FROM oracle_vrf_requests WHERE status = 'delivered' AND delivered_at < ?", now - 3_600_000);
    this.sql.exec("DELETE FROM oracle_vrf_partials WHERE request_id NOT IN (SELECT id FROM oracle_vrf_requests)");
    // Prune failed VRF requests older than 10 minutes
    this.sql.exec("DELETE FROM oracle_vrf_requests WHERE status = 'failed' AND created_at < ?", now - 600_000);
  }

  // ─── Helpers ────────────────────────────────────────────────────────────

  /**
   * Simple synchronous hash for hot paths (observations hash).
   * Uses a basic string hash — not cryptographic, just for dedup/verification.
   * For production, replace with a synchronous SHA256 if available.
   */
  private syncHash(input: string): string {
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
      const chr = input.charCodeAt(i);
      hash = ((hash << 5) - hash) + chr;
      hash |= 0; // Convert to 32bit integer
    }
    // Pad to look like a hash
    return Math.abs(hash).toString(16).padStart(8, "0");
  }

  private getCurrentMaxRound(): number {
    const rows = [...this.sql.exec("SELECT MAX(current_round) as mr FROM oracle_feeds")];
    return rows[0]?.mr ?? 0;
  }

  private rowToFeedConfig(row: any): OracleFeedConfig {
    return {
      id: row.id,
      description: row.description,
      decimals: row.decimals,
      heartbeat_ms: row.heartbeat_ms,
      deviation_bps: row.deviation_bps,
      aggregation: row.aggregation,
      sources: typeof row.sources === "string" ? JSON.parse(row.sources) : row.sources,
      status: row.status,
      category: row.category,
      created_at: row.created_at,
      updated_at: row.updated_at,
      current_round: row.current_round,
    };
  }

  private rowToFeedRound(row: any): FeedRound {
    return {
      feed_id: row.feed_id,
      round: row.round,
      value: row.value,
      value_num: row.value_num,
      observers: row.observers,
      observations_hash: row.observations_hash,
      committed_at: row.committed_at,
    };
  }

  private rowToSubscription(row: any): OracleSubscription {
    return {
      id: row.id,
      feed_id: row.feed_id,
      contract: row.contract,
      callback_method: row.callback_method,
      deviation_bps: row.deviation_bps,
      min_interval_ms: row.min_interval_ms,
      last_delivered_at: row.last_delivered_at,
      last_delivered_value: row.last_delivered_value,
      enabled: !!row.enabled,
      created_at: row.created_at,
    };
  }

  // ─── Graduated Oracle Slashing ──────────────────────────────────────────

  /**
   * After a round commits, evaluate each validator's observation against the
   * consensus value and apply graduated reputation adjustments.
   *
   * Called from aggregateAndCommit() after a successful commit.
   * Tiers:
   *   - accurate (within feed deviation_bps): +1 reputation
   *   - moderate deviation (>2% from consensus): -5
   *   - large deviation (>10% from consensus): -15
   *   - missing observation (active validator didn't submit): -2
   *   - contradictory (two values same round — detected separately): -50
   */
  evaluateObservers(feedId: string, round: number, consensusValue: number): void {
    if (consensusValue === 0) return; // can't compute deviation from zero

    const observations = [...this.sql.exec(
      "SELECT observer, value_num FROM oracle_observations WHERE feed_id = ? AND round = ?",
      feedId, round,
    )] as any[];

    const observerSet = new Set(observations.map((o: any) => o.observer));

    for (const obs of observations) {
      if (obs.value_num === null || obs.value_num === undefined) continue;

      const deviationBps = Math.abs((obs.value_num - consensusValue) / consensusValue) * 10_000;

      if (deviationBps > SLASH_DEVIATION_LARGE_BPS) {
        this.adjustValidatorReputation(obs.observer, SLASH_LARGE_DEVIATION);
      } else if (deviationBps > SLASH_DEVIATION_MODERATE_BPS) {
        this.adjustValidatorReputation(obs.observer, SLASH_MODERATE_DEVIATION);
      } else {
        this.adjustValidatorReputation(obs.observer, REWARD_ACCURATE_OBSERVATION);
      }
    }

    // Penalize active validators who didn't submit observations
    try {
      const activeValidators = [...this.sql.exec(
        "SELECT pubkey FROM validators WHERE status = 'active' AND reputation >= 50",
      )] as any[];
      for (const v of activeValidators) {
        if (!observerSet.has(v.pubkey)) {
          this.adjustValidatorReputation(v.pubkey, SLASH_MISSED_OBSERVATION);
        }
      }
    } catch { /* validators table may not exist in tests */ }
  }

  /**
   * Detect contradictory observations: a validator submitting different values
   * for the same feed+round via different gossip paths. This is the most severe
   * oracle offense (equivalent to equivocation in consensus).
   *
   * Called when receiving a new observation — checks if the observer already
   * submitted a different value for this feed+round.
   */
  checkContradiction(feedId: string, round: number, observer: string, newValue: string): boolean {
    const existing = [...this.sql.exec(
      "SELECT value FROM oracle_observations WHERE feed_id = ? AND round = ? AND observer = ?",
      feedId, round, observer,
    )] as any[];

    if (existing.length > 0 && existing[0].value !== newValue) {
      this.adjustValidatorReputation(observer, SLASH_CONTRADICTORY_OBSERVATION);
      return true; // contradiction detected
    }
    return false;
  }

  // ─── Attestation Fraud-Proof Challenges ─────────────────────────────────

  /**
   * After a round commits, any validator can challenge an observation they
   * believe was fraudulent. The challenge is evaluated automatically:
   * if the challenged observation deviates > 10% from consensus, the
   * challenger is rewarded and the offender is slashed. If the challenge
   * is invalid (observation was within tolerance), the challenger is penalized.
   *
   * Returns { valid: boolean, penalty_applied: number } so callers can log it.
   */
  challengeObservation(
    challengerPubkey: string,
    feedId: string,
    round: number,
    targetObserver: string,
  ): { valid: boolean; penalty_applied: number; reason: string } {
    // Get the committed consensus value
    const committedRound = this.getFeedRound(feedId, round);
    if (!committedRound || committedRound.value_num === null) {
      return { valid: false, penalty_applied: 0, reason: "round_not_committed" };
    }

    // Get the target's observation
    const obs = [...this.sql.exec(
      "SELECT value_num FROM oracle_observations WHERE feed_id = ? AND round = ? AND observer = ?",
      feedId, round, targetObserver,
    )] as any[];

    if (obs.length === 0) {
      return { valid: false, penalty_applied: 0, reason: "observation_not_found" };
    }

    if (obs[0].value_num === null) {
      return { valid: false, penalty_applied: 0, reason: "non_numeric_observation" };
    }

    const consensusValue = committedRound.value_num;
    if (consensusValue === 0) {
      return { valid: false, penalty_applied: 0, reason: "zero_consensus" };
    }

    const deviationBps = Math.abs((obs[0].value_num - consensusValue) / consensusValue) * 10_000;

    if (deviationBps > SLASH_DEVIATION_LARGE_BPS) {
      // Valid challenge — offender already slashed by evaluateObservers,
      // but reward the challenger for vigilance
      this.adjustValidatorReputation(challengerPubkey, 5);
      return {
        valid: true,
        penalty_applied: SLASH_LARGE_DEVIATION,
        reason: `deviation_${Math.round(deviationBps)}bps`,
      };
    }

    // Invalid challenge — challenger pays a small penalty for wasting network attention
    this.adjustValidatorReputation(challengerPubkey, -3);
    return {
      valid: false,
      penalty_applied: -3,
      reason: `within_tolerance_${Math.round(deviationBps)}bps`,
    };
  }

  // ─── Reputation Helpers ─────────────────────────────────────────────────

  /**
   * Adjust a validator's reputation in the shared validators table.
   * Clamps to [0, 10000]. Shared with ValidatorRegistry.
   */
  private adjustValidatorReputation(pubkey: string, delta: number): void {
    try {
      const rows = [...this.sql.exec(
        "SELECT reputation FROM validators WHERE pubkey = ?", pubkey,
      )] as any[];
      if (rows.length === 0) return;

      const current = rows[0].reputation ?? 0;
      const newRep = Math.max(0, Math.min(10000, current + delta));
      this.sql.exec("UPDATE validators SET reputation = ? WHERE pubkey = ?", newRep, pubkey);
    } catch { /* validators table may not exist */ }
  }
}
