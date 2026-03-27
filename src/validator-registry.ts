// ─── Tokenless Validator Registry ──────────────────────────────────────────────
// Sybil resistance without a gas token, using three complementary mechanisms:
//
// 1. Proof-of-Work Registration: Solve a CPU puzzle to claim a validator slot.
//    Mass identity creation becomes expensive (time cost, not token cost).
//
// 2. Reputation-Weighted Participation: Validators earn "weight" from consistent
//    honest behavior. Weight determines quorum contribution. New validators start
//    at minimum weight; established validators have outsized influence.
//    Time investment = real cost, making reputation valuable without tokens.
//
// 3. Governance Admission: Existing validators can vote to admit or remove members.
//    Supermajority (2/3) required for governance actions.
//
// Equivocation = reputation destruction (tokenless slashing).
// An equivocating validator's reputation drops to zero and must re-register (new PoW).

import { sha256 } from "./consensus";

// ─── Configuration ────────────────────────────────────────────────────────────

// PoW difficulty: SHA256(pubkey + nonce) must have this many leading zero bits.
// 20 bits ≈ ~1M hashes ≈ ~1-5 seconds on modern hardware.
// 24 bits ≈ ~16M hashes ≈ ~15-60 seconds. Adjustable per deployment.
const DEFAULT_POW_DIFFICULTY = 20;

// Reputation scoring
const INITIAL_REPUTATION = 100;          // new validators start here
const MAX_REPUTATION = 10000;            // cap to prevent unbounded growth
const MIN_REPUTATION_FOR_QUORUM = 50;    // below this, your votes don't count

// Reputation rewards
const REWARD_VALID_VERTEX = 5;           // per vertex included in committed round
const REWARD_TIMELY_VERTEX = 2;          // bonus for producing vertex within expected window
const REWARD_COMMIT_PARTICIPATION = 10;  // participated in a committed anchor round

// Reputation penalties
const PENALTY_EQUIVOCATION = -10000;     // instant death — reputation goes to 0
const PENALTY_MISSED_ROUND = -3;         // was active but didn't produce a vertex
const PENALTY_INVALID_VERTEX = -20;      // submitted a vertex that failed validation

// Governance
const GOVERNANCE_SUPERMAJORITY = 2 / 3;  // 2/3 of reputation-weighted votes
const VOTE_EXPIRY_MS = 86_400_000;       // votes expire after 24 hours

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ValidatorRecord {
  pubkey: string;
  url: string;
  reputation: number;
  pow_nonce: string;           // PoW solution that granted admission
  pow_hash: string;            // the resulting hash (for verification)
  registered_at: number;
  last_active_round: number;
  status: "active" | "suspended" | "removed";
  equivocation_count: number;
  total_vertices: number;
  total_commits: number;
}

export interface EquivocationEvidence {
  id: string;                  // SHA256 of evidence
  validator_pubkey: string;
  round: number;
  vertex_hash_1: string;
  vertex_hash_2: string;
  detected_at: number;
  reported_by: string;         // pubkey of the node that detected it
}

export interface GovernanceVote {
  id: string;
  action: "admit" | "remove" | "set_difficulty";
  target: string;              // pubkey for admit/remove, difficulty value for set_difficulty
  voter_pubkey: string;
  voter_reputation: number;    // reputation at time of vote
  created_at: number;
}

// ─── PoW Verification ─────────────────────────────────────────────────────────

/**
 * Verify a Proof-of-Work solution.
 * The hash of (pubkey + ":" + nonce) must have `difficulty` leading zero bits.
 */
export async function verifyPoW(
  pubkey: string,
  nonce: string,
  difficulty: number = DEFAULT_POW_DIFFICULTY,
): Promise<{ valid: boolean; hash: string }> {
  const hash = await sha256(`${pubkey}:${nonce}`);
  const leading = countLeadingZeroBits(hash);
  return { valid: leading >= difficulty, hash };
}

/**
 * Count leading zero bits in a hex string.
 */
function countLeadingZeroBits(hexHash: string): number {
  let bits = 0;
  for (const ch of hexHash) {
    const nibble = parseInt(ch, 16);
    if (nibble === 0) {
      bits += 4;
    } else {
      // Count leading zeros in this nibble
      if (nibble < 2) bits += 3;
      else if (nibble < 4) bits += 2;
      else if (nibble < 8) bits += 1;
      break;
    }
  }
  return bits;
}

// ─── ValidatorRegistry ────────────────────────────────────────────────────────

export class ValidatorRegistry {
  private sql: any;
  private powDifficulty: number;
  private _quorumCache: { eligible: ValidatorRecord[]; threshold: number; ts: number } | null = null;
  private static readonly QUORUM_CACHE_TTL = 5_000; // 5s TTL

  constructor(sql: any, difficulty?: number) {
    this.sql = sql;
    this.powDifficulty = difficulty || DEFAULT_POW_DIFFICULTY;

    // Load configured difficulty from DB
    const rows = [...sql.exec(
      "SELECT value FROM consensus_state WHERE key = 'pow_difficulty'",
    )] as any[];
    if (rows.length > 0) {
      this.powDifficulty = parseInt(rows[0].value) || DEFAULT_POW_DIFFICULTY;
    }
  }

  /** Invalidate quorum cache after mutations (register, reputation change, governance) */
  private invalidateQuorumCache() { this._quorumCache = null; }

  private ensureQuorumCache() {
    const now = Date.now();
    if (this._quorumCache && (now - this._quorumCache.ts) < ValidatorRegistry.QUORUM_CACHE_TTL) return;
    const eligible = this.getActiveValidators();
    const totalReputation = eligible.reduce((sum, v) => sum + v.reputation, 0);
    this._quorumCache = { eligible, threshold: Math.ceil(totalReputation * 2 / 3), ts: now };
  }

  // ─── Registration ───────────────────────────────────────────────────────

  /**
   * Register a new validator with Proof-of-Work.
   * Returns the validator record on success.
   */
  async register(
    pubkey: string,
    url: string,
    powNonce: string,
  ): Promise<{ ok: boolean; error?: string; validator?: ValidatorRecord }> {
    // Check if already registered
    const existing = [...this.sql.exec(
      "SELECT pubkey, status FROM validators WHERE pubkey = ?", pubkey,
    )] as any[];
    if (existing.length > 0) {
      if (existing[0].status === "active") {
        return { ok: false, error: "Already registered" };
      }
      if (existing[0].status === "removed") {
        // Must re-register with new PoW (previous equivocation or governance removal)
      }
    }

    // Verify PoW
    const { valid, hash } = await verifyPoW(pubkey, powNonce, this.powDifficulty);
    if (!valid) {
      return { ok: false, error: `PoW invalid: need ${this.powDifficulty} leading zero bits` };
    }

    // Check PoW hasn't been used before (prevent replay)
    const usedPow = [...this.sql.exec(
      "SELECT pubkey FROM validators WHERE pow_hash = ?", hash,
    )] as any[];
    if (usedPow.length > 0) {
      return { ok: false, error: "PoW solution already used" };
    }

    // Register
    const now = Date.now();
    this.sql.exec(
      `INSERT INTO validators (pubkey, url, reputation, pow_nonce, pow_hash, registered_at, last_active_round, status, equivocation_count, total_vertices, total_commits)
       VALUES (?, ?, ?, ?, ?, ?, 0, 'active', 0, 0, 0)
       ON CONFLICT(pubkey) DO UPDATE SET url = ?, reputation = ?, pow_nonce = ?, pow_hash = ?, registered_at = ?, status = 'active', equivocation_count = 0`,
      pubkey, url, INITIAL_REPUTATION, powNonce, hash, now,
      url, INITIAL_REPUTATION, powNonce, hash, now,
    );

    this.invalidateQuorumCache();
    const validator = this.getValidator(pubkey)!;
    return { ok: true, validator };
  }

  // ─── Validator Lookup ───────────────────────────────────────────────────

  getValidator(pubkey: string): ValidatorRecord | null {
    const rows = [...this.sql.exec(
      "SELECT * FROM validators WHERE pubkey = ?", pubkey,
    )] as any[];
    if (rows.length === 0) return null;
    return this.rowToRecord(rows[0]);
  }

  getActiveValidators(): ValidatorRecord[] {
    const rows = [...this.sql.exec(
      "SELECT * FROM validators WHERE status = 'active' AND reputation >= ? ORDER BY reputation DESC",
      MIN_REPUTATION_FOR_QUORUM,
    )] as any[];
    return rows.map((r: any) => this.rowToRecord(r));
  }

  /**
   * Get validators eligible for quorum (active + sufficient reputation).
   */
  getQuorumEligible(): ValidatorRecord[] {
    this.ensureQuorumCache();
    return this._quorumCache!.eligible;
  }

  private rowToRecord(row: any): ValidatorRecord {
    return {
      pubkey: row.pubkey,
      url: row.url,
      reputation: row.reputation,
      pow_nonce: row.pow_nonce,
      pow_hash: row.pow_hash,
      registered_at: row.registered_at,
      last_active_round: row.last_active_round,
      status: row.status,
      equivocation_count: row.equivocation_count,
      total_vertices: row.total_vertices,
      total_commits: row.total_commits,
    };
  }

  // ─── Reputation-Weighted Quorum ─────────────────────────────────────────

  /**
   * Calculate quorum threshold based on total reputation.
   * Quorum = 2/3 of total active reputation (BFT standard).
   */
  getQuorumThreshold(): number {
    this.ensureQuorumCache();
    return this._quorumCache!.threshold;
  }

  /**
   * Check if a set of validator pubkeys meets the reputation-weighted quorum.
   * Uses cached eligible set — no per-voter DB lookups.
   */
  isQuorumMet(voterPubkeys: Set<string>): boolean {
    this.ensureQuorumCache();
    const { threshold, eligible } = this._quorumCache!;
    let totalVoteWeight = 0;
    for (const v of eligible) {
      if (voterPubkeys.has(v.pubkey)) totalVoteWeight += v.reputation;
    }
    return totalVoteWeight >= threshold;
  }

  /**
   * Get the reputation weight for a specific validator (for leader selection weighting).
   */
  getWeight(pubkey: string): number {
    const v = this.getValidator(pubkey);
    if (!v || v.status !== "active" || v.reputation < MIN_REPUTATION_FOR_QUORUM) return 0;
    return v.reputation;
  }

  /**
   * Get the total active node count for backward compatibility.
   */
  getActiveCount(): number {
    return this.getQuorumEligible().length;
  }

  // ─── Reputation Updates ─────────────────────────────────────────────────

  /**
   * Reward a validator for producing a valid vertex.
   */
  rewardVertex(pubkey: string, round: number) {
    this.adjustReputation(pubkey, REWARD_VALID_VERTEX);
    this.sql.exec(
      "UPDATE validators SET total_vertices = total_vertices + 1, last_active_round = MAX(last_active_round, ?) WHERE pubkey = ?",
      round, pubkey,
    );
  }

  /**
   * Reward validators who participated in a committed round.
   */
  rewardCommitParticipation(pubkeys: string[]) {
    for (const pk of pubkeys) {
      this.adjustReputation(pk, REWARD_COMMIT_PARTICIPATION);
      this.sql.exec(
        "UPDATE validators SET total_commits = total_commits + 1 WHERE pubkey = ?", pk,
      );
    }
  }

  /**
   * Reward a validator for timely vertex submission.
   */
  rewardTimely(pubkey: string) {
    this.adjustReputation(pubkey, REWARD_TIMELY_VERTEX);
  }

  /**
   * Penalize a validator for missing a round they were expected to participate in.
   */
  penalizeMissedRound(pubkey: string) {
    this.adjustReputation(pubkey, PENALTY_MISSED_ROUND);
  }

  /**
   * Penalize for submitting an invalid vertex.
   */
  penalizeInvalidVertex(pubkey: string) {
    this.adjustReputation(pubkey, PENALTY_INVALID_VERTEX);
  }

  private adjustReputation(pubkey: string, delta: number) {
    const current = [...this.sql.exec(
      "SELECT reputation FROM validators WHERE pubkey = ?", pubkey,
    )] as any[];
    if (current.length === 0) return;

    const newRep = Math.max(0, Math.min(MAX_REPUTATION, (current[0].reputation || 0) + delta));
    this.sql.exec("UPDATE validators SET reputation = ? WHERE pubkey = ?", newRep, pubkey);

    // Auto-suspend if reputation drops below threshold
    if (newRep < MIN_REPUTATION_FOR_QUORUM) {
      this.sql.exec("UPDATE validators SET status = 'suspended' WHERE pubkey = ? AND status = 'active'", pubkey);
    }
    this.invalidateQuorumCache();
  }

  // ─── Equivocation Detection & Slashing ──────────────────────────────────

  /**
   * Record equivocation evidence and slash the validator's reputation.
   * This is the tokenless equivalent of slashing — reputation goes to zero.
   */
  async recordEquivocation(
    validatorPubkey: string,
    round: number,
    vertexHash1: string,
    vertexHash2: string,
    reportedBy: string,
  ): Promise<EquivocationEvidence> {
    const evidenceId = await sha256(
      `equivocation:${validatorPubkey}:${round}:${vertexHash1}:${vertexHash2}`,
    );

    // Store evidence (permanent record)
    this.sql.exec(
      `INSERT OR IGNORE INTO equivocation_evidence
       (id, validator_pubkey, round, vertex_hash_1, vertex_hash_2, detected_at, reported_by)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      evidenceId, validatorPubkey, round, vertexHash1, vertexHash2, Date.now(), reportedBy,
    );

    // Slash reputation to zero
    this.sql.exec(
      "UPDATE validators SET reputation = 0, equivocation_count = equivocation_count + 1, status = 'suspended' WHERE pubkey = ?",
      validatorPubkey,
    );

    console.warn(`EQUIVOCATION SLASHED: ${validatorPubkey} at round ${round} (evidence: ${evidenceId.slice(0, 12)})`);

    return {
      id: evidenceId,
      validator_pubkey: validatorPubkey,
      round,
      vertex_hash_1: vertexHash1,
      vertex_hash_2: vertexHash2,
      detected_at: Date.now(),
      reported_by: reportedBy,
    };
  }

  /**
   * Get equivocation evidence for a validator.
   */
  getEquivocationEvidence(pubkey?: string): EquivocationEvidence[] {
    const query = pubkey
      ? "SELECT * FROM equivocation_evidence WHERE validator_pubkey = ? ORDER BY detected_at DESC"
      : "SELECT * FROM equivocation_evidence ORDER BY detected_at DESC LIMIT 50";
    const params = pubkey ? [pubkey] : [];
    return [...this.sql.exec(query, ...params)].map((r: any) => ({
      id: r.id,
      validator_pubkey: r.validator_pubkey,
      round: r.round,
      vertex_hash_1: r.vertex_hash_1,
      vertex_hash_2: r.vertex_hash_2,
      detected_at: r.detected_at,
      reported_by: r.reported_by,
    }));
  }

  // ─── Governance ─────────────────────────────────────────────────────────

  /**
   * Cast a governance vote (admit, remove, or adjust difficulty).
   * When supermajority (2/3 of reputation) agrees, the action executes.
   */
  async vote(
    voterPubkey: string,
    action: "admit" | "remove" | "set_difficulty",
    target: string,
  ): Promise<{ ok: boolean; executed: boolean; error?: string; votes_for: number; threshold: number }> {
    const voter = this.getValidator(voterPubkey);
    if (!voter || voter.status !== "active") {
      return { ok: false, executed: false, error: "Not an active validator", votes_for: 0, threshold: 0 };
    }

    const voteId = await sha256(`vote:${voterPubkey}:${action}:${target}:${Date.now()}`);

    // Store vote
    this.sql.exec(
      `INSERT INTO governance_votes (id, action, target, voter_pubkey, voter_reputation, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      voteId, action, target, voterPubkey, voter.reputation, Date.now(),
    );

    // Clean expired votes
    const cutoff = Date.now() - VOTE_EXPIRY_MS;
    this.sql.exec("DELETE FROM governance_votes WHERE created_at < ?", cutoff);

    // Tally votes for this action+target
    const votes = [...this.sql.exec(
      "SELECT DISTINCT voter_pubkey, voter_reputation FROM governance_votes WHERE action = ? AND target = ? AND created_at >= ?",
      action, target, cutoff,
    )] as any[];

    const totalVoteWeight = votes.reduce((sum: number, v: any) => sum + (v.voter_reputation || 0), 0);
    const threshold = this.getQuorumThreshold();

    if (totalVoteWeight >= threshold) {
      // Execute the governance action
      await this.executeGovernance(action, target);
      this.invalidateQuorumCache();

      // Clean up votes for this action
      this.sql.exec("DELETE FROM governance_votes WHERE action = ? AND target = ?", action, target);

      return { ok: true, executed: true, votes_for: totalVoteWeight, threshold };
    }

    return { ok: true, executed: false, votes_for: totalVoteWeight, threshold };
  }

  private async executeGovernance(action: string, target: string) {
    switch (action) {
      case "admit":
        // Admit a validator without PoW (governance override)
        this.sql.exec(
          `INSERT INTO validators (pubkey, url, reputation, pow_nonce, pow_hash, registered_at, last_active_round, status, equivocation_count, total_vertices, total_commits)
           VALUES (?, '', ?, 'governance', 'governance', ?, 0, 'active', 0, 0, 0)
           ON CONFLICT(pubkey) DO UPDATE SET reputation = ?, status = 'active'`,
          target, INITIAL_REPUTATION, Date.now(), INITIAL_REPUTATION,
        );
        console.log(`GOVERNANCE: Admitted validator ${target}`);
        break;

      case "remove":
        this.sql.exec(
          "UPDATE validators SET status = 'removed', reputation = 0 WHERE pubkey = ?",
          target,
        );
        console.log(`GOVERNANCE: Removed validator ${target}`);
        break;

      case "set_difficulty": {
        const newDifficulty = parseInt(target);
        if (newDifficulty >= 10 && newDifficulty <= 32) {
          this.powDifficulty = newDifficulty;
          this.sql.exec(
            "INSERT INTO consensus_state (key, value) VALUES ('pow_difficulty', ?) ON CONFLICT(key) DO UPDATE SET value = ?",
            target, target,
          );
          console.log(`GOVERNANCE: PoW difficulty set to ${newDifficulty}`);
        }
        break;
      }
    }
  }

  // ─── Rate Limiting ──────────────────────────────────────────────────────

  /**
   * Check if a pubkey is rate-limited for event submission.
   * Uses a token bucket: validators get higher limits based on reputation.
   */
  checkRateLimit(pubkey: string, windowMs: number = 60_000, maxEvents?: number): boolean {
    const validator = this.getValidator(pubkey);

    // Base limit for non-validators (1000/min allows stress testing)
    let limit = maxEvents || 1000;

    // Validators get higher limits scaled by reputation
    if (validator && validator.status === "active") {
      const reputationMultiplier = Math.max(1, Math.floor(validator.reputation / 100));
      limit = Math.min(1000, limit * reputationMultiplier);
    }

    // Count recent events from this pubkey
    const cutoff = Date.now() - windowMs;
    const rows = [...this.sql.exec(
      "SELECT COUNT(*) as cnt FROM rate_limit_log WHERE pubkey = ? AND timestamp > ?",
      pubkey, cutoff,
    )] as any[];

    const count = (rows[0]?.cnt || 0) as number;
    if (count >= limit) return false; // rate limited

    // Log this event
    this.sql.exec(
      "INSERT INTO rate_limit_log (pubkey, timestamp) VALUES (?, ?)",
      pubkey, Date.now(),
    );

    return true;
  }

  /**
   * Prune stale rate-limit entries. Call from alarm handler (not per-request).
   */
  pruneRateLimitLog(maxAgeMs: number = 120_000) {
    this.sql.exec("DELETE FROM rate_limit_log WHERE timestamp < ?", Date.now() - maxAgeMs);
  }

  /**
   * Rate-limit gossip traffic. Registered validators get generous limits;
   * unregistered peers get 10x stricter limits to make PoW serve double duty.
   */
  checkGossipRateLimit(pubkey: string): boolean {
    const validator = this.getValidator(pubkey);
    const isRegistered = validator && validator.status === "active";

    // Registered validators: 200/min scaled by reputation. Unregistered: 20/min.
    const baseLimit = isRegistered ? 200 : 20;
    return this.checkRateLimit(pubkey, 60_000, baseLimit);
  }

  // ─── PoW Difficulty Info ────────────────────────────────────────────────

  getDifficulty(): number {
    return this.powDifficulty;
  }

  getRegistrationInfo(): { difficulty: number; leading_zero_bits: number; estimated_hashes: number } {
    return {
      difficulty: this.powDifficulty,
      leading_zero_bits: this.powDifficulty,
      estimated_hashes: Math.pow(2, this.powDifficulty),
    };
  }
}
