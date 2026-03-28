// ─── Fraud Proof Protocol ────────────────────────────────────────────────────
// Pure functions for challenge lifecycle management. No DO dependency.
// Uses existing escrow holds (wallet.ts) for bond mechanics.

import type { ChallengeRecord, ChallengeWindow, ChallengeWitness, SignedEvent } from "./types";
import { sha256 } from "./consensus";

// ─── Constants ──────────────────────────────────────────────────────────────

export const DEFAULT_CHALLENGE_BOND = 1000n;        // PERSIST
export const DEFAULT_VALIDATOR_BOND_MIN = 5000n;     // PERSIST
export const DEFAULT_CHALLENGE_WINDOW = 100;         // rounds
export const DEFAULT_RESPONSE_WINDOW = 50;           // rounds

// ─── Challenge ID Generation ────────────────────────────────────────────────

export async function generateChallengeId(blockNumber: number, challenger: string): Promise<string> {
  return `challenge_${await sha256(`${blockNumber}:${challenger}:${Date.now()}`)}`.slice(0, 48);
}

// ─── Challenge Window Management ────────────────────────────────────────────

/**
 * Create a challenge window entry after a block is committed.
 * Called from commitAnchor().
 */
export function createChallengeWindow(
  blockNumber: number,
  proposer: string,
  postStateRoot: string,
  currentRound: number,
  windowSize: number = DEFAULT_CHALLENGE_WINDOW,
): ChallengeWindow {
  return {
    block_number: blockNumber,
    proposer,
    post_state_root: postStateRoot,
    expires_at_round: currentRound + windowSize,
    status: "open",
  };
}

/**
 * Check if a challenge window has expired without being challenged.
 */
export function isWindowExpired(window: ChallengeWindow, currentRound: number): boolean {
  return window.status === "open" && currentRound >= window.expires_at_round;
}

/**
 * Check if a challenge response has timed out.
 */
export function isChallengeTimedOut(challenge: ChallengeRecord, currentRound: number): boolean {
  return challenge.status === "challenged" && currentRound >= challenge.response_deadline_round;
}

// ─── Challenge Validation ───────────────────────────────────────────────────

export interface ChallengeSubmission {
  block_number: number;
  challenger: string;
  claimed_invalid_root: string | null;
}

export interface ChallengeValidationResult {
  valid: boolean;
  error?: string;
}

/**
 * Validate that a challenge submission is well-formed and within window.
 */
export function validateChallengeSubmission(
  submission: ChallengeSubmission,
  window: ChallengeWindow | null,
  currentRound: number,
  challengerIsValidator: boolean,
): ChallengeValidationResult {
  if (!window) {
    return { valid: false, error: "No challenge window found for this block" };
  }
  if (window.status !== "open") {
    return { valid: false, error: `Challenge window is ${window.status}, not open` };
  }
  if (currentRound >= window.expires_at_round) {
    return { valid: false, error: "Challenge window has expired" };
  }
  if (!challengerIsValidator) {
    return { valid: false, error: "Only registered validators can submit challenges" };
  }
  if (submission.challenger === window.proposer) {
    return { valid: false, error: "Proposer cannot challenge their own block" };
  }
  return { valid: true };
}

// ─── Challenge Resolution ───────────────────────────────────────────────────

export interface ResolutionResult {
  outcome: "valid" | "fraud" | "timeout";
  slash_target: string;        // pubkey of party to slash
  slash_amount: bigint;
  reward_target: string;       // pubkey of party to reward
  reward_amount: bigint;
  rollback_block: boolean;     // whether the block should be rolled back
}

/**
 * Compute resolution when a ZK proof is submitted responding to a challenge.
 * The proof either confirms the proposer's state root (challenger loses)
 * or shows a different root (proposer loses).
 */
export function resolveWithProof(
  challenge: ChallengeRecord,
  window: ChallengeWindow,
  proofStateRoot: string,
  challengeBond: bigint = DEFAULT_CHALLENGE_BOND,
): ResolutionResult {
  const proposerCorrect = proofStateRoot === window.post_state_root;

  if (proposerCorrect) {
    // Challenger was wrong — slash challenger's bond, reward proposer
    return {
      outcome: "valid",
      slash_target: challenge.challenger,
      slash_amount: challengeBond,
      reward_target: window.proposer,
      reward_amount: challengeBond,
      rollback_block: false,
    };
  } else {
    // Proposer committed invalid state — slash proposer, reward challenger
    return {
      outcome: "fraud",
      slash_target: window.proposer,
      slash_amount: challengeBond * 5n,  // proposer penalized more heavily
      reward_target: challenge.challenger,
      reward_amount: challengeBond * 2n, // challenger gets bond back + reward
      rollback_block: true,
    };
  }
}

/**
 * Compute resolution when the proposer fails to respond within the window.
 * Treated as fraud confirmed.
 */
export function resolveTimeout(
  challenge: ChallengeRecord,
  window: ChallengeWindow,
  challengeBond: bigint = DEFAULT_CHALLENGE_BOND,
): ResolutionResult {
  return {
    outcome: "timeout",
    slash_target: window.proposer,
    slash_amount: challengeBond * 3n,
    reward_target: challenge.challenger,
    reward_amount: challengeBond * 2n,
    rollback_block: true,
  };
}

// ─── Witness Builder Helpers ────────────────────────────────────────────────

/**
 * Build a challenge witness from block data.
 * The caller (PersistiaDO) provides the raw SQL data.
 */
export function buildChallengeWitness(params: {
  block_number: number;
  prev_state_root: string;
  post_state_root: string;
  events: SignedEvent[];
  event_hashes: string[];
  mutations: { key: string; old_value: string | null; new_value: string | null }[];
  commit_signatures: { pubkey: string; signature: string; message: string }[];
  active_nodes: number;
  prev_header_hash: string;
  validator_set_hash: string;
}): ChallengeWitness {
  return {
    block_number: params.block_number,
    prev_state_root: params.prev_state_root,
    post_state_root: params.post_state_root,
    events: params.events,
    event_hashes: params.event_hashes,
    mutations: params.mutations,
    commit_signatures: params.commit_signatures,
    active_nodes: params.active_nodes,
    prev_header_hash: params.prev_header_hash,
    validator_set_hash: params.validator_set_hash,
  };
}

// ─── SQL Helpers (stateless — caller provides sql handle) ───────────────────

export interface FraudProofSQL {
  exec(query: string, ...params: any[]): IterableIterator<Record<string, any>>;
}

/**
 * Insert a challenge window record.
 */
export function insertChallengeWindow(sql: FraudProofSQL, w: ChallengeWindow): void {
  sql.exec(
    `INSERT OR REPLACE INTO challenge_windows (block_number, proposer, post_state_root, expires_at_round, status)
     VALUES (?, ?, ?, ?, ?)`,
    w.block_number, w.proposer, w.post_state_root, w.expires_at_round, w.status,
  );
}

/**
 * Get the challenge window for a block.
 */
export function getChallengeWindow(sql: FraudProofSQL, blockNumber: number): ChallengeWindow | null {
  const rows = [...sql.exec(
    "SELECT * FROM challenge_windows WHERE block_number = ?", blockNumber,
  )] as any[];
  return rows.length > 0 ? rows[0] as ChallengeWindow : null;
}

/**
 * Finalize expired unchallenged windows. Returns count finalized.
 */
export function finalizeExpiredWindows(sql: FraudProofSQL, currentRound: number): number {
  const expired = [...sql.exec(
    "SELECT block_number FROM challenge_windows WHERE status = 'open' AND expires_at_round <= ?",
    currentRound,
  )] as any[];
  if (expired.length === 0) return 0;
  sql.exec(
    "UPDATE challenge_windows SET status = 'finalized' WHERE status = 'open' AND expires_at_round <= ?",
    currentRound,
  );
  return expired.length;
}

/**
 * Insert a fraud challenge record.
 */
export function insertChallenge(sql: FraudProofSQL, c: ChallengeRecord): void {
  sql.exec(
    `INSERT INTO fraud_challenges
       (id, block_number, challenger, bond_hold_id, claimed_invalid_root,
        response_deadline_round, status, created_at, resolved_at,
        resolution_proof_hash, resolution_type)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    c.id, c.block_number, c.challenger, c.bond_hold_id,
    c.claimed_invalid_root, c.response_deadline_round, c.status,
    c.created_at, c.resolved_at, c.resolution_proof_hash, c.resolution_type,
  );
}

/**
 * Get active challenge for a block (if any).
 */
export function getActiveChallenge(sql: FraudProofSQL, blockNumber: number): ChallengeRecord | null {
  const rows = [...sql.exec(
    "SELECT * FROM fraud_challenges WHERE block_number = ? AND status = 'challenged' LIMIT 1",
    blockNumber,
  )] as any[];
  return rows.length > 0 ? rows[0] as ChallengeRecord : null;
}

/**
 * Find all timed-out challenges. Returns challenge + window pairs.
 */
export function findTimedOutChallenges(
  sql: FraudProofSQL,
  currentRound: number,
): { challenge: ChallengeRecord; window: ChallengeWindow }[] {
  const challenges = [...sql.exec(
    "SELECT * FROM fraud_challenges WHERE status = 'challenged' AND response_deadline_round <= ?",
    currentRound,
  )] as any[];
  const results: { challenge: ChallengeRecord; window: ChallengeWindow }[] = [];
  for (const c of challenges) {
    const w = getChallengeWindow(sql, c.block_number);
    if (w) results.push({ challenge: c as ChallengeRecord, window: w });
  }
  return results;
}

/**
 * Update challenge status.
 */
export function updateChallengeStatus(
  sql: FraudProofSQL,
  challengeId: string,
  status: string,
  resolvedAt?: number,
  proofHash?: string,
  resolutionType?: string,
): void {
  sql.exec(
    `UPDATE fraud_challenges
     SET status = ?, resolved_at = ?, resolution_proof_hash = ?, resolution_type = ?
     WHERE id = ?`,
    status, resolvedAt ?? null, proofHash ?? null, resolutionType ?? null, challengeId,
  );
}

/**
 * Update challenge window status.
 */
export function updateWindowStatus(sql: FraudProofSQL, blockNumber: number, status: string): void {
  sql.exec(
    "UPDATE challenge_windows SET status = ? WHERE block_number = ?",
    status, blockNumber,
  );
}
