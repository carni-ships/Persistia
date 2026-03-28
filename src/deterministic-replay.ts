// ─── Deterministic Replay Engine ─────────────────────────────────────────────
// Extracts the pure state transition logic from PersistiaDO for use in:
//   1. Fraud proof challenge verification (Phase 1)
//   2. zkVM guest program witness generation (Phase 2)
//   3. Future full validity proving inside SP1 (Phase 3)
//
// The key abstraction: given pre-state + ordered events, compute post-state root.
// This module does NOT execute events itself — it delegates to a StateTransitionFn
// provided by the caller (PersistiaDO passes its own applyEvent). The replay engine
// handles ordering, validation, and state root computation.

import type { SignedEvent } from "./types";
import { sha256, computeEventHash } from "./consensus";

// ─── Types ──────────────────────────────────────────────────────────────────

/** A single state mutation produced by applying an event. */
export interface StateMutation {
  key: string;
  old_value: string | null;
  new_value: string | null;
}

/** Recorded state read during event execution (for witness generation). */
export interface StateRead {
  key: string;
  value: string | null;
}

/** The function signature for applying a single event to state. */
export type ApplyEventFn = (
  type: string,
  payload: any,
  pubkey: string,
) => Promise<void>;

/** The function signature for validating an event before application. */
export type ValidateRulesFn = (
  event: SignedEvent,
) => { ok: boolean; error?: string };

/** Result of replaying a block's events. */
export interface ReplayResult {
  success: boolean;
  events_applied: number;
  events_skipped: number;
  skipped_reasons: { hash: string; error: string }[];
  mutations: StateMutation[];
}

// ─── Witness Recorder ───────────────────────────────────────────────────────
// Wraps SQL access to capture all reads/writes during block execution.
// Used by PersistiaDO to generate challenge witnesses.

export class WitnessRecorder {
  readonly stateReads: Map<string, string | null> = new Map();
  readonly stateWrites: Map<string, string | null> = new Map();
  private _recording = false;

  startRecording(): void {
    this.stateReads.clear();
    this.stateWrites.clear();
    this._recording = true;
  }

  stopRecording(): { reads: StateRead[]; writes: StateMutation[] } {
    this._recording = false;
    const reads: StateRead[] = [];
    for (const [key, value] of this.stateReads) {
      reads.push({ key, value });
    }
    const writes: StateMutation[] = [];
    for (const [key, newValue] of this.stateWrites) {
      const oldValue = this.stateReads.get(key) ?? null;
      writes.push({ key, old_value: oldValue, new_value: newValue });
    }
    return { reads, writes };
  }

  get isRecording(): boolean {
    return this._recording;
  }

  /** Call when a state key is read. Only records the first read per key (pre-state). */
  recordRead(key: string, value: string | null): void {
    if (!this._recording) return;
    if (!this.stateReads.has(key)) {
      this.stateReads.set(key, value);
    }
  }

  /** Call when a state key is written. */
  recordWrite(key: string, newValue: string | null): void {
    if (!this._recording) return;
    this.stateWrites.set(key, newValue);
  }
}

// ─── Replay Engine ──────────────────────────────────────────────────────────

/**
 * Replay a block's events using the provided apply/validate functions.
 * This is the core deterministic execution path.
 *
 * @param events - Ordered events from the committed vertex
 * @param applyEvent - Function to apply a single event (from PersistiaDO)
 * @param validateRules - Function to validate an event (from PersistiaDO)
 * @param finalizedEventHashes - Set of already-finalized event hashes to skip
 */
export async function replayBlock(
  events: SignedEvent[],
  applyEvent: ApplyEventFn,
  validateRules: ValidateRulesFn,
  finalizedEventHashes: Set<string>,
): Promise<ReplayResult> {
  let applied = 0;
  let skipped = 0;
  const skippedReasons: { hash: string; error: string }[] = [];

  for (const event of events) {
    const hash = await computeEventHash(event);

    // Skip already-finalized events
    if (finalizedEventHashes.has(hash)) {
      skipped++;
      continue;
    }

    // Validate rules
    const ruleCheck = validateRules(event);
    if (!ruleCheck.ok) {
      skipped++;
      skippedReasons.push({ hash, error: ruleCheck.error || "Rule validation failed" });
      continue;
    }

    // Apply event
    const payload = typeof event.payload === "string" ? JSON.parse(event.payload) : event.payload;
    await applyEvent(event.type, payload, event.pubkey);
    applied++;
  }

  return {
    success: true,
    events_applied: applied,
    events_skipped: skipped,
    skipped_reasons: skippedReasons,
    mutations: [], // Mutations are captured by WitnessRecorder if active
  };
}

// ─── State Root Verification ────────────────────────────────────────────────

/**
 * Verify that a set of mutations applied to a pre-state root produces the
 * claimed post-state root. Used in fraud proof resolution.
 *
 * This is a simplified check — the full Merkle proof verification happens
 * in the ZK circuit (Noir). This function provides a quick sanity check
 * for the challenge protocol.
 */
export async function computeMutationsHash(
  mutations: StateMutation[],
): Promise<string> {
  const sorted = [...mutations].sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
  const canonical = JSON.stringify(sorted.map(m => ({
    k: m.key,
    o: m.old_value,
    n: m.new_value,
  })));
  return sha256(canonical);
}

/**
 * Compare two replay results to determine if state transitions match.
 * Used when a challenger claims a different post-state root.
 */
export function compareReplayResults(
  proposerMutations: StateMutation[],
  challengerMutations: StateMutation[],
): { match: boolean; divergence_key?: string } {
  const proposerMap = new Map(proposerMutations.map(m => [m.key, m.new_value]));
  const challengerMap = new Map(challengerMutations.map(m => [m.key, m.new_value]));

  // Check all proposer keys exist in challenger with same values
  for (const [key, value] of proposerMap) {
    if (challengerMap.get(key) !== value) {
      return { match: false, divergence_key: key };
    }
  }
  // Check challenger doesn't have extra keys
  for (const key of challengerMap.keys()) {
    if (!proposerMap.has(key)) {
      return { match: false, divergence_key: key };
    }
  }

  return { match: true };
}
