// ─── Adaptive Network Parameters (EIP-1559-style) ─────────────────────────────
//
// Dynamically adjusts round_interval_ms based on network load and prover health.
//
// Signals:
//   1. Event pressure   — pending events / max_events_per_vertex (vertex utilization)
//   2. Prover lag        — how far behind the ZK prover is (unproven rounds)
//   3. Vertex emptiness  — consecutive empty vertices (no demand)
//
// Mechanics (inspired by EIP-1559 base fee):
//   - Each committed round, compute a load factor from the signals
//   - Adjust round_interval_ms by at most ±12.5% per round
//   - Prover lag acts as a hard brake — if too far behind, always slow down
//   - Consecutive empty rounds trigger progressive slowdown
//   - All changes are bounded by GOVERNABLE_PARAMS limits (5s–600s)
//   - Changes are recorded in network_config_history with changedBy="adaptive"
//
// The system finds equilibrium: high load + healthy prover → fast rounds,
// low load or struggling prover → slow rounds to conserve resources.

export interface AdaptiveSignals {
  pendingEvents: number;        // current pending event queue size
  maxEventsPerVertex: number;   // max events per vertex (capacity)
  eventsInLastVertex: number;   // events actually included in the last committed vertex
  currentRound: number;         // current consensus round
  latestProvenBlock: number;    // highest block proven by ZK prover (0 if none)
  lastCommittedRound: number;   // latest committed round
  consecutiveEmptyRounds: number; // how many recent rounds had 0 events
}

export interface AdaptiveResult {
  newIntervalMs: number;
  reason: string;
  loadFactor: number;          // -1 to +1: negative = speed up, positive = slow down
  proverLag: number;
  utilization: number;
}

// ─── Constants ─────────────────────────────────────────────────────────────────

/** Max adjustment per round: 12.5% (same as EIP-1559 base fee change denominator of 8) */
const MAX_CHANGE_RATE = 0.125;

/** Target vertex utilization: 50% of capacity */
const TARGET_UTILIZATION = 0.5;

/** Prover lag thresholds (in rounds) */
const PROVER_LAG_SOFT = 30;   // start slowing down
const PROVER_LAG_HARD = 100;  // force maximum slowdown

/** After this many consecutive empty rounds, start slowing down */
const EMPTY_ROUND_THRESHOLD = 3;

/** Minimum interval to prevent thrashing (don't go below this even if GOVERNABLE_PARAMS allows) */
const ADAPTIVE_FLOOR_MS = 1_000;    // 1s — match GOVERNABLE_PARAMS floor

/**
 * Compute the next round_interval_ms based on current network signals.
 *
 * Returns the new interval (clamped to bounds) and a human-readable reason.
 */
export function computeAdaptiveInterval(
  currentIntervalMs: number,
  signals: AdaptiveSignals,
  bounds: { min: number; max: number },
): AdaptiveResult {
  const {
    pendingEvents,
    maxEventsPerVertex,
    eventsInLastVertex,
    currentRound,
    latestProvenBlock,
    lastCommittedRound,
    consecutiveEmptyRounds,
  } = signals;

  // ── 1. Compute utilization ──────────────────────────────────────────────
  // Blend of: events in last vertex (recent) + pending queue pressure (forward-looking)
  const vertexUtilization = maxEventsPerVertex > 0
    ? eventsInLastVertex / maxEventsPerVertex
    : 0;
  const queuePressure = maxEventsPerVertex > 0
    ? Math.min(pendingEvents / maxEventsPerVertex, 2.0)  // cap at 2x (queue is 2 vertices deep)
    : 0;

  // Weighted blend: 60% recent vertex, 40% queue pressure
  const utilization = vertexUtilization * 0.6 + queuePressure * 0.4;

  // ── 2. Compute prover lag ───────────────────────────────────────────────
  // Only relevant if proofs exist (latestProvenBlock > 0)
  let proverLag = 0;
  let proverBrakeFactor = 0;
  if (latestProvenBlock > 0) {
    proverLag = lastCommittedRound - latestProvenBlock;
    if (proverLag > PROVER_LAG_HARD) {
      proverBrakeFactor = 1.0; // maximum slowdown
    } else if (proverLag > PROVER_LAG_SOFT) {
      // Linear ramp from 0 to 1 between soft and hard thresholds
      proverBrakeFactor = (proverLag - PROVER_LAG_SOFT) / (PROVER_LAG_HARD - PROVER_LAG_SOFT);
    }
  }

  // ── 3. Compute empty-round drag ─────────────────────────────────────────
  // Progressive slowdown when network is idle
  let emptyDrag = 0;
  if (consecutiveEmptyRounds > EMPTY_ROUND_THRESHOLD) {
    // Each additional empty round beyond threshold adds 25% of max change
    emptyDrag = Math.min(
      (consecutiveEmptyRounds - EMPTY_ROUND_THRESHOLD) * 0.25,
      1.0,
    );
  }

  // ── 4. Combine into load factor ─────────────────────────────────────────
  // Negative = network is loaded → speed up (decrease interval)
  // Positive = network is idle or prover is behind → slow down (increase interval)

  // Base: deviation from target utilization (EIP-1559 style)
  // utilization > target → negative (speed up)
  // utilization < target → positive (slow down)
  let baseFactor = (TARGET_UTILIZATION - utilization) / TARGET_UTILIZATION;

  // Clamp base factor to [-1, 1]
  baseFactor = Math.max(-1, Math.min(1, baseFactor));

  // Apply prover brake — overrides speedup if prover is lagging
  // If prover brake is active, load factor can't go below the brake level
  let loadFactor = baseFactor;
  if (proverBrakeFactor > 0) {
    loadFactor = Math.max(loadFactor, proverBrakeFactor);
  }

  // Apply empty-round drag — adds to slowdown
  if (emptyDrag > 0 && loadFactor < emptyDrag) {
    loadFactor = emptyDrag;
  }

  // Final clamp
  loadFactor = Math.max(-1, Math.min(1, loadFactor));

  // ── 5. Apply adjustment ─────────────────────────────────────────────────
  const change = loadFactor * MAX_CHANGE_RATE;
  let newInterval = currentIntervalMs * (1 + change);

  // Clamp to bounds
  const effectiveMin = Math.max(bounds.min, ADAPTIVE_FLOOR_MS);
  newInterval = Math.max(effectiveMin, Math.min(bounds.max, newInterval));

  // Round to nearest 100ms to avoid noisy oscillation
  newInterval = Math.round(newInterval / 100) * 100;

  // ── 6. Build reason string ──────────────────────────────────────────────
  const parts: string[] = [];
  if (Math.abs(change) < 0.001) {
    parts.push("stable");
  } else if (change < 0) {
    parts.push(`speeding up (${(Math.abs(change) * 100).toFixed(1)}%)`);
  } else {
    parts.push(`slowing down (${(change * 100).toFixed(1)}%)`);
  }
  if (proverBrakeFactor > 0) parts.push(`prover lag=${proverLag} rounds`);
  if (emptyDrag > 0) parts.push(`${consecutiveEmptyRounds} empty rounds`);
  parts.push(`util=${(utilization * 100).toFixed(0)}%`);

  return {
    newIntervalMs: newInterval,
    reason: parts.join(", "),
    loadFactor,
    proverLag,
    utilization,
  };
}
