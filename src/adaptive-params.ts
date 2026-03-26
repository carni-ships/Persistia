// ─── Adaptive Network Parameters (EIP-1559-style) ─────────────────────────────
//
// Dynamically adjusts round_interval_ms and max_events_per_vertex based on
// network load and prover health.
//
// Signals:
//   1. Event pressure   — pending events / max_events_per_vertex (vertex utilization)
//   2. Prover lag        — how far behind the ZK prover is (unproven rounds)
//   3. Vertex emptiness  — consecutive empty vertices (no demand)
//
// Mechanics (inspired by EIP-1559 base fee):
//   - Each committed round, compute a smoothed load factor from recent history
//   - Adjust round_interval_ms by at most ±12.5% per round
//   - Adjust max_events_per_vertex by at most ±6.25% per round
//   - Prover lag acts as a hard brake — if too far behind, always slow down
//   - Consecutive empty rounds trigger progressive slowdown
//   - All changes are bounded by GOVERNABLE_PARAMS limits
//   - Changes are recorded in network_config_history with changedBy="adaptive"
//
// Smoothing: uses an exponential moving average over the last SMOOTHING_WINDOW
// rounds to prevent oscillation under bursty load.

export interface AdaptiveSignals {
  pendingEvents: number;        // current pending event queue size
  maxEventsPerVertex: number;   // max events per vertex (capacity)
  eventsInLastVertex: number;   // events actually included in the last committed vertex
  currentRound: number;         // current consensus round
  latestProvenBlock: number;    // highest block proven by ZK prover (0 if none)
  lastCommittedRound: number;   // latest committed round
  consecutiveEmptyRounds: number; // how many recent rounds had 0 events
  utilizationHistory: number[]; // recent utilization values for smoothing
}

export interface AdaptiveResult {
  newIntervalMs: number;
  newMaxEvents: number | null;   // null = no change
  reason: string;
  loadFactor: number;            // -1 to +1: negative = speed up, positive = slow down
  proverLag: number;
  utilization: number;           // smoothed utilization
  rawUtilization: number;        // instant (unsmoothed) utilization
}

// ─── Constants ─────────────────────────────────────────────────────────────────

/** Max adjustment per round: 12.5% (same as EIP-1559 base fee change denominator of 8) */
const MAX_CHANGE_RATE = 0.125;

/** Max adjustment for max_events_per_vertex: 6.25% (more conservative) */
const MAX_EVENTS_CHANGE_RATE = 0.0625;

/** Target vertex utilization: 50% of capacity */
const TARGET_UTILIZATION = 0.5;

/** Smoothing window: average over this many recent rounds */
export const SMOOTHING_WINDOW = 5;

/** Prover lag thresholds (in rounds) */
const PROVER_LAG_SOFT = 30;   // start slowing down
const PROVER_LAG_HARD = 100;  // force maximum slowdown

/** After this many consecutive empty rounds, start slowing down */
const EMPTY_ROUND_THRESHOLD = 3;

/** Minimum interval to prevent thrashing */
const ADAPTIVE_FLOOR_MS = 1_000;    // 1s — match GOVERNABLE_PARAMS floor

/** Events capacity adjustment thresholds */
const EVENTS_UPSCALE_UTILIZATION = 0.8;   // scale up capacity when consistently >80% full
const EVENTS_DOWNSCALE_UTILIZATION = 0.2; // scale down when consistently <20% full

/**
 * Compute smoothed utilization from history using exponential weighting.
 * More recent values are weighted more heavily.
 */
function smoothedUtilization(history: number[], currentValue: number): number {
  const values = [...history, currentValue];
  if (values.length <= 1) return currentValue;

  // Exponential weights: most recent = 1.0, previous = 0.7, etc.
  const DECAY = 0.7;
  let weightedSum = 0;
  let weightTotal = 0;
  for (let i = values.length - 1; i >= 0; i--) {
    const age = values.length - 1 - i;
    const weight = Math.pow(DECAY, age);
    weightedSum += values[i] * weight;
    weightTotal += weight;
  }
  return weightTotal > 0 ? weightedSum / weightTotal : currentValue;
}

/**
 * Compute the next round_interval_ms and optionally max_events_per_vertex
 * based on current network signals.
 */
export function computeAdaptiveInterval(
  currentIntervalMs: number,
  currentMaxEvents: number,
  signals: AdaptiveSignals,
  intervalBounds: { min: number; max: number },
  eventsBounds: { min: number; max: number },
): AdaptiveResult {
  const {
    pendingEvents,
    maxEventsPerVertex,
    eventsInLastVertex,
    latestProvenBlock,
    lastCommittedRound,
    consecutiveEmptyRounds,
    utilizationHistory,
  } = signals;

  // ── 1. Compute instant utilization ────────────────────────────────────
  const vertexUtilization = maxEventsPerVertex > 0
    ? eventsInLastVertex / maxEventsPerVertex
    : 0;
  const queuePressure = maxEventsPerVertex > 0
    ? Math.min(pendingEvents / maxEventsPerVertex, 2.0)
    : 0;

  // Weighted blend: 60% recent vertex, 40% queue pressure
  const rawUtilization = vertexUtilization * 0.6 + queuePressure * 0.4;

  // ── 2. Smooth utilization over recent history ─────────────────────────
  const utilization = smoothedUtilization(utilizationHistory, rawUtilization);

  // ── 3. Compute prover lag brake ───────────────────────────────────────
  let proverLag = 0;
  let proverBrakeFactor = 0;
  if (latestProvenBlock > 0) {
    proverLag = lastCommittedRound - latestProvenBlock;
    if (proverLag > PROVER_LAG_HARD) {
      proverBrakeFactor = 1.0;
    } else if (proverLag > PROVER_LAG_SOFT) {
      proverBrakeFactor = (proverLag - PROVER_LAG_SOFT) / (PROVER_LAG_HARD - PROVER_LAG_SOFT);
    }
  }

  // ── 4. Compute empty-round drag ───────────────────────────────────────
  let emptyDrag = 0;
  if (consecutiveEmptyRounds > EMPTY_ROUND_THRESHOLD) {
    emptyDrag = Math.min(
      (consecutiveEmptyRounds - EMPTY_ROUND_THRESHOLD) * 0.25,
      1.0,
    );
  }

  // ── 5. Combine into load factor ───────────────────────────────────────
  let baseFactor = (TARGET_UTILIZATION - utilization) / TARGET_UTILIZATION;
  baseFactor = Math.max(-1, Math.min(1, baseFactor));

  let loadFactor = baseFactor;
  if (proverBrakeFactor > 0) {
    loadFactor = Math.max(loadFactor, proverBrakeFactor);
  }
  if (emptyDrag > 0 && loadFactor < emptyDrag) {
    loadFactor = emptyDrag;
  }
  loadFactor = Math.max(-1, Math.min(1, loadFactor));

  // ── 6. Adjust round_interval_ms ───────────────────────────────────────
  const change = loadFactor * MAX_CHANGE_RATE;
  let newInterval = currentIntervalMs * (1 + change);

  const effectiveMin = Math.max(intervalBounds.min, ADAPTIVE_FLOOR_MS);
  newInterval = Math.max(effectiveMin, Math.min(intervalBounds.max, newInterval));
  newInterval = Math.round(newInterval / 100) * 100;
  // Ensure we don't round below floor
  if (newInterval < effectiveMin) newInterval = effectiveMin;

  // ── 7. Adjust max_events_per_vertex ───────────────────────────────────
  // More conservative: only adjust when sustained high/low utilization
  let newMaxEvents: number | null = null;
  if (utilization > EVENTS_UPSCALE_UTILIZATION && proverBrakeFactor === 0) {
    // High sustained utilization + prover healthy → increase capacity
    const eventsChange = Math.ceil(currentMaxEvents * MAX_EVENTS_CHANGE_RATE);
    const proposed = currentMaxEvents + eventsChange;
    if (proposed <= eventsBounds.max && proposed !== currentMaxEvents) {
      newMaxEvents = proposed;
    }
  } else if (utilization < EVENTS_DOWNSCALE_UTILIZATION && consecutiveEmptyRounds === 0) {
    // Low sustained utilization (but not idle) → decrease capacity to lighten vertices
    const eventsChange = Math.ceil(currentMaxEvents * MAX_EVENTS_CHANGE_RATE);
    const proposed = currentMaxEvents - eventsChange;
    if (proposed >= eventsBounds.min && proposed !== currentMaxEvents) {
      newMaxEvents = proposed;
    }
  }

  // ── 8. Build reason string ────────────────────────────────────────────
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
  parts.push(`util=${(utilization * 100).toFixed(0)}% (raw=${(rawUtilization * 100).toFixed(0)}%)`);
  if (newMaxEvents !== null) parts.push(`max_events→${newMaxEvents}`);

  return {
    newIntervalMs: newInterval,
    newMaxEvents,
    reason: parts.join(", "),
    loadFactor,
    proverLag,
    utilization,
    rawUtilization,
  };
}
