// ─── Consensus Pure Functions ──────────────────────────────────────────────────
// No DO dependency. All functions are deterministic and unit-testable.

import type { DAGVertex, StoredVertex } from "./types";

// ─── Hashing ──────────────────────────────────────────────────────────────────

export async function sha256(data: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function computeVertexHash(v: DAGVertex): Promise<string> {
  const canonical = JSON.stringify({
    author: v.author,
    round: v.round,
    event_hashes: [...v.event_hashes].sort(),
    refs: [...v.refs].sort(),
    timestamp: v.timestamp,
  });
  return sha256(canonical);
}

export async function computeEventHash(event: { type: string; payload: any; pubkey: string; timestamp: number }): Promise<string> {
  const data = JSON.stringify({
    type: event.type,
    payload: typeof event.payload === "string" ? JSON.parse(event.payload) : event.payload,
    pubkey: event.pubkey,
    timestamp: event.timestamp,
  });
  return sha256(data);
}

// ─── Quorum ───────────────────────────────────────────────────────────────────

export function getQuorumSize(activeCount: number): number {
  if (activeCount < 1) return 1;
  const f = Math.floor((activeCount - 1) / 3);
  return 2 * f + 1;
}

export function getMaxFaults(activeCount: number): number {
  return Math.floor((activeCount - 1) / 3);
}

export function isQuorumMet(voteCount: number, activeCount: number): boolean {
  return voteCount >= getQuorumSize(activeCount);
}

// ─── Leader Selection ─────────────────────────────────────────────────────────

export async function selectLeader(round: number, activePubkeys: string[]): Promise<string> {
  if (activePubkeys.length === 0) throw new Error("No active nodes");
  const sorted = [...activePubkeys].sort();
  const roundHash = await sha256(round.toString());
  const idx = parseInt(roundHash.slice(0, 8), 16) % sorted.length;
  return sorted[idx];
}

// ─── Active Set ───────────────────────────────────────────────────────────────

export const ACTIVE_WINDOW = 10; // rounds

export function computeActiveSet(
  vertices: { author: string; round: number }[],
  currentRound: number,
  window: number = ACTIVE_WINDOW,
): Set<string> {
  const minRound = Math.max(0, currentRound - window);
  const active = new Set<string>();
  for (const v of vertices) {
    if (v.round >= minRound && v.round < currentRound) {
      active.add(v.author);
    }
  }
  return active;
}

// ─── Topological Sort (Causal Event Ordering) ─────────────────────────────────

export interface VertexNode {
  hash: string;
  author: string;
  round: number;
  event_hashes: string[];
  refs: string[];
}

/**
 * Collect all vertices reachable from `anchorHash` in the DAG,
 * return them in deterministic causal order (topological sort).
 * Within the same round, tie-break by vertex hash (lexicographic).
 */
export function topologicalSort(
  anchorHash: string,
  vertexMap: Map<string, VertexNode>,
  alreadyFinalized: Set<string>,
): VertexNode[] {
  // BFS backwards from anchor to collect reachable vertices
  const reachable = new Set<string>();
  const queue: string[] = [anchorHash];

  while (queue.length > 0) {
    const hash = queue.shift()!;
    if (reachable.has(hash) || alreadyFinalized.has(hash)) continue;
    reachable.add(hash);
    const vertex = vertexMap.get(hash);
    if (vertex) {
      for (const ref of vertex.refs) {
        if (!reachable.has(ref) && !alreadyFinalized.has(ref)) {
          queue.push(ref);
        }
      }
    }
  }

  // Collect and sort: by round ascending, then by hash for deterministic tie-breaking
  const sorted = [...reachable]
    .map(h => vertexMap.get(h)!)
    .filter(v => v != null)
    .sort((a, b) => {
      if (a.round !== b.round) return a.round - b.round;
      return a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0;
    });

  return sorted;
}

// ─── Commit Rule (Bullshark-style) ────────────────────────────────────────────

export interface CommitCheckResult {
  committed: boolean;
  anchorHash: string | null;
  reason: string;
}

/**
 * Check if the anchor at `round` (must be even) has been committed.
 * An anchor is committed when >= quorum vertices in round+1 reference it.
 */
export function checkCommit(
  round: number,
  leaderPubkey: string,
  verticesByRound: Map<number, VertexNode[]>,
  activeCount: number,
): CommitCheckResult {
  if (round % 2 !== 0) {
    return { committed: false, anchorHash: null, reason: "Not an anchor round (must be even)" };
  }

  const quorum = getQuorumSize(activeCount);
  if (activeCount < 4) {
    return { committed: false, anchorHash: null, reason: `Need >= 4 active nodes, have ${activeCount}` };
  }

  // Find leader's vertex at this round
  const roundVertices = verticesByRound.get(round) || [];
  const anchor = roundVertices.find(v => v.author === leaderPubkey);
  if (!anchor) {
    return { committed: false, anchorHash: null, reason: "Leader did not produce a vertex this round" };
  }

  // Count distinct authors in round+1 that reference the anchor
  const nextRoundVertices = verticesByRound.get(round + 1) || [];
  const supporters = new Set<string>();
  for (const v of nextRoundVertices) {
    if (v.refs.includes(anchor.hash)) {
      supporters.add(v.author);
    }
  }

  if (supporters.size >= quorum) {
    return { committed: true, anchorHash: anchor.hash, reason: `Quorum met: ${supporters.size}/${quorum}` };
  }

  return {
    committed: false,
    anchorHash: anchor.hash,
    reason: `Insufficient support: ${supporters.size}/${quorum}`,
  };
}
