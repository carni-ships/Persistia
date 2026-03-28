// ─── Gossip Protocol ──────────────────────────────────────────────────────────
// Node-to-node communication for multi-node decentralization.
// Each independent Cloudflare account runs the same code and gossips
// vertices + events to form a unified BFT consensus network.
//
// Protocol:
//   1. Nodes discover each other via seed list or manual addNode()
//   2. On new vertex/event: flood to all known peers (HTTP POST)
//   3. Periodic sync: pull missing vertices from peers (every alarm cycle)
//   4. Peer exchange: share peer lists to enable mesh discovery

import { sha256 } from "./consensus";
import { signData, verifyNodeSignature, type NodeIdentity } from "./node-identity";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface GossipPeer {
  pubkey: string;
  url: string;
  last_seen: number;
  last_sync_round: number;
  failures: number;          // consecutive failure count
  added_at: number;
}

export interface GossipEnvelope {
  type: "vertex" | "event" | "peer_exchange" | "sync_request" | "sync_response" | "zk_proof" | "service_request" | "service_response";
  sender_pubkey: string;
  sender_url: string;
  signature: string;         // signs the payload JSON
  payload: any;
  timestamp: number;
  nonce: string;             // dedup
  grumpkin_x?: string;       // sender's Grumpkin public key x-coordinate
  grumpkin_y?: string;       // sender's Grumpkin public key y-coordinate
}

// ─── Service Federation Payloads ──────────────────────────────────────────────

export interface ServiceRequestPayload {
  request_id: string;          // unique ID for correlating responses
  service: string;             // e.g. "llm", "tts"
  model: string;               // model ID
  input_hash: string;          // H(request body) — peers fetch actual body from originator
  input_body_b64?: string;     // base64-encoded request body (included for verified/parallel modes)
  mode: "verified" | "parallel";  // solo doesn't gossip
  originator_pubkey: string;   // node that received the original client request
  originator_url: string;      // where to POST the response back
  min_responses: number;       // minimum agreeing nodes for quorum
  expires_at: number;          // reject if past this timestamp
}

export interface ServiceResponsePayload {
  request_id: string;          // correlates to the original request
  responder_pubkey: string;    // node that executed the inference
  output_hash: string;         // H(output) for agreement checking
  output_body_b64?: string;    // base64-encoded output (only for parallel split recombination)
  attestation_id: string;      // the responder's local attestation ID
  timestamp: number;
}

export interface PeerExchangePayload {
  peers: { pubkey: string; url: string; grumpkin_x?: string; grumpkin_y?: string }[];
}

export interface SyncRequestPayload {
  after_round: number;
  limit: number;
}

export interface SyncResponsePayload {
  vertices: any[];
  commits: any[];
  proofs?: any[];
  latest_round: number;
  adaptive_state?: {
    round_interval_ms: number;
    max_events_per_vertex: number;
  };
  snapshot?: {
    anchor_id: string;
    finalized_seq: number;
    snapshot_hash: string;
  };
  // State root checkpoint — peers compare these to detect forks
  checkpoint?: {
    finalized_seq: number;
    finalized_root: string;
    last_committed_round: number;
  };
}

// ─── Constants ────────────────────────────────────────────────────────────────

const MAX_PEERS = 50;
const MAX_FAILURES = 5;          // remove peer after this many consecutive failures
const GOSSIP_TIMEOUT_MS = 2000;
const DEDUP_WINDOW = 1000;       // keep last N nonces for dedup
const PEER_EXCHANGE_INTERVAL = 3; // exchange peers every N sync cycles
const FLOOD_CONCURRENCY = 6;     // max parallel outbound connections per flood
const GOSSIP_SAMPLE_THRESHOLD = 12; // above this peer count, sample instead of flooding all
const GOSSIP_SAMPLE_SIZE = 8;       // number of peers to sample (≥ quorum for Byzantine safety)

/**
 * Build a URL by appending a path to a peer base URL.
 * Handles peer URLs that contain query parameters (e.g. ?shard=node-1)
 * by inserting the path before the query string.
 */
function buildPeerUrl(baseUrl: string, path: string, extraParams?: Record<string, string>): string {
  try {
    const u = new URL(baseUrl);
    // Append path, merging with any existing path
    const existingPath = u.pathname.replace(/\/$/, ""); // strip trailing slash
    u.pathname = existingPath + path;
    if (extraParams) {
      for (const [k, v] of Object.entries(extraParams)) {
        u.searchParams.set(k, v);
      }
    }
    return u.toString();
  } catch {
    // Fallback for malformed URLs
    return `${baseUrl}${path}`;
  }
}

// ─── GossipManager ───────────────────────────────────────────────────────────

export class GossipManager {
  private sql: any;
  private identity: NodeIdentity | null = null;
  private seenNonces: Set<string> = new Set();
  private syncCycleCount: number = 0;

  constructor(sql: any) {
    this.sql = sql;
  }

  setIdentity(identity: NodeIdentity) {
    this.identity = identity;
  }

  // ─── Peer Management ────────────────────────────────────────────────────

  addPeer(pubkey: string, url: string): boolean {
    if (!url || !pubkey) return false;
    if (this.identity && pubkey === this.identity.pubkey) return false; // don't add self

    const existing = [...this.sql.exec("SELECT pubkey FROM gossip_peers WHERE pubkey = ?", pubkey)];
    if (existing.length > 0) {
      this.sql.exec(
        "UPDATE gossip_peers SET url = ?, last_seen = ?, failures = 0 WHERE pubkey = ?",
        url, Date.now(), pubkey,
      );
      return true;
    }

    const count = [...this.sql.exec("SELECT COUNT(*) as cnt FROM gossip_peers")] as any[];
    if ((count[0]?.cnt || 0) >= MAX_PEERS) return false;

    this.sql.exec(
      `INSERT INTO gossip_peers (pubkey, url, last_seen, last_sync_round, failures, added_at)
       VALUES (?, ?, ?, 0, 0, ?)`,
      pubkey, url, Date.now(), Date.now(),
    );
    return true;
  }

  removePeer(pubkey: string) {
    this.sql.exec("DELETE FROM gossip_peers WHERE pubkey = ?", pubkey);
  }

  getPeers(): GossipPeer[] {
    return [...this.sql.exec(
      "SELECT pubkey, url, last_seen, last_sync_round, failures, added_at FROM gossip_peers ORDER BY last_seen DESC",
    )].map((r: any) => ({
      pubkey: r.pubkey,
      url: r.url,
      last_seen: r.last_seen,
      last_sync_round: r.last_sync_round,
      failures: r.failures,
      added_at: r.added_at,
    }));
  }

  getHealthyPeers(): GossipPeer[] {
    return this.getPeers().filter(p => p.failures < MAX_FAILURES);
  }

  getPeerUrl(pubkey: string): string | null {
    const rows = [...this.sql.exec("SELECT url FROM gossip_peers WHERE pubkey = ?", pubkey)] as any[];
    return rows.length > 0 && rows[0].url ? rows[0].url : null;
  }

  private markPeerSuccess(pubkey: string) {
    this.sql.exec(
      "UPDATE gossip_peers SET last_seen = ?, failures = 0 WHERE pubkey = ?",
      Date.now(), pubkey,
    );
  }

  private markPeerFailure(pubkey: string) {
    this.sql.exec(
      "UPDATE gossip_peers SET failures = failures + 1 WHERE pubkey = ?",
      pubkey,
    );
    // Auto-remove after too many failures — but only if we have enough healthy peers
    const rows = [...this.sql.exec("SELECT failures FROM gossip_peers WHERE pubkey = ?", pubkey)] as any[];
    const healthyCount = this.getHealthyPeers().length;
    if (rows.length > 0 && rows[0].failures >= MAX_FAILURES && healthyCount >= 2) {
      this.sql.exec("DELETE FROM gossip_peers WHERE pubkey = ?", pubkey);
    }
  }

  /**
   * Re-probe peers that have been marked as failed.
   * Resets failure counters for peers that respond to /network.
   * Called on startup to recover from DO restarts.
   */
  async reprobeFailedPeers(): Promise<number> {
    const failedPeers = [...this.sql.exec(
      "SELECT pubkey, url FROM gossip_peers WHERE failures >= ? AND url != ''",
      MAX_FAILURES,
    )] as any[];

    let recovered = 0;
    for (const peer of failedPeers) {
      try {
        const networkUrl = peer.url.includes("?")
          ? peer.url.replace("?", "/network?")
          : peer.url.replace(/\/?$/, "/network");
        const res = await fetchWithTimeout(networkUrl, { method: "GET" }, GOSSIP_TIMEOUT_MS);
        if (res.ok) {
          this.sql.exec(
            "UPDATE gossip_peers SET failures = 0, last_seen = ? WHERE pubkey = ?",
            Date.now(), peer.pubkey,
          );
          recovered++;
        }
      } catch {
        // Still dead
      }
    }
    if (recovered > 0) console.log(`Reprobed ${recovered}/${failedPeers.length} failed peers`);
    return recovered;
  }

  // ─── Envelope Construction ──────────────────────────────────────────────

  async createEnvelope(
    type: GossipEnvelope["type"],
    payload: any,
  ): Promise<GossipEnvelope | null> {
    if (!this.identity) return null;

    const nonce = await sha256(`${Date.now()}:${Math.random()}`);
    const timestamp = Date.now();
    const payloadStr = JSON.stringify(payload);
    const sigData = `${type}:${payloadStr}:${timestamp}:${nonce}`;
    const signature = await signData(this.identity, sigData);

    return {
      type,
      sender_pubkey: this.identity.pubkey,
      sender_url: this.identity.url,
      signature,
      payload,
      timestamp,
      nonce,
      grumpkin_x: this.identity.grumpkinPublicKey ? "0x" + this.identity.grumpkinPublicKey.x.toString(16).padStart(64, "0") : undefined,
      grumpkin_y: this.identity.grumpkinPublicKey ? "0x" + this.identity.grumpkinPublicKey.y.toString(16).padStart(64, "0") : undefined,
    };
  }

  async verifyEnvelope(envelope: GossipEnvelope): Promise<boolean> {
    // Check dedup
    if (this.seenNonces.has(envelope.nonce)) return false;

    // Check freshness (reject messages older than 5 minutes)
    if (Date.now() - envelope.timestamp > 300_000) return false;

    // Proactively trim nonce set regardless of validity (prevents invalid-message leak)
    if (this.seenNonces.size >= DEDUP_WINDOW) {
      const iter = this.seenNonces.values();
      const toRemove = this.seenNonces.size - (DEDUP_WINDOW / 2);
      for (let i = 0; i < toRemove; i++) {
        this.seenNonces.delete(iter.next().value!);
      }
    }

    const sigData = `${envelope.type}:${JSON.stringify(envelope.payload)}:${envelope.timestamp}:${envelope.nonce}`;
    const valid = await verifyNodeSignature(envelope.sender_pubkey, envelope.signature, sigData);

    if (valid) {
      this.seenNonces.add(envelope.nonce);
    }

    return valid;
  }

  // ─── Gossip Flooding ────────────────────────────────────────────────────

  /**
   * Flood a message to all healthy peers with bounded concurrency.
   * Limits parallel outbound connections to avoid exhausting CF Workers' connection pool.
   */
  async flood(envelope: GossipEnvelope, excludePubkeys: Set<string> = new Set()): Promise<number> {
    let peers = this.getHealthyPeers().filter(p => !excludePubkeys.has(p.pubkey));

    // Probabilistic sampling: when many peers are available, pick a random subset.
    // Byzantine-safe as long as sample_size ≥ 2f+1 (messages propagate via multi-hop).
    if (peers.length > GOSSIP_SAMPLE_THRESHOLD) {
      // Fisher-Yates partial shuffle to select GOSSIP_SAMPLE_SIZE random peers
      for (let i = peers.length - 1; i > 0 && i >= peers.length - GOSSIP_SAMPLE_SIZE; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [peers[i], peers[j]] = [peers[j], peers[i]];
      }
      peers = peers.slice(peers.length - GOSSIP_SAMPLE_SIZE);
    }

    let delivered = 0;
    const body = compactEnvelope(envelope); // compact wire format (~35% smaller)

    // Process peers in batches of FLOOD_CONCURRENCY
    for (let i = 0; i < peers.length; i += FLOOD_CONCURRENCY) {
      const batch = peers.slice(i, i + FLOOD_CONCURRENCY);
      const results = await Promise.allSettled(batch.map(async (peer) => {
        try {
          const res = await fetchWithTimeout(buildPeerUrl(peer.url, "/gossip/push"), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body,
          }, GOSSIP_TIMEOUT_MS);

          if (res.ok) {
            this.markPeerSuccess(peer.pubkey);
            delivered++;
          } else {
            this.markPeerFailure(peer.pubkey);
          }
        } catch {
          this.markPeerFailure(peer.pubkey);
        }
      }));
    }
    return delivered;
  }

  /**
   * Gossip a new vertex to all peers.
   */
  async gossipVertex(vertex: any, excludePubkeys: Set<string> = new Set()): Promise<number> {
    const envelope = await this.createEnvelope("vertex", vertex);
    if (!envelope) return 0;
    return this.flood(envelope, excludePubkeys);
  }

  /**
   * Gossip a new event to all peers.
   */
  async gossipEvent(event: any): Promise<number> {
    const envelope = await this.createEnvelope("event", event);
    if (!envelope) return 0;
    return this.flood(envelope);
  }

  // ─── Periodic Sync ──────────────────────────────────────────────────────

  /**
   * Pull missing vertices from peers. Called from alarm handler.
   * Returns the number of new vertices received.
   */
  async syncFromPeers(
    currentRound: number,
    activeWindow: number,
    onVertex: (vertex: any) => Promise<void>,
    onProof?: (proof: any) => Promise<void>,
    onAdaptiveState?: (state: { round_interval_ms: number; max_events_per_vertex: number }) => void,
    onDivergence?: (peerPubkey: string, peerUrl: string, local: { seq: number; root: string }, remote: { seq: number; root: string }) => void,
    localCheckpoint?: { finalized_seq: number; finalized_root: string },
  ): Promise<{ synced: number; peersContacted: number }> {
    const peers = this.getHealthyPeers();
    let synced = 0;
    let peersContacted = 0;

    // Per-peer sync helper — uses delta protocol when available
    const syncOnePeer = async (peer: GossipPeer): Promise<{ synced: number; contacted: boolean }> => {
      try {
        const afterRound = Math.max(0, peer.last_sync_round || (currentRound - activeWindow));

        // Try delta sync first: fetch hashes, identify missing, fetch only those bodies
        let data: SyncResponsePayload;
        let peerSynced = 0;
        let usedDelta = false;

        try {
          const hashRes = await fetchWithTimeout(
            buildPeerUrl(peer.url, "/gossip/sync/hashes", { after_round: String(afterRound), limit: "5000" }),
            { method: "GET" },
            GOSSIP_TIMEOUT_MS,
          );
          if (hashRes.ok) {
            const hashData = await hashRes.json() as any;
            // Find hashes we don't have locally
            const localHashes = new Set<string>(
              [...this.sql.exec(
                "SELECT hash FROM dag_vertices WHERE round >= ? LIMIT 10000", afterRound,
              )].map((r: any) => r.hash),
            );
            const missingHashes = (hashData.hashes || [])
              .filter((h: any) => !localHashes.has(h.h))
              .map((h: any) => h.h);

            if (missingHashes.length === 0) {
              // Fully synced — still process checkpoint/adaptive
              data = { vertices: [], commits: [], latest_round: hashData.latest_round, checkpoint: hashData.checkpoint };
              usedDelta = true;
            } else if (missingHashes.length < (hashData.hashes?.length || 0) * 0.5) {
              // Delta is worthwhile (missing < 50% of total)
              const bodyRes = await fetchWithTimeout(
                buildPeerUrl(peer.url, "/gossip/sync/bodies"),
                { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ hashes: missingHashes.slice(0, 500) }) },
                GOSSIP_TIMEOUT_MS,
              );
              if (bodyRes.ok) {
                const bodyData = await bodyRes.json() as any;
                data = { vertices: bodyData.vertices || [], commits: [], latest_round: hashData.latest_round, checkpoint: hashData.checkpoint };
                usedDelta = true;
              }
            }
          }
        } catch { /* delta not supported, fall through to full sync */ }

        // Fallback: full sync
        if (!usedDelta) {
          const res = await fetchWithTimeout(
            buildPeerUrl(peer.url, "/gossip/sync", { after_round: String(afterRound), limit: "2000" }),
            { method: "GET" },
            GOSSIP_TIMEOUT_MS,
          );
          if (!res.ok) {
            this.markPeerFailure(peer.pubkey);
            return { synced: 0, contacted: false };
          }
          data = await res.json() as SyncResponsePayload;
        }

        for (const v of data!.vertices || []) {
          try {
            await onVertex(v);
            peerSynced++;
          } catch {
            // skip invalid vertices
          }
        }

        // Process proofs from sync response
        if (onProof && data.proofs) {
          for (const p of data.proofs) {
            try { await onProof(p); } catch {}
          }
        }

        // Bootstrap adaptive params from peer (cold-start convergence)
        if (onAdaptiveState && data.adaptive_state) {
          onAdaptiveState(data.adaptive_state);
        }

        // Divergence detection: compare finalized state roots at the same seq
        if (onDivergence && localCheckpoint && data.checkpoint) {
          const remote = data.checkpoint;
          // Only compare when both nodes have committed to at least the same seq
          // (comparing at different progress levels is meaningless)
          if (remote.finalized_seq > 0 && localCheckpoint.finalized_seq > 0 &&
              remote.finalized_seq === localCheckpoint.finalized_seq &&
              remote.finalized_root !== localCheckpoint.finalized_root) {
            onDivergence(
              peer.pubkey, peer.url,
              { seq: localCheckpoint.finalized_seq, root: localCheckpoint.finalized_root },
              { seq: remote.finalized_seq, root: remote.finalized_root },
            );
          }
        }

        // Update sync cursor
        const now = Date.now();
        this.sql.exec(
          "UPDATE gossip_peers SET last_sync_round = ?, last_seen = ?, failures = 0 WHERE pubkey = ?",
          data.latest_round || currentRound, now, peer.pubkey,
        );
        // Also refresh active_nodes so dashboard shows peer as recently seen
        this.sql.exec(
          "UPDATE active_nodes SET last_seen = ? WHERE pubkey = ?",
          now, peer.pubkey,
        );

        return { synced: peerSynced, contacted: true };
      } catch {
        this.markPeerFailure(peer.pubkey);
        return { synced: 0, contacted: false };
      }
    };

    // Process peers in batches of FLOOD_CONCURRENCY
    for (let i = 0; i < peers.length; i += FLOOD_CONCURRENCY) {
      const batch = peers.slice(i, i + FLOOD_CONCURRENCY);
      const results = await Promise.allSettled(batch.map(syncOnePeer));
      for (const result of results) {
        if (result.status === "fulfilled") {
          synced += result.value.synced;
          if (result.value.contacted) peersContacted++;
        }
      }
    }

    // Peer exchange every N cycles
    this.syncCycleCount++;
    if (this.syncCycleCount % PEER_EXCHANGE_INTERVAL === 0) {
      await this.exchangePeers();
    }

    return { synced, peersContacted };
  }

  /**
   * Exchange peer lists with known peers to discover new nodes.
   */
  async exchangePeers(): Promise<number> {
    // Include grumpkin keys from gossip_peers table
    const healthyPeers = this.getHealthyPeers();
    const myPeers = healthyPeers.map(p => {
      const grumpkinRows = [...this.sql.exec(
        "SELECT grumpkin_x, grumpkin_y FROM gossip_peers WHERE pubkey = ?", p.pubkey,
      )] as any[];
      return {
        pubkey: p.pubkey,
        url: p.url,
        grumpkin_x: grumpkinRows[0]?.grumpkin_x || undefined,
        grumpkin_y: grumpkinRows[0]?.grumpkin_y || undefined,
      };
    });
    const envelope = await this.createEnvelope("peer_exchange", { peers: myPeers } as PeerExchangePayload);
    if (!envelope) return 0;

    const peers = this.getHealthyPeers();
    let discovered = 0;

    for (const peer of peers.slice(0, 5)) { // limit to 5 peers per exchange
      try {
        const res = await fetchWithTimeout(buildPeerUrl(peer.url, "/gossip/peers"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: compactEnvelope(envelope),
        }, GOSSIP_TIMEOUT_MS);

        if (!res.ok) continue;

        const data = await res.json() as any;
        const remotePeers = data.peers || [];
        for (const rp of remotePeers) {
          if (rp.pubkey && rp.url && this.addPeer(rp.pubkey, rp.url)) {
            discovered++;
          }
        }
        this.markPeerSuccess(peer.pubkey);
      } catch {
        this.markPeerFailure(peer.pubkey);
      }
    }

    return discovered;
  }

  // ─── Seed Nodes ─────────────────────────────────────────────────────────

  /**
   * Bootstrap from seed node URLs. Fetches their identity and peer lists.
   */
  async bootstrapFromSeeds(seedUrls: string[]): Promise<number> {
    let added = 0;

    for (const seedUrl of seedUrls) {
      try {
        // Fetch node info to get pubkey (use /dag/status which returns JSON with node_pubkey)
        const statusUrl = buildPeerUrl(seedUrl, "/dag/status");
        const res = await fetchWithTimeout(statusUrl, { method: "GET" }, GOSSIP_TIMEOUT_MS);
        if (!res.ok) continue;

        const info = await res.json() as any;
        if (info.node_pubkey) {
          if (this.addPeer(info.node_pubkey, seedUrl)) added++;
        }

        // Also try to get their peer list
        const peersUrl = buildPeerUrl(seedUrl, "/gossip/peers");
        const peersRes = await fetchWithTimeout(peersUrl, { method: "GET" }, GOSSIP_TIMEOUT_MS);
        if (peersRes.ok) {
          const data = await peersRes.json() as any;
          for (const p of data.peers || []) {
            if (p.pubkey && p.url && this.addPeer(p.pubkey, p.url)) added++;
          }
        }
      } catch {
        // seed unreachable
      }
    }

    return added;
  }
}

// ─── Compact Wire Format ─────────────────────────────────────────────────────
// Reduces gossip payload size ~35-40% by using short keys and omitting nulls.
// Compatible with standard JSON — no external dependency needed.

const COMPACT_KEYS: Record<string, string> = {
  type: "t", sender_pubkey: "sp", sender_url: "su", signature: "s",
  payload: "p", timestamp: "ts", nonce: "n", grumpkin_x: "gx", grumpkin_y: "gy",
};
const EXPAND_KEYS: Record<string, string> = Object.fromEntries(
  Object.entries(COMPACT_KEYS).map(([k, v]) => [v, k]),
);

export function compactEnvelope(env: GossipEnvelope): string {
  const obj: any = {};
  for (const [full, short] of Object.entries(COMPACT_KEYS)) {
    const val = (env as any)[full];
    if (val !== undefined && val !== null) obj[short] = val;
  }
  return JSON.stringify(obj);
}

export function expandEnvelope(data: string | any): GossipEnvelope {
  const obj = typeof data === "string" ? JSON.parse(data) : data;
  // If already has full keys, return as-is
  if (obj.type && obj.sender_pubkey) return obj as GossipEnvelope;
  // Expand compact keys
  const expanded: any = {};
  for (const [short, val] of Object.entries(obj)) {
    const full = EXPAND_KEYS[short];
    if (full) expanded[full] = val;
    else expanded[short] = val; // pass through unknown keys
  }
  return expanded as GossipEnvelope;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function fetchWithTimeout(
  url: string,
  init: RequestInit = {},
  timeoutMs: number = GOSSIP_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}
