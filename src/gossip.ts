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
  type: "vertex" | "event" | "peer_exchange" | "sync_request" | "sync_response";
  sender_pubkey: string;
  sender_url: string;
  signature: string;         // signs the payload JSON
  payload: any;
  timestamp: number;
  nonce: string;             // dedup
}

export interface PeerExchangePayload {
  peers: { pubkey: string; url: string }[];
}

export interface SyncRequestPayload {
  after_round: number;
  limit: number;
}

export interface SyncResponsePayload {
  vertices: any[];
  commits: any[];
  latest_round: number;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const MAX_PEERS = 50;
const MAX_FAILURES = 5;          // remove peer after this many consecutive failures
const GOSSIP_TIMEOUT_MS = 5000;
const DEDUP_WINDOW = 1000;       // keep last N nonces for dedup
const PEER_EXCHANGE_INTERVAL = 3; // exchange peers every N sync cycles
const FLOOD_CONCURRENCY = 6;     // max parallel outbound connections per flood

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
    // Auto-remove after too many failures
    const rows = [...this.sql.exec("SELECT failures FROM gossip_peers WHERE pubkey = ?", pubkey)] as any[];
    if (rows.length > 0 && rows[0].failures >= MAX_FAILURES) {
      this.sql.exec("DELETE FROM gossip_peers WHERE pubkey = ?", pubkey);
    }
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
    const peers = this.getHealthyPeers().filter(p => !excludePubkeys.has(p.pubkey));
    let delivered = 0;
    const body = JSON.stringify(envelope); // serialize once

    // Process peers in batches of FLOOD_CONCURRENCY
    for (let i = 0; i < peers.length; i += FLOOD_CONCURRENCY) {
      const batch = peers.slice(i, i + FLOOD_CONCURRENCY);
      const results = await Promise.allSettled(batch.map(async (peer) => {
        try {
          const res = await fetchWithTimeout(`${peer.url}/gossip/push`, {
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
  ): Promise<{ synced: number; peersContacted: number }> {
    const peers = this.getHealthyPeers();
    let synced = 0;
    let peersContacted = 0;

    for (const peer of peers) {
      try {
        const afterRound = Math.max(0, peer.last_sync_round || (currentRound - activeWindow));
        const res = await fetchWithTimeout(
          `${peer.url}/gossip/sync?after_round=${afterRound}&limit=500`,
          { method: "GET" },
          GOSSIP_TIMEOUT_MS,
        );

        if (!res.ok) {
          this.markPeerFailure(peer.pubkey);
          continue;
        }

        const data = await res.json() as SyncResponsePayload;
        peersContacted++;

        for (const v of data.vertices || []) {
          try {
            await onVertex(v);
            synced++;
          } catch {
            // skip invalid vertices
          }
        }

        // Update sync cursor
        this.sql.exec(
          "UPDATE gossip_peers SET last_sync_round = ?, last_seen = ?, failures = 0 WHERE pubkey = ?",
          data.latest_round || currentRound, Date.now(), peer.pubkey,
        );
      } catch {
        this.markPeerFailure(peer.pubkey);
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
    const myPeers = this.getHealthyPeers().map(p => ({ pubkey: p.pubkey, url: p.url }));
    const envelope = await this.createEnvelope("peer_exchange", { peers: myPeers } as PeerExchangePayload);
    if (!envelope) return 0;

    const peers = this.getHealthyPeers();
    let discovered = 0;

    for (const peer of peers.slice(0, 5)) { // limit to 5 peers per exchange
      try {
        const res = await fetchWithTimeout(`${peer.url}/gossip/peers`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(envelope),
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

    for (const url of seedUrls) {
      try {
        // Fetch node info to get pubkey
        const res = await fetchWithTimeout(url, { method: "GET" }, GOSSIP_TIMEOUT_MS);
        if (!res.ok) continue;

        const info = await res.json() as any;
        if (info.node_pubkey) {
          if (this.addPeer(info.node_pubkey, url)) added++;
        }

        // Also try to get their peer list
        const peersRes = await fetchWithTimeout(`${url}/gossip/peers`, { method: "GET" }, GOSSIP_TIMEOUT_MS);
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
