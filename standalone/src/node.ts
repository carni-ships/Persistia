// ─── Standalone Persistia Validator Node ─────────────────────────────────────────
// Runs on any VM (AWS t2.micro, Azure B1S, bare metal) without Cloudflare.
// Uses better-sqlite3 for state, plain HTTP for gossip, setInterval for consensus.
//
// What it does:
//   - Participates in BFT consensus (creates vertices, gossips, commits rounds)
//   - Earns reputation from honest participation
//   - Routes AI requests to external providers (no local Workers AI)
//   - Serves as a marketplace gateway for provider registration
//
// What it doesn't do (yet):
//   - Run Workers AI inference (CF-specific binding)
//   - Generate ZK proofs (needs 4GB+ RAM)
//   - Execute WASM smart contracts (needs CF WASM binding)

import { createDatabase, type SqlCompat } from "./sql-compat.ts";

// Use namespace imports for CJS interop (root package.json has no "type": "module")
import * as _consensus from "../../src/consensus.ts";
const { sha256, computeVertexHash, computeEventHash, getQuorumSize, isQuorumMet, selectLeader, ACTIVE_WINDOW, topologicalSort, checkCommit } = _consensus;

import * as _nodeId from "../../src/node-identity.ts";
const { loadOrCreateNodeIdentity, signVertex, verifyVertexSignature, verifyNodeSignature, signDataSchnorr } = _nodeId;
type NodeIdentity = _nodeId.NodeIdentity;

import * as _gossip from "../../src/gossip.ts";
const { GossipManager } = _gossip;
type GossipEnvelope = _gossip.GossipEnvelope;
type SyncResponsePayload = _gossip.SyncResponsePayload;

import * as _valReg from "../../src/validator-registry.ts";
const { ValidatorRegistry, verifyPoW } = _valReg;

import * as _wallet from "../../src/wallet.ts";
const { AccountManager, pubkeyB64ToAddress, validateAddress } = _wallet;

import * as _attestations from "../../src/service-attestations.ts";
const { ServiceAttestationManager } = _attestations;

import * as _feeSplitter from "../../src/fee-splitter.ts";
const { FeeSplitter, PERSIST_FEE_SPLIT } = _feeSplitter;
type FeeSplitConfig = _feeSplitter.FeeSplitConfig;

import * as _providerReg from "../../src/provider-registry.ts";
const { ProviderRegistry } = _providerReg;

import * as _providerProxy from "../../src/provider-proxy.ts";
const { ProviderProxy } = _providerProxy;

import * as _settlement from "../../src/settlement.ts";
const { SettlementBatcher } = _settlement;

import * as _federation from "../../src/service-federation.ts";
const { ServiceFederation } = _federation;

import * as _adaptive from "../../src/adaptive-params.ts";
const { computeAdaptiveInterval, SMOOTHING_WINDOW } = _adaptive;

// ─── Configuration ──────────────────────────────────────────────────────────

export interface NodeConfig {
  dataDir: string;            // path to SQLite database
  port: number;               // HTTP server port
  nodeUrl: string;            // public URL of this node (e.g. http://1.2.3.4:3000)
  seedNodes: string[];        // URLs of existing nodes to bootstrap from
  roundIntervalMs?: number;   // consensus round interval (default 60s)
}

// ─── Schema ─────────────────────────────────────────────────────────────────

function initSchema(sql: SqlCompat): void {
  // Check if already initialized
  const existing = sql.exec("SELECT name FROM sqlite_master WHERE type='table' AND name='events' LIMIT 1");
  if (existing.length > 0) return;

  sql.exec(`
    CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, payload TEXT NOT NULL, pubkey TEXT NOT NULL, signature TEXT NOT NULL, timestamp INTEGER NOT NULL, hash TEXT NOT NULL);
    CREATE TABLE blocks (x INTEGER NOT NULL, z INTEGER NOT NULL, block_type INTEGER NOT NULL, placed_by TEXT NOT NULL, PRIMARY KEY (x, z));
    CREATE TABLE ownership (asset_id TEXT PRIMARY KEY, owner_pubkey TEXT NOT NULL, metadata TEXT DEFAULT '', created_at INTEGER NOT NULL);
    CREATE TABLE inventory (pubkey TEXT NOT NULL, item TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (pubkey, item));
    CREATE TABLE roots (id INTEGER PRIMARY KEY AUTOINCREMENT, root TEXT NOT NULL, seq INTEGER NOT NULL, timestamp INTEGER NOT NULL);
    CREATE INDEX idx_events_seq ON events(seq);
    CREATE INDEX idx_events_hash ON events(hash);
    CREATE TABLE node_identity (pubkey TEXT PRIMARY KEY, privkey_encrypted TEXT NOT NULL, node_url TEXT NOT NULL, created_at INTEGER NOT NULL)
  `);

  sql.exec(`
    CREATE TABLE dag_vertices (hash TEXT PRIMARY KEY, author TEXT NOT NULL, round INTEGER NOT NULL, events_json TEXT NOT NULL, refs_json TEXT NOT NULL, signature TEXT NOT NULL, received_at INTEGER NOT NULL, timestamp INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX idx_vertices_round_author ON dag_vertices(round, author);
    CREATE INDEX idx_vertices_round_hash ON dag_vertices(round, hash);
    CREATE INDEX idx_vertices_author_round ON dag_vertices(author, round);
    CREATE TABLE dag_commits (round INTEGER PRIMARY KEY, anchor_hash TEXT NOT NULL, committed_at INTEGER NOT NULL, signatures_json TEXT NOT NULL DEFAULT '[]');
    CREATE TABLE consensus_events (consensus_seq INTEGER PRIMARY KEY AUTOINCREMENT, event_hash TEXT NOT NULL UNIQUE, vertex_hash TEXT NOT NULL, round INTEGER NOT NULL, finalized_at INTEGER NOT NULL);
    CREATE TABLE pending_events (hash TEXT PRIMARY KEY, type TEXT NOT NULL, payload TEXT NOT NULL, pubkey TEXT NOT NULL, signature TEXT NOT NULL, timestamp INTEGER NOT NULL);
    CREATE TABLE active_nodes (pubkey TEXT PRIMARY KEY, url TEXT NOT NULL, last_vertex_round INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL, is_self INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE consensus_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)
  `);

  sql.exec(`
    CREATE TABLE contracts (address TEXT PRIMARY KEY, deployer TEXT NOT NULL, wasm_hash TEXT NOT NULL, wasm_bytes BLOB NOT NULL, created_at INTEGER NOT NULL, deploy_seq INTEGER NOT NULL);
    CREATE TABLE contract_state (contract_address TEXT NOT NULL, key BLOB NOT NULL, value BLOB NOT NULL, PRIMARY KEY (contract_address, key));
    CREATE TABLE oracle_requests (id TEXT PRIMARY KEY, contract TEXT NOT NULL, callback_method TEXT NOT NULL, url TEXT NOT NULL, json_path TEXT, aggregation TEXT NOT NULL DEFAULT 'identical', status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, result_value TEXT, result_sources INTEGER DEFAULT 0, delivered_at INTEGER);
    CREATE INDEX idx_oracle_status ON oracle_requests(status);
    CREATE TABLE oracle_responses (request_id TEXT NOT NULL, node_pubkey TEXT NOT NULL, value TEXT NOT NULL, fetched_at INTEGER NOT NULL, PRIMARY KEY (request_id, node_pubkey));
    CREATE TABLE triggers (id TEXT PRIMARY KEY, contract TEXT NOT NULL, method TEXT NOT NULL, args_b64 TEXT NOT NULL DEFAULT '', interval_ms INTEGER NOT NULL, next_fire INTEGER NOT NULL, creator TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, last_fired INTEGER NOT NULL DEFAULT 0, fire_count INTEGER NOT NULL DEFAULT 0, max_fires INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX idx_triggers_next ON triggers(enabled, next_fire)
  `);

  sql.exec(`
    CREATE TABLE xshard_outbox (id TEXT PRIMARY KEY, target_shard TEXT NOT NULL, message_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, delivered_at INTEGER);
    CREATE TABLE xshard_inbox (id TEXT PRIMARY KEY, source_shard TEXT NOT NULL, message_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', received_at INTEGER NOT NULL, processed_at INTEGER);
    CREATE TABLE zk_proofs (block_number INTEGER PRIMARY KEY, proof_hex TEXT NOT NULL, state_root TEXT NOT NULL, proven_blocks INTEGER NOT NULL DEFAULT 1, proof_type TEXT NOT NULL DEFAULT 'compressed', submitted_at INTEGER NOT NULL, verified INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE validators (pubkey TEXT PRIMARY KEY, url TEXT NOT NULL DEFAULT '', reputation INTEGER NOT NULL DEFAULT 100, pow_nonce TEXT NOT NULL DEFAULT '', pow_hash TEXT NOT NULL DEFAULT '', registered_at INTEGER NOT NULL, last_active_round INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'active', equivocation_count INTEGER NOT NULL DEFAULT 0, total_vertices INTEGER NOT NULL DEFAULT 0, total_commits INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX idx_validators_status ON validators(status);
    CREATE TABLE equivocation_evidence (id TEXT PRIMARY KEY, validator_pubkey TEXT NOT NULL, round INTEGER NOT NULL, vertex_hash_1 TEXT NOT NULL, vertex_hash_2 TEXT NOT NULL, detected_at INTEGER NOT NULL, reported_by TEXT NOT NULL);
    CREATE INDEX idx_equivocation_validator ON equivocation_evidence(validator_pubkey)
  `);

  sql.exec(`
    CREATE TABLE governance_votes (id TEXT PRIMARY KEY, action TEXT NOT NULL, target TEXT NOT NULL, voter_pubkey TEXT NOT NULL, voter_reputation INTEGER NOT NULL, created_at INTEGER NOT NULL);
    CREATE INDEX idx_governance_action ON governance_votes(action, target);
    CREATE TABLE rate_limit_log (pubkey TEXT NOT NULL, timestamp INTEGER NOT NULL);
    CREATE INDEX idx_rate_limit ON rate_limit_log(pubkey, timestamp);
    CREATE TABLE gossip_peers (pubkey TEXT PRIMARY KEY, url TEXT NOT NULL, last_seen INTEGER NOT NULL, last_sync_round INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0, added_at INTEGER NOT NULL);
    CREATE TABLE anchors (id TEXT PRIMARY KEY, bundle_json TEXT NOT NULL, arweave_tx TEXT, celestia_height INTEGER, celestia_commitment TEXT, status TEXT NOT NULL DEFAULT 'pending', finalized_seq INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, confirmed_at INTEGER);
    CREATE INDEX idx_anchors_status ON anchors(status);
    CREATE INDEX idx_anchors_seq ON anchors(finalized_seq);
    CREATE TABLE accounts (address TEXT PRIMARY KEY, pubkey TEXT NOT NULL UNIQUE, key_type TEXT NOT NULL DEFAULT 'ed25519', nonce INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
    CREATE INDEX idx_accounts_pubkey ON accounts(pubkey);
    CREATE TABLE token_balances (address TEXT NOT NULL, denom TEXT NOT NULL, amount TEXT NOT NULL DEFAULT '0', PRIMARY KEY (address, denom))
  `);

  sql.exec(`
    CREATE TABLE block_headers (block_number INTEGER PRIMARY KEY, state_root TEXT NOT NULL, prev_header_hash TEXT NOT NULL, validator_set_hash TEXT NOT NULL, timestamp INTEGER NOT NULL, tx_count INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE notes (id TEXT PRIMARY KEY, creator TEXT NOT NULL, recipient TEXT, asset_type TEXT NOT NULL, amount TEXT NOT NULL, script TEXT NOT NULL DEFAULT '', shard TEXT NOT NULL, state_root TEXT NOT NULL, created_round INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
    CREATE INDEX idx_notes_recipient ON notes(recipient);
    CREATE INDEX idx_notes_shard ON notes(shard);
    CREATE TABLE nullifiers (nullifier TEXT PRIMARY KEY, note_id TEXT NOT NULL, consumed_by TEXT NOT NULL, consumed_at INTEGER NOT NULL);
    CREATE TABLE covenants (id TEXT PRIMARY KEY, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, current_state TEXT NOT NULL, allowed_transitions TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
    CREATE INDEX idx_covenants_entity ON covenants(entity_type, entity_id);
    CREATE TABLE private_state (contract_address TEXT NOT NULL, key_hash TEXT NOT NULL, commitment TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (contract_address, key_hash))
  `);
}

// ─── Standalone Node ────────────────────────────────────────────────────────

export class StandaloneNode {
  config: NodeConfig;
  sql: SqlCompat;
  db: any;

  // Managers
  nodeIdentity!: NodeIdentity;
  gossipManager!: GossipManager;
  validatorRegistry!: ValidatorRegistry;
  accountManager!: AccountManager;
  feeSplitter!: FeeSplitter;
  attestationMgr!: ServiceAttestationManager;
  providerRegistry!: ProviderRegistry;
  providerProxy!: ProviderProxy;
  settlementBatcher!: SettlementBatcher;
  serviceFederation!: ServiceFederation;

  // Consensus state
  currentRound: number = 0;
  finalizedSeq: number = 0;
  finalizedRoot: string = "";
  lastCommittedRound: number = -2;

  private alarmInterval: ReturnType<typeof setInterval> | null = null;
  private _initialized = false;

  constructor(config: NodeConfig) {
    this.config = config;
    const { db, sql } = createDatabase(`${config.dataDir}/persistia.db`);
    this.db = db;
    this.sql = sql;
  }

  async init(): Promise<void> {
    if (this._initialized) return;

    console.log("Initializing standalone Persistia node...");

    // 1. Create schema
    initSchema(this.sql);

    // 2. Init additional tables from modules
    ServiceAttestationManager.initTables(this.sql);
    FeeSplitter.initTables(this.sql);
    AccountManager.initBurnTable(this.sql);
    AccountManager.initHoldsTable(this.sql);
    ProviderRegistry.initTables(this.sql);

    // 3. Initialize managers
    this.gossipManager = new GossipManager(this.sql);
    this.validatorRegistry = new ValidatorRegistry(this.sql);
    this.accountManager = new AccountManager(this.sql);

    const feeSplitConfig: FeeSplitConfig = {
      ...PERSIST_FEE_SPLIT,
      treasuryAddress: "persistia1treasury",
    };
    this.feeSplitter = new FeeSplitter(this.sql, this.accountManager, this.validatorRegistry, feeSplitConfig);

    this.providerRegistry = new ProviderRegistry(this.sql, this.accountManager);
    this.settlementBatcher = new SettlementBatcher(this.accountManager, this.providerRegistry);

    // 4. Node identity (creates or loads Ed25519 keypair)
    this.nodeIdentity = await loadOrCreateNodeIdentity(this.sql, this.config.nodeUrl);
    this.gossipManager.setIdentity(this.nodeIdentity);
    console.log(`Node pubkey: ${this.nodeIdentity.pubkey}`);
    console.log(`Node URL: ${this.config.nodeUrl}`);

    // 5. Attestation manager
    this.attestationMgr = new ServiceAttestationManager(this.sql, this.nodeIdentity);
    await this.attestationMgr.init();

    // 6. Provider proxy (no local Workers AI — external providers only)
    this.providerProxy = new ProviderProxy(this.providerRegistry, this.settlementBatcher, this.attestationMgr);

    // 7. Service federation
    this.serviceFederation = new ServiceFederation(
      this.gossipManager, this.validatorRegistry,
      this.nodeIdentity.pubkey, this.config.nodeUrl,
    );

    // 8. Register self in active_nodes
    this.sql.exec(
      `INSERT INTO active_nodes (pubkey, url, last_vertex_round, last_seen, is_self)
       VALUES (?, ?, 0, ?, 1)
       ON CONFLICT(pubkey) DO UPDATE SET url = ?, last_seen = ?, is_self = 1`,
      this.nodeIdentity.pubkey, this.config.nodeUrl, Date.now(),
      this.config.nodeUrl, Date.now(),
    );

    // 9. Load consensus state
    this.currentRound = this.getKV("current_round", 0);
    this.finalizedSeq = this.getKV("finalized_seq", 0);
    this.finalizedRoot = this.getKVStr("finalized_root", "");
    this.lastCommittedRound = this.getKV("last_committed_round", -2);

    // 10. Bootstrap from seed nodes
    if (this.config.seedNodes.length > 0) {
      console.log(`Bootstrapping from ${this.config.seedNodes.length} seed node(s)...`);
      const added = await this.gossipManager.bootstrapFromSeeds(this.config.seedNodes);
      console.log(`Discovered ${added} peer(s)`);

      // Also register seed peers in active_nodes
      for (const peer of this.gossipManager.getPeers()) {
        if (peer.pubkey && peer.url) {
          this.sql.exec(
            `INSERT INTO active_nodes (pubkey, url, last_vertex_round, last_seen, is_self)
             VALUES (?, ?, 0, ?, 0)
             ON CONFLICT(pubkey) DO UPDATE SET url = ?, last_seen = ?`,
            peer.pubkey, peer.url, Date.now(), peer.url, Date.now(),
          );
        }
      }

      // Pull initial state from peers
      await this.gossipSync();
    }

    this._initialized = true;
    console.log(`Standalone node initialized at round ${this.currentRound}`);
  }

  // ─── Consensus Loop ───────────────────────────────────────────────────

  startConsensus(): void {
    const intervalMs = this.config.roundIntervalMs || 60_000;
    console.log(`Starting consensus loop (${intervalMs}ms interval)`);

    this.alarmInterval = setInterval(async () => {
      try {
        await this.consensusTick();
      } catch (e: any) {
        console.error("Consensus tick error:", e.message);
      }
    }, intervalMs);

    // Also run one tick immediately
    this.consensusTick().catch(e => console.error("Initial tick error:", e.message));
  }

  stopConsensus(): void {
    if (this.alarmInterval) {
      clearInterval(this.alarmInterval);
      this.alarmInterval = null;
    }
  }

  private async consensusTick(): Promise<void> {
    // 1. Sync from peers
    await this.gossipSync();

    // 2. Refresh self last_seen
    this.sql.exec(
      "UPDATE active_nodes SET last_seen = ? WHERE pubkey = ? AND is_self = 1",
      Date.now(), this.nodeIdentity.pubkey,
    );

    // 3. Create vertex for current round
    const existing = this.sql.exec(
      "SELECT hash FROM dag_vertices WHERE author = ? AND round = ?",
      this.nodeIdentity.pubkey, this.currentRound,
    );

    if (existing.length === 0) {
      await this.createAndBroadcastVertex();
    } else {
      // Already created — advance round
      this.currentRound++;
      this.setKV("current_round", this.currentRound);
      await this.createAndBroadcastVertex();
    }

    // 4. Try to commit rounds
    await this.tryCommitRounds(10);

    // 5. Housekeeping
    this.validatorRegistry.pruneRateLimitLog();
    if (this.settlementBatcher.getPendingCount() > 0) {
      const result = this.settlementBatcher.flush();
      if (result.entries_settled > 0) {
        console.log(`Settlement: ${result.entries_settled} entries, ${result.total_amount} PERSIST`);
      }
    }
    this.accountManager.cleanupExpiredHolds();

    // Resolve downtime reports
    for (const provider of this.providerRegistry.getAllActive()) {
      if (provider.down_reported_at) {
        this.providerRegistry.resolveDownReport(provider.provider_id);
      }
    }
  }

  // ─── Gossip Sync ──────────────────────────────────────────────────────

  private async gossipSync(): Promise<void> {
    try {
      const result = await this.gossipManager.syncFromPeers(
        this.currentRound,
        ACTIVE_WINDOW,
        async (vertex) => {
          await this.receiveVertex(vertex);
        },
      );
      if (result.synced > 0) {
        console.log(`Synced ${result.synced} vertices from ${result.peersContacted} peer(s)`);
      }
    } catch (e: any) {
      // Gossip failures are non-fatal
    }
  }

  // ─── Vertex Creation ──────────────────────────────────────────────────

  private async createAndBroadcastVertex(): Promise<void> {
    // Gather pending events
    const pendingRows = this.sql.exec(
      "SELECT * FROM pending_events ORDER BY timestamp ASC LIMIT 25",
    );

    const events = pendingRows.map((r: any) => ({
      type: r.type,
      payload: r.payload,
      pubkey: r.pubkey,
      signature: r.signature,
      timestamp: r.timestamp,
      hash: r.hash,
    }));

    // Get references to previous round vertices
    const prevRound = Math.max(0, this.currentRound - 1);
    const refRows = this.sql.exec(
      "SELECT hash FROM dag_vertices WHERE round = ? LIMIT 10",
      prevRound,
    );
    const refs = refRows.map((r: any) => r.hash);

    // Build vertex (event_hashes required by computeVertexHash and signVertex)
    const eventHashes = events.map(e => e.hash).filter(Boolean);
    const vertex: any = {
      author: this.nodeIdentity.pubkey,
      round: this.currentRound,
      event_hashes: eventHashes,
      events,
      refs,
      timestamp: Date.now(),
    };

    vertex.hash = await computeVertexHash(vertex);
    vertex.signature = await signVertex(this.nodeIdentity, vertex);

    // Store locally
    this.sql.exec(
      `INSERT OR IGNORE INTO dag_vertices (hash, author, round, events_json, refs_json, signature, received_at, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      vertex.hash, vertex.author, vertex.round,
      JSON.stringify(events), JSON.stringify(refs),
      vertex.signature, Date.now(), vertex.timestamp,
    );

    // Clear pending events that were included
    for (const evt of events) {
      this.sql.exec("DELETE FROM pending_events WHERE hash = ?", evt.hash);
    }

    // Gossip to peers
    const delivered = await this.gossipManager.gossipVertex(vertex);
    if (delivered > 0) {
      console.log(`Round ${this.currentRound}: vertex ${vertex.hash.slice(0, 12)} (${events.length} events) → ${delivered} peers`);
    }
  }

  // ─── Vertex Reception ─────────────────────────────────────────────────

  async receiveVertex(vertex: any): Promise<{ ok: boolean; error?: string }> {
    if (!vertex.hash || !vertex.author || vertex.round === undefined) {
      return { ok: false, error: "Invalid vertex" };
    }

    // Check duplicate
    const exists = this.sql.exec("SELECT hash FROM dag_vertices WHERE hash = ?", vertex.hash);
    if (exists.length > 0) return { ok: true };

    // Store
    const events = vertex.events || [];
    const refs = vertex.refs || [];
    this.sql.exec(
      `INSERT OR IGNORE INTO dag_vertices (hash, author, round, events_json, refs_json, signature, received_at, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      vertex.hash, vertex.author, vertex.round,
      JSON.stringify(events), JSON.stringify(refs),
      vertex.signature || "", Date.now(), vertex.timestamp || Date.now(),
    );

    // Update active_nodes
    this.sql.exec(
      `INSERT INTO active_nodes (pubkey, url, last_vertex_round, last_seen, is_self)
       VALUES (?, '', ?, ?, 0)
       ON CONFLICT(pubkey) DO UPDATE SET last_vertex_round = MAX(last_vertex_round, ?), last_seen = ?`,
      vertex.author, vertex.round, Date.now(), vertex.round, Date.now(),
    );

    // Advance our round if we see higher rounds
    if (vertex.round >= this.currentRound) {
      this.currentRound = vertex.round + 1;
      this.setKV("current_round", this.currentRound);
    }

    // Reward the vertex author
    this.validatorRegistry.rewardVertex(vertex.author, vertex.round);

    return { ok: true };
  }

  // ─── Round Commitment ─────────────────────────────────────────────────

  private async tryCommitRounds(maxRounds: number): Promise<void> {
    for (let i = 0; i < maxRounds; i++) {
      const roundToCommit = this.lastCommittedRound + 2; // Bullshark commits every other round
      if (roundToCommit > this.currentRound) break;

      // Get all vertices in this round
      const vertices = this.sql.exec(
        "SELECT hash, author, events_json, signature FROM dag_vertices WHERE round = ?",
        roundToCommit,
      );

      if (vertices.length === 0) break;

      // Simple commit: if we have at least one vertex, commit the round
      const anchorHash = vertices[0].hash;
      const signatures = vertices.map((v: any) => ({
        author: v.author,
        signature: v.signature,
        hash: v.hash,
      }));

      this.sql.exec(
        `INSERT OR IGNORE INTO dag_commits (round, anchor_hash, committed_at, signatures_json)
         VALUES (?, ?, ?, ?)`,
        roundToCommit, anchorHash, Date.now(), JSON.stringify(signatures),
      );

      // Finalize events from committed vertices
      for (const v of vertices) {
        let events: any[];
        try { events = JSON.parse(v.events_json); } catch { events = []; }
        for (const evt of events) {
          if (evt.hash) {
            this.sql.exec(
              `INSERT OR IGNORE INTO consensus_events (event_hash, vertex_hash, round, finalized_at)
               VALUES (?, ?, ?, ?)`,
              evt.hash, v.hash, roundToCommit, Date.now(),
            );
            this.finalizedSeq++;
          }
        }
      }

      this.lastCommittedRound = roundToCommit;
      this.setKV("last_committed_round", this.lastCommittedRound);
      this.setKV("finalized_seq", this.finalizedSeq);
    }
  }

  // ─── Gossip Push Handler ──────────────────────────────────────────────

  async handleGossipPush(envelope: GossipEnvelope): Promise<{ ok: boolean; error?: string }> {
    // Rate limit
    if (envelope.sender_pubkey && !this.validatorRegistry.checkGossipRateLimit(envelope.sender_pubkey)) {
      return { ok: false, error: "Rate limited" };
    }

    const valid = await this.gossipManager.verifyEnvelope(envelope);
    if (!valid) return { ok: false, error: "Invalid or duplicate envelope" };

    // Auto-discover peer
    if (envelope.sender_pubkey && envelope.sender_url) {
      this.gossipManager.addPeer(envelope.sender_pubkey, envelope.sender_url);
    }

    switch (envelope.type) {
      case "vertex": {
        const result = await this.receiveVertex(envelope.payload);
        if (result.ok) {
          const exclude = new Set([envelope.sender_pubkey]);
          this.gossipManager.flood(envelope, exclude).catch(() => {});
        }
        return result;
      }
      case "event": {
        const event = envelope.payload;
        if (event.hash) {
          this.sql.exec(
            `INSERT OR IGNORE INTO pending_events (hash, type, payload, pubkey, signature, timestamp)
             VALUES (?, ?, ?, ?, ?, ?)`,
            event.hash, event.type || "", JSON.stringify(event.payload || {}),
            event.pubkey || "", event.signature || "", event.timestamp || Date.now(),
          );
        }
        return { ok: true };
      }
      case "service_request": {
        // We don't have local Workers AI, so we route to external providers
        const payload = envelope.payload;
        if (this.serviceFederation?.shouldHandleRequest(payload)) {
          this.handleFederatedRequest(payload).catch(() => {});
        }
        return { ok: true };
      }
      case "service_response": {
        if (this.serviceFederation) {
          this.serviceFederation.handleResponse(envelope.payload);
        }
        return { ok: true };
      }
      case "zk_proof": {
        const proof = envelope.payload;
        if (proof.block_number && proof.proof && proof.state_root) {
          this.sql.exec(
            `INSERT OR IGNORE INTO zk_proofs (block_number, proof_hex, state_root, proven_blocks, proof_type, submitted_at, verified)
             VALUES (?, ?, ?, ?, ?, ?, 0)`,
            proof.block_number, proof.proof, proof.state_root,
            proof.proven_blocks || 1, proof.proof_type || "compressed", Date.now(),
          );
          const exclude = new Set([envelope.sender_pubkey]);
          this.gossipManager.flood(envelope, exclude).catch(() => {});
        }
        return { ok: true };
      }
      default:
        return { ok: false, error: "Unknown gossip type" };
    }
  }

  private async handleFederatedRequest(payload: any): Promise<void> {
    if (!payload.input_body_b64) return;

    // Route to external providers via proxy
    const bodyRaw = atob(payload.input_body_b64);
    const proxyResult = await this.providerProxy.routeToProvider({
      serviceType: payload.service,
      model: payload.model,
      requestBody: bodyRaw,
      buyerAddress: "",
    });

    if (!proxyResult) return;

    // Hash the output
    const clone = proxyResult.response.clone();
    const outputBytes = new Uint8Array(await clone.arrayBuffer());
    const outputHex = Array.from(outputBytes).map(b => b.toString(16).padStart(2, "0")).join("");
    const outputHash = await sha256(outputHex);

    // Create attestation
    const preCommit = await this.attestationMgr.preCommit(payload.service, payload.model, bodyRaw);
    const attestation = await this.attestationMgr.attest({
      service: payload.service,
      model: payload.model,
      input_hash: preCommit.input_hash,
      output_bytes: outputBytes,
      pre_commitment: preCommit.pre_commitment,
      nonce: preCommit.nonce,
    });

    await this.serviceFederation.sendResponse({
      request_id: payload.request_id,
      output_hash: outputHash,
      attestation_id: attestation.attestation_id,
    });
  }

  // ─── Gossip Sync Handler ──────────────────────────────────────────────

  getSyncResponse(afterRound: number, limit: number): SyncResponsePayload {
    const vertices = this.sql.exec(
      "SELECT hash, author, round, events_json, refs_json, signature, timestamp FROM dag_vertices WHERE round >= ? ORDER BY round ASC, hash ASC LIMIT ?",
      afterRound, limit,
    ).map((r: any) => ({
      hash: r.hash, author: r.author, round: r.round,
      events: (() => { try { return JSON.parse(r.events_json); } catch { return []; } })(),
      refs: (() => { try { return JSON.parse(r.refs_json); } catch { return []; } })(),
      timestamp: r.timestamp, signature: r.signature,
    }));

    const commits = this.sql.exec(
      "SELECT round, anchor_hash, committed_at FROM dag_commits WHERE round >= ? ORDER BY round ASC",
      afterRound,
    );

    return {
      vertices, commits, latest_round: this.currentRound,
      checkpoint: {
        finalized_seq: this.finalizedSeq,
        finalized_root: this.finalizedRoot,
        last_committed_round: this.lastCommittedRound,
      },
    };
  }

  // ─── KV Helpers ───────────────────────────────────────────────────────

  private getKV(key: string, defaultVal: number): number {
    const rows = this.sql.exec("SELECT value FROM consensus_state WHERE key = ?", key);
    return rows.length > 0 ? parseInt(rows[0].value) || defaultVal : defaultVal;
  }

  private getKVStr(key: string, defaultVal: string): string {
    const rows = this.sql.exec("SELECT value FROM consensus_state WHERE key = ?", key);
    return rows.length > 0 ? rows[0].value : defaultVal;
  }

  private setKV(key: string, value: number | string): void {
    this.sql.exec(
      "INSERT INTO consensus_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?",
      key, String(value), String(value),
    );
  }

  // ─── Status ───────────────────────────────────────────────────────────

  getStatus(): any {
    const activeNodes = this.sql.exec(
      "SELECT COUNT(*) as cnt FROM active_nodes WHERE last_seen > ?",
      Date.now() - 5 * 60_000,
    );
    const peers = this.gossipManager.getHealthyPeers();
    const providerStats = this.providerRegistry.getStats();

    return {
      name: "Persistia Standalone Node",
      version: "0.1.0",
      runtime: "node",
      consensus: true,
      node_pubkey: this.nodeIdentity.pubkey,
      node_url: this.config.nodeUrl,
      current_round: this.currentRound,
      finalized_seq: this.finalizedSeq,
      finalized_root: this.finalizedRoot,
      active_nodes: activeNodes[0]?.cnt || 0,
      gossip_peers: peers.length,
      last_committed_round: this.lastCommittedRound,
      has_workers_ai: false,
      external_providers: providerStats.active_providers,
      marketplace_models: providerStats.total_models,
    };
  }

  // ─── Shutdown ─────────────────────────────────────────────────────────

  shutdown(): void {
    this.stopConsensus();
    this.db.close();
    console.log("Node shut down cleanly");
  }
}
