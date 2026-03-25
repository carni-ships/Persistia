// ─── Persistia Durable Object ─────────────────────────────────────────────────
// BFT consensus via DAG (Bullshark-adapted) + signed event ledger.

import type { SignedEvent, StoredEvent, DAGVertex, StoredVertex, ConsensusStatus } from "./types";
import {
  sha256, computeVertexHash, computeEventHash,
  getQuorumSize, isQuorumMet, selectLeader,
  ACTIVE_WINDOW, topologicalSort, checkCommit,
  type VertexNode,
} from "./consensus";
import {
  loadOrCreateNodeIdentity, signVertex, verifyVertexSignature, verifyNodeSignature,
  type NodeIdentity,
} from "./node-identity";
import { ContractExecutor, type OracleRequestEmit, type TriggerRequestEmit } from "./contract-executor";
import {
  aggregate, extractJsonPath, fetchWithTimeout, computeRequestId,
  type OracleRequest, type NodeFetchResult, type AggregationStrategy,
} from "./oracle";
import { TriggerManager, MIN_INTERVAL_MS, MAX_INTERVAL_MS } from "./triggers";
import { computeStateCommitment, generateStateProof, verifyProof, IncrementalStateTree } from "./state-proofs";
import { type CrossShardMessage, type CrossShardReceipt, validateMessage, createCrossShardMessage } from "./cross-shard";
import { GossipManager, type GossipEnvelope, type SyncResponsePayload } from "./gossip";
import { AnchorManager, type AnchorConfig, type AnchorRecord } from "./anchoring";
import { ValidatorRegistry, verifyPoW } from "./validator-registry";
import { AccountManager, pubkeyB64ToAddress, validateAddress } from "./wallet";
import { MPPHandler, type MPPConfig } from "./mpp";

// ─── Configuration ────────────────────────────────────────────────────────────

const CONSENSUS_ENABLED = true;
const ROUND_INTERVAL_MS = 12_000;  // 12s rounds — tuned so single prover keeps up with batch-32
const MIN_NODES_FOR_CONSENSUS = 3;

// ─── Durable Object ──────────────────────────────────────────────────────────

export class PersistiaWorldV4 implements DurableObject {
  state: DurableObjectState;
  env: any;
  sockets: Map<WebSocket, { pubkey?: string; channels: Set<string>; isValidator: boolean; msgCount: number; msgWindowStart: number }> = new Map();

  // Legacy state (backward compat when consensus off)
  currentRoot: string = "";
  latestSeq: number = 0;

  // Consensus state
  nodeIdentity: NodeIdentity | null = null;
  contractExecutor!: ContractExecutor;
  triggerManager!: TriggerManager;
  gossipManager!: GossipManager;
  anchorManager!: AnchorManager;
  validatorRegistry!: ValidatorRegistry;
  accountManager!: AccountManager;
  mppHandler!: MPPHandler;
  shardName: string = "global-world";
  currentRound: number = 0;
  finalizedSeq: number = 0;
  finalizedRoot: string = "";
  lastCommittedRound: number = -2;
  nodeUrl: string = "";

  // ─── Incremental state commitment ──────────────────────────────────
  stateTree: IncrementalStateTree = new IncrementalStateTree();

  // ─── Cached queries (invalidated on round change / node join) ──────
  private _activeCache: {
    round: number;
    count: number;
    pubkeys: string[];
    nodes: { pubkey: string; url: string; last_vertex_round: number; is_self: boolean }[];
  } | null = null;

  private _initialized = false;
  private _nextAlarmTime: number = 0;

  constructor(state: DurableObjectState, env: any) {
    this.state = state;
    this.env = env;
    this.nodeUrl = env.NODE_URL || "";
    this.state.blockConcurrencyWhile(async () => {
      try {
        this.initDB();
        await this.loadState();
        this._initialized = true;
      } catch (e: any) {
        // SQL quota may be exhausted — log but don't crash the DO.
        // We'll retry initialization on each fetch until it succeeds.
        console.error(`Constructor init failed: ${e.message}`);
      }
    });
  }

  /** Lazy init: retries DB setup if constructor failed (e.g. quota was exhausted). */
  private async ensureInitialized() {
    if (this._initialized) return;
    this.initDB();
    await this.loadState();
    this._initialized = true;
  }

  // ─── Schema ──────────────────────────────────────────────────────────────

  private initDB() {
    // Guard: skip DDL if schema already exists (1 row read vs 43).
    const existing = [...this.state.storage.sql.exec(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='events' LIMIT 1"
    )];
    if (existing.length > 0) {
      // Migrations for existing DOs
      this.migrateDB();
      return;
    }

    // First init: create all tables + indexes in small batches to stay within free-tier row limits.
    const sql = this.state.storage.sql;

    // Batch 1: core event + world tables
    sql.exec(`
      CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, payload TEXT NOT NULL, pubkey TEXT NOT NULL, signature TEXT NOT NULL, timestamp INTEGER NOT NULL, hash TEXT NOT NULL);
      CREATE TABLE blocks (x INTEGER NOT NULL, z INTEGER NOT NULL, block_type INTEGER NOT NULL, placed_by TEXT NOT NULL, PRIMARY KEY (x, z));
      CREATE TABLE ownership (asset_id TEXT PRIMARY KEY, owner_pubkey TEXT NOT NULL, metadata TEXT DEFAULT '', created_at INTEGER NOT NULL);
      CREATE TABLE inventory (pubkey TEXT NOT NULL, item TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (pubkey, item));
      CREATE TABLE roots (id INTEGER PRIMARY KEY AUTOINCREMENT, root TEXT NOT NULL, seq INTEGER NOT NULL, timestamp INTEGER NOT NULL);
      CREATE INDEX idx_events_seq ON events(seq);
      CREATE INDEX idx_events_hash ON events(hash);
      CREATE TABLE node_identity (pubkey TEXT PRIMARY KEY, privkey_encrypted TEXT NOT NULL, node_url TEXT NOT NULL, created_at INTEGER NOT NULL);
    `);

    // Batch 2: DAG consensus tables
    sql.exec(`
      CREATE TABLE dag_vertices (hash TEXT PRIMARY KEY, author TEXT NOT NULL, round INTEGER NOT NULL, events_json TEXT NOT NULL, refs_json TEXT NOT NULL, signature TEXT NOT NULL, received_at INTEGER NOT NULL, timestamp INTEGER NOT NULL DEFAULT 0);
      CREATE INDEX idx_vertices_round_author ON dag_vertices(round, author);
      CREATE INDEX idx_vertices_round_hash ON dag_vertices(round, hash);
      CREATE INDEX idx_vertices_author_round ON dag_vertices(author, round);
      CREATE TABLE dag_commits (round INTEGER PRIMARY KEY, anchor_hash TEXT NOT NULL, committed_at INTEGER NOT NULL, signatures_json TEXT NOT NULL DEFAULT '[]');
      CREATE TABLE consensus_events (consensus_seq INTEGER PRIMARY KEY AUTOINCREMENT, event_hash TEXT NOT NULL UNIQUE, vertex_hash TEXT NOT NULL, round INTEGER NOT NULL, finalized_at INTEGER NOT NULL);
      CREATE TABLE pending_events (hash TEXT PRIMARY KEY, type TEXT NOT NULL, payload TEXT NOT NULL, pubkey TEXT NOT NULL, signature TEXT NOT NULL, timestamp INTEGER NOT NULL);
      CREATE TABLE active_nodes (pubkey TEXT PRIMARY KEY, url TEXT NOT NULL, last_vertex_round INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL, is_self INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE consensus_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    `);

    // Batch 3: smart contract + oracle tables
    sql.exec(`
      CREATE TABLE contracts (address TEXT PRIMARY KEY, deployer TEXT NOT NULL, wasm_hash TEXT NOT NULL, wasm_bytes BLOB NOT NULL, created_at INTEGER NOT NULL, deploy_seq INTEGER NOT NULL);
      CREATE TABLE contract_state (contract_address TEXT NOT NULL, key BLOB NOT NULL, value BLOB NOT NULL, PRIMARY KEY (contract_address, key));
      CREATE TABLE oracle_requests (id TEXT PRIMARY KEY, contract TEXT NOT NULL, callback_method TEXT NOT NULL, url TEXT NOT NULL, json_path TEXT, aggregation TEXT NOT NULL DEFAULT 'identical', status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, result_value TEXT, result_sources INTEGER DEFAULT 0, delivered_at INTEGER);
      CREATE INDEX idx_oracle_status ON oracle_requests(status);
      CREATE TABLE oracle_responses (request_id TEXT NOT NULL, node_pubkey TEXT NOT NULL, value TEXT NOT NULL, fetched_at INTEGER NOT NULL, PRIMARY KEY (request_id, node_pubkey));
      CREATE TABLE triggers (id TEXT PRIMARY KEY, contract TEXT NOT NULL, method TEXT NOT NULL, args_b64 TEXT NOT NULL DEFAULT '', interval_ms INTEGER NOT NULL, next_fire INTEGER NOT NULL, creator TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, last_fired INTEGER NOT NULL DEFAULT 0, fire_count INTEGER NOT NULL DEFAULT 0, max_fires INTEGER NOT NULL DEFAULT 0);
      CREATE INDEX idx_triggers_next ON triggers(enabled, next_fire);
    `);

    // Batch 4: cross-shard + ZK + validator tables
    sql.exec(`
      CREATE TABLE xshard_outbox (id TEXT PRIMARY KEY, target_shard TEXT NOT NULL, message_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, delivered_at INTEGER);
      CREATE TABLE xshard_inbox (id TEXT PRIMARY KEY, source_shard TEXT NOT NULL, message_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', received_at INTEGER NOT NULL, processed_at INTEGER);
      CREATE TABLE zk_proofs (block_number INTEGER PRIMARY KEY, proof_hex TEXT NOT NULL, state_root TEXT NOT NULL, proven_blocks INTEGER NOT NULL DEFAULT 1, proof_type TEXT NOT NULL DEFAULT 'compressed', submitted_at INTEGER NOT NULL, verified INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE validators (pubkey TEXT PRIMARY KEY, url TEXT NOT NULL DEFAULT '', reputation INTEGER NOT NULL DEFAULT 100, pow_nonce TEXT NOT NULL DEFAULT '', pow_hash TEXT NOT NULL DEFAULT '', registered_at INTEGER NOT NULL, last_active_round INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'active', equivocation_count INTEGER NOT NULL DEFAULT 0, total_vertices INTEGER NOT NULL DEFAULT 0, total_commits INTEGER NOT NULL DEFAULT 0);
      CREATE INDEX idx_validators_status ON validators(status);
      CREATE TABLE equivocation_evidence (id TEXT PRIMARY KEY, validator_pubkey TEXT NOT NULL, round INTEGER NOT NULL, vertex_hash_1 TEXT NOT NULL, vertex_hash_2 TEXT NOT NULL, detected_at INTEGER NOT NULL, reported_by TEXT NOT NULL);
      CREATE INDEX idx_equivocation_validator ON equivocation_evidence(validator_pubkey);
      CREATE TABLE proof_claims (block_start INTEGER NOT NULL, block_end INTEGER NOT NULL, prover_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'claimed', claimed_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, completed_at INTEGER, proof_hash TEXT, PRIMARY KEY (block_start, block_end));
      CREATE INDEX idx_proof_claims_status ON proof_claims(status);
      CREATE INDEX idx_proof_claims_prover ON proof_claims(prover_id);
    `);

    // Batch 5: governance + rate limiting + gossip + anchors + accounts
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
      CREATE TABLE token_balances (address TEXT NOT NULL, denom TEXT NOT NULL, amount TEXT NOT NULL DEFAULT '0', PRIMARY KEY (address, denom));
    `);

    // Batch 6: light client headers + notes/nullifiers + covenants + private accounts
    sql.exec(`
      CREATE TABLE block_headers (block_number INTEGER PRIMARY KEY, state_root TEXT NOT NULL, prev_header_hash TEXT NOT NULL, validator_set_hash TEXT NOT NULL, timestamp INTEGER NOT NULL, tx_count INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE notes (id TEXT PRIMARY KEY, creator TEXT NOT NULL, recipient TEXT, asset_type TEXT NOT NULL, amount TEXT NOT NULL, script TEXT NOT NULL DEFAULT '', shard TEXT NOT NULL, state_root TEXT NOT NULL, created_round INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
      CREATE INDEX idx_notes_recipient ON notes(recipient);
      CREATE INDEX idx_notes_shard ON notes(shard);
      CREATE TABLE nullifiers (nullifier TEXT PRIMARY KEY, note_id TEXT NOT NULL, consumed_by TEXT NOT NULL, consumed_at INTEGER NOT NULL);
      CREATE TABLE covenants (id TEXT PRIMARY KEY, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, current_state TEXT NOT NULL, allowed_transitions TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
      CREATE INDEX idx_covenants_entity ON covenants(entity_type, entity_id);
      CREATE TABLE private_state (contract_address TEXT NOT NULL, key_hash TEXT NOT NULL, commitment TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (contract_address, key_hash));
    `);
  }

  private migrateDB() {
    const sql = this.state.storage.sql;
    // Migration: add signatures_json to dag_commits if missing
    try {
      const cols = [...sql.exec("PRAGMA table_info(dag_commits)")] as any[];
      if (!cols.some((c: any) => c.name === "signatures_json")) {
        sql.exec("ALTER TABLE dag_commits ADD COLUMN signatures_json TEXT NOT NULL DEFAULT '[]'");
      }
    } catch {}
    // Migration: add proof_claims table if missing
    try {
      const tables = [...sql.exec("SELECT name FROM sqlite_master WHERE type='table' AND name='proof_claims'")] as any[];
      if (tables.length === 0) {
        sql.exec(`
          CREATE TABLE proof_claims (block_start INTEGER NOT NULL, block_end INTEGER NOT NULL, prover_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'claimed', claimed_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, completed_at INTEGER, proof_hash TEXT, PRIMARY KEY (block_start, block_end));
          CREATE INDEX idx_proof_claims_status ON proof_claims(status);
          CREATE INDEX idx_proof_claims_prover ON proof_claims(prover_id);
        `);
      }
    } catch {}
    // Migration: add light client + notes + covenants + private state tables
    const newTables = [
      ["block_headers", `CREATE TABLE block_headers (block_number INTEGER PRIMARY KEY, state_root TEXT NOT NULL, prev_header_hash TEXT NOT NULL, validator_set_hash TEXT NOT NULL, timestamp INTEGER NOT NULL, tx_count INTEGER NOT NULL DEFAULT 0)`],
      ["notes", `CREATE TABLE notes (id TEXT PRIMARY KEY, creator TEXT NOT NULL, recipient TEXT, asset_type TEXT NOT NULL, amount TEXT NOT NULL, script TEXT NOT NULL DEFAULT '', shard TEXT NOT NULL, state_root TEXT NOT NULL, created_round INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL); CREATE INDEX idx_notes_recipient ON notes(recipient); CREATE INDEX idx_notes_shard ON notes(shard)`],
      ["nullifiers", `CREATE TABLE nullifiers (nullifier TEXT PRIMARY KEY, note_id TEXT NOT NULL, consumed_by TEXT NOT NULL, consumed_at INTEGER NOT NULL)`],
      ["covenants", `CREATE TABLE covenants (id TEXT PRIMARY KEY, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, current_state TEXT NOT NULL, allowed_transitions TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL); CREATE INDEX idx_covenants_entity ON covenants(entity_type, entity_id)`],
      ["private_state", `CREATE TABLE private_state (contract_address TEXT NOT NULL, key_hash TEXT NOT NULL, commitment TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (contract_address, key_hash))`],
      ["mpp_challenges", `CREATE TABLE mpp_challenges (challenge_id TEXT PRIMARY KEY, resource TEXT NOT NULL, amount TEXT NOT NULL, denom TEXT NOT NULL, recipient TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)`],
      ["mpp_receipts", `CREATE TABLE mpp_receipts (receipt_id TEXT PRIMARY KEY, challenge_id TEXT NOT NULL, tx_hash TEXT NOT NULL, payer TEXT NOT NULL, amount TEXT NOT NULL, denom TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'paid', created_at INTEGER NOT NULL); CREATE INDEX idx_mpp_receipts_challenge ON mpp_receipts(challenge_id); CREATE INDEX idx_mpp_receipts_payer ON mpp_receipts(payer)`],
    ] as const;
    for (const [name, ddl] of newTables) {
      try {
        const exists = [...sql.exec("SELECT name FROM sqlite_master WHERE type='table' AND name=?", name)] as any[];
        if (exists.length === 0) sql.exec(ddl);
      } catch {}
    }

    // Migration: add proof_bytes and public_values columns to zk_proofs
    try {
      const cols = [...sql.exec("PRAGMA table_info(zk_proofs)")] as any[];
      if (!cols.some((c: any) => c.name === "proof_bytes")) {
        sql.exec("ALTER TABLE zk_proofs ADD COLUMN proof_bytes BLOB");
      }
      if (!cols.some((c: any) => c.name === "public_values")) {
        sql.exec("ALTER TABLE zk_proofs ADD COLUMN public_values TEXT");
      }
      if (!cols.some((c: any) => c.name === "genesis_root")) {
        sql.exec("ALTER TABLE zk_proofs ADD COLUMN genesis_root TEXT");
      }
    } catch {}
  }

  private async loadState() {
    const sql = this.state.storage.sql;

    // Legacy state — use indexed lookups to avoid full table scans on free tier
    const seqRows = [...sql.exec("SELECT seq FROM events ORDER BY seq DESC LIMIT 1")];
    this.latestSeq = seqRows[0]?.seq ?? 0;
    const rootRows = [...sql.exec("SELECT root FROM roots ORDER BY id DESC LIMIT 1")];
    this.currentRoot = rootRows[0]?.root ?? await sha256("");

    // Consensus state
    this.currentRound = parseInt(this.getKV("current_round") || "0");
    this.finalizedSeq = parseInt(this.getKV("finalized_seq") || "0");
    this.finalizedRoot = this.getKV("finalized_root") || await sha256("");
    this.lastCommittedRound = parseInt(this.getKV("last_committed_round") || "-2");

    // Contract executor + trigger manager
    this.contractExecutor = new ContractExecutor(sql);
    this.triggerManager = new TriggerManager(sql);

    // Gossip + anchoring + validator registry
    this.gossipManager = new GossipManager(sql);
    this.validatorRegistry = new ValidatorRegistry(sql, this.env.POW_DIFFICULTY ? parseInt(this.env.POW_DIFFICULTY) : undefined);
    this.accountManager = new AccountManager(sql);

    // MPP (Machine Payment Protocol) handler
    const mppConfig: MPPConfig = {
      realm: this.shardName || "Persistia",
      recipient: this.env.MPP_RECIPIENT || "persistia1default",
      challengeTtlMs: 300_000, // 5 minutes
      routes: this.env.MPP_ROUTES ? JSON.parse(this.env.MPP_ROUTES) : [],
    };
    this.mppHandler = new MPPHandler(sql, mppConfig);

    const anchorConfig: Partial<AnchorConfig> = {};
    if (this.env.BERACHAIN_RPC) {
      anchorConfig.berachain = {
        rpc_url: this.env.BERACHAIN_RPC || "https://rpc.berachain.com",
        private_key: this.env.BERACHAIN_PRIVATE_KEY,
        hyberdb_address: this.env.HYBERDB_ADDRESS || "0x375B45C2c0Be74a79D8a23501fC13dc78eCd6294",
        hyberdb_namespace: this.env.HYBERDB_NAMESPACE,
        chain_id: 80094,
      };
    }
    this.anchorManager = new AnchorManager(sql, anchorConfig);

    // Node identity
    if (CONSENSUS_ENABLED) {
      this.nodeIdentity = await loadOrCreateNodeIdentity(sql, this.nodeUrl);
      this.gossipManager.setIdentity(this.nodeIdentity);

      // Bootstrap from seed nodes if configured
      if (this.env.SEED_NODES) {
        const seeds = (this.env.SEED_NODES as string).split(",").map(s => s.trim()).filter(Boolean);
        if (seeds.length > 0) {
          this.gossipManager.bootstrapFromSeeds(seeds)
            .then(n => {
              if (n > 0) {
                console.log(`Bootstrapped ${n} peers from seeds`);
                // Register seed peers in active_nodes to prevent bootstrap deadlock
                for (const peer of this.gossipManager.getPeers()) {
                  if (peer.pubkey && peer.url) {
                    this.state.storage.sql.exec(
                      `INSERT INTO active_nodes (pubkey, url, last_vertex_round, last_seen, is_self)
                       VALUES (?, ?, 0, ?, 0)
                       ON CONFLICT(pubkey) DO UPDATE SET url = ?, last_seen = ?`,
                      peer.pubkey, peer.url, Date.now(), peer.url, Date.now(),
                    );
                  }
                }
                this.invalidateActiveCache();
              }
            })
            .catch(e => console.warn(`Seed bootstrap failed: ${e.message}`));
        }
      }

      // Re-verify existing gossip peers on startup (handles DO restarts/evictions)
      this.gossipManager.reprobeFailedPeers()
        .catch(e => console.warn(`Peer reprobe failed: ${e.message}`));

      // Register self in active_nodes — use actual last vertex round, not currentRound
      const selfVertexRows = [...sql.exec(
        "SELECT MAX(round) as max_round FROM dag_vertices WHERE author = ?",
        this.nodeIdentity.pubkey,
      )];
      const selfLastVertexRound = (selfVertexRows[0]?.max_round ?? this.currentRound) as number;
      sql.exec(
        `INSERT INTO active_nodes (pubkey, url, last_vertex_round, last_seen, is_self)
         VALUES (?, ?, ?, ?, 1)
         ON CONFLICT(pubkey) DO UPDATE SET url = ?, last_seen = ?, is_self = 1, last_vertex_round = MAX(last_vertex_round, ?)`,
        this.nodeIdentity.pubkey, this.nodeIdentity.url, selfLastVertexRound, Date.now(),
        this.nodeIdentity.url, Date.now(), selfLastVertexRound,
      );
      this.invalidateActiveCache();
    }

    // Always ensure alarm is scheduled on startup
    if (CONSENSUS_ENABLED) {
      this.scheduleAlarm();
    }
  }

  // ─── KV helpers for consensus_state ─────────────────────────────────────

  private getKV(key: string): string | null {
    const rows = [...this.state.storage.sql.exec("SELECT value FROM consensus_state WHERE key = ?", key)];
    return rows.length > 0 ? (rows[0].value as string) : null;
  }

  private setKV(key: string, value: string) {
    this.state.storage.sql.exec(
      "INSERT INTO consensus_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?",
      key, value, value,
    );
  }

  // ─── HTTP Router ─────────────────────────────────────────────────────────

  async fetch(req: Request): Promise<Response> {
    // Retry initialization if constructor failed (e.g. SQL quota was exhausted)
    try {
      await this.ensureInitialized();
    } catch (e: any) {
      return new Response(JSON.stringify({ error: "DO not ready", detail: e.message }), {
        status: 503,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
      });
    }

    const url = new URL(req.url);

    // Pick up shard name from Worker relay header
    const shardHeader = req.headers.get("X-Shard-Name");
    if (shardHeader) this.shardName = shardHeader;

    // WebSocket upgrade
    if (req.headers.get("Upgrade") === "websocket") {
      const pair = new WebSocketPair();
      this.handleWebSocket(pair[1]);
      return new Response(null, { status: 101, webSocket: pair[0] });
    }

    try {
      // DAG consensus endpoints
      if (url.pathname.startsWith("/dag/")) {
        return this.handleDagRoute(req, url);
      }
      if (url.pathname.startsWith("/admin/")) {
        return this.handleAdminRoute(req, url);
      }
      if (url.pathname.startsWith("/contract/")) {
        return this.handleContractRoute(req, url);
      }
      if (url.pathname.startsWith("/proof/")) {
        return this.handleProofRoute(req, url);
      }
      if (url.pathname.startsWith("/xshard/")) {
        return this.handleCrossShardRoute(req, url);
      }
      if (url.pathname.startsWith("/validator/")) {
        return this.handleValidatorRoute(req, url);
      }
      if (url.pathname.startsWith("/gossip/")) {
        return this.handleGossipRoute(req, url);
      }
      if (url.pathname.startsWith("/anchor/")) {
        return this.handleAnchorRoute(req, url);
      }
      if (url.pathname.startsWith("/mpp/")) {
        return this.handleMPPRoute(req, url);
      }

      // MPP middleware: check if route requires payment
      const mppResult = await this.mppHandler.middleware(req);
      if (mppResult.response) return mppResult.response;

      switch (url.pathname) {
        case "/root":
          return this.json({
            root: CONSENSUS_ENABLED ? this.finalizedRoot : this.currentRoot,
            seq: CONSENSUS_ENABLED ? this.finalizedSeq : this.latestSeq,
            timestamp: Date.now(),
          });

        case "/transfer": {
          if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
          const body = await req.json() as SignedEvent;
          body.type = "transfer";
          return this.json(await this.receiveClientEvent(body));
        }

        case "/craft": {
          if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
          const body = await req.json() as SignedEvent;
          body.type = "craft";
          return this.json(await this.receiveClientEvent(body));
        }

        case "/event": {
          if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
          const body = await req.json() as SignedEvent;
          if (!body.type) return this.json({ error: "Missing event type" }, 400);
          return this.json(await this.receiveClientEvent(body));
        }

        case "/seed": {
          if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
          const { pubkey, amount } = await req.json() as any;
          if (!pubkey) return this.json({ error: "Missing pubkey" }, 400);
          // Auto-create wallet account on seed
          const seedAcct = await this.accountManager.getOrCreate(pubkey);
          if (amount && typeof amount === "number") {
            for (const item of ["dirt", "stone", "wood"]) {
              this.addToInventory(pubkey, item, amount);
            }
          } else {
            this.ensureStartingInventory(pubkey);
          }
          return this.json({ ok: true, address: seedAcct.address, inventory: this.getPlayerInventory(pubkey) });
        }

        // ─── Wallet Endpoints ──────────────────────────────────────────────
        case "/wallet/info": {
          const addr = url.searchParams.get("address");
          const pk = url.searchParams.get("pubkey");
          if (!addr && !pk) return this.json({ error: "address or pubkey required" }, 400);
          if (addr) {
            if (!validateAddress(addr)) return this.json({ error: "Invalid address" }, 400);
            const acct = this.accountManager.getByAddress(addr);
            if (!acct) return this.json({ error: "Account not found" }, 404);
            const balances = this.accountManager.getAllBalances(acct.address);
            return this.json({ account: acct, balances: balances.map(b => ({ denom: b.denom, amount: b.amount.toString() })) });
          }
          const acct = await this.accountManager.getOrCreate(pk!);
          const balances = this.accountManager.getAllBalances(acct.address);
          return this.json({ account: acct, balances: balances.map(b => ({ denom: b.denom, amount: b.amount.toString() })) });
        }

        case "/wallet/balance": {
          const addr = url.searchParams.get("address");
          if (!addr) return this.json({ error: "address required" }, 400);
          const balances = this.accountManager.getAllBalances(addr);
          return this.json({ balances: balances.map(b => ({ denom: b.denom, amount: b.amount.toString() })) });
        }

        case "/wallet/address": {
          const pk = url.searchParams.get("pubkey");
          if (!pk) return this.json({ error: "pubkey required" }, 400);
          const address = await pubkeyB64ToAddress(pk);
          return this.json({ address, pubkey: pk });
        }

        case "/wallet/faucet": {
          if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
          const { pubkey: faucetPk, denom, amount } = await req.json() as any;
          if (!faucetPk) return this.json({ error: "pubkey required" }, 400);
          const acct = await this.accountManager.getOrCreate(faucetPk);
          const mintDenom = denom || "PERSIST";
          const mintAmount = BigInt(amount || 1000);
          this.accountManager.mint(acct.address, mintDenom, mintAmount);
          return this.json({ ok: true, address: acct.address, balance: this.accountManager.getBalance(acct.address, mintDenom).toString() });
        }

        case "/sync": {
          const afterSeq = parseInt(url.searchParams.get("after") || "0");
          const limit = Math.min(parseInt(url.searchParams.get("limit") || "1000"), 1000);
          const events = [...this.state.storage.sql.exec(
            "SELECT consensus_seq, event_hash, vertex_hash, round, finalized_at FROM consensus_events WHERE consensus_seq > ? ORDER BY consensus_seq ASC LIMIT ?",
            afterSeq, limit,
          )];
          return this.json({ events, finalizedSeq: this.finalizedSeq, root: this.finalizedRoot });
        }

        case "/state": {
          const blocks = [...this.state.storage.sql.exec("SELECT x, z, block_type FROM blocks")];
          return this.json({
            blocks,
            root: CONSENSUS_ENABLED ? this.finalizedRoot : this.currentRoot,
            seq: CONSENSUS_ENABLED ? this.finalizedSeq : this.latestSeq,
          });
        }

        case "/query": {
          const q = url.searchParams.get("q");
          if (!q) return this.json({ error: "q parameter required (SQL query)" }, 400);
          // Read-only: reject anything that could mutate
          const normalized = q.trim().toUpperCase();
          if (!normalized.startsWith("SELECT") && !normalized.startsWith("PRAGMA") && !normalized.startsWith("EXPLAIN")) {
            return this.json({ error: "Only SELECT, PRAGMA, and EXPLAIN queries allowed" }, 403);
          }
          try {
            const rows = [...this.state.storage.sql.exec(q)];
            return this.json({ rows, count: rows.length });
          } catch (e: any) {
            return this.json({ error: e.message }, 400);
          }
        }

        case "/schema": {
          const tables = [...this.state.storage.sql.exec(
            "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
          )];
          const indexes = [...this.state.storage.sql.exec(
            "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL ORDER BY tbl_name"
          )];
          return this.json({ tables, indexes });
        }

        // ─── Light Client Header Endpoints (Handshake SPV-inspired) ──────
        case "/headers": {
          const after = parseInt(url.searchParams.get("after") || "0");
          const limit = Math.min(parseInt(url.searchParams.get("limit") || "100"), 1000);
          const db = this.state.storage.sql;
          const headers = [...db.exec(
            "SELECT * FROM block_headers WHERE block_number > ? ORDER BY block_number ASC LIMIT ?",
            after, limit,
          )] as any[];
          // Attach BFT commit certificates (validator signatures) to each header
          for (const h of headers) {
            const commit = [...db.exec(
              "SELECT signatures_json FROM dag_commits WHERE round = ?", h.block_number,
            )] as any[];
            h.bft_certificate = commit.length > 0 ? JSON.parse(commit[0].signatures_json || "[]") : [];
          }
          return this.json({ headers, count: headers.length });
        }

        case "/headers/latest": {
          const db = this.state.storage.sql;
          const rows = [...db.exec("SELECT * FROM block_headers ORDER BY block_number DESC LIMIT 1")] as any[];
          if (rows.length === 0) return this.json({ error: "No headers yet" }, 404);
          const header = rows[0];
          // Attach BFT commit certificate: 2/3+ validator signatures over this round's state
          const commit = [...db.exec(
            "SELECT signatures_json FROM dag_commits WHERE round = ?", header.block_number,
          )] as any[];
          header.bft_certificate = commit.length > 0 ? JSON.parse(commit[0].signatures_json || "[]") : [];
          return this.json(header);
        }

        // ─── Note/Nullifier Endpoints (Miden-inspired) ──────────────────
        case "/notes/create": {
          if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
          const body = await req.json() as any;
          const { creator, recipient, asset_type, amount, script } = body;
          if (!creator || !asset_type || !amount) {
            return this.json({ error: "creator, asset_type, amount required" }, 400);
          }
          const noteId = await sha256(`note:${creator}:${asset_type}:${amount}:${Date.now()}:${Math.random()}`);
          const commitment = await this.stateTree.computeCommitment(sql);
          sql.exec(
            `INSERT INTO notes (id, creator, recipient, asset_type, amount, script, shard, state_root, created_round, consumed, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
            noteId, creator, recipient || null, asset_type, String(amount),
            script || "", this.shardName, commitment.root, this.lastCommittedRound, Date.now(),
          );
          return this.json({ ok: true, note_id: noteId });
        }

        case "/notes/consume": {
          if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
          const body = await req.json() as any;
          const { note_id, consumer } = body;
          if (!note_id || !consumer) return this.json({ error: "note_id, consumer required" }, 400);
          // Verify note exists and is unconsumed
          const notes = [...sql.exec("SELECT * FROM notes WHERE id = ?", note_id)] as any[];
          if (notes.length === 0) return this.json({ error: "Note not found" }, 404);
          if (notes[0].consumed) return this.json({ error: "Note already consumed" }, 409);
          // Check recipient restriction
          if (notes[0].recipient && notes[0].recipient !== consumer) {
            return this.json({ error: "Not authorized to consume this note" }, 403);
          }
          // Create nullifier (prevents double-spend)
          const nullifier = await sha256(`nullifier:${note_id}:${consumer}`);
          const existing = [...sql.exec("SELECT 1 FROM nullifiers WHERE nullifier = ?", nullifier)] as any[];
          if (existing.length > 0) return this.json({ error: "Nullifier already exists (double spend)" }, 409);
          sql.exec("UPDATE notes SET consumed = 1 WHERE id = ?", note_id);
          sql.exec(
            "INSERT INTO nullifiers (nullifier, note_id, consumed_by, consumed_at) VALUES (?, ?, ?, ?)",
            nullifier, note_id, consumer, Date.now(),
          );
          // Mark nullifier in state tree for ZK proof inclusion
          this.stateTree.markDirty(`nullifier:${nullifier}`, "1");
          return this.json({ ok: true, nullifier });
        }

        case "/notes/list": {
          const owner = url.searchParams.get("recipient") || url.searchParams.get("creator");
          const field = url.searchParams.get("recipient") ? "recipient" : "creator";
          if (!owner) return this.json({ error: "recipient or creator required" }, 400);
          const notes = [...sql.exec(
            `SELECT id, creator, recipient, asset_type, amount, script, shard, created_round, consumed, created_at FROM notes WHERE ${field} = ? ORDER BY created_at DESC LIMIT 100`,
            owner,
          )];
          return this.json({ notes });
        }

        case "/nullifiers/check": {
          const nullifier = url.searchParams.get("nullifier");
          if (!nullifier) return this.json({ error: "nullifier required" }, 400);
          const rows = [...sql.exec("SELECT * FROM nullifiers WHERE nullifier = ?", nullifier)] as any[];
          return this.json({ exists: rows.length > 0, nullifier: rows[0] || null });
        }

        // ─── Covenant State Machine Endpoints (Handshake-inspired) ───────
        case "/covenant/create": {
          if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
          const body = await req.json() as any;
          const { entity_type, entity_id, initial_state, transitions } = body;
          if (!entity_type || !entity_id || !initial_state || !transitions) {
            return this.json({ error: "entity_type, entity_id, initial_state, transitions required" }, 400);
          }
          const id = await sha256(`covenant:${entity_type}:${entity_id}`);
          sql.exec(
            `INSERT OR REPLACE INTO covenants (id, entity_type, entity_id, current_state, allowed_transitions, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            id, entity_type, entity_id, initial_state, JSON.stringify(transitions), Date.now(), Date.now(),
          );
          return this.json({ ok: true, covenant_id: id, state: initial_state });
        }

        case "/covenant/transition": {
          if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
          const body = await req.json() as any;
          const { entity_type, entity_id, new_state } = body;
          if (!entity_type || !entity_id || !new_state) {
            return this.json({ error: "entity_type, entity_id, new_state required" }, 400);
          }
          const covId = await sha256(`covenant:${entity_type}:${entity_id}`);
          const rows = [...sql.exec("SELECT * FROM covenants WHERE id = ?", covId)] as any[];
          if (rows.length === 0) return this.json({ error: "Covenant not found" }, 404);
          const covenant = rows[0];
          let transitions: Record<string, string[]>;
          try { transitions = JSON.parse(covenant.allowed_transitions); } catch { return this.json({ error: "Invalid transitions config" }, 500); }
          const allowed = transitions[covenant.current_state] || [];
          if (!allowed.includes(new_state)) {
            return this.json({
              error: `Transition ${covenant.current_state} → ${new_state} not allowed`,
              current_state: covenant.current_state,
              allowed_transitions: allowed,
            }, 403);
          }
          sql.exec(
            "UPDATE covenants SET current_state = ?, updated_at = ? WHERE id = ?",
            new_state, Date.now(), covId,
          );
          return this.json({ ok: true, previous_state: covenant.current_state, new_state });
        }

        case "/covenant/get": {
          const entityType = url.searchParams.get("entity_type");
          const entityId = url.searchParams.get("entity_id");
          if (!entityType || !entityId) return this.json({ error: "entity_type, entity_id required" }, 400);
          const covId = await sha256(`covenant:${entityType}:${entityId}`);
          const rows = [...sql.exec("SELECT * FROM covenants WHERE id = ?", covId)] as any[];
          if (rows.length === 0) return this.json({ error: "Covenant not found" }, 404);
          return this.json({ ...rows[0], allowed_transitions: JSON.parse(rows[0].allowed_transitions) });
        }

        // ─── Private State Endpoints (Miden-inspired) ────────────────────
        case "/private/commit": {
          if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
          const body = await req.json() as any;
          const { contract_address, key_hash, commitment } = body;
          if (!contract_address || !key_hash || !commitment) {
            return this.json({ error: "contract_address, key_hash, commitment required" }, 400);
          }
          sql.exec(
            `INSERT OR REPLACE INTO private_state (contract_address, key_hash, commitment, updated_at) VALUES (?, ?, ?, ?)`,
            contract_address, key_hash, commitment, Date.now(),
          );
          // Track in state tree for ZK proof (only commitment, not value)
          this.stateTree.markDirty(`private:${contract_address}:${key_hash}`, commitment);
          return this.json({ ok: true });
        }

        case "/private/verify": {
          const contractAddr = url.searchParams.get("contract");
          const keyHash = url.searchParams.get("key_hash");
          if (!contractAddr || !keyHash) return this.json({ error: "contract, key_hash required" }, 400);
          const rows = [...sql.exec(
            "SELECT commitment, updated_at FROM private_state WHERE contract_address = ? AND key_hash = ?",
            contractAddr, keyHash,
          )] as any[];
          if (rows.length === 0) return this.json({ exists: false });
          return this.json({ exists: true, commitment: rows[0].commitment, updated_at: rows[0].updated_at });
        }

        case "/private/proof": {
          const contractAddr = url.searchParams.get("contract");
          const keyHash = url.searchParams.get("key_hash");
          if (!contractAddr || !keyHash) return this.json({ error: "contract, key_hash required" }, 400);
          const stateKey = `private:${contractAddr}:${keyHash}`;
          const proof = await this.stateTree.generateProof(stateKey);
          if (!proof) return this.json({ error: "Proof generation failed" }, 500);
          return this.json(proof);
        }

        case "/inventory": {
          const pubkey = url.searchParams.get("pubkey");
          if (!pubkey) return this.json({ error: "pubkey required" }, 400);
          return this.json({ inventory: this.getPlayerInventory(pubkey) });
        }

        case "/addNode": {
          if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
          const { url: peerUrl, pubkey: peerPubkey } = await req.json() as any;
          if (!peerUrl) return this.json({ error: "url required" }, 400);

          let resolvedPubkey = peerPubkey;
          if (peerPubkey) {
            this.gossipManager.addPeer(peerPubkey, peerUrl);
          } else {
            // Fetch the node's identity via /network endpoint
            try {
              const networkUrl = peerUrl.includes("?")
                ? peerUrl.replace("?", "/network?")
                : peerUrl.replace(/\/?$/, "/network");
              const res = await fetch(networkUrl);
              if (res.ok) {
                const info = await res.json() as any;
                if (info.node_pubkey) {
                  resolvedPubkey = info.node_pubkey;
                  this.gossipManager.addPeer(info.node_pubkey, peerUrl);
                }
              }
            } catch {}
          }

          // Register peer in active_nodes so it counts toward consensus quorum
          if (resolvedPubkey) {
            this.state.storage.sql.exec(
              `INSERT INTO active_nodes (pubkey, url, last_vertex_round, last_seen, is_self)
               VALUES (?, ?, 0, ?, 0)
               ON CONFLICT(pubkey) DO UPDATE SET url = ?, last_seen = ?`,
              resolvedPubkey, peerUrl, Date.now(), peerUrl, Date.now(),
            );
            this.invalidateActiveCache();
          }

          // Ensure alarm is running now that we have peers
          if (CONSENSUS_ENABLED) this.scheduleAlarm();

          return this.json({ ok: true, peers: this.gossipManager.getPeers() });
        }

        default: {
          const contractCount = [...this.state.storage.sql.exec("SELECT COUNT(*) as c FROM contracts")] as any[];
          const gossipPeerCount = this.gossipManager.getHealthyPeers().length;
          const latestAnchor = this.anchorManager.getLatestAnchor();
          const validatorCount = this.validatorRegistry.getActiveCount();
          return this.json({
            name: "Persistia Ledger Node",
            version: "0.7.0",
            consensus: CONSENSUS_ENABLED,
            node_pubkey: this.nodeIdentity?.pubkey || null,
            node_url: this.nodeIdentity?.url || null,
            current_round: this.currentRound,
            finalized_seq: this.finalizedSeq,
            finalized_root: this.finalizedRoot,
            active_nodes: this.getActiveNodeCount(),
            gossip_peers: gossipPeerCount,
            pending_events: this.getPendingEventCount(),
            registered_validators: validatorCount,
            quorum_threshold: this.validatorRegistry.getQuorumThreshold(),
            pow_difficulty: this.validatorRegistry.getDifficulty(),
            contracts: contractCount[0]?.c || 0,
            latest_anchor: latestAnchor ? {
              id: latestAnchor.id,
              berachain_tx: latestAnchor.berachain_tx,
              berachain_block: latestAnchor.berachain_block,
              finalized_seq: latestAnchor.bundle.finalized_seq,
              timestamp: latestAnchor.created_at,
            } : null,
          });
        }
      }
    } catch (e: any) {
      return this.json({ error: e.message }, 500);
    }
  }

  // ─── DO Alarm (round timer) ─────────────────────────────────────────────

  async alarm() {
    try {
      // 1. Fire due cron triggers (works regardless of consensus mode)
      await this.fireDueTriggers();

      // 2. Process pending oracle requests
      await this.processPendingOracles();

      if (CONSENSUS_ENABLED && this.nodeIdentity) {
        // 3. Pull from gossip peers
        await this.gossipSync();

        // 4. Create vertex for current round if we haven't yet
        const existing = [...this.state.storage.sql.exec(
          "SELECT hash FROM dag_vertices WHERE author = ? AND round = ?",
          this.nodeIdentity.pubkey, this.currentRound,
        )];
        if (existing.length === 0) {
          await this.createAndBroadcastVertex();
        }

        // 5. Anchor state if due
        await this.maybeAnchorState();
      }

      // 6. Housekeeping: prune stale rate-limit entries + old anchor bundles
      this.validatorRegistry.pruneRateLimitLog();
      this.anchorManager.pruneOldAnchors();

      // 7. Prune old DAG data to stay within free-tier row limits
      // Keep last 100 rounds of vertices, prune 200 per cycle to avoid heavy deletes
      if (this.currentRound > 150) {
        const pruneBelow = this.currentRound - 100;
        this.state.storage.sql.exec(
          "DELETE FROM dag_vertices WHERE rowid IN (SELECT rowid FROM dag_vertices WHERE round < ? LIMIT 200)",
          pruneBelow,
        );
        this.state.storage.sql.exec(
          "DELETE FROM consensus_events WHERE rowid IN (SELECT rowid FROM consensus_events WHERE round < ? LIMIT 200)",
          pruneBelow,
        );
      }

      // 7b. Prune old events (keep last 1000 for sync, rest recoverable from anchors)
      const lastAnchorRows = [...sql.exec(
        "SELECT MAX(finalized_seq) as max_seq FROM anchors WHERE status IN ('submitted','confirmed')"
      )];
      const lastAnchoredSeq = (lastAnchorRows[0]?.max_seq ?? 0) as number;
      if (lastAnchoredSeq > 1000) {
        const pruneSeq = lastAnchoredSeq - 1000;
        sql.exec("DELETE FROM events WHERE seq < ? LIMIT 200", pruneSeq);
      }

      // 7c. Prune delivered oracle requests older than 1 hour
      const oneHourAgo = Date.now() - 3_600_000;
      sql.exec("DELETE FROM oracle_requests WHERE status = 'delivered' AND delivered_at < ? LIMIT 50", oneHourAgo);
      sql.exec("DELETE FROM oracle_responses WHERE request_id NOT IN (SELECT id FROM oracle_requests) LIMIT 50");

      // 7d. Prune old ZK proofs — recursive IVC means the latest proof subsumes all previous.
      // Keep only the last 5 proofs for redundancy; older ones are cryptographically unnecessary.
      const zkKeep = 5;
      sql.exec(
        `DELETE FROM zk_proofs WHERE block_number NOT IN (
           SELECT block_number FROM zk_proofs ORDER BY block_number DESC LIMIT ?
         )`, zkKeep,
      );

      // 7e. Prune old block headers — keep last 1000 for light client sync
      if (this.currentRound > 1200) {
        sql.exec(
          "DELETE FROM block_headers WHERE block_number < ? LIMIT 200",
          this.currentRound - 1000,
        );
      }

      // 7f. Prune cross-shard messages: expire undelivered outbox after 100 rounds,
      // delete processed inbox older than 1 hour
      const xshardExpireRound = Math.max(0, this.currentRound - 100);
      sql.exec(
        "UPDATE xshard_outbox SET status = 'expired' WHERE status = 'pending' AND created_at < ?",
        Date.now() - 100 * ROUND_INTERVAL_MS,
      );
      sql.exec("DELETE FROM xshard_outbox WHERE status IN ('delivered', 'expired') AND created_at < ? LIMIT 100", oneHourAgo);
      sql.exec("DELETE FROM xshard_inbox WHERE status IN ('processed', 'failed') AND processed_at < ? LIMIT 100", oneHourAgo);

      // 7g. Prune consumed notes older than 1000 rounds (nullifiers must stay forever)
      if (this.currentRound > 1200) {
        sql.exec(
          "DELETE FROM notes WHERE consumed = 1 AND created_round < ? LIMIT 100",
          this.currentRound - 1000,
        );
      }

      // 7h. Prune expired MPP challenges (unconsumed + expired)
      sql.exec("DELETE FROM mpp_challenges WHERE consumed = 0 AND expires_at < ? LIMIT 100", Date.now());

      // 7i. Prune old governance votes (keep last 90 days)
      const ninetyDaysAgo = Date.now() - 90 * 86_400_000;
      sql.exec("DELETE FROM governance_votes WHERE created_at < ? LIMIT 50", ninetyDaysAgo);

      // 7j. Prune old equivocation evidence (keep last 30 days)
      const thirtyDaysAgo = Date.now() - 30 * 86_400_000;
      sql.exec("DELETE FROM equivocation_evidence WHERE detected_at < ? LIMIT 50", thirtyDaysAgo);

      // 7k. Prune stale private_state entries not updated in 90 days
      sql.exec("DELETE FROM private_state WHERE updated_at < ? LIMIT 50", ninetyDaysAgo);

      // 7l. Prune expired proof_claims (completed or expired older than 1 day)
      const oneDayAgo = Date.now() - 86_400_000;
      sql.exec("DELETE FROM proof_claims WHERE status IN ('completed', 'expired') AND claimed_at < ? LIMIT 50", oneDayAgo);

      // 8. Periodically reprobe failed peers (every ~5 min)
      if (CONSENSUS_ENABLED && this.currentRound % 10 === 0) {
        this.gossipManager.reprobeFailedPeers().catch(() => {});
      }
    } catch (e: any) {
      console.error(`Alarm error: ${e.message}`);
    }

    // 9. Re-schedule alarm even if there was an error
    this.scheduleAlarm();
  }

  private scheduleAlarm() {
    const now = Date.now();
    // Use the sooner of: round interval or next trigger fire time
    const nextTrigger = this.triggerManager.getNextFireTime();
    const roundTime = now + ROUND_INTERVAL_MS;
    const alarmTime = nextTrigger ? Math.min(roundTime, Math.max(nextTrigger, now + 1000)) : roundTime;
    this._nextAlarmTime = alarmTime;
    this.state.storage.setAlarm(alarmTime);
  }

  /**
   * Reactive alarm rescheduling: after round advancement or a commit, fire
   * the alarm sooner (now + 100 ms) so the node can act on the new state
   * without waiting for the next regular tick (up to ROUND_INTERVAL_MS away).
   * Skipped when an alarm is already imminent (within 500 ms).
   */
  private scheduleReactiveAlarm() {
    const now = Date.now();
    const IMMINENT_THRESHOLD_MS = 500;
    if (this._nextAlarmTime - now <= IMMINENT_THRESHOLD_MS) return; // already firing soon
    const reactiveTime = now + 100;
    this._nextAlarmTime = reactiveTime;
    this.state.storage.setAlarm(reactiveTime);
  }

  // ─── DAG Routes ─────────────────────────────────────────────────────────

  private async handleDagRoute(req: Request, url: URL): Promise<Response> {
    const sql = this.state.storage.sql;
    switch (url.pathname) {
      case "/dag/vertex": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const vertex = await req.json() as DAGVertex;
        // Rate-limit vertex submissions by author
        if (vertex.author && !this.validatorRegistry.checkGossipRateLimit(vertex.author)) {
          return this.json({ error: "Vertex rate limited" }, 429);
        }
        const result = await this.receiveVertex(vertex);
        return this.json(result, result.ok ? 200 : 400);
      }

      case "/dag/sync": {
        const afterRound = parseInt(url.searchParams.get("after_round") || "0");
        const limit = Math.min(parseInt(url.searchParams.get("limit") || "500"), 500);
        const vertices = [...this.state.storage.sql.exec(
          "SELECT hash, author, round, events_json, refs_json, signature, received_at FROM dag_vertices WHERE round > ? ORDER BY round ASC, hash ASC LIMIT ?",
          afterRound, limit,
        )].map((r: any) => ({
          hash: r.hash,
          author: r.author,
          round: r.round,
          events_json: r.events_json,
          refs_json: r.refs_json,
          signature: r.signature,
        }));

        const commits = [...this.state.storage.sql.exec(
          "SELECT round, anchor_hash, committed_at FROM dag_commits WHERE round >= ? ORDER BY round ASC",
          afterRound,
        )];

        // Also include recent direct-apply events (for single-node mode)
        const afterSeq = parseInt(url.searchParams.get("after_seq") || "0");
        const recentEvents = [...this.state.storage.sql.exec(
          "SELECT seq, type, payload, pubkey, timestamp FROM events WHERE seq > ? ORDER BY seq ASC LIMIT ?",
          afterSeq, limit,
        )].map((r: any) => ({
          seq: r.seq,
          type: r.type,
          payload: typeof r.payload === "string" ? r.payload : JSON.stringify(r.payload),
          pubkey: r.pubkey,
          timestamp: r.timestamp,
        }));

        return this.json({
          vertices,
          commits,
          recent_events: recentEvents,
          latest_round: this.currentRound,
          latest_seq: this.latestSeq,
          finalized_seq: this.finalizedSeq,
          finalized_root: this.finalizedRoot,
        });
      }

      case "/dag/status":
        return this.json(this.getConsensusStatus());

      // Fetch a committed block by round number (used by ZK prover)
      case "/dag/block": {
        const round = parseInt(url.searchParams.get("round") || "0");
        if (!round) return this.json({ error: "round parameter required" }, 400);

        // Get the committed vertex for this round
        const commits = [...sql.exec(
          "SELECT anchor_hash, committed_at, signatures_json FROM dag_commits WHERE round = ?", round
        )] as any[];
        if (commits.length === 0) return this.json({ error: "Round not committed" }, 404);

        const anchor = commits[0];
        const vertices = [...sql.exec(
          "SELECT hash, author, round, events_json, refs_json, signature FROM dag_vertices WHERE round = ?", round
        )] as any[];

        // Use persisted signatures from dag_commits (survives pruning), fall back to live vertices
        let signatures: any[];
        if (anchor.signatures_json && anchor.signatures_json !== '[]') {
          try { signatures = JSON.parse(anchor.signatures_json); } catch { signatures = []; }
        } else {
          signatures = vertices.map((v: any) => ({
            pubkey: v.author,
            signature: v.signature,
          }));
        }

        // Parse events from the anchor vertex
        const anchorVertex = vertices.find((v: any) => v.hash === anchor.anchor_hash);
        let events: any[] = [];
        if (anchorVertex?.events_json) {
          try { events = JSON.parse(anchorVertex.events_json); } catch {}
        }

        // Compute active_nodes at commit time from the signature/vertex count
        // This is more accurate than the current live count for historical blocks
        const commitActiveNodes = Math.max(signatures.length, vertices.length, 1);

        return this.json({
          round,
          hash: anchor.anchor_hash,
          committed_at: anchor.committed_at,
          signatures,
          events,
          vertex_count: vertices.length,
          active_nodes: commitActiveNodes,
        });
      }

      // Find the next committed round after a given round (used by ZK prover to skip gaps)
      case "/dag/next_committed": {
        const afterRound = parseInt(url.searchParams.get("after") || "0");
        const nextCommit = [...sql.exec(
          "SELECT round FROM dag_commits WHERE round > ? ORDER BY round ASC LIMIT 1", afterRound
        )] as any[];
        if (nextCommit.length === 0) return this.json({ round: null });
        return this.json({ round: nextCommit[0].round });
      }

      // Fetch all vertices for a round with full data (used by ZK prover for canonical JSON reconstruction)
      case "/dag/vertices": {
        const vRound = parseInt(url.searchParams.get("round") || "0");
        if (!vRound) return this.json({ error: "round parameter required" }, 400);
        const verts = [...sql.exec(
          "SELECT hash, author, round, events_json, refs_json, signature, timestamp FROM dag_vertices WHERE round = ?", vRound
        )] as any[];
        return this.json(verts.map((v: any) => {
          let event_hashes: string[] = [];
          try {
            const events = JSON.parse(v.events_json);
            event_hashes = events.map((e: any) => e.hash).filter(Boolean);
          } catch {}
          let refs: string[] = [];
          try { refs = JSON.parse(v.refs_json); } catch {}
          return {
            hash: v.hash,
            author: v.author,
            round: v.round,
            event_hashes,
            refs,
            timestamp: v.timestamp,
            signature: v.signature,
          };
        }));
      }

      case "/dag/snapshot": {
        const blocks = [...this.state.storage.sql.exec("SELECT x, z, block_type, placed_by FROM blocks")];
        const ownership = [...this.state.storage.sql.exec("SELECT asset_id, owner_pubkey, metadata, created_at FROM ownership")];
        const inventory = [...this.state.storage.sql.exec("SELECT pubkey, item, count FROM inventory WHERE count > 0")];
        return this.json({
          finalized_root: this.finalizedRoot,
          finalized_seq: this.finalizedSeq,
          last_committed_round: this.lastCommittedRound,
          state: { blocks, ownership, inventory },
        });
      }

      default:
        return this.json({ error: "Unknown DAG endpoint" }, 404);
    }
  }

  // ─── Admin Routes ───────────────────────────────────────────────────────

  private async handleAdminRoute(req: Request, url: URL): Promise<Response> {
    switch (url.pathname) {
      case "/admin/register": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const { pubkey, url: peerUrl, signature } = await req.json() as any;

        // Verify the registration is signed by the claimed pubkey
        const valid = await verifyNodeSignature(pubkey, signature, JSON.stringify({ pubkey, url: peerUrl }));
        if (!valid) return this.json({ error: "Invalid signature" }, 400);

        this.state.storage.sql.exec(
          `INSERT INTO active_nodes (pubkey, url, last_vertex_round, last_seen, is_self)
           VALUES (?, ?, 0, ?, 0)
           ON CONFLICT(pubkey) DO UPDATE SET url = ?, last_seen = ?`,
          pubkey, peerUrl, Date.now(), peerUrl, Date.now(),
        );
        this.invalidateActiveCache();

        // Ensure alarm is running now that we have peers
        this.scheduleAlarm();

        return this.json({ ok: true, peers: this.getActiveNodes() });
      }

      case "/admin/peers":
        return this.json({ peers: this.getActiveNodes() });

      case "/admin/reset": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        // Nuclear reset — drops all data and reinitializes
        await this.state.storage.deleteAll();
        this.initDB();
        this.currentRound = 0;
        this.lastCommittedRound = -2;
        this.finalizedSeq = 0;
        this.finalizedRoot = await sha256("");
        this.latestSeq = 0;
        this.currentRoot = await sha256("");
        await this.loadState();
        return this.json({ ok: true, message: "Storage reset. Node will reinitialize on next alarm." });
      }

      case "/admin/prune": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const sql = this.state.storage.sql;
        const keep = parseInt(url.searchParams.get("keep") || "100");
        const pruneBelow = Math.max(0, this.currentRound - keep);
        let totalDeleted = 0;
        // Delete in small batches
        for (let i = 0; i < 20; i++) {
          const result = sql.exec("DELETE FROM dag_vertices WHERE rowid IN (SELECT rowid FROM dag_vertices WHERE round < ? LIMIT 100)", pruneBelow);
          totalDeleted += result.rowsWritten || 0;
          if (!result.rowsWritten) break;
        }

        for (let i = 0; i < 10; i++) {
          const result = sql.exec("DELETE FROM consensus_events WHERE rowid IN (SELECT rowid FROM consensus_events WHERE round < ? LIMIT 100)", pruneBelow);
          totalDeleted += result.rowsWritten || 0;
          if (!result.rowsWritten) break;
        }
        return this.json({ ok: true, pruned_below_round: pruneBelow, rows_deleted: totalDeleted });
      }

      default:
        return this.json({ error: "Unknown admin endpoint" }, 404);
    }
  }

  // ─── Contract Routes ────────────────────────────────────────────────────

  private async handleContractRoute(req: Request, url: URL): Promise<Response> {
    switch (url.pathname) {
      case "/contract/deploy": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as SignedEvent;
        body.type = "contract.deploy";
        return this.json(await this.receiveClientEvent(body));
      }

      case "/contract/call": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as SignedEvent;
        body.type = "contract.call";
        return this.json(await this.receiveClientEvent(body));
      }

      case "/contract/query": {
        const address = url.searchParams.get("address");
        const method = url.searchParams.get("method");
        if (!address || !method) return this.json({ error: "address and method required" }, 400);
        const argsB64 = url.searchParams.get("args") || "";
        const args = argsB64 ? this.b64ToBytes(argsB64) : new Uint8Array();

        const result = await this.contractExecutor.query(address, method, args);
        return this.json({
          ok: result.ok,
          return_data: result.return_data ? btoa(String.fromCharCode(...result.return_data)) : null,
          logs: result.logs,
          error: result.error,
        });
      }

      case "/contract/info": {
        const address = url.searchParams.get("address");
        if (!address) return this.json({ error: "address required" }, 400);
        const info = this.contractExecutor.getContractInfo(address);
        if (!info) return this.json({ error: "Contract not found" }, 404);
        return this.json(info);
      }

      // ─── Oracle endpoints ───────────────────────────────────────────

      case "/contract/oracle/request": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        body.type = "oracle.request";
        return this.json(await this.receiveClientEvent(body));
      }

      case "/contract/oracle/status": {
        const requestId = url.searchParams.get("id");
        if (!requestId) return this.json({ error: "id required" }, 400);
        const rows = [...this.state.storage.sql.exec(
          "SELECT * FROM oracle_requests WHERE id = ?", requestId,
        )];
        if (rows.length === 0) return this.json({ error: "Request not found" }, 404);
        return this.json(rows[0]);
      }

      // ─── Trigger endpoints ──────────────────────────────────────────

      case "/contract/trigger/create": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        body.type = "trigger.create";
        return this.json(await this.receiveClientEvent(body));
      }

      case "/contract/trigger/remove": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        body.type = "trigger.remove";
        return this.json(await this.receiveClientEvent(body));
      }

      case "/contract/trigger/list": {
        const contract = url.searchParams.get("contract");
        if (!contract) return this.json({ error: "contract required" }, 400);
        return this.json({ triggers: this.triggerManager.listForContract(contract) });
      }

      default:
        return this.json({ error: "Unknown contract endpoint" }, 404);
    }
  }

  // ─── State Proof Routes ─────────────────────────────────────────────────

  private async handleProofRoute(req: Request, url: URL): Promise<Response> {
    const sql = this.state.storage.sql;

    switch (url.pathname) {
      case "/proof/commitment": {
        // Use incremental tree (only recomputes dirty leaves)
        const commitment = await this.stateTree.computeCommitment(sql);
        return this.json(commitment);
      }

      case "/proof/generate": {
        const key = url.searchParams.get("key");
        if (!key) return this.json({ error: "key required" }, 400);
        // Try incremental tree first, fall back to full scan
        const proof = await this.stateTree.generateProof(key)
          || await generateStateProof(sql, key);
        if (!proof) return this.json({ error: "key not found in state" }, 404);
        return this.json(proof);
      }

      case "/proof/verify": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const proof = await req.json();
        const valid = await verifyProof(proof);
        return this.json({ valid });
      }

      // ─── ZK Proof Endpoints ──────────────────────────────────────────
      case "/proof/zk/submit": {
        // Accept a ZK proof from the prover sidecar
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        if (!body.block_number || !body.proof || !body.state_root) {
          return this.json({ error: "block_number, proof, and state_root required" }, 400);
        }
        // Decode proof bytes if provided (base64-encoded)
        let proofBytes: ArrayBuffer | null = null;
        if (body.proof_bytes_b64) {
          const raw = atob(body.proof_bytes_b64);
          const arr = new Uint8Array(raw.length);
          for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
          proofBytes = arr.buffer;
        }
        sql.exec(
          `INSERT OR REPLACE INTO zk_proofs (block_number, proof_hex, state_root, proven_blocks, proof_type, submitted_at, verified, proof_bytes, public_values, genesis_root)
           VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
          body.block_number,
          body.proof,
          body.state_root,
          body.proven_blocks || 1,
          body.proof_type || "compressed",
          Date.now(),
          proofBytes,
          body.public_values ? JSON.stringify(body.public_values) : null,
          body.genesis_root || null,
        );
        this.broadcast({
          type: "zk.proof_submitted",
          block_number: body.block_number,
          state_root: body.state_root,
          proven_blocks: body.proven_blocks || 1,
          genesis_root: body.genesis_root || null,
        });

        // Fan out proof to sibling shards (skip if this is already a relay)
        if (!body._relayed && this.env.PERSISTIA_WORLD) {
          const relayBody = { ...body, _relayed: true };
          const siblings = ["node-1", "node-2", "node-3", "global-world"]
            .filter(s => s !== this.shardName);
          for (const shard of siblings) {
            try {
              const id = this.env.PERSISTIA_WORLD.idFromName(shard);
              const stub = this.env.PERSISTIA_WORLD.get(id);
              stub.fetch(new Request(`${url.origin}/proof/zk/submit`, {
                method: "POST",
                headers: { "Content-Type": "application/json", "X-Shard-Name": shard },
                body: JSON.stringify(relayBody),
              })).catch(() => {}); // fire-and-forget
            } catch {}
          }
        }

        return this.json({ ok: true, block_number: body.block_number });
      }

      case "/proof/zk/latest": {
        // Get the latest ZK proof
        const rows = [...sql.exec(
          "SELECT block_number, state_root, proven_blocks, proof_type, submitted_at, verified FROM zk_proofs ORDER BY block_number DESC LIMIT 1"
        )] as any[];
        if (rows.length === 0) return this.json({ error: "No ZK proofs available" }, 404);
        return this.json(rows[0]);
      }

      case "/proof/zk/get": {
        // Get a specific ZK proof by block number (includes the full proof hex)
        const blockNum = url.searchParams.get("block");
        if (!blockNum) return this.json({ error: "block parameter required" }, 400);
        const rows = [...sql.exec(
          "SELECT * FROM zk_proofs WHERE block_number = ?", parseInt(blockNum)
        )] as any[];
        if (rows.length === 0) return this.json({ error: "Proof not found" }, 404);
        return this.json(rows[0]);
      }

      case "/proof/zk/status": {
        // Summary of ZK proof coverage
        const latest = [...sql.exec(
          "SELECT MAX(block_number) as latest_block, MAX(proven_blocks) as max_chain_length FROM zk_proofs"
        )] as any[];
        const count = [...sql.exec("SELECT COUNT(*) as total FROM zk_proofs")] as any[];
        return this.json({
          total_proofs: count[0]?.total || 0,
          latest_proven_block: latest[0]?.latest_block || null,
          max_chain_length: latest[0]?.max_chain_length || 0,
          last_committed_round: this.lastCommittedRound,
          proof_gap: (this.lastCommittedRound || 0) - (latest[0]?.latest_block || 0),
        });
      }

      case "/proof/zk/chain": {
        // Return the full IVC proof chain for browser verification.
        // Each entry includes public values (state_root, block_number, proven_blocks, genesis_root)
        // but NOT the full proof bytes (too large). Use /proof/zk/download for that.
        const rows = [...sql.exec(
          `SELECT block_number, proof_hex, state_root, proven_blocks, proof_type,
                  submitted_at, verified, public_values, genesis_root
           FROM zk_proofs ORDER BY block_number ASC`
        )] as any[];
        // Parse public_values JSON if available
        const chain = rows.map((r: any) => ({
          block_number: r.block_number,
          proof_hash: r.proof_hex,
          state_root: r.state_root,
          proven_blocks: r.proven_blocks,
          proof_type: r.proof_type,
          submitted_at: r.submitted_at,
          verified: r.verified,
          genesis_root: r.genesis_root,
          public_values: r.public_values ? JSON.parse(r.public_values) : null,
          has_proof_bytes: r.proof_bytes != null,
        }));
        return this.json({ chain, count: chain.length });
      }

      case "/proof/zk/download": {
        // Download raw proof bytes for a specific block (for offline verification)
        const blockNum = url.searchParams.get("block");
        if (!blockNum) return this.json({ error: "block parameter required" }, 400);
        const rows = [...sql.exec(
          "SELECT proof_bytes, proof_type, block_number FROM zk_proofs WHERE block_number = ?",
          parseInt(blockNum),
        )] as any[];
        if (rows.length === 0 || !rows[0].proof_bytes) {
          return this.json({ error: "Proof bytes not available" }, 404);
        }
        return new Response(rows[0].proof_bytes as ArrayBuffer, {
          headers: {
            "Content-Type": "application/octet-stream",
            "Content-Disposition": `attachment; filename="proof_block_${blockNum}.bin"`,
            "X-Proof-Type": rows[0].proof_type,
          },
        });
      }

      // ─── Multi-Prover Claim-Based Coordination ─────────────────────────

      case "/proof/claim": {
        // Prover claims a block range to prove. Prevents duplicate work.
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        const { prover_id, block_start, block_end, ttl_seconds } = body;
        if (!prover_id || block_start == null || block_end == null) {
          return this.json({ error: "prover_id, block_start, block_end required" }, 400);
        }
        if (block_start > block_end) return this.json({ error: "block_start must be <= block_end" }, 400);
        const ttl = (ttl_seconds || 300) * 1000; // default 5 min
        const now = Date.now();

        // Expire stale claims first
        sql.exec("UPDATE proof_claims SET status = 'expired' WHERE status = 'claimed' AND expires_at < ?", now);

        // Check for overlapping active claims
        const overlaps = [...sql.exec(
          `SELECT prover_id, block_start, block_end FROM proof_claims
           WHERE status = 'claimed' AND block_start <= ? AND block_end >= ?`,
          block_end, block_start,
        )] as any[];
        if (overlaps.length > 0) {
          return this.json({ error: "Range overlaps existing claim", overlaps }, 409);
        }

        // Check if range already proven
        const proven = [...sql.exec(
          "SELECT block_number FROM zk_proofs WHERE block_number >= ? AND block_number <= ?",
          block_start, block_end,
        )] as any[];
        if (proven.length === (block_end - block_start + 1)) {
          return this.json({ error: "Range already fully proven", proven_blocks: proven.map((r: any) => r.block_number) }, 409);
        }

        sql.exec(
          `INSERT OR REPLACE INTO proof_claims (block_start, block_end, prover_id, status, claimed_at, expires_at)
           VALUES (?, ?, ?, 'claimed', ?, ?)`,
          block_start, block_end, prover_id, now, now + ttl,
        );
        return this.json({ ok: true, block_start, block_end, expires_at: now + ttl });
      }

      case "/proof/release": {
        // Prover releases a claim (completed or abandoned)
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        const { prover_id, block_start, block_end, proof_hash, status } = body;
        if (!prover_id || block_start == null || block_end == null) {
          return this.json({ error: "prover_id, block_start, block_end required" }, 400);
        }
        const newStatus = status === "completed" ? "completed" : "released";
        if (newStatus === "completed" && proof_hash) {
          sql.exec(
            "UPDATE proof_claims SET status = ?, completed_at = ?, proof_hash = ? WHERE block_start = ? AND block_end = ? AND prover_id = ?",
            newStatus, Date.now(), proof_hash, block_start, block_end, prover_id,
          );
        } else {
          sql.exec(
            "UPDATE proof_claims SET status = ? WHERE block_start = ? AND block_end = ? AND prover_id = ?",
            newStatus, block_start, block_end, prover_id,
          );
        }
        return this.json({ ok: true, status: newStatus });
      }

      case "/proof/claims": {
        // List active claims and their status
        sql.exec("UPDATE proof_claims SET status = 'expired' WHERE status = 'claimed' AND expires_at < ?", Date.now());
        const statusFilter = url.searchParams.get("status");
        const rows = statusFilter
          ? [...sql.exec("SELECT * FROM proof_claims WHERE status = ? ORDER BY block_start", statusFilter)]
          : [...sql.exec("SELECT * FROM proof_claims ORDER BY block_start DESC LIMIT 100")];
        return this.json({ claims: rows });
      }

      case "/proof/next_unclaimed": {
        // Returns the next block range that needs proving (not claimed, not proven)
        sql.exec("UPDATE proof_claims SET status = 'expired' WHERE status = 'claimed' AND expires_at < ?", Date.now());
        const batchSize = parseInt(url.searchParams.get("batch") || "1");
        const afterBlock = parseInt(url.searchParams.get("after") || "0");

        // Find committed rounds not yet proven or claimed
        const committed = [...sql.exec(
          `SELECT round FROM dag_commits
           WHERE round > ?
           AND round NOT IN (SELECT block_number FROM zk_proofs)
           ORDER BY round ASC LIMIT ?`,
          afterBlock, batchSize,
        )] as any[];

        if (committed.length === 0) {
          return this.json({ available: false });
        }

        // Filter out claimed ranges
        const unclaimed = [];
        for (const row of committed) {
          const claims = [...sql.exec(
            "SELECT 1 FROM proof_claims WHERE status = 'claimed' AND block_start <= ? AND block_end >= ?",
            row.round, row.round,
          )] as any[];
          if (claims.length === 0) unclaimed.push(row.round);
        }

        if (unclaimed.length === 0) {
          return this.json({ available: false, reason: "all pending blocks are claimed" });
        }

        return this.json({
          available: true,
          block_start: unclaimed[0],
          block_end: unclaimed[unclaimed.length - 1],
          blocks: unclaimed,
        });
      }

      default:
        return this.json({ error: "Unknown proof endpoint" }, 404);
    }
  }

  // ─── Cross-Shard Routes ─────────────────────────────────────────────────

  private async handleCrossShardRoute(req: Request, url: URL): Promise<Response> {
    const sql = this.state.storage.sql;

    switch (url.pathname) {
      case "/xshard/send": {
        // Send a cross-shard message (queued in outbox for Worker to relay)
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;

        const stateRoot = CONSENSUS_ENABLED ? this.finalizedRoot : this.currentRoot;
        const msg = await createCrossShardMessage(
          this.shardName, body.target_shard, body.type, body.payload,
          stateRoot, body.sender_pubkey || "",
        );

        const validation = validateMessage(msg);
        if (!validation.ok) return this.json(validation, 400);

        sql.exec(
          `INSERT INTO xshard_outbox (id, target_shard, message_json, status, created_at)
           VALUES (?, ?, ?, 'pending', ?)`,
          msg.id, msg.target_shard, JSON.stringify(msg), Date.now(),
        );

        this.broadcast({ type: "xshard.queued", message_id: msg.id, target: msg.target_shard });
        return this.json({ ok: true, message_id: msg.id });
      }

      case "/xshard/receive": {
        // Receive a cross-shard message (called by Worker relay)
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const msg = await req.json() as CrossShardMessage;

        const validation = validateMessage(msg);
        if (!validation.ok) return this.json(validation, 400);

        // Deduplicate
        const existing = [...sql.exec("SELECT id FROM xshard_inbox WHERE id = ?", msg.id)];
        if (existing.length > 0) return this.json({ ok: true, status: "already_received" });

        sql.exec(
          `INSERT INTO xshard_inbox (id, source_shard, message_json, status, received_at)
           VALUES (?, ?, ?, 'pending', ?)`,
          msg.id, msg.source_shard, JSON.stringify(msg), Date.now(),
        );

        // Process the message
        const receipt = await this.processInboundMessage(msg);
        return this.json(receipt);
      }

      case "/xshard/outbox": {
        // List pending outbound messages (for Worker relay to pick up)
        const status = url.searchParams.get("status") || "pending";
        const rows = [...sql.exec(
          "SELECT id, target_shard, message_json, status, created_at FROM xshard_outbox WHERE status = ? ORDER BY created_at ASC LIMIT 50",
          status,
        )];
        return this.json({ messages: rows });
      }

      case "/xshard/inbox": {
        const rows = [...sql.exec(
          "SELECT id, source_shard, status, received_at, processed_at FROM xshard_inbox ORDER BY received_at DESC LIMIT 50",
        )];
        return this.json({ messages: rows });
      }

      case "/xshard/ack": {
        // Mark outbox message as delivered (Worker confirms delivery)
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const { message_id, status } = await req.json() as any;
        sql.exec(
          "UPDATE xshard_outbox SET status = ?, delivered_at = ? WHERE id = ?",
          status || "delivered", Date.now(), message_id,
        );
        return this.json({ ok: true });
      }

      default:
        return this.json({ error: "Unknown xshard endpoint" }, 404);
    }
  }

  private async processInboundMessage(msg: CrossShardMessage): Promise<CrossShardReceipt> {
    const stateRoot = CONSENSUS_ENABLED ? this.finalizedRoot : this.currentRoot;

    try {
      switch (msg.type) {
        case "token.transfer": {
          // Cross-shard token transfer: credit tokens on this shard
          // payload: { token_contract, token_id, to, amount }
          const { token_contract, token_id, to, amount } = msg.payload;
          if (token_contract) {
            const args = JSON.stringify({ token_id, to, amount: String(amount) });
            const argsBytes = new TextEncoder().encode(args);
            await this.contractExecutor.call(token_contract, "mint", argsBytes, `xshard:${msg.source_shard}`, 1_000_000);
          }
          break;
        }

        case "contract.call": {
          // Cross-shard contract call
          const { contract, method, args_b64 } = msg.payload;
          const args = args_b64 ? this.b64ToBytes(args_b64) : new Uint8Array();
          await this.contractExecutor.call(contract, method, args, `xshard:${msg.source_shard}`, 1_000_000);
          break;
        }

        case "state.sync": {
          // State synchronization request — respond with current state
          break;
        }
      }

      this.state.storage.sql.exec(
        "UPDATE xshard_inbox SET status = 'processed', processed_at = ? WHERE id = ?",
        Date.now(), msg.id,
      );

      this.broadcast({ type: "xshard.processed", message_id: msg.id, source: msg.source_shard });

      return {
        message_id: msg.id,
        status: "delivered",
        target_state_root: stateRoot,
        timestamp: Date.now(),
      };
    } catch (e: any) {
      this.state.storage.sql.exec(
        "UPDATE xshard_inbox SET status = 'failed', processed_at = ? WHERE id = ?",
        Date.now(), msg.id,
      );

      return {
        message_id: msg.id,
        status: "failed",
        error: e.message,
        target_state_root: stateRoot,
        timestamp: Date.now(),
      };
    }
  }

  // ─── Validator Registry Routes ───────────────────────────────────────

  private async handleValidatorRoute(req: Request, url: URL): Promise<Response> {
    switch (url.pathname) {
      case "/validator/register": {
        // Register with Proof-of-Work
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const { pubkey, url: peerUrl, pow_nonce, signature } = await req.json() as any;
        if (!pubkey || !pow_nonce) return this.json({ error: "pubkey and pow_nonce required" }, 400);

        // Verify the registration is signed by the claimed pubkey
        const valid = await verifyNodeSignature(pubkey, signature, JSON.stringify({ pubkey, url: peerUrl || "", pow_nonce }));
        if (!valid) return this.json({ error: "Invalid signature" }, 400);

        const result = await this.validatorRegistry.register(pubkey, peerUrl || "", pow_nonce);
        if (!result.ok) return this.json(result, 400);

        // Also register in active_nodes for backward compat
        this.state.storage.sql.exec(
          `INSERT INTO active_nodes (pubkey, url, last_vertex_round, last_seen, is_self)
           VALUES (?, ?, 0, ?, 0)
           ON CONFLICT(pubkey) DO UPDATE SET url = ?, last_seen = ?`,
          pubkey, peerUrl || "", Date.now(), peerUrl || "", Date.now(),
        );
        this.invalidateActiveCache();

        this.scheduleAlarm();
        return this.json(result);
      }

      case "/validator/info": {
        const pubkey = url.searchParams.get("pubkey");
        if (!pubkey) return this.json({ error: "pubkey required" }, 400);
        const v = this.validatorRegistry.getValidator(pubkey);
        if (!v) return this.json({ error: "Validator not found" }, 404);
        return this.json(v);
      }

      case "/validator/list":
        return this.json({
          validators: this.validatorRegistry.getActiveValidators(),
          quorum_threshold: this.validatorRegistry.getQuorumThreshold(),
          total_active: this.validatorRegistry.getActiveCount(),
        });

      case "/validator/registration-info":
        return this.json(this.validatorRegistry.getRegistrationInfo());

      case "/validator/equivocations": {
        const pubkey = url.searchParams.get("pubkey") || undefined;
        return this.json({ evidence: this.validatorRegistry.getEquivocationEvidence(pubkey) });
      }

      case "/validator/vote": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const { voter_pubkey, action, target, signature } = await req.json() as any;
        if (!voter_pubkey || !action || !target) {
          return this.json({ error: "voter_pubkey, action, and target required" }, 400);
        }

        // Verify signature
        const valid = await verifyNodeSignature(
          voter_pubkey, signature,
          JSON.stringify({ action, target }),
        );
        if (!valid) return this.json({ error: "Invalid signature" }, 400);

        const result = await this.validatorRegistry.vote(voter_pubkey, action, target);
        return this.json(result, result.ok ? 200 : 400);
      }

      default:
        return this.json({ error: "Unknown validator endpoint" }, 404);
    }
  }

  // ─── Gossip Routes ──────────────────────────────────────────────────────

  private async handleGossipRoute(req: Request, url: URL): Promise<Response> {
    switch (url.pathname) {
      case "/gossip/push": {
        // Receive a gossipped message (vertex or event)
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const envelope = await req.json() as GossipEnvelope;

        // Rate-limit gossip by sender pubkey (stricter for unregistered peers)
        if (envelope.sender_pubkey && !this.validatorRegistry.checkGossipRateLimit(envelope.sender_pubkey)) {
          return this.json({ error: "Gossip rate limited" }, 429);
        }

        const valid = await this.gossipManager.verifyEnvelope(envelope);
        if (!valid) return this.json({ error: "Invalid or duplicate gossip envelope" }, 400);

        // Auto-discover the sender as a peer
        if (envelope.sender_pubkey && envelope.sender_url) {
          this.gossipManager.addPeer(envelope.sender_pubkey, envelope.sender_url);
        }

        switch (envelope.type) {
          case "vertex": {
            const vertex = envelope.payload;
            const result = await this.receiveVertex(vertex);
            if (result.ok) {
              // Re-gossip to our peers (excluding sender to avoid loops)
              const exclude = new Set([envelope.sender_pubkey]);
              this.gossipManager.flood(envelope, exclude).catch(() => {});
            }
            return this.json(result, result.ok ? 200 : 400);
          }
          case "event": {
            const event = envelope.payload;
            const result = await this.receiveClientEvent(event);
            return this.json(result);
          }
          default:
            return this.json({ error: "Unknown gossip type" }, 400);
        }
      }

      case "/gossip/sync": {
        // Rate-limit sync requests by IP (no pubkey available on GET)
        // Sync is expensive — cap at 10 requests/min per caller
        const syncCaller = req.headers.get("CF-Connecting-IP") || "unknown";
        if (!this.validatorRegistry.checkRateLimit(`sync:${syncCaller}`, 60_000, 10)) {
          return this.json({ error: "Sync rate limited" }, 429);
        }

        // Respond to sync requests from peers
        const afterRound = parseInt(url.searchParams.get("after_round") || "0");
        const limit = Math.min(parseInt(url.searchParams.get("limit") || "500"), 500);

        const vertices = [...this.state.storage.sql.exec(
          "SELECT hash, author, round, events_json, refs_json, signature, timestamp FROM dag_vertices WHERE round >= ? ORDER BY round ASC, hash ASC LIMIT ?",
          afterRound, limit,
        )].map((r: any) => ({
          hash: r.hash, author: r.author, round: r.round,
          event_hashes: (() => { try { return JSON.parse(r.events_json).map((e: any) => e.hash).filter(Boolean); } catch { return []; } })(),
          events: (() => { try { return JSON.parse(r.events_json); } catch { return []; } })(),
          refs: (() => { try { return JSON.parse(r.refs_json); } catch { return []; } })(),
          timestamp: r.timestamp,
          signature: r.signature,
        }));

        const commits = [...this.state.storage.sql.exec(
          "SELECT round, anchor_hash, committed_at FROM dag_commits WHERE round >= ? ORDER BY round ASC",
          afterRound,
        )];

        return this.json({
          vertices,
          commits,
          latest_round: this.currentRound,
        } as SyncResponsePayload);
      }

      case "/gossip/peers": {
        // Peer exchange endpoint
        if (req.method === "POST") {
          const envelope = await req.json() as GossipEnvelope;

          // Rate-limit peer exchange by sender
          if (envelope.sender_pubkey && !this.validatorRegistry.checkGossipRateLimit(envelope.sender_pubkey)) {
            return this.json({ error: "Gossip rate limited" }, 429);
          }

          const valid = await this.gossipManager.verifyEnvelope(envelope);
          if (valid && envelope.payload?.peers) {
            for (const p of envelope.payload.peers) {
              if (p.pubkey && p.url) this.gossipManager.addPeer(p.pubkey, p.url);
            }
          }
          // Auto-discover sender
          if (envelope.sender_pubkey && envelope.sender_url) {
            this.gossipManager.addPeer(envelope.sender_pubkey, envelope.sender_url);
          }
        }
        // Always return our peer list
        const myPeers = this.gossipManager.getHealthyPeers().map(p => ({ pubkey: p.pubkey, url: p.url }));
        // Include self
        if (this.nodeIdentity) {
          myPeers.push({ pubkey: this.nodeIdentity.pubkey, url: this.nodeIdentity.url });
        }
        return this.json({ peers: myPeers });
      }

      default:
        return this.json({ error: "Unknown gossip endpoint" }, 404);
    }
  }

  // ─── MPP Routes ──────────────────────────────────────────────────────────

  private async handleMPPRoute(_req: Request, url: URL): Promise<Response> {
    switch (url.pathname) {
      case "/mpp/info":
        return this.json(this.mppHandler.getPaymentInfo());

      case "/mpp/receipts": {
        const payer = url.searchParams.get("payer");
        if (!payer) return this.json({ error: "payer required" }, 400);
        return this.json(this.mppHandler.listReceipts(payer));
      }

      case "/mpp/receipt": {
        const id = url.searchParams.get("id");
        if (!id) return this.json({ error: "id required" }, 400);
        const receipt = this.mppHandler.getReceipt(id);
        if (!receipt) return this.json({ error: "not found" }, 404);
        return this.json(receipt);
      }

      case "/mpp/status":
        return this.json({ active_challenges: this.mppHandler.activeChallenges() });

      default:
        return this.json({ error: "unknown mpp route" }, 404);
    }
  }

  // ─── Anchor Routes ─────────────────────────────────────────────────────

  private async handleAnchorRoute(req: Request, url: URL): Promise<Response> {
    switch (url.pathname) {
      case "/anchor/latest": {
        const anchor = this.anchorManager.getLatestAnchor();
        if (!anchor) return this.json({ error: "No anchors yet" }, 404);
        return this.json(anchor);
      }

      case "/anchor/history": {
        const limit = parseInt(url.searchParams.get("limit") || "20");
        return this.json({ anchors: this.anchorManager.getAnchorHistory(limit) });
      }

      case "/anchor/submit": {
        // Manually trigger an anchor
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const record = await this.performAnchor();
        return this.json(record);
      }

      case "/anchor/verify": {
        // Verify an anchor from Berachain
        const berachainTx = url.searchParams.get("berachain_tx");

        if (berachainTx) {
          const result = await this.anchorManager.verifyFromBerachain(berachainTx);
          return this.json(result);
        }
        return this.json({ error: "berachain_tx required" }, 400);
      }

      case "/anchor/bootstrap": {
        // Bootstrap from the latest anchor (for new nodes)
        const latestForBootstrap = this.anchorManager.getLatestAnchor();
        if (!latestForBootstrap) return this.json({ error: "No anchor found" }, 404);
        return this.json({
          bundle: latestForBootstrap.bundle,
          berachain_tx: latestForBootstrap.berachain_tx,
          instructions: "Use /dag/snapshot to get the full state after syncing to this anchor's round",
        });
      }

      default:
        return this.json({ error: "Unknown anchor endpoint" }, 404);
    }
  }

  // ─── Gossip Sync (called from alarm) ───────────────────────────────────

  private async gossipSync() {
    // Use gossip manager for peer sync — skip per-vertex consensus, do it in batch after
    const result = await this.gossipManager.syncFromPeers(
      this.currentRound,
      ACTIVE_WINDOW,
      async (v: any) => {
        const vertex = {
          author: v.author,
          round: v.round,
          event_hashes: v.event_hashes || [],
          events: v.events || [],
          refs: v.refs || [],
          timestamp: v.timestamp || 0,
          signature: v.signature,
        };
        await this.receiveVertex(vertex, true); // skip consensus during bulk sync
      },
    );

    // Run round advancement + commits once after all vertices are stored
    if (result.synced > 0) {
      // Fast-forward: if synced vertices are far ahead, jump to their round range
      // instead of advancing round-by-round (which would take forever with pruned history).
      const maxSyncedRound = [...this.state.storage.sql.exec(
        "SELECT MAX(round) as mr FROM dag_vertices"
      )];
      const peerMaxRound = (maxSyncedRound[0]?.mr ?? this.currentRound) as number;
      if (peerMaxRound > this.currentRound + ACTIVE_WINDOW) {
        // Jump to peerMaxRound - 2 so we can participate in current rounds
        const jumpTo = peerMaxRound - 2;
        console.log(`Fast-forward: round ${this.currentRound} → ${jumpTo} (peers at ${peerMaxRound})`);
        this.currentRound = jumpTo;
        this.setKV("current_round", this.currentRound.toString());
      }
      const advanced = this.tryAdvanceRound();
      const committed = await this.tryCommitRounds();
      if (advanced || committed) this.scheduleReactiveAlarm();
      this.broadcastToChannel("status", { type: "status.update", ...this.getConsensusStatus() });
    }
  }

  // ─── Anchor State (called from alarm) ──────────────────────────────────

  private async maybeAnchorState() {
    const effectiveSeq = this.finalizedSeq > 0 ? this.finalizedSeq : this.latestSeq;
    if (!this.anchorManager.shouldAnchor(effectiveSeq)) return;
    await this.performAnchor();
  }

  private async performAnchor(): Promise<AnchorRecord> {
    const sql = this.state.storage.sql;
    const effectiveSeq = this.finalizedSeq > 0 ? this.finalizedSeq : this.latestSeq;
    const effectiveRoot = this.finalizedRoot || this.currentRoot;

    // Get vertex count
    const vcRows = [...sql.exec("SELECT COUNT(*) as cnt FROM dag_vertices")] as any[];
    const vertexCount = (vcRows[0]?.cnt || 0) as number;

    // Get latest ZK proof hash if available
    let zkProofHash: string | undefined;
    let zkProvenBlock: number | undefined;
    const zkRows = [...sql.exec(
      "SELECT block_number, proof_hex FROM zk_proofs ORDER BY block_number DESC LIMIT 1",
    )] as any[];
    if (zkRows.length > 0) {
      zkProvenBlock = zkRows[0].block_number;
      // proof_hex is already a hash (we changed it to SHA-256 hash earlier)
      zkProofHash = zkRows[0].proof_hex;
    }

    const record = await this.anchorManager.anchor({
      stateRoot: effectiveRoot,
      finalizedSeq: effectiveSeq,
      lastCommittedRound: this.lastCommittedRound,
      shardName: this.shardName,
      nodePubkey: this.nodeIdentity?.pubkey || "",
      activeNodes: this.getActiveNodeCount(),
      vertexCount,
      zkProofHash,
      zkProvenBlock,
    });

    // Broadcast anchor event
    this.broadcastToChannel("status", {
      type: "anchor.submitted",
      anchor_id: record.id,
      berachain_tx: record.berachain_tx,
      berachain_block: record.berachain_block,
      state_root: effectiveRoot,
      finalized_seq: effectiveSeq,
    });

    return record;
  }

  // ─── WebSocket ───────────────────────────────────────────────────────────

  private handleWebSocket(ws: WebSocket) {
    ws.accept();
    this.sockets.set(ws, { channels: new Set(), isValidator: false, msgCount: 0, msgWindowStart: Date.now() });

    ws.addEventListener("message", async (event) => {
      try {
        // Per-connection message budget: max 100 msgs/sec
        const meta = this.sockets.get(ws);
        if (meta) {
          const now = Date.now();
          if (now - meta.msgWindowStart > 1000) {
            meta.msgCount = 0;
            meta.msgWindowStart = now;
          }
          meta.msgCount++;
          if (meta.msgCount > 100) {
            ws.send(JSON.stringify({ type: "error", message: "Message rate exceeded (max 100/sec)" }));
            ws.close(4029, "Rate limit exceeded");
            this.sockets.delete(ws);
            return;
          }
        }

        const msg = JSON.parse(event.data as string);
        await this.handleWsMessage(ws, msg);
      } catch (e: any) {
        ws.send(JSON.stringify({ type: "error", message: e.message }));
      }
    });

    ws.addEventListener("close", () => this.sockets.delete(ws));
    ws.addEventListener("error", () => this.sockets.delete(ws));
  }

  private async handleWsMessage(ws: WebSocket, msg: any) {
    const meta = this.sockets.get(ws);

    if (msg.type === "join") {
      if (msg.pubkey && meta) meta.pubkey = msg.pubkey;
      if (msg.pubkey) this.ensureStartingInventory(msg.pubkey);
      const blocks = [...this.state.storage.sql.exec("SELECT x, z, block_type FROM blocks")];
      const inventory = msg.pubkey ? this.getPlayerInventory(msg.pubkey) : {};

      ws.send(JSON.stringify({
        type: "state",
        blocks,
        inventory,
        root: CONSENSUS_ENABLED ? this.finalizedRoot : this.currentRoot,
        seq: CONSENSUS_ENABLED ? this.finalizedSeq : this.latestSeq,
        consensus: CONSENSUS_ENABLED ? {
          round: this.currentRound,
          active_nodes: this.getActiveNodeCount(),
          node_pubkey: this.nodeIdentity?.pubkey,
        } : undefined,
      }));

      if (CONSENSUS_ENABLED) this.scheduleAlarm();
      return;
    }

    if (msg.type === "submit") {
      const result = await this.receiveClientEvent(msg.event as SignedEvent);
      ws.send(JSON.stringify({ type: "result", ...result }));
      return;
    }

    // Subscribe to push channels: dag, status, peers, zk
    if (msg.type === "subscribe") {
      if (meta && Array.isArray(msg.channels)) {
        for (const ch of msg.channels) meta.channels.add(ch);
      }
      ws.send(JSON.stringify({ type: "subscribed", channels: Array.from(meta?.channels || []) }));
      return;
    }

    // Validator registration via WS (supports both PoW and legacy modes)
    if (msg.type === "register") {
      const valid = await verifyNodeSignature(
        msg.pubkey, msg.signature,
        msg.pow_nonce
          ? JSON.stringify({ pubkey: msg.pubkey, url: msg.url || "", pow_nonce: msg.pow_nonce })
          : JSON.stringify({ pubkey: msg.pubkey, url: msg.url || "" }),
      );
      if (!valid) {
        ws.send(JSON.stringify({ type: "register.result", ok: false, error: "Invalid signature" }));
        return;
      }

      // If PoW nonce provided, register through validator registry (Sybil-resistant)
      if (msg.pow_nonce) {
        const regResult = await this.validatorRegistry.register(msg.pubkey, msg.url || "", msg.pow_nonce);
        if (!regResult.ok) {
          ws.send(JSON.stringify({ type: "register.result", ok: false, error: regResult.error }));
          return;
        }
      }

      // Also register in active_nodes for backward compat
      this.state.storage.sql.exec(
        `INSERT INTO active_nodes (pubkey, url, last_vertex_round, last_seen, is_self)
         VALUES (?, ?, 0, ?, 0)
         ON CONFLICT(pubkey) DO UPDATE SET url = ?, last_seen = ?`,
        msg.pubkey, msg.url || "", Date.now(), msg.url || "", Date.now(),
      );
      this.invalidateActiveCache();
      if (meta) { meta.isValidator = true; meta.pubkey = msg.pubkey; }
      this.scheduleAlarm();
      const peers = this.getActiveNodes();
      ws.send(JSON.stringify({ type: "register.result", ok: true, peers }));
      this.broadcastToChannel("peers", { type: "peers.update", peers });
      return;
    }

    // Submit vertex via WS (replaces POST /dag/vertex)
    if (msg.type === "vertex") {
      const vertex = msg as DAGVertex;
      if (vertex.author && !this.validatorRegistry.checkGossipRateLimit(vertex.author)) {
        ws.send(JSON.stringify({ type: "vertex.result", ok: false, error: "Vertex rate limited" }));
        return;
      }
      const result = await this.receiveVertex(vertex);
      ws.send(JSON.stringify({ type: "vertex.result", ...result }));
      return;
    }

    // Request DAG sync (one-time pull, replaces GET /dag/sync)
    if (msg.type === "sync") {
      const sql = this.state.storage.sql;
      const afterRound = msg.after_round || 0;
      const limit = Math.min(msg.limit || 500, 500);
      const vertices = [...sql.exec(
        "SELECT hash, author, round, events_json, refs_json, signature, received_at FROM dag_vertices WHERE round > ? ORDER BY round ASC, hash ASC LIMIT ?",
        afterRound, limit,
      )].map((r: any) => ({
        hash: r.hash, author: r.author, round: r.round,
        events_json: r.events_json, refs_json: r.refs_json, signature: r.signature,
      }));
      const commits = [...sql.exec(
        "SELECT round, anchor_hash, committed_at FROM dag_commits WHERE round >= ? ORDER BY round ASC",
        afterRound,
      )];
      ws.send(JSON.stringify({
        type: "sync.result", vertices, commits,
        latest_round: this.currentRound, finalized_seq: this.finalizedSeq,
      }));
      return;
    }

    // Request status (one-time, replaces GET /dag/status)
    if (msg.type === "status") {
      ws.send(JSON.stringify({ type: "status.result", ...this.getConsensusStatus() }));
      return;
    }

    ws.send(JSON.stringify({ type: "error", message: "Unknown message type" }));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CONSENSUS ENGINE
  // ═══════════════════════════════════════════════════════════════════════════

  // ─── Receive Client Event (→ pending pool) ──────────────────────────────

  private async receiveClientEvent(
    event: SignedEvent,
  ): Promise<{ ok: boolean; seq?: number; pending?: boolean; error?: string }> {
    // 0. Rate limiting
    if (!this.validatorRegistry.checkRateLimit(event.pubkey)) {
      return { ok: false, error: "Rate limited — too many events, try again later" };
    }

    // 1. Verify signature
    const valid = await this.verifySignature(event);
    if (!valid) return { ok: false, error: "Invalid signature" };

    // 2. Compute event hash
    const eventHash = await computeEventHash(event);

    // 3. Check if already finalized
    const finalized = [...this.state.storage.sql.exec(
      "SELECT consensus_seq FROM consensus_events WHERE event_hash = ?", eventHash,
    )];
    if (finalized.length > 0) return { ok: true, seq: finalized[0].consensus_seq as number };

    // 4. Check if already pending
    const pending = [...this.state.storage.sql.exec(
      "SELECT hash FROM pending_events WHERE hash = ?", eventHash,
    )];
    if (pending.length > 0) return { ok: true, pending: true };

    if (CONSENSUS_ENABLED && this.getActiveNodeCount() >= MIN_NODES_FOR_CONSENSUS) {
      // Consensus mode: validate rules optimistically, add to pending pool
      const ruleCheck = this.validateRules(event);
      if (!ruleCheck.ok) return ruleCheck;

      this.state.storage.sql.exec(
        "INSERT OR IGNORE INTO pending_events (hash, type, payload, pubkey, signature, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        eventHash,
        event.type,
        typeof event.payload === "string" ? event.payload : JSON.stringify(event.payload),
        event.pubkey,
        event.signature,
        event.timestamp,
      );

      // Broadcast optimistic update to clients
      const payload = typeof event.payload === "string" ? JSON.parse(event.payload) : event.payload;
      this.broadcast({
        type: "pending",
        event: { type: event.type, payload, pubkey: event.pubkey, hash: eventHash },
      });

      // Try to create a vertex immediately if we have pending events
      await this.maybeCreateVertex();

      return { ok: true, pending: true };
    } else {
      // Fallback: direct apply (no consensus, legacy mode)
      return this.directApplyEvent(event, eventHash);
    }
  }

  // ─── Direct Apply (legacy / single-node mode) ──────────────────────────

  private async directApplyEvent(
    event: SignedEvent,
    eventHash: string,
  ): Promise<{ ok: boolean; seq?: number; error?: string }> {
    const ruleCheck = this.validateRules(event);
    if (!ruleCheck.ok) return ruleCheck;

    // Deduplicate
    const existing = [...this.state.storage.sql.exec("SELECT seq FROM events WHERE hash = ?", eventHash)];
    if (existing.length > 0) return { ok: true, seq: existing[0].seq as number };

    // Append to legacy events table
    this.state.storage.sql.exec(
      "INSERT INTO events (type, payload, pubkey, signature, timestamp, hash) VALUES (?, ?, ?, ?, ?, ?)",
      event.type,
      typeof event.payload === "string" ? event.payload : JSON.stringify(event.payload),
      event.pubkey, event.signature, event.timestamp, eventHash,
    );

    const seqRows = [...this.state.storage.sql.exec("SELECT MAX(seq) as seq FROM events")];
    const newSeq = seqRows[0].seq as number;
    this.latestSeq = newSeq;

    const payload = typeof event.payload === "string" ? JSON.parse(event.payload) : event.payload;
    await this.applyEvent(event.type, payload, event.pubkey);
    this.currentRoot = await sha256(this.currentRoot + eventHash);

    this.broadcast({
      type: "event.finalized",
      event: { type: event.type, payload, pubkey: event.pubkey, seq: newSeq, hash: eventHash },
    });
    this.broadcastToChannel("status", { type: "status.update", ...this.getConsensusStatus() });

    return { ok: true, seq: newSeq };
  }

  // ─── Vertex Creation ────────────────────────────────────────────────────

  private async maybeCreateVertex() {
    if (!this.nodeIdentity) return;

    // Don't create if we already have a vertex this round
    const existing = [...this.state.storage.sql.exec(
      "SELECT hash FROM dag_vertices WHERE author = ? AND round = ?",
      this.nodeIdentity.pubkey, this.currentRound,
    )];
    if (existing.length > 0) return;

    await this.createAndBroadcastVertex();
  }

  private async createAndBroadcastVertex() {
    if (!this.nodeIdentity) return;

    // Gather pending events
    const pendingRows = [...this.state.storage.sql.exec(
      "SELECT hash, type, payload, pubkey, signature, timestamp FROM pending_events ORDER BY timestamp ASC LIMIT 500",
    )];

    const events: SignedEvent[] = pendingRows.map((r: any) => ({
      type: r.type,
      payload: JSON.parse(r.payload),
      pubkey: r.pubkey,
      signature: r.signature,
      timestamp: r.timestamp,
    }));
    const eventHashes: string[] = pendingRows.map((r: any) => r.hash);

    // Get strong parents: vertices from previous round
    const refs = this.getStrongParents();

    const vertex: DAGVertex = {
      author: this.nodeIdentity.pubkey,
      round: this.currentRound,
      event_hashes: eventHashes,
      events,
      refs,
      timestamp: Date.now(),
      signature: "",
    };

    vertex.signature = await signVertex(this.nodeIdentity, vertex);
    const vHash = await computeVertexHash(vertex);

    // Store locally
    this.storeVertex(vHash, vertex);

    // Update self in active_nodes (receiveVertex does this for peer vertices, but not for self-created ones)
    this.state.storage.sql.exec(
      `INSERT INTO active_nodes (pubkey, url, last_vertex_round, last_seen, is_self)
       VALUES (?, ?, ?, ?, 1)
       ON CONFLICT(pubkey) DO UPDATE SET last_vertex_round = MAX(last_vertex_round, ?), last_seen = ?`,
      this.nodeIdentity!.pubkey, this.nodeIdentity!.url, vertex.round, Date.now(), vertex.round, Date.now(),
    );
    this.invalidateActiveCache();

    // Clear pending events that were included
    if (eventHashes.length > 0) {
      const placeholders = eventHashes.map(() => "?").join(",");
      sql.exec(`DELETE FROM pending_events WHERE hash IN (${placeholders})`, ...eventHashes);
    }

    // Try round advancement + commits
    const advanced = this.tryAdvanceRound();
    const committed = await this.tryCommitRounds();
    if (advanced || committed) this.scheduleReactiveAlarm();

    // Broadcast: WS push to local validators + gossip flood to remote peers
    await this.broadcastVertexToPeers(vertex);
    this.gossipManager.gossipVertex(vertex).catch(() => {});
  }

  private getStrongParents(): string[] {
    if (this.currentRound === 0) return [];
    const prevVertices = [...this.state.storage.sql.exec(
      "SELECT hash FROM dag_vertices WHERE round = ? ORDER BY hash ASC",
      this.currentRound - 1,
    )];
    return prevVertices.map((r: any) => r.hash as string);
  }

  // ─── Vertex Reception ───────────────────────────────────────────────────

  private async receiveVertex(vertex: DAGVertex, skipConsensus = false): Promise<{ ok: boolean; error?: string }> {
    // 1. Verify vertex signature
    const validSig = await verifyVertexSignature(vertex);
    if (!validSig) return { ok: false, error: "Invalid vertex signature" };

    // 2. Verify all contained events' signatures
    for (const event of vertex.events) {
      const validEvent = await this.verifySignature(event);
      if (!validEvent) return { ok: false, error: "Invalid event signature in vertex" };
    }

    // 3. Reject if too far ahead — unless we need to fast-forward
    if (vertex.round > this.currentRound + ACTIVE_WINDOW) {
      // Fast-forward: jump our round to catch up with the network
      const jumpTo = vertex.round - 2;
      console.log(`Fast-forward on vertex receipt: round ${this.currentRound} → ${jumpTo}`);
      this.currentRound = jumpTo;
      this.setKV("current_round", this.currentRound.toString());
    }
    if (vertex.round > this.currentRound + ACTIVE_WINDOW) {
      return { ok: false, error: "Vertex round too far ahead" };
    }

    // 4. Compute hash and check for duplicate
    const vHash = await computeVertexHash(vertex);
    const existing = [...this.state.storage.sql.exec(
      "SELECT hash FROM dag_vertices WHERE hash = ?", vHash,
    )];
    if (existing.length > 0) return { ok: true }; // idempotent

    // 5. Check for equivocation (same author, same round)
    const equivocation = [...this.state.storage.sql.exec(
      "SELECT hash FROM dag_vertices WHERE author = ? AND round = ?",
      vertex.author, vertex.round,
    )];
    if (equivocation.length > 0) {
      // Record evidence and slash reputation
      const existingHash = (equivocation[0] as any).hash;
      await this.validatorRegistry.recordEquivocation(
        vertex.author, vertex.round, existingHash, vHash,
        this.nodeIdentity?.pubkey || "system",
      );
      // Broadcast evidence to all peers
      this.broadcast({
        type: "equivocation.detected",
        validator: vertex.author,
        round: vertex.round,
        vertex_hash_1: existingHash,
        vertex_hash_2: vHash,
      });
      return { ok: false, error: "Equivocation: duplicate vertex for same round (slashed)" };
    }

    // 6. Store + reward reputation
    this.storeVertex(vHash, vertex);
    this.validatorRegistry.rewardVertex(vertex.author, vertex.round);

    // 6b. Broadcast vertex to all WS clients (with hash for ref tracking)
    this.broadcast({
      type: "vertex.new",
      hash: vHash,
      author: vertex.author,
      round: vertex.round,
      event_hashes: vertex.event_hashes,
      refs: vertex.refs,
      timestamp: vertex.timestamp,
    });

    // 7. Update active_nodes — resolve author URL from gossip_peers if available
    const authorUrl = this.gossipManager.getPeerUrl(vertex.author) || "";
    this.state.storage.sql.exec(
      `INSERT INTO active_nodes (pubkey, url, last_vertex_round, last_seen, is_self)
       VALUES (?, ?, ?, ?, 0)
       ON CONFLICT(pubkey) DO UPDATE SET
         last_vertex_round = MAX(last_vertex_round, ?),
         last_seen = ?,
         url = CASE WHEN excluded.url != '' THEN excluded.url ELSE active_nodes.url END`,
      vertex.author, authorUrl, vertex.round, Date.now(), vertex.round, Date.now(),
    );
    this.invalidateActiveCache();

    // 8. Try round advancement + commits (skip during bulk sync for performance)
    if (!skipConsensus) {
      const advanced = this.tryAdvanceRound();
      const committed = await this.tryCommitRounds();
      if (advanced || committed) this.scheduleReactiveAlarm();
    }

    // 9. DO should also produce a vertex if it hasn't for this round
    if (!skipConsensus) await this.maybeCreateVertex();

    // Push status update to subscribers (replaces client polling)
    this.broadcastToChannel("status", { type: "status.update", ...this.getConsensusStatus() });

    return { ok: true };
  }

  private storeVertex(hash: string, vertex: DAGVertex) {
    const sql = this.state.storage.sql;

    sql.exec(
      "INSERT OR IGNORE INTO dag_vertices (hash, author, round, events_json, refs_json, signature, received_at, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      hash,
      vertex.author,
      vertex.round,
      JSON.stringify(vertex.events.map((e, i) => ({ ...e, hash: vertex.event_hashes[i] }))),
      JSON.stringify(vertex.refs),
      vertex.signature,
      Date.now(),
      vertex.timestamp,
    );

    // dag_edges removed — topologicalSort uses in-memory refs_json
  }

  // ─── Round Advancement ──────────────────────────────────────────────────

  private tryAdvanceRound(): boolean {
    const activeCount = this.getActiveNodeCount();
    if (activeCount < MIN_NODES_FOR_CONSENSUS) return false;

    const quorum = getQuorumSize(activeCount);

    // Advance through rounds that have quorum — cap to prevent runaway
    let advanced = false;
    for (let i = 0; i < 20; i++) {
      const countRows = [...this.state.storage.sql.exec(
        "SELECT COUNT(DISTINCT author) as cnt FROM dag_vertices WHERE round = ?",
        this.currentRound,
      )];
      const count = (countRows[0]?.cnt ?? 0) as number;

      if (count >= quorum) {
        this.currentRound++;
        advanced = true;
      } else {
        break;
      }
    }
    if (advanced) {
      this.setKV("current_round", this.currentRound.toString());
      this.invalidateActiveCache();
    }
    return advanced;
  }

  // ─── Commit Rule ────────────────────────────────────────────────────────

  private async tryCommitRounds(): Promise<boolean> {
    const activeCount = this.getActiveNodeCount();
    if (activeCount < MIN_NODES_FOR_CONSENSUS) return false;

    // Check uncommitted even rounds — cap at 10 commits per cycle to avoid CPU exhaustion
    let commitsThisCycle = 0;
    for (let r = this.lastCommittedRound + 2; r <= this.currentRound - 1 && commitsThisCycle < 10; r += 2) {
      // Already committed?
      const existing = [...this.state.storage.sql.exec(
        "SELECT round FROM dag_commits WHERE round = ?", r,
      )];
      if (existing.length > 0) continue;

      // Build vertex data for this round and next
      const verticesByRound = new Map<number, VertexNode[]>();
      for (const roundNum of [r, r + 1]) {
        const rows = [...this.state.storage.sql.exec(
          "SELECT hash, author, round, events_json, refs_json FROM dag_vertices WHERE round = ?",
          roundNum,
        )];
        verticesByRound.set(roundNum, rows.map((row: any) => ({
          hash: row.hash,
          author: row.author,
          round: row.round,
          event_hashes: JSON.parse(row.events_json).map((e: any) => e.hash),
          refs: JSON.parse(row.refs_json),
        })));
      }

      // Get active pubkeys for leader selection
      const activePubkeys = this.getActivePubkeys();
      const leader = await selectLeader(r, activePubkeys);

      const result = checkCommit(r, leader, verticesByRound, activeCount);
      if (result.committed && result.anchorHash) {
        await this.commitAnchor(r, result.anchorHash);
        commitsThisCycle++;
      }
    }
    return commitsThisCycle > 0;
  }

  private async commitAnchor(round: number, anchorHash: string) {
    const sql = this.state.storage.sql;

    // Collect vertex signatures + data for this round (persisted for ZK prover after pruning)
    const roundVertices = [...sql.exec(
      "SELECT author, signature, round, events_json, refs_json, timestamp FROM dag_vertices WHERE round = ?", round
    )] as any[];
    const commitSigs = JSON.stringify(roundVertices.map((v: any) => {
      let eventHashes: string[] = [];
      try {
        const events = JSON.parse(v.events_json || "[]");
        eventHashes = events.map((e: any) => e.hash || "").filter(Boolean);
      } catch {}
      let refs: string[] = [];
      try { refs = JSON.parse(v.refs_json || "[]"); } catch {}
      return {
        pubkey: v.author,
        signature: v.signature,
        round: v.round,
        event_hashes: eventHashes,
        refs,
        timestamp: v.timestamp || 0,
      };
    }));

    // Record commit with signatures
    sql.exec(
      "INSERT OR IGNORE INTO dag_commits (round, anchor_hash, committed_at, signatures_json) VALUES (?, ?, ?, ?)",
      round, anchorHash, Date.now(), commitSigs,
    );

    // Build vertex map for topological sort — load vertices within a bounded window
    // Only need vertices back to lastCommittedRound (older ones are already finalized)
    const minRound = Math.max(0, this.lastCommittedRound - 2);
    const allVertices = [...sql.exec(
      "SELECT hash, author, round, events_json, refs_json FROM dag_vertices WHERE round >= ? AND round <= ?",
      minRound, round,
    )];
    const vertexMap = new Map<string, VertexNode>();
    const eventsMap = new Map<string, any[]>(); // hash → parsed events (avoid re-query + re-parse)
    for (const row of allVertices as any[]) {
      const events = JSON.parse(row.events_json);
      const refs = JSON.parse(row.refs_json);
      vertexMap.set(row.hash, {
        hash: row.hash,
        author: row.author,
        round: row.round,
        event_hashes: events.map((e: any) => e.hash),
        refs,
      });
      eventsMap.set(row.hash, events);
    }

    // Get already-finalized event hashes — scoped to relevant rounds
    const finalizedVertices = new Set<string>(
      [...sql.exec("SELECT DISTINCT vertex_hash FROM consensus_events WHERE round >= ?", minRound)].map((r: any) => r.vertex_hash),
    );
    const finalizedEventHashes = new Set<string>(
      [...sql.exec("SELECT event_hash FROM consensus_events WHERE round >= ?", minRound)].map((r: any) => r.event_hash),
    );

    // Topological sort from anchor
    const orderedVertices = topologicalSort(anchorHash, vertexMap, finalizedVertices);

    // Extract and apply events in order — use pre-loaded eventsMap instead of re-querying
    const newlyFinalizedHashes: string[] = [];

    // Batch accumulators: SQL rows and WS broadcast entries are collected during the loop,
    // then flushed once after the loop.  For N events this reduces sql.exec calls from
    // 2N individual INSERTs to 2 bulk INSERT … VALUES (…) statements, and WS sends from
    // N individual broadcast calls to 1 "finalized_batch" message.
    const consensusRows: [string, string, number, number][] = []; // [event_hash, vertex_hash, round, finalized_at]
    const eventRows: [string, string, string, string, number, string][] = []; // [type, payload, pubkey, sig, ts, hash]
    const finalizedBroadcasts: object[] = [];

    const nowMs = Date.now();
    for (const vNode of orderedVertices) {
      const events = eventsMap.get(vNode.hash);
      if (!events) continue;

      for (const event of events) {
        const eventHash = event.hash || await computeEventHash(event);

        // Skip already finalized (in-memory set lookup, not DB query)
        if (finalizedEventHashes.has(eventHash)) continue;

        // Validate rules against current finalized state
        const ruleCheck = this.validateRules(event);
        if (!ruleCheck.ok) continue; // skip invalid

        // Apply to state
        const payload = typeof event.payload === "string" ? JSON.parse(event.payload) : event.payload;
        await this.applyEvent(event.type, payload, event.pubkey);

        // Track for batch pending cleanup
        newlyFinalizedHashes.push(eventHash);

        // Accumulate consensus_events row
        this.finalizedSeq++;
        consensusRows.push([eventHash, vNode.hash, round, nowMs]);

        // Accumulate legacy events row
        eventRows.push([
          event.type,
          typeof event.payload === "string" ? event.payload : JSON.stringify(event.payload),
          event.pubkey, event.signature, event.timestamp, eventHash,
        ]);
        this.latestSeq++;

        // Advance finalized root
        this.finalizedRoot = await sha256(this.finalizedRoot + eventHash);

        // Accumulate broadcast entry (sent as one batch message after the loop)
        finalizedBroadcasts.push({
          type: event.type,
          payload,
          pubkey: event.pubkey,
          hash: eventHash,
          consensus_seq: this.finalizedSeq,
        });
      }
    }

    // ── Batch SQL flush ──────────────────────────────────────────────────────
    // Insert all consensus_events rows in a single multi-row VALUES statement.
    if (consensusRows.length > 0) {
      const placeholders = consensusRows.map(() => "(?, ?, ?, ?)").join(", ");
      sql.exec(
        `INSERT OR IGNORE INTO consensus_events (event_hash, vertex_hash, round, finalized_at) VALUES ${placeholders}`,
        ...consensusRows.flat(),
      );
    }

    // Insert all legacy events rows in a single multi-row VALUES statement.
    if (eventRows.length > 0) {
      const placeholders = eventRows.map(() => "(?, ?, ?, ?, ?, ?)").join(", ");
      sql.exec(
        `INSERT OR IGNORE INTO events (type, payload, pubkey, signature, timestamp, hash) VALUES ${placeholders}`,
        ...eventRows.flat(),
      );
    }

    // ── Batch WebSocket broadcast ────────────────────────────────────────────
    // Send all finalized events as one "finalized_batch" message instead of one
    // "finalized" message per event.
    if (finalizedBroadcasts.length > 0) {
      this.broadcast({ type: "finalized_batch", events: finalizedBroadcasts });
    }

    // Remove finalized events from pending pool
    if (newlyFinalizedHashes.length > 0) {
      const placeholders = newlyFinalizedHashes.map(() => "?").join(",");
      sql.exec(`DELETE FROM pending_events WHERE hash IN (${placeholders})`, ...newlyFinalizedHashes);
    }

    // Update state
    this.lastCommittedRound = round;
    this.setKV("last_committed_round", round.toString());
    this.setKV("finalized_seq", this.finalizedSeq.toString());
    this.setKV("finalized_root", this.finalizedRoot);

    // Anchor root periodically
    if (this.finalizedSeq > 0 && this.finalizedSeq % 100 === 0) {
      sql.exec(
        "INSERT INTO roots (root, seq, timestamp) VALUES (?, ?, ?)",
        this.finalizedRoot, this.finalizedSeq, Date.now(),
      );
    }

    // Broadcast commit notification
    this.broadcast({
      type: "commit",
      round,
      finalized_seq: this.finalizedSeq,
      root: this.finalizedRoot,
    });

    // ── Light Client Header Generation ─────────────────────────────────────
    // Produce a compact block header for light client sync (Handshake SPV-inspired)
    {
      const prevHeaders = [...sql.exec(
        "SELECT block_number, state_root FROM block_headers ORDER BY block_number DESC LIMIT 1",
      )] as any[];
      const prevHeaderHash = prevHeaders.length > 0
        ? await sha256(`header:${prevHeaders[0].block_number}:${prevHeaders[0].state_root}`)
        : await sha256("genesis");
      const activeNodes = this.getActiveNodes();
      const validatorSetHash = await sha256(activeNodes.map(n => n.pubkey).sort().join(","));
      sql.exec(
        "INSERT OR IGNORE INTO block_headers (block_number, state_root, prev_header_hash, validator_set_hash, timestamp, tx_count) VALUES (?, ?, ?, ?, ?, ?)",
        round, this.finalizedRoot, prevHeaderHash, validatorSetHash, nowMs, finalizedBroadcasts.length,
      );
    }

    // ── Reputation Decay (Handshake name-expiry inspired) ────────────────
    // Every 50 committed rounds, decay inactive validators by 1%
    if (round % 50 === 0) {
      sql.exec(
        `UPDATE validators SET reputation = MAX(0, reputation - CAST(reputation * 0.01 AS INTEGER))
         WHERE status = 'active' AND last_active_round < ?`,
        round - 100,
      );
    }

    // Reward validators who participated in this committed round
    const commitParticipants = [...this.state.storage.sql.exec(
      "SELECT DISTINCT author FROM dag_vertices WHERE round = ?", round,
    )].map((r: any) => r.author as string);
    this.validatorRegistry.rewardCommitParticipation(commitParticipants);

    console.log(`Committed round=${round} anchor=${anchorHash.slice(0, 12)} seq=${this.finalizedSeq}`);
  }

  // ─── Peer Communication ─────────────────────────────────────────────────

  private async broadcastVertexToPeers(vertex: DAGVertex) {
    // First, push to all validators connected via WebSocket
    const wsPeers = new Set<string>();
    for (const [ws, meta] of this.sockets) {
      if (meta.isValidator && meta.pubkey !== vertex.author) {
        try {
          ws.send(JSON.stringify({ type: "vertex.new", ...vertex }));
          if (meta.pubkey) wsPeers.add(meta.pubkey);
        } catch { this.sockets.delete(ws); }
      }
    }

    // HTTP fallback removed — gossipManager.gossipVertex handles remote flood with signed envelopes
  }

  private async syncFromPeers() {
    const peers = this.getActiveNodes().filter(n => !n.is_self && n.url);
    for (const peer of peers) {
      try {
        const syncUrl = new URL(peer.url || this.nodeUrl);
        syncUrl.pathname = syncUrl.pathname.replace(/\/$/, "") + "/dag/sync";
        syncUrl.searchParams.set("after_round", String(Math.max(0, this.currentRound - ACTIVE_WINDOW)));
        const res = await fetch(syncUrl.toString());
        if (!res.ok) continue;
        const data = await res.json() as any;

        for (const v of data.vertices || []) {
          // Reconstruct DAGVertex from sync data
          const vertex: DAGVertex = {
            author: v.author,
            round: v.round,
            event_hashes: JSON.parse(v.events_json).map((e: any) => e.hash || ""),
            events: JSON.parse(v.events_json),
            refs: JSON.parse(v.refs_json),
            timestamp: 0,
            signature: v.signature,
          };
          await this.receiveVertex(vertex, true); // skip consensus during bulk sync
        }
        // Run consensus once after bulk sync
        const advanced = this.tryAdvanceRound();
        const committed = await this.tryCommitRounds();
        if (advanced || committed) this.scheduleReactiveAlarm();
        break; // synced from one peer is enough
      } catch {
        // try next peer
      }
    }
  }

  // ─── Active Node Tracking (cached per round) ────────────────────────────

  private invalidateActiveCache() {
    this._activeCache = null;
  }

  private ensureActiveCache() {
    if (this._activeCache && this._activeCache.round === this.currentRound) return;
    const minRound = Math.max(0, this.currentRound - ACTIVE_WINDOW);
    // A node is active if:
    //  1. It has produced a vertex within the last ACTIVE_WINDOW rounds, OR
    //  2. It is this node (is_self), OR
    //  3. It was seen recently via gossip (last_seen within 5 minutes) — prevents
    //     deadlock when nodes are at different rounds but all alive
    const recentlySeen = Date.now() - 5 * 60_000;
    const rows = [...this.state.storage.sql.exec(
      "SELECT pubkey, url, last_vertex_round, last_seen, is_self FROM active_nodes WHERE last_vertex_round >= ? OR is_self = 1 OR last_seen >= ? ORDER BY pubkey",
      minRound, recentlySeen,
    )].map((r: any) => ({
      pubkey: r.pubkey as string,
      url: r.url as string,
      last_vertex_round: r.last_vertex_round as number,
      last_seen: r.last_seen as number,
      is_self: !!r.is_self,
    }));
    this._activeCache = {
      round: this.currentRound,
      count: Math.max(rows.length, 1),
      pubkeys: rows.map(r => r.pubkey),
      nodes: rows,
    };
  }

  private getActiveNodeCount(): number {
    this.ensureActiveCache();
    return this._activeCache!.count;
  }

  private getActivePubkeys(): string[] {
    this.ensureActiveCache();
    return this._activeCache!.pubkeys;
  }

  private getActiveNodes(): { pubkey: string; url: string; last_vertex_round: number; is_self: boolean }[] {
    this.ensureActiveCache();
    return this._activeCache!.nodes;
  }

  private getConsensusStatus(): ConsensusStatus {
    // In single-node / direct-apply mode, report latestSeq as finalized
    const effectiveSeq = this.finalizedSeq > 0 ? this.finalizedSeq : this.latestSeq;
    const effectiveRoot = this.finalizedRoot || this.currentRoot;
    return {
      node_pubkey: this.nodeIdentity?.pubkey || "",
      current_round: this.currentRound,
      finalized_seq: effectiveSeq,
      finalized_root: effectiveRoot,
      last_committed_round: this.lastCommittedRound,
      active_nodes: this.getActiveNodeCount(),
      pending_events: this.getPendingEventCount(),
    };
  }

  private getPendingEventCount(): number {
    const rows = [...this.state.storage.sql.exec("SELECT COUNT(*) as cnt FROM pending_events")];
    return (rows[0]?.cnt ?? 0) as number;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // GAME LOGIC (unchanged from v0.2)
  // ═══════════════════════════════════════════════════════════════════════════

  // ─── Signature Verification (player events) ─────────────────────────────

  private async verifySignature(event: SignedEvent): Promise<boolean> {
    try {
      const pubKeyBytes = this.b64ToBytes(event.pubkey);
      const signatureBytes = this.b64ToBytes(event.signature);
      const dataToVerify = JSON.stringify({
        type: event.type,
        payload: typeof event.payload === "string" ? JSON.parse(event.payload) : event.payload,
        timestamp: event.timestamp,
      });
      const dataBytes = new TextEncoder().encode(dataToVerify);
      const key = await crypto.subtle.importKey("raw", pubKeyBytes, "Ed25519", false, ["verify"]);
      return await crypto.subtle.verify("Ed25519", key, signatureBytes, dataBytes);
    } catch {
      return false;
    }
  }

  // ─── Rule Validation ────────────────────────────────────────────────────

  private validateRules(event: SignedEvent): { ok: boolean; error?: string } {
    const payload = typeof event.payload === "string" ? JSON.parse(event.payload) : event.payload;
    const pubkey = event.pubkey;

    switch (event.type) {
      case "place": {
        const item = this.blockTypeToItem(payload.block);
        if (this.getItemCount(pubkey, item) <= 0) {
          return { ok: false, error: `Not enough ${item} in inventory` };
        }
        return { ok: true };
      }
      case "break": {
        const block = [...this.state.storage.sql.exec(
          "SELECT block_type FROM blocks WHERE x = ? AND z = ?", payload.x, payload.z,
        )];
        if (block.length === 0) return { ok: false, error: "No block at position" };
        return { ok: true };
      }
      case "transfer": {
        const owner = [...this.state.storage.sql.exec(
          "SELECT owner_pubkey FROM ownership WHERE asset_id = ?", payload.assetId,
        )];
        if (owner.length === 0 || owner[0].owner_pubkey !== pubkey) {
          return { ok: false, error: "Not the owner of this asset" };
        }
        return { ok: true };
      }
      case "craft":
        return this.validateCraftRecipe(pubkey, payload.recipe);
      case "contract.deploy": {
        if (!payload.wasm_b64) return { ok: false, error: "Missing wasm_b64" };
        const wasmBytes = this.b64ToBytes(payload.wasm_b64);
        if (wasmBytes.length > 1_048_576) return { ok: false, error: "WASM too large (max 1MB)" };
        return { ok: true };
      }
      case "contract.call": {
        if (!payload.contract || !payload.method) return { ok: false, error: "Missing contract/method" };
        const rows = [...this.state.storage.sql.exec("SELECT 1 FROM contracts WHERE address = ?", payload.contract)];
        if (rows.length === 0) return { ok: false, error: "Contract not found" };
        return { ok: true };
      }
      case "oracle.request": {
        if (!payload.contract || !payload.callback_method || !payload.url) {
          return { ok: false, error: "Missing contract, callback_method, or url" };
        }
        const agg = payload.aggregation || "identical";
        if (!["identical", "median", "majority"].includes(agg)) {
          return { ok: false, error: `Invalid aggregation: ${agg}` };
        }
        // Verify the contract exists
        const cRows = [...this.state.storage.sql.exec("SELECT 1 FROM contracts WHERE address = ?", payload.contract)];
        if (cRows.length === 0) return { ok: false, error: "Contract not found" };
        return { ok: true };
      }
      case "trigger.create": {
        if (!payload.contract || !payload.method || !payload.interval_ms) {
          return { ok: false, error: "Missing contract, method, or interval_ms" };
        }
        if (payload.interval_ms < MIN_INTERVAL_MS || payload.interval_ms > MAX_INTERVAL_MS) {
          return { ok: false, error: `interval_ms must be between ${MIN_INTERVAL_MS} and ${MAX_INTERVAL_MS}` };
        }
        const tRows = [...this.state.storage.sql.exec("SELECT 1 FROM contracts WHERE address = ?", payload.contract)];
        if (tRows.length === 0) return { ok: false, error: "Contract not found" };
        return { ok: true };
      }
      case "trigger.remove": {
        if (!payload.trigger_id) return { ok: false, error: "Missing trigger_id" };
        return { ok: true };
      }
      case "token.transfer": {
        if (!payload.to || !payload.amount) return { ok: false, error: "Missing to or amount" };
        const amt = BigInt(payload.amount);
        if (amt <= 0n) return { ok: false, error: "Amount must be positive" };
        const denom = payload.denom || "PERSIST";
        // Sender address derived from pubkey
        const senderRows = [...this.state.storage.sql.exec("SELECT address FROM accounts WHERE pubkey = ?", pubkey)];
        if (senderRows.length === 0) return { ok: false, error: "Sender account not found — call /wallet/faucet first" };
        const senderAddr = senderRows[0].address as string;
        const balance = this.accountManager.getBalance(senderAddr, denom);
        if (balance < amt) return { ok: false, error: `Insufficient balance: have ${balance}, need ${amt}` };
        // Validate recipient address
        if (!validateAddress(payload.to)) return { ok: false, error: "Invalid recipient address" };
        return { ok: true };
      }
      case "oracle.response":
        // System-generated — always valid if it reaches here
        return { ok: true };
      default:
        return { ok: false, error: `Unknown event type: ${event.type}` };
    }
  }

  // ─── State Mutation ─────────────────────────────────────────────────────

  private async applyEvent(type: string, payload: any, pubkey: string) {
    const sql = this.state.storage.sql;
    switch (type) {
      case "place":
        sql.exec("INSERT OR REPLACE INTO blocks (x, z, block_type, placed_by) VALUES (?, ?, ?, ?)",
          payload.x, payload.z, payload.block, pubkey);
        this.addToInventory(pubkey, this.blockTypeToItem(payload.block), -1);
        this.stateTree.markDirty(`block:${payload.x},${payload.z}`, `${payload.block}:${pubkey}`);
        this.stateTree.markDirty(`inv:${pubkey}:${this.blockTypeToItem(payload.block)}`, null); // simplified; full value set on next commit
        break;
      case "break": {
        const rows = [...sql.exec("SELECT block_type FROM blocks WHERE x = ? AND z = ?", payload.x, payload.z)];
        if (rows.length > 0) {
          sql.exec("DELETE FROM blocks WHERE x = ? AND z = ?", payload.x, payload.z);
          this.addToInventory(pubkey, this.blockTypeToItem(rows[0].block_type as number), 1);
          this.stateTree.markDirty(`block:${payload.x},${payload.z}`, null);
        }
        break;
      }
      case "transfer":
        sql.exec("UPDATE ownership SET owner_pubkey = ? WHERE asset_id = ?", payload.toPubkey, payload.assetId);
        break;
      case "craft":
        this.applyCraft(pubkey, payload.recipe);
        break;
      case "token.transfer": {
        const senderRows = [...sql.exec("SELECT address FROM accounts WHERE pubkey = ?", pubkey)];
        const senderAddr = senderRows[0].address as string;
        const denom = payload.denom || "PERSIST";
        const amount = BigInt(payload.amount);
        const err = this.accountManager.transfer(senderAddr, payload.to, denom, amount);
        if (err) console.warn(`Transfer failed in apply: ${err}`);
        this.stateTree.markDirty(`bal:${senderAddr}:${denom}`, null);
        this.stateTree.markDirty(`bal:${payload.to}:${denom}`, null);
        this.broadcast({ type: "token.transfer", from: senderAddr, to: payload.to, denom, amount: amount.toString() });
        break;
      }
      case "contract.deploy": {
        const wasmBytes = this.b64ToBytes(payload.wasm_b64);
        const address = await this.contractExecutor.deploy(wasmBytes, pubkey, this.latestSeq);
        this.stateTree.markDirty(`deployed:${address}`, `${pubkey}:${address}`);
        this.broadcast({ type: "contract.deployed", address, deployer: pubkey });
        break;
      }
      case "contract.call": {
        const args = payload.args_b64 ? this.b64ToBytes(payload.args_b64) : new Uint8Array();
        const result = await this.contractExecutor.call(
          payload.contract, payload.method, args, pubkey, payload.gas || 1_000_000,
        );
        if (!result.ok) {
          console.warn(`Contract call failed: ${result.error}`);
        }
        // Track flushed contract state keys for incremental Merkle
        if (result.flushed_keys) {
          for (const fk of result.flushed_keys) {
            const stateKey = `contract:${fk.contract}:${fk.key}`;
            this.stateTree.markDirty(stateKey, fk.deleted ? null : stateKey);
          }
        }
        // Process any oracle/trigger requests emitted by the contract
        if (result.oracle_requests) {
          await this.processOracleEmits(payload.contract, result.oracle_requests);
        }
        if (result.trigger_requests) {
          await this.processTriggerEmits(payload.contract, pubkey, result.trigger_requests);
        }
        break;
      }
      case "oracle.request": {
        const reqId = await computeRequestId(
          payload.contract, payload.callback_method, payload.url, Date.now(),
        );
        this.state.storage.sql.exec(
          `INSERT OR IGNORE INTO oracle_requests (id, contract, callback_method, url, json_path, aggregation, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`,
          reqId, payload.contract, payload.callback_method, payload.url,
          payload.json_path || null, payload.aggregation || "identical", Date.now(),
        );
        // Ensure alarm is scheduled to process this
        this.scheduleAlarm();
        break;
      }
      case "oracle.response": {
        // Deliver oracle result to the contract's callback
        const contract = payload.contract;
        const method = payload.callback_method;
        const resultBytes = new TextEncoder().encode(JSON.stringify({
          request_id: payload.request_id,
          value: payload.value,
          sources: payload.sources,
        }));
        const callResult = await this.contractExecutor.call(
          contract, method, resultBytes, "oracle:system", 1_000_000,
        );
        if (!callResult.ok) {
          console.warn(`Oracle callback failed: ${callResult.error}`);
        }
        // Process any nested emits from the callback
        if (callResult.oracle_requests) {
          await this.processOracleEmits(contract, callResult.oracle_requests);
        }
        if (callResult.trigger_requests) {
          await this.processTriggerEmits(contract, "oracle:system", callResult.trigger_requests);
        }
        break;
      }
      case "trigger.create": {
        const triggerId = await this.triggerManager.create(
          payload.contract, payload.method, payload.args_b64 || "",
          payload.interval_ms, pubkey, payload.max_fires || 0,
        );
        this.broadcast({ type: "trigger.created", trigger_id: triggerId, contract: payload.contract });
        // Re-schedule alarm to account for new trigger
        this.scheduleAlarm();
        break;
      }
      case "trigger.remove": {
        this.triggerManager.remove(payload.trigger_id, pubkey);
        this.broadcast({ type: "trigger.removed", trigger_id: payload.trigger_id });
        break;
      }
    }
  }

  // ─── Oracle Processing ──────────────────────────────────────────────────

  /**
   * Process oracle requests emitted by a contract during execution.
   * Creates oracle_requests records for later fetching.
   */
  private async processOracleEmits(fallbackContract: string, requests: OracleRequestEmit[]) {
    for (const req of requests) {
      const contract = req.contract || fallbackContract;
      const reqId = await computeRequestId(contract, req.callback_method, req.url, Date.now());
      this.state.storage.sql.exec(
        `INSERT OR IGNORE INTO oracle_requests (id, contract, callback_method, url, json_path, aggregation, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`,
        reqId, contract, req.callback_method, req.url,
        req.json_path || null, req.aggregation, Date.now(),
      );
    }
    this.scheduleAlarm();
  }

  /**
   * Process trigger management requests emitted by a contract during execution.
   */
  private async processTriggerEmits(fallbackContract: string, creator: string, requests: TriggerRequestEmit[]) {
    for (const req of requests) {
      const contract = req.contract || fallbackContract;
      if (req.action === "create" && req.method && req.interval_ms) {
        await this.triggerManager.create(
          contract, req.method, req.args_b64 || "",
          req.interval_ms, creator, req.max_fires || 0,
        );
      } else if (req.action === "remove" && req.trigger_id) {
        this.triggerManager.remove(req.trigger_id, creator);
      }
    }
    this.scheduleAlarm();
  }

  /**
   * Fetch pending oracle requests and deliver results.
   * In single-node mode: fetch directly and deliver.
   * In multi-node mode: each node fetches, results aggregated via consensus.
   */
  private async processPendingOracles() {
    const pending = [...this.state.storage.sql.exec(
      "SELECT * FROM oracle_requests WHERE status = 'pending' ORDER BY created_at ASC LIMIT 10",
    )] as any[];

    for (const req of pending) {
      try {
        // Mark as fetching
        this.state.storage.sql.exec(
          "UPDATE oracle_requests SET status = 'fetching' WHERE id = ?", req.id,
        );

        // Fetch the data
        const rawResponse = await fetchWithTimeout(req.url);
        const extracted = extractJsonPath(rawResponse, req.json_path);

        if (this.getActiveNodeCount() < MIN_NODES_FOR_CONSENSUS) {
          // Single-node mode: deliver directly
          this.state.storage.sql.exec(
            "UPDATE oracle_requests SET status = 'delivered', result_value = ?, result_sources = 1, delivered_at = ? WHERE id = ?",
            extracted, Date.now(), req.id,
          );

          // Call the contract's callback
          await this.applyEvent("oracle.response", {
            contract: req.contract,
            callback_method: req.callback_method,
            request_id: req.id,
            value: extracted,
            sources: 1,
          }, "oracle:system");

          this.broadcast({
            type: "oracle.delivered",
            request_id: req.id,
            contract: req.contract,
          });
        } else {
          // Multi-node mode: store our result, wait for peer results
          const nodePubkey = this.nodeIdentity?.pubkey || "self";
          this.state.storage.sql.exec(
            `INSERT OR REPLACE INTO oracle_responses (request_id, node_pubkey, value, fetched_at)
             VALUES (?, ?, ?, ?)`,
            req.id, nodePubkey, extracted, Date.now(),
          );

          // Check if we have enough responses for consensus
          const responses = [...this.state.storage.sql.exec(
            "SELECT * FROM oracle_responses WHERE request_id = ?", req.id,
          )] as any[];

          const quorum = Math.ceil((this.getActiveNodeCount() * 2) / 3) + 1;
          const aggregated = aggregate(
            responses.map(r => ({
              node_pubkey: r.node_pubkey,
              request_id: r.request_id,
              value: r.value,
              fetched_at: r.fetched_at,
            })),
            req.aggregation as AggregationStrategy,
            quorum,
          );

          if (aggregated) {
            this.state.storage.sql.exec(
              "UPDATE oracle_requests SET status = 'delivered', result_value = ?, result_sources = ?, delivered_at = ? WHERE id = ?",
              aggregated.value, aggregated.sources, Date.now(), req.id,
            );

            await this.applyEvent("oracle.response", {
              contract: req.contract,
              callback_method: req.callback_method,
              request_id: req.id,
              value: aggregated.value,
              sources: aggregated.sources,
            }, "oracle:system");

            this.broadcast({
              type: "oracle.delivered",
              request_id: req.id,
              contract: req.contract,
            });
          } else {
            // Not enough responses yet — mark as aggregating
            this.state.storage.sql.exec(
              "UPDATE oracle_requests SET status = 'aggregating' WHERE id = ?", req.id,
            );
          }
        }
      } catch (e: any) {
        console.warn(`Oracle fetch failed for ${req.id}: ${e.message}`);
        this.state.storage.sql.exec(
          "UPDATE oracle_requests SET status = 'failed' WHERE id = ?", req.id,
        );
      }
    }
  }

  /**
   * Fire all cron triggers that are due.
   */
  private async fireDueTriggers() {
    const due = this.triggerManager.getDueTriggers();

    for (const trigger of due) {
      try {
        const args = trigger.args_b64 ? this.b64ToBytes(trigger.args_b64) : new Uint8Array();
        const result = await this.contractExecutor.call(
          trigger.contract, trigger.method, args, `trigger:${trigger.id}`, 1_000_000,
        );

        this.triggerManager.markFired(trigger.id);

        if (!result.ok) {
          console.warn(`Trigger ${trigger.id} call failed: ${result.error}`);
        } else {
          // Process any emits from the triggered call
          if (result.oracle_requests) {
            await this.processOracleEmits(trigger.contract, result.oracle_requests);
          }
          if (result.trigger_requests) {
            await this.processTriggerEmits(trigger.contract, trigger.creator, result.trigger_requests);
          }
        }

        this.broadcast({
          type: "trigger.fired",
          trigger_id: trigger.id,
          contract: trigger.contract,
          method: trigger.method,
          ok: result.ok,
        });
      } catch (e: any) {
        console.warn(`Trigger ${trigger.id} error: ${e.message}`);
        this.triggerManager.markFired(trigger.id); // Advance even on error to avoid stuck triggers
      }
    }
  }

  // ─── Inventory ──────────────────────────────────────────────────────────

  private ensureStartingInventory(pubkey: string) {
    const existing = [...this.state.storage.sql.exec("SELECT COUNT(*) as cnt FROM inventory WHERE pubkey = ?", pubkey)];
    if ((existing[0]?.cnt ?? 0) === 0) {
      for (const [item, count] of [["dirt", 20], ["stone", 10], ["wood", 10]] as [string, number][]) {
        this.state.storage.sql.exec("INSERT OR IGNORE INTO inventory (pubkey, item, count) VALUES (?, ?, ?)", pubkey, item, count);
      }
    }
  }

  private getPlayerInventory(pubkey: string): Record<string, number> {
    const rows = [...this.state.storage.sql.exec("SELECT item, count FROM inventory WHERE pubkey = ? AND count > 0", pubkey)];
    return Object.fromEntries(rows.map((r: any) => [r.item, r.count]));
  }

  private getItemCount(pubkey: string, item: string): number {
    const rows = [...this.state.storage.sql.exec("SELECT count FROM inventory WHERE pubkey = ? AND item = ?", pubkey, item)];
    return rows.length > 0 ? (rows[0].count as number) : 0;
  }

  private addToInventory(pubkey: string, item: string, delta: number) {
    const current = this.getItemCount(pubkey, item);
    this.state.storage.sql.exec(
      "INSERT INTO inventory (pubkey, item, count) VALUES (?, ?, ?) ON CONFLICT(pubkey, item) DO UPDATE SET count = ?",
      pubkey, item, current + delta, current + delta,
    );
  }

  // ─── Crafting ───────────────────────────────────────────────────────────

  private static readonly RECIPES: Record<string, Record<string, number>> = {
    house: { dirt: 5, wood: 5 },
    wall: { stone: 3 },
    bridge: { wood: 8 },
  };

  private validateCraftRecipe(pubkey: string, recipe: string): { ok: boolean; error?: string } {
    const cost = PersistiaWorld.RECIPES[recipe];
    if (!cost) return { ok: false, error: `Unknown recipe: ${recipe}` };
    for (const [item, needed] of Object.entries(cost)) {
      if (this.getItemCount(pubkey, item) < needed) {
        return { ok: false, error: `Not enough ${item} (need ${needed}, have ${this.getItemCount(pubkey, item)})` };
      }
    }
    return { ok: true };
  }

  private applyCraft(pubkey: string, recipe: string) {
    const cost = PersistiaWorld.RECIPES[recipe];
    if (!cost) return;
    for (const [item, needed] of Object.entries(cost)) this.addToInventory(pubkey, item, -needed);
    this.addToInventory(pubkey, recipe, 1);
  }

  private blockTypeToItem(blockType: number): string {
    return { 1: "dirt", 2: "stone", 3: "wood", 4: "grass" }[blockType] || "unknown";
  }

  // ─── Broadcast ──────────────────────────────────────────────────────────

  private broadcast(msg: any, channel?: string) {
    const str = JSON.stringify(msg);
    for (const [ws, meta] of this.sockets) {
      try {
        // No channel: broadcast to all. With channel: only to explicit subscribers.
        if (!channel || meta.channels.has(channel)) {
          ws.send(str);
        }
      } catch { this.sockets.delete(ws); }
    }
  }

  private broadcastToChannel(channel: string, msg: any) {
    const str = JSON.stringify(msg);
    for (const [ws, meta] of this.sockets) {
      try {
        if (meta.channels.has(channel)) ws.send(str);
      } catch { this.sockets.delete(ws); }
    }
  }

  // ─── Helpers ────────────────────────────────────────────────────────────

  private json(data: any, status = 200): Response {
    return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
  }

  private b64ToBytes(b64: string): Uint8Array {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
}
