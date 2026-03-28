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
  signDataSchnorr,
  type NodeIdentity,
} from "./node-identity";
import { ContractExecutor, type OracleRequestEmit, type TriggerRequestEmit, type DeployRequestEmit } from "./contract-executor";
import {
  aggregate, extractJsonPath, fetchWithTimeout, computeRequestId,
  type OracleRequest, type NodeFetchResult, type AggregationStrategy,
} from "./oracle";
import { TriggerManager, MIN_INTERVAL_MS, MAX_INTERVAL_MS } from "./triggers";
import { computeStateCommitment, generateStateProof, verifyProof, IncrementalStateTree, type HashFunctionName } from "./state-proofs";
import { type CrossShardMessage, type CrossShardReceipt, validateMessage, createCrossShardMessage } from "./cross-shard";
import { GossipManager, expandEnvelope, type GossipEnvelope, type SyncResponsePayload } from "./gossip";
import { AnchorManager, type AnchorConfig, type AnchorRecord } from "./anchoring";
import { ValidatorRegistry, verifyPoW } from "./validator-registry";
import { AccountManager, pubkeyB64ToAddress, validateAddress } from "./wallet";
import { MPPHandler, type MPPConfig, type MPPReceipt } from "./mpp";
import { dispatchApiRoute } from "./ai-services";
import { ServiceAttestationManager } from "./service-attestations";
import {
  createChallengeWindow, generateChallengeId, validateChallengeSubmission,
  resolveWithProof, resolveTimeout, buildChallengeWitness,
  insertChallengeWindow, getChallengeWindow, finalizeExpiredWindows,
  insertChallenge, getActiveChallenge, findTimedOutChallenges,
  updateChallengeStatus, updateWindowStatus,
  DEFAULT_CHALLENGE_BOND, DEFAULT_CHALLENGE_WINDOW, DEFAULT_RESPONSE_WINDOW,
} from "./fraud-proofs";
import { WitnessRecorder } from "./deterministic-replay";
import type { ChallengeRecord } from "./types";
import { FeeSplitter, type FeeSplitConfig, PERSIST_FEE_SPLIT } from "./fee-splitter";
import { computeAdaptiveInterval, SMOOTHING_WINDOW, type AdaptiveSignals } from "./adaptive-params";
import { SnapshotManager, type SnapshotMeta } from "./snapshot";
import { ServiceFederation, type FederationMode, type FederationResult } from "./service-federation";
import type { ServiceRequestPayload, ServiceResponsePayload } from "./gossip";
import { ProviderRegistry, type ProviderRecord } from "./provider-registry";
import { ProviderProxy } from "./provider-proxy";
import { SettlementBatcher } from "./settlement";

// ─── Configuration ────────────────────────────────────────────────────────────

const CONSENSUS_ENABLED = true;
const ROUND_INTERVAL_MS = 60_000;  // 60s rounds — slower to let single prover keep up
const MAX_EVENTS_PER_VERTEX = 500;  // cap events per vertex
const PENDING_EVENT_TTL_MS = 5 * 60_000;  // expire pending events older than 5 minutes
const MIN_NODES_FOR_CONSENSUS = 3;

// ─── Durable Object ──────────────────────────────────────────────────────────

export class PersistiaWorldV4 implements DurableObject {
  state: DurableObjectState;
  env: any;
  // Lightweight rate-limiter per WebSocket — uses WeakMap so closed sockets are GC'd automatically
  private _wsRateLimit: WeakMap<WebSocket, { msgCount: number; msgWindowStart: number }> = new WeakMap();

  // Legacy state (backward compat when consensus off)
  currentRoot: string = "";
  latestSeq: number = 0;

  // Consensus state
  nodeIdentity: NodeIdentity | null = null;
  contractExecutor!: ContractExecutor;
  triggerManager!: TriggerManager;
  gossipManager!: GossipManager;
  anchorManager!: AnchorManager;
  snapshotManager!: SnapshotManager;
  validatorRegistry!: ValidatorRegistry;
  accountManager!: AccountManager;
  mppHandler!: MPPHandler;
  attestationMgr!: ServiceAttestationManager;
  feeSplitter!: FeeSplitter;
  serviceFederation!: ServiceFederation;
  providerRegistry!: ProviderRegistry;
  providerProxy!: ProviderProxy;
  settlementBatcher!: SettlementBatcher;
  shardName: string = "global-world";
  currentRound: number = 0;
  finalizedSeq: number = 0;
  finalizedRoot: string = "";
  lastCommittedRound: number = -2;
  nodeUrl: string = "";

  // ─── Adaptive parameters (EIP-1559 style) ───────────────────────────
  private _consecutiveEmptyRounds: number = 0;
  private _adaptiveEnabled: boolean = true;
  private _utilizationHistory: number[] = []; // last N rounds for smoothing

  // ─── Incremental state commitment ──────────────────────────────────
  stateTree!: IncrementalStateTree;

  // ─── Cached queries (invalidated on round change / node join) ──────
  private _activeCache: {
    round: number;
    count: number;
    pubkeys: string[];
    nodes: { pubkey: string; url: string; last_vertex_round: number; is_self: boolean }[];
  } | null = null;

  private _initialized = false;

  // ─── Speculative execution cache ──────────────────────────────────
  // Pre-executed events: hash → true (already applied speculatively).
  // On commit, if an event was speculatively executed, skip re-execution.
  // Cleared on each commit cycle to prevent stale speculation.
  private _speculativelyApplied = new Set<string>();
  private _speculativeRound = -1; // round when speculation was last run
  private _witnessRecorder = new WitnessRecorder();
  private _nextAlarmTime: number = 0;
  private _alarmCycle: number = 0;      // monotonic counter for deferring non-critical work

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

    // Batch 7: network config + governance
    sql.exec(`
      CREATE TABLE network_config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL DEFAULT 'system');
      CREATE TABLE governance_proposals (id TEXT PRIMARY KEY, param_key TEXT NOT NULL, proposed_value TEXT NOT NULL, activate_at_round INTEGER NOT NULL, proposer TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, activated_at INTEGER, quorum_reached_at INTEGER);
      CREATE INDEX idx_governance_proposals_status ON governance_proposals(status);
      CREATE TABLE governance_proposal_votes (proposal_id TEXT NOT NULL, voter TEXT NOT NULL, vote TEXT NOT NULL, reputation INTEGER NOT NULL DEFAULT 100, voted_at INTEGER NOT NULL, PRIMARY KEY (proposal_id, voter));
      CREATE TABLE network_config_history (id INTEGER PRIMARY KEY AUTOINCREMENT, param_key TEXT NOT NULL, old_value TEXT, new_value TEXT NOT NULL, changed_by TEXT NOT NULL, proposal_id TEXT, round INTEGER NOT NULL, changed_at INTEGER NOT NULL);
    `);

    // Seed default network config values
    const defaults: [string, string][] = [
      ["round_interval_ms", "60000"],
      ["max_events_per_vertex", "500"],
      ["pending_event_ttl_ms", "300000"],
      ["min_nodes_for_consensus", "3"],
      ["state_hash_function", "poseidon2"],
    ];
    for (const [k, v] of defaults) {
      sql.exec(
        "INSERT OR IGNORE INTO network_config (key, value, updated_at, updated_by) VALUES (?, ?, ?, 'genesis')",
        k, v, Date.now(),
      );
    }
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
      ["network_config", `CREATE TABLE network_config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL DEFAULT 'system')`],
      ["governance_proposals", `CREATE TABLE governance_proposals (id TEXT PRIMARY KEY, param_key TEXT NOT NULL, proposed_value TEXT NOT NULL, activate_at_round INTEGER NOT NULL, proposer TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, activated_at INTEGER, quorum_reached_at INTEGER); CREATE INDEX idx_governance_proposals_status ON governance_proposals(status)`],
      ["governance_proposal_votes", `CREATE TABLE governance_proposal_votes (proposal_id TEXT NOT NULL, voter TEXT NOT NULL, vote TEXT NOT NULL, reputation INTEGER NOT NULL DEFAULT 100, voted_at INTEGER NOT NULL, PRIMARY KEY (proposal_id, voter))`],
      ["network_config_history", `CREATE TABLE network_config_history (id INTEGER PRIMARY KEY AUTOINCREMENT, param_key TEXT NOT NULL, old_value TEXT, new_value TEXT NOT NULL, changed_by TEXT NOT NULL, proposal_id TEXT, round INTEGER NOT NULL, changed_at INTEGER NOT NULL)`],
      ["block_mutations", `CREATE TABLE block_mutations (block_number INTEGER NOT NULL, key TEXT NOT NULL, new_value TEXT, is_delete INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (block_number, key)); CREATE INDEX idx_block_mutations_block ON block_mutations(block_number)`],
    ] as const;
    for (const [name, ddl] of newTables) {
      try {
        const exists = [...sql.exec("SELECT name FROM sqlite_master WHERE type='table' AND name=?", name)] as any[];
        if (exists.length === 0) sql.exec(ddl);
      } catch {}
    }

    // Migration: seed default network config values if table was just created
    try {
      const configCount = [...sql.exec("SELECT COUNT(*) as cnt FROM network_config")] as any[];
      if ((configCount[0]?.cnt ?? 0) === 0) {
        const defaults: [string, string][] = [
          ["round_interval_ms", "60000"],
          ["max_events_per_vertex", "500"],
          ["pending_event_ttl_ms", "300000"],
          ["min_nodes_for_consensus", "3"],
        ];
        for (const [k, v] of defaults) {
          sql.exec(
            "INSERT OR IGNORE INTO network_config (key, value, updated_at, updated_by) VALUES (?, ?, ?, 'genesis')",
            k, v, Date.now(),
          );
        }
      }
    } catch {}

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

    // Migration: add grumpkin_x/grumpkin_y columns to active_nodes and gossip_peers
    try {
      const anCols = [...sql.exec("PRAGMA table_info(active_nodes)")] as any[];
      if (!anCols.some((c: any) => c.name === "grumpkin_x")) {
        sql.exec("ALTER TABLE active_nodes ADD COLUMN grumpkin_x TEXT");
      }
      if (!anCols.some((c: any) => c.name === "grumpkin_y")) {
        sql.exec("ALTER TABLE active_nodes ADD COLUMN grumpkin_y TEXT");
      }
    } catch {}
    try {
      const gpCols = [...sql.exec("PRAGMA table_info(gossip_peers)")] as any[];
      if (!gpCols.some((c: any) => c.name === "grumpkin_x")) {
        sql.exec("ALTER TABLE gossip_peers ADD COLUMN grumpkin_x TEXT");
      }
      if (!gpCols.some((c: any) => c.name === "grumpkin_y")) {
        sql.exec("ALTER TABLE gossip_peers ADD COLUMN grumpkin_y TEXT");
      }
    } catch {}

    // Migration: add schnorr_sig column to dag_vertices for ZK proving
    try {
      const vCols = [...sql.exec("PRAGMA table_info(dag_vertices)")] as any[];
      if (!vCols.some((c: any) => c.name === "schnorr_sig")) {
        sql.exec("ALTER TABLE dag_vertices ADD COLUMN schnorr_sig TEXT");
      }
    } catch {}

    // Migration: state expiry — chunk archive tracking
    try {
      sql.exec(`
        CREATE TABLE IF NOT EXISTS chunk_archive (
          chunk_x INTEGER NOT NULL,
          chunk_z INTEGER NOT NULL,
          r2_key TEXT NOT NULL,
          block_count INTEGER NOT NULL,
          archived_at INTEGER NOT NULL,
          PRIMARY KEY (chunk_x, chunk_z)
        )
      `);
    } catch {}

    // Migration: add accessed_at to blocks for state expiry tracking
    try {
      const blockCols = [...sql.exec("PRAGMA table_info(blocks)")] as any[];
      if (!blockCols.some((c: any) => c.name === "accessed_at")) {
        sql.exec("ALTER TABLE blocks ADD COLUMN accessed_at INTEGER DEFAULT 0");
      }
    } catch {}

    // Migration: epoch proof aggregation table (SnarkFold)
    try {
      sql.exec(`
        CREATE TABLE IF NOT EXISTS epoch_proofs (
          epoch INTEGER PRIMARY KEY,
          block_start INTEGER NOT NULL,
          block_end INTEGER NOT NULL,
          proof_count INTEGER NOT NULL,
          proof_hex TEXT NOT NULL,
          proof_bytes BLOB,
          public_values TEXT,
          state_root TEXT NOT NULL,
          genesis_root TEXT,
          submitted_at INTEGER NOT NULL,
          verified INTEGER NOT NULL DEFAULT 0
        )
      `);
    } catch {}

    // Migration: fraud proof challenge tables
    try {
      sql.exec(`
        CREATE TABLE IF NOT EXISTS challenge_windows (
          block_number INTEGER PRIMARY KEY,
          proposer TEXT NOT NULL,
          post_state_root TEXT NOT NULL,
          expires_at_round INTEGER NOT NULL,
          status TEXT NOT NULL DEFAULT 'open'
        )
      `);
      sql.exec(`
        CREATE TABLE IF NOT EXISTS fraud_challenges (
          id TEXT PRIMARY KEY,
          block_number INTEGER NOT NULL,
          challenger TEXT NOT NULL,
          bond_hold_id TEXT NOT NULL,
          claimed_invalid_root TEXT,
          response_deadline_round INTEGER NOT NULL,
          status TEXT NOT NULL DEFAULT 'challenged',
          created_at INTEGER NOT NULL,
          resolved_at INTEGER,
          resolution_proof_hash TEXT,
          resolution_type TEXT
        )
      `);
      sql.exec("CREATE INDEX IF NOT EXISTS idx_fraud_challenges_block ON fraud_challenges(block_number)");
      sql.exec("CREATE INDEX IF NOT EXISTS idx_fraud_challenges_status ON fraud_challenges(status)");
    } catch {}

    // Migration: conviction voting — add staked_at column for time-weighted votes
    try {
      const voteCols = [...sql.exec("PRAGMA table_info(governance_proposal_votes)")] as any[];
      if (!voteCols.some((c: any) => c.name === "staked_at")) {
        sql.exec("ALTER TABLE governance_proposal_votes ADD COLUMN staked_at INTEGER");
        // Backfill: set staked_at = voted_at for existing votes
        sql.exec("UPDATE governance_proposal_votes SET staked_at = voted_at WHERE staked_at IS NULL");
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

    // State tree (hash function is immutable genesis config)
    const hashFn = this.getNetworkParamString("state_hash_function", "poseidon2") as HashFunctionName;
    this.stateTree = new IncrementalStateTree(hashFn);

    // Restore adaptive tuning preference (persisted so deploys don't re-enable it)
    const adaptiveKV = this.getKV("adaptive_enabled");
    if (adaptiveKV !== null) this._adaptiveEnabled = adaptiveKV === "1";

    // Contract executor + trigger manager
    this.contractExecutor = new ContractExecutor(sql, this.env.BLOB_STORE);
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

    // Fee splitter (distributes MPP payments: node/validators/burn/treasury)
    const feeSplitConfig: FeeSplitConfig = {
      treasuryAddress: this.env.MPP_RECIPIENT || "persistia1default",
      ...PERSIST_FEE_SPLIT,
    };
    this.feeSplitter = new FeeSplitter(sql, this.accountManager, this.validatorRegistry, feeSplitConfig);

    // Service attestation tables (created before identity is available)
    ServiceAttestationManager.initTables(sql);
    FeeSplitter.initTables(sql);
    AccountManager.initBurnTable(sql);
    AccountManager.initHoldsTable(sql);
    ProviderRegistry.initTables(sql);

    // External provider marketplace
    this.providerRegistry = new ProviderRegistry(sql, this.accountManager);
    this.settlementBatcher = new SettlementBatcher(this.accountManager, this.providerRegistry);

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
    this.snapshotManager = new SnapshotManager(sql, this.env.BLOB_STORE);

    // Node identity
    if (CONSENSUS_ENABLED) {
      this.nodeIdentity = await loadOrCreateNodeIdentity(sql, this.nodeUrl);
      this.gossipManager.setIdentity(this.nodeIdentity);

      // Service attestation manager (needs node identity for signing)
      this.attestationMgr = new ServiceAttestationManager(sql, this.nodeIdentity);
      await this.attestationMgr.init();

      // Service federation (pools validator compute for multi-node AI service calls)
      this.serviceFederation = new ServiceFederation(
        this.gossipManager, this.validatorRegistry,
        this.nodeIdentity.pubkey, this.nodeUrl,
      );

      // Register this node's available services (all AI services)
      this.validatorRegistry.updateServices(this.nodeIdentity.pubkey, [
        "llm", "tts", "stt", "image", "embed", "translate", "vision",
        "classify", "summarize", "code", "screenshot",
      ]);

      // Provider proxy (routes to external providers with failover, falls back to local Workers AI)
      this.providerProxy = new ProviderProxy(
        this.providerRegistry, this.settlementBatcher, this.attestationMgr,
      );

      // Bootstrap from seed nodes if configured
      if (this.env.SEED_NODES) {
        const seeds = (this.env.SEED_NODES as string).split(",").map(s => s.trim()).filter(Boolean);
        if (seeds.length > 0) {
          this.gossipManager.bootstrapFromSeeds(seeds)
            .then(async (n) => {
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

                // If this is a fresh node, try snapshot bootstrap instead of full replay
                if (this.finalizedSeq === 0 && this.currentRound === 0) {
                  await this.bootstrapFromSnapshot(seeds);
                }
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
      const initGrumpkinX = this.nodeIdentity.grumpkinPublicKey ? "0x" + this.nodeIdentity.grumpkinPublicKey.x.toString(16).padStart(64, "0") : null;
      const initGrumpkinY = this.nodeIdentity.grumpkinPublicKey ? "0x" + this.nodeIdentity.grumpkinPublicKey.y.toString(16).padStart(64, "0") : null;
      sql.exec(
        `INSERT INTO active_nodes (pubkey, url, last_vertex_round, last_seen, is_self, grumpkin_x, grumpkin_y)
         VALUES (?, ?, ?, ?, 1, ?, ?)
         ON CONFLICT(pubkey) DO UPDATE SET url = ?, last_seen = ?, is_self = 1, last_vertex_round = MAX(last_vertex_round, ?), grumpkin_x = ?, grumpkin_y = ?`,
        this.nodeIdentity.pubkey, this.nodeIdentity.url, selfLastVertexRound, Date.now(), initGrumpkinX, initGrumpkinY,
        this.nodeIdentity.url, Date.now(), selfLastVertexRound, initGrumpkinX, initGrumpkinY,
      );
      this.invalidateActiveCache();
    }

    // Always ensure alarm is scheduled on startup
    if (CONSENSUS_ENABLED) {
      this.scheduleAlarm();
    }
  }

  // ─── Snapshot Bootstrap (fast catchup for new nodes) ──────────────────

  private async bootstrapFromSnapshot(seedUrls: string[]): Promise<boolean> {
    for (const seedUrl of seedUrls) {
      try {
        // Check if peer has a snapshot
        const metaRes = await fetch(`${seedUrl.replace(/\/$/, "")}/snapshot/latest`, {
          headers: { "Accept": "application/json" },
        });
        if (!metaRes.ok) continue;

        const snapInfo = await metaRes.json() as any;
        if (!snapInfo.anchor_id || !snapInfo.snapshot_hash) continue;
        if (snapInfo.finalized_seq <= 0) continue;

        console.log(
          `Snapshot found on ${seedUrl}: seq=${snapInfo.finalized_seq} ` +
          `round=${snapInfo.last_committed_round} hash=${snapInfo.snapshot_hash.slice(0, 12)}`,
        );

        // Download and apply
        const meta = await this.snapshotManager.applySnapshot(
          seedUrl, snapInfo.anchor_id, snapInfo.snapshot_hash,
        );
        if (!meta) {
          console.warn(`Snapshot from ${seedUrl} failed verification, trying next peer`);
          continue;
        }

        // Update consensus state from snapshot
        this.finalizedSeq = meta.finalized_seq;
        this.finalizedRoot = meta.finalized_root;
        this.lastCommittedRound = meta.last_committed_round;
        this.currentRound = meta.last_committed_round;
        this.setKV("finalized_seq", String(meta.finalized_seq));
        this.setKV("finalized_root", meta.finalized_root);
        this.setKV("last_committed_round", String(meta.last_committed_round));
        this.setKV("current_round", String(meta.last_committed_round));

        // Reload latestSeq from events table (snapshot includes events)
        const seqRows = [...this.state.storage.sql.exec("SELECT seq FROM events ORDER BY seq DESC LIMIT 1")];
        this.latestSeq = seqRows[0]?.seq ?? 0;
        const rootRows = [...this.state.storage.sql.exec("SELECT root FROM roots ORDER BY id DESC LIMIT 1")];
        this.currentRoot = rootRows[0]?.root ?? this.finalizedRoot;

        // Invalidate state tree — it needs to rebuild from the snapshot's state
        this.stateTree.invalidate();
        this.invalidateActiveCache();

        console.log(
          `Snapshot bootstrap complete: seq=${this.finalizedSeq} round=${this.currentRound} ` +
          `— gossip sync will catch up from here`,
        );

        return true;
      } catch (e: any) {
        console.warn(`Snapshot bootstrap from ${seedUrl} failed: ${e.message}`);
      }
    }

    console.log("No snapshot available from peers — falling back to full event replay");
    return false;
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

  // ─── Network Config ─────────────────────────────────────────────────────

  private static GOVERNABLE_PARAMS: Record<string, { min: number; max: number }> = {
    round_interval_ms: { min: 1_000, max: 180_000 },
    max_events_per_vertex: { min: 5, max: 500 },
    pending_event_ttl_ms: { min: 30_000, max: 3_600_000 },
    min_nodes_for_consensus: { min: 1, max: 100 },
    reactive_alarm_delay_ms: { min: 100, max: 30_000 },
    challenge_bond_amount: { min: 100, max: 100_000 },
    challenge_window_rounds: { min: 10, max: 500 },
    challenge_response_rounds: { min: 10, max: 200 },
    validator_bond_minimum: { min: 1000, max: 1_000_000 },
  };

  private getNetworkParam(key: string, fallback: number): number {
    try {
      const rows = [...this.state.storage.sql.exec("SELECT value FROM network_config WHERE key = ?", key)];
      if (rows.length > 0) return parseInt(rows[0].value as string) || fallback;
    } catch {}
    return fallback;
  }

  private getNetworkParamString(key: string, fallback: string): string {
    try {
      const rows = [...this.state.storage.sql.exec("SELECT value FROM network_config WHERE key = ?", key)];
      if (rows.length > 0) return rows[0].value as string;
    } catch {}
    return fallback;
  }

  private static IMMUTABLE_PARAMS = new Set(["state_hash_function"]);

  private setNetworkParam(key: string, value: string, changedBy: string, proposalId?: string) {
    if (PersistiaWorldV4.IMMUTABLE_PARAMS.has(key)) {
      const existing = [...this.state.storage.sql.exec("SELECT value FROM network_config WHERE key = ?", key)];
      if (existing.length > 0) throw new Error(`Parameter '${key}' is immutable after genesis`);
    }
    const sql = this.state.storage.sql;
    const oldRows = [...sql.exec("SELECT value FROM network_config WHERE key = ?", key)];
    const oldValue = oldRows.length > 0 ? (oldRows[0].value as string) : null;
    sql.exec(
      "INSERT INTO network_config (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = ?, updated_by = ?",
      key, value, Date.now(), changedBy, value, Date.now(), changedBy,
    );
    sql.exec(
      "INSERT INTO network_config_history (param_key, old_value, new_value, changed_by, proposal_id, round, changed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      key, oldValue, value, changedBy, proposalId || null, this.lastCommittedRound, Date.now(),
    );
  }

  // ─── Adaptive Parameter Adjustment (EIP-1559 style) ─────────────────────

  /**
   * Called after each round commit. Adjusts round_interval_ms and
   * max_events_per_vertex based on smoothed network signals.
   *
   * Uses exponential moving average over the last SMOOTHING_WINDOW rounds
   * to prevent oscillation under bursty load patterns.
   */
  private adjustAdaptiveParams(round: number, eventsInRound: number) {
    if (!this._adaptiveEnabled) return;

    const sql = this.state.storage.sql;

    // Track consecutive empty rounds
    if (eventsInRound === 0) {
      this._consecutiveEmptyRounds++;
    } else {
      this._consecutiveEmptyRounds = 0;
    }

    const currentInterval = this.getNetworkParam("round_interval_ms", ROUND_INTERVAL_MS);
    const maxEvents = this.getNetworkParam("max_events_per_vertex", MAX_EVENTS_PER_VERTEX);
    const pendingEvents = this.getPendingEventCount();

    // Get latest ZK-proven block
    let latestProvenBlock = 0;
    try {
      const rows = [...sql.exec("SELECT MAX(block_number) as b FROM zk_proofs")];
      latestProvenBlock = (rows[0]?.b ?? 0) as number;
    } catch {}

    const signals: AdaptiveSignals = {
      pendingEvents,
      maxEventsPerVertex: maxEvents,
      eventsInLastVertex: eventsInRound,
      currentRound: this.currentRound,
      latestProvenBlock,
      lastCommittedRound: this.lastCommittedRound,
      consecutiveEmptyRounds: this._consecutiveEmptyRounds,
      utilizationHistory: this._utilizationHistory,
      // ZK circuit mutation ceiling: 512 slots, ~5 mutations/event, 2 vertices/block
      circuitMutationSlots: 512,
      avgMutationsPerEvent: 5,
      verticesPerBlock: 2,
    };

    const intervalBounds = PersistiaWorldV4.GOVERNABLE_PARAMS["round_interval_ms"];
    const eventsBounds = PersistiaWorldV4.GOVERNABLE_PARAMS["max_events_per_vertex"];
    const result = computeAdaptiveInterval(currentInterval, maxEvents, signals, intervalBounds, eventsBounds);

    // Update utilization history (sliding window)
    this._utilizationHistory.push(result.rawUtilization);
    if (this._utilizationHistory.length > SMOOTHING_WINDOW) {
      this._utilizationHistory.shift();
    }

    // Only write if actually changed (avoid spamming config history)
    if (result.newIntervalMs !== currentInterval) {
      this.setNetworkParam("round_interval_ms", result.newIntervalMs.toString(), "adaptive");
      console.log(`Adaptive: round_interval_ms ${currentInterval}→${result.newIntervalMs}ms (${result.reason})`);
    }

    if (result.newMaxEvents !== null && result.newMaxEvents !== maxEvents) {
      this.setNetworkParam("max_events_per_vertex", result.newMaxEvents.toString(), "adaptive");
      console.log(`Adaptive: max_events_per_vertex ${maxEvents}→${result.newMaxEvents}`);
    }
  }

  // ─── Shard-aware peer discovery ──────────────────────────────────────────

  private updateShardAwareUrl(requestUrl: URL) {
    const sql = this.state.storage.sql;

    let resolvedUrl: string;
    if (this.env.NODE_URL) {
      // External node: use explicitly configured URL (no shard routing)
      resolvedUrl = this.env.NODE_URL;
    } else {
      // Multi-shard deployment: construct shard-qualified URL
      resolvedUrl = `${requestUrl.origin}/?shard=${this.shardName}`;
    }

    // Update node identity URL
    this.nodeIdentity!.url = resolvedUrl;
    this.nodeUrl = resolvedUrl;
    sql.exec("UPDATE node_identity SET node_url = ?", resolvedUrl);

    // Update self in active_nodes
    sql.exec(
      "UPDATE active_nodes SET url = ? WHERE pubkey = ? AND is_self = 1",
      resolvedUrl, this.nodeIdentity!.pubkey,
    );
    this.invalidateActiveCache();

    // Auto-seed sibling shards — discover peers we lost after deploy
    // (only relevant for multi-shard deployments, not external nodes)
    if (!this.env.NODE_URL) {
      const siblingShards = (this.env.SHARD_NAMES || "node-1,node-2,node-3")
        .split(",").map((s: string) => s.trim()).filter((s: string) => s && s !== this.shardName);
      const siblingUrls = siblingShards.map((s: string) => `${requestUrl.origin}/?shard=${s}`);

      if (siblingUrls.length > 0) {
        this.gossipManager.bootstrapFromSeeds(siblingUrls)
          .then(n => {
            if (n > 0) {
              console.log(`Shard ${this.shardName}: discovered ${n} sibling peers`);
              for (const peer of this.gossipManager.getPeers()) {
                if (peer.pubkey && peer.url) {
                  sql.exec(
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
          .catch(e => console.warn(`Sibling bootstrap failed: ${e.message}`));
      }
    }
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
    if (shardHeader && shardHeader !== this.shardName) {
      const firstDiscovery = this.shardName === "global-world";
      this.shardName = shardHeader;
      if (firstDiscovery && this.nodeIdentity) {
        // Now we know our shard — fix the node URL to include shard routing
        this.updateShardAwareUrl(url);
      }
    }

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
      if (url.pathname.startsWith("/snapshot/")) {
        return this.handleSnapshotRoute(req, url);
      }
      if (url.pathname.startsWith("/mpp/")) {
        return this.handleMPPRoute(req, url);
      }
      if (url.pathname.startsWith("/governance/")) {
        return this.handleGovernanceRoute(req, url);
      }
      if (url.pathname.startsWith("/providers/")) {
        return this.handleProviderRoute(req, url);
      }
      if (url.pathname === "/app-serve") {
        return this.handleAppServe(req, url);
      }

      // MPP middleware: check if route requires payment
      const mppResult = await this.mppHandler.middleware(req);
      if (mppResult.response) return mppResult.response;

      // ─── AI Services Gateway (/api/*) ─────────────────────────────────
      if (url.pathname.startsWith("/api/")) {
        // Attestation query endpoints (free, no payment)
        if (url.pathname === "/api/attestation" || url.pathname === "/api/attestations") {
          return this.handleAttestationQuery(req, url);
        }
        if (url.pathname === "/api/verify") {
          return this.handleAttestationVerify(req, url);
        }

        // Federation mode: ?federation=verified|parallel (default: solo)
        const federationMode = (url.searchParams.get("federation") || "solo") as FederationMode;

        // Federation catalog/stats endpoint
        if (url.pathname === "/api/federation") {
          const stats = this.serviceFederation?.getStats() || { pending: 0, active_nodes: 0, federation_capable: false };
          const networkServices = this.validatorRegistry.getNetworkServices();
          const proxyStats = this.providerProxy?.getStats() || { external_providers: 0, available_models: 0, pending_settlements: 0, pending_settlement_amount: 0n };
          return this.json({
            federation: stats, network_services: networkServices,
            marketplace: {
              ...proxyStats,
              pending_settlement_amount: proxyStats.pending_settlement_amount.toString(),
              providers: this.providerRegistry.getAvailableModels().map(m => ({
                ...m, cheapest: m.cheapest.toString(), most_expensive: m.most_expensive.toString(),
              })),
            },
          });
        }

        // ─── External Provider Routing (try external providers first) ─────
        const serviceId = url.pathname.replace(/^\/api\//, "").replace(/\/$/, "");
        let response: Response;
        let usedExternalProvider = false;

        // Try external providers first (if any registered for this service)
        const bodyCloneForProxy = req.clone();
        let requestBodyText = "";
        try { requestBodyText = await bodyCloneForProxy.text(); } catch {}

        if (this.providerProxy && requestBodyText) {
          const body = JSON.parse(requestBodyText);
          const model = body.model || "";

          // Place escrow hold for external provider payment
          const buyerAddress = mppResult.receipt?.payer || "";
          let holdId: string | null = null;
          if (buyerAddress) {
            const hold = this.accountManager.placeHold(buyerAddress, "PERSIST", 500n, `api:${serviceId}`);
            if (hold.ok) holdId = hold.hold_id || null;
          }

          const proxyResult = await this.providerProxy.routeToProvider({
            serviceType: serviceId,
            model,
            requestBody: requestBodyText,
            buyerAddress,
          });

          if (proxyResult) {
            response = proxyResult.response;
            usedExternalProvider = true;

            // Release hold — settle the provider's price
            if (holdId && proxyResult.provider) {
              this.accountManager.releaseHold(holdId, proxyResult.provider.price);
            } else if (holdId) {
              this.accountManager.releaseHold(holdId);
            }
          } else {
            // No external providers — release hold and fall back to local Workers AI
            if (holdId) this.accountManager.releaseHold(holdId);

            // Reconstruct request for local dispatch
            const localReq = new Request(req.url, {
              method: req.method,
              headers: req.headers,
              body: requestBodyText,
            });
            response = await dispatchApiRoute(
              url.pathname, localReq,
              { AI: this.env.AI, BROWSER: this.env.BROWSER },
              this.attestationMgr,
            );
          }
        } else {
          response = await dispatchApiRoute(
            url.pathname, req,
            { AI: this.env.AI, BROWSER: this.env.BROWSER },
            this.attestationMgr,
          );
        }

        // If federation requested and response is OK, initiate multi-node verification
        let federationResult: FederationResult | null = null;
        if (federationMode !== "solo" && response.ok && this.serviceFederation) {
          const attestationId = response.headers.get("X-Attestation-Id") || "";
          const responseClone = response.clone();
          const outputBytes = new Uint8Array(await responseClone.arrayBuffer());
          const outputHex = Array.from(outputBytes).map(b => b.toString(16).padStart(2, "0")).join("");
          const outputHash = await sha256(outputHex);

          // Get the original request body for federation
          const bodyClone = req.clone();
          let inputBodyB64 = "";
          try {
            const bodyText = await bodyClone.text();
            inputBodyB64 = btoa(bodyText);
          } catch {}

          const service = url.pathname.replace(/^\/api\//, "").replace(/\/$/, "");
          federationResult = await this.serviceFederation.initiateRequest({
            service,
            model: "", // model is inside the body
            inputBodyB64,
            mode: federationMode,
            localOutputHash: outputHash,
            localAttestationId: attestationId,
          });
        }

        // Attach MPP receipt header + split fees if payment was verified
        if (mppResult.receipt) {
          const nodeAddr = this.nodeIdentity
            ? await import("./wallet").then(w => w.pubkeyB64ToAddress(this.nodeIdentity!.pubkey))
            : this.feeSplitter["config"].treasuryAddress;

          // Use federated payment split if multiple nodes participated
          if (federationResult && federationResult.participating_nodes.length > 1) {
            this.feeSplitter.splitFederatedPayment({
              receiptId: mppResult.receipt.receipt_id,
              originatorAddress: nodeAddr,
              participantPubkeys: federationResult.participating_nodes,
              amount: BigInt(mppResult.receipt.amount),
              denom: mppResult.receipt.denom,
              payerAddress: mppResult.receipt.payer,
            });
          } else {
            // Solo payment split
            this.feeSplitter.splitPayment({
              receiptId: mppResult.receipt.receipt_id,
              nodeAddress: nodeAddr,
              amount: BigInt(mppResult.receipt.amount),
              denom: mppResult.receipt.denom,
              payerAddress: mppResult.receipt.payer,
            });
          }

          const receiptResponse = new Response(response.body, response);
          receiptResponse.headers.set(
            "Payment-Receipt",
            MPPHandler.formatReceiptHeader(mppResult.receipt),
          );
          // Attach federation result if available
          if (federationResult) {
            receiptResponse.headers.set("X-Federation", JSON.stringify({
              mode: federationResult.mode,
              agreed: federationResult.agreed,
              participating_nodes: federationResult.participating_nodes.length,
              agreeing_nodes: federationResult.agreeing_nodes.length,
              required: federationResult.required_responses,
            }));
          }
          return receiptResponse;
        }

        // No MPP receipt — still attach federation headers if applicable
        if (federationResult) {
          const fedResponse = new Response(response.body, response);
          fedResponse.headers.set("X-Federation", JSON.stringify({
            mode: federationResult.mode,
            agreed: federationResult.agreed,
            participating_nodes: federationResult.participating_nodes.length,
            agreeing_nodes: federationResult.agreeing_nodes.length,
            required: federationResult.required_responses,
          }));
          return fedResponse;
        }
        return response;
      }

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

        case "/economics": {
          const feeStats = this.feeSplitter.getStats();
          const totalBurned = this.accountManager.totalBurned("PERSIST");
          return this.json({
            fee_splits: feeStats.totalSplits,
            total_node_earnings: feeStats.totalNodeEarnings.toString(),
            total_validator_rewards: feeStats.totalValidatorRewards.toString(),
            total_burned: totalBurned.toString(),
            total_treasury: feeStats.totalTreasuryEarnings.toString(),
            validator_pool_balance: feeStats.poolBalance.toString(),
            burn_history: this.accountManager.burnHistory({ denom: "PERSIST", limit: 10 })
              .map(b => ({ ...b, amount: b.amount.toString() })),
          });
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
          let latestProvenStatus = 0;
          try {
            const rows = [...this.state.storage.sql.exec("SELECT MAX(block_number) as b FROM zk_proofs")];
            latestProvenStatus = (rows[0]?.b ?? 0) as number;
          } catch {}
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
            round_interval_ms: this.getNetworkParam("round_interval_ms", ROUND_INTERVAL_MS),
            max_events_per_vertex: this.getNetworkParam("max_events_per_vertex", MAX_EVENTS_PER_VERTEX),
            adaptive: {
              enabled: this._adaptiveEnabled,
              prover_lag: latestProvenStatus > 0 ? this.lastCommittedRound - latestProvenStatus : null,
              consecutive_empty_rounds: this._consecutiveEmptyRounds,
            },
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
    this._alarmCycle++;
    const cycle = this._alarmCycle;
    let needsRapidFollowUp = false;

    try {
      // ── Essential work (every cycle) ─────────────────────────────────────
      // Kept minimal to stay within CF free-tier CPU (10ms) and SQLite (100 ops) limits.

      // 1. Fire due cron triggers (works regardless of consensus mode)
      await this.fireDueTriggers();

      if (CONSENSUS_ENABLED && this.nodeIdentity) {
        // 2. Pull from gossip peers
        await this.gossipSync();

        // 3. Refresh self-node last_seen so dashboard shows node as active
        this.state.storage.sql.exec(
          `UPDATE active_nodes SET last_seen = ? WHERE pubkey = ? AND is_self = 1`,
          Date.now(), this.nodeIdentity.pubkey,
        );
        this.invalidateActiveCache();

        // 4. Create vertex for current round if we haven't yet
        const existing = [...this.state.storage.sql.exec(
          "SELECT hash FROM dag_vertices WHERE author = ? AND round = ?",
          this.nodeIdentity.pubkey, this.currentRound,
        )];
        if (existing.length === 0) {
          await this.createAndBroadcastVertex();
        } else {
          this.currentRound++;
          this.setKV("current_round", this.currentRound.toString());
          this.invalidateActiveCache();
          await this.createAndBroadcastVertex();
        }

        // 5. Commit rounds — CAPPED to 3 per alarm to stay within free-tier limits.
        //    During catch-up, schedule rapid 1s follow-up alarms instead of batching 50+.
        const MAX_COMMITS_PER_ALARM = 3;
        const committed = await this.tryCommitRounds(MAX_COMMITS_PER_ALARM);
        const gap = this.currentRound - this.lastCommittedRound;
        if (committed && gap > 5) {
          needsRapidFollowUp = true; // more commits pending — come back in 1s
        }
      }

      // ── Deferred work (every Nth cycle) ──────────────────────────────────
      // Spread non-critical operations across alarm cycles to reduce per-alarm load.

      // Every 5th cycle: oracle processing + settlement + anchoring
      if (cycle % 5 === 0) {
        await this.processPendingOracles();

        if (CONSENSUS_ENABLED) {
          await this.maybeAnchorState();
        }

        if (this.settlementBatcher?.getPendingCount() > 0) {
          const result = this.settlementBatcher.flush();
          if (result.entries_settled > 0) {
            console.log(`Settlement: ${result.entries_settled} entries, ${result.total_amount} PERSIST`);
          }
        }
        this.accountManager.cleanupExpiredHolds();

        // Fraud proof: finalize expired challenge windows + resolve timed-out challenges
        this.processFraudProofCycle();

        for (const provider of this.providerRegistry.getAllActive()) {
          if (provider.down_reported_at) {
            this.providerRegistry.resolveDownReport(provider.provider_id);
          }
        }
      }

      // Every 10th cycle: all pruning operations + state expiry
      if (cycle % 10 === 0) {
        this.validatorRegistry.pruneRateLimitLog();
        this.anchorManager.pruneOldAnchors();
        this.alarmPrune();
        // Archive cold game world chunks to R2 (state expiry)
        this.archiveColdChunks().catch(e => console.warn(`Chunk archival error: ${e.message}`));
      }

      // Every 10th cycle (offset by 5): reprobe failed peers
      if (cycle % 10 === 5 && CONSENSUS_ENABLED) {
        this.gossipManager.reprobeFailedPeers().catch(() => {});
      }
    } catch (e: any) {
      console.error(`Alarm error: ${e.message}`);
    }

    // Re-schedule: rapid 1s follow-up during catch-up, normal interval otherwise
    if (needsRapidFollowUp) {
      const catchUpDelay = 1000; // 1s between catch-up alarms
      this._nextAlarmTime = Date.now() + catchUpDelay;
      this.state.storage.setAlarm(this._nextAlarmTime);
    } else {
      this.scheduleAlarm();
    }
  }

  /**
   * All pruning operations consolidated into a single method.
   * Called every 10th alarm cycle to amortize SQL cost.
   */
  private alarmPrune() {
    const sql = this.state.storage.sql;
    const oneHourAgo = Date.now() - 3_600_000;
    const oneDayAgo = Date.now() - 86_400_000;
    const sevenDaysAgo = Date.now() - 7 * 86_400_000;
    const thirtyDaysAgo = Date.now() - 30 * 86_400_000;

    // DAG data — keep last 50 committed rounds (reduced from 100 to lower storage)
    if (this.currentRound > 80) {
      const pruneBelow = Math.min(this.currentRound - 50, this.lastCommittedRound);
      sql.exec("DELETE FROM dag_vertices WHERE rowid IN (SELECT rowid FROM dag_vertices WHERE round < ? LIMIT 500)", pruneBelow);
      sql.exec("DELETE FROM consensus_events WHERE rowid IN (SELECT rowid FROM consensus_events WHERE round < ? LIMIT 500)", pruneBelow);
    }

    // Oracle requests/responses
    sql.exec("DELETE FROM oracle_requests WHERE status = 'delivered' AND delivered_at < ? LIMIT 100", oneHourAgo);
    sql.exec("DELETE FROM oracle_responses WHERE request_id NOT IN (SELECT id FROM oracle_requests) LIMIT 100");

    // ZK proofs — IVC means latest subsumes previous; keep 3
    sql.exec(`DELETE FROM zk_proofs WHERE block_number NOT IN (SELECT block_number FROM zk_proofs ORDER BY block_number DESC LIMIT 3)`);

    // Block headers — keep last 500 (reduced from 1000)
    if (this.currentRound > 600) {
      sql.exec("DELETE FROM block_headers WHERE block_number < ? LIMIT 500", this.currentRound - 500);
    }

    // Cross-shard messages
    sql.exec(
      "UPDATE xshard_outbox SET status = 'expired' WHERE status = 'pending' AND created_at < ?",
      Date.now() - 100 * this.getNetworkParam("round_interval_ms", ROUND_INTERVAL_MS),
    );
    sql.exec("DELETE FROM xshard_outbox WHERE status IN ('delivered', 'expired') AND created_at < ? LIMIT 200", oneHourAgo);
    sql.exec("DELETE FROM xshard_inbox WHERE status IN ('processed', 'failed') AND processed_at < ? LIMIT 200", oneHourAgo);

    // Consumed notes
    if (this.currentRound > 600) {
      sql.exec("DELETE FROM notes WHERE consumed = 1 AND created_round < ? LIMIT 200", this.currentRound - 500);
    }

    // MPP challenges, governance, equivocation, private state, proof claims
    sql.exec("DELETE FROM mpp_challenges WHERE consumed = 0 AND expires_at < ? LIMIT 200", Date.now());
    sql.exec("DELETE FROM governance_votes WHERE created_at < ? LIMIT 100", thirtyDaysAgo);
    sql.exec("DELETE FROM equivocation_evidence WHERE detected_at < ? LIMIT 100", sevenDaysAgo);
    sql.exec("DELETE FROM private_state WHERE updated_at < ? LIMIT 100", thirtyDaysAgo);
    sql.exec("DELETE FROM proof_claims WHERE status IN ('completed', 'expired') AND claimed_at < ? LIMIT 100", oneDayAgo);

    // dag_commits — keep last 200 rounds regardless of prover progress (reduced from 50-below-proven)
    if (this.lastCommittedRound > 250) {
      sql.exec("DELETE FROM dag_commits WHERE round < ? LIMIT 500", this.lastCommittedRound - 200);
    }

    // Merkle roots — keep last 1000 (reduced from 2000)
    const maxRootSeq = [...sql.exec("SELECT MAX(seq) as s FROM roots")];
    const latestRootSeq = (maxRootSeq[0]?.s ?? 0) as number;
    if (latestRootSeq > 1200) {
      sql.exec("DELETE FROM roots WHERE seq < ? LIMIT 500", latestRootSeq - 1000);
    }

    // Events — keep last 2000 (reduced from 5000)
    const lastAnchorRows = [...sql.exec("SELECT MAX(finalized_seq) as max_seq FROM anchors WHERE status IN ('submitted','confirmed')")];
    const lastAnchoredSeq = (lastAnchorRows[0]?.max_seq ?? 0) as number;
    const maxEvtSeq = [...sql.exec("SELECT MAX(seq) as s FROM events")];
    const latestEvtSeq = (maxEvtSeq[0]?.s ?? 0) as number;
    if (latestEvtSeq > 2500) {
      const evtPruneSeq = Math.min(
        latestEvtSeq - 2000,
        lastAnchoredSeq > 0 ? lastAnchoredSeq - 500 : latestEvtSeq - 2000,
      );
      sql.exec("DELETE FROM events WHERE seq < ? LIMIT 500", evtPruneSeq);
    }

    // Anchors — keep last 100 (new: previously unbounded)
    sql.exec("DELETE FROM anchors WHERE rowid IN (SELECT rowid FROM anchors ORDER BY created_at DESC LIMIT -1 OFFSET 100)");

    // Rate limit log — prune older than 1 hour (new: explicit cleanup)
    sql.exec("DELETE FROM rate_limit_log WHERE timestamp < ? LIMIT 500", oneHourAgo);

    // Pending events — TTL enforcement (safety net for stale pending events)
    sql.exec("DELETE FROM pending_events WHERE timestamp < ? LIMIT 200", Date.now() - 300_000);
  }

  private scheduleAlarm() {
    const now = Date.now();
    // Use the sooner of: round interval or next trigger fire time
    const nextTrigger = this.triggerManager.getNextFireTime();
    const roundTime = now + this.getNetworkParam("round_interval_ms", ROUND_INTERVAL_MS);
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
    // Use configurable minimum delay (default 5s) to prevent runaway block production
    const minDelay = this.getNetworkParam("reactive_alarm_delay_ms", 5000);
    if (this._nextAlarmTime - now <= minDelay) return; // already firing soon enough
    const reactiveTime = now + minDelay;
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
          "SELECT hash, author, round, events_json, refs_json, signature, received_at, schnorr_sig FROM dag_vertices WHERE round > ? ORDER BY round ASC, hash ASC LIMIT ?",
          afterRound, limit,
        )].map((r: any) => ({
          hash: r.hash,
          author: r.author,
          round: r.round,
          events_json: r.events_json,
          refs_json: r.refs_json,
          signature: r.signature,
          schnorr_sig: r.schnorr_sig || undefined,
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
          block_number: round,
          hash: anchor.anchor_hash,
          committed_at: anchor.committed_at,
          signatures: signatures.map((s: any) => ({
            ...s,
            message: `block:${round}`,
          })),
          events,
          mutations: events.filter((e: any) => e.type === "state_mutation"),
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
        if (req.method === "DELETE") {
          const { pubkey } = await req.json() as any;
          if (!pubkey) return this.json({ error: "pubkey required" }, 400);
          this.state.storage.sql.exec("DELETE FROM active_nodes WHERE pubkey = ? AND is_self = 0", pubkey);
          this.state.storage.sql.exec("DELETE FROM gossip_peers WHERE pubkey = ?", pubkey);
          this.invalidateActiveCache();
          return this.json({ ok: true, peers: this.getActiveNodes() });
        }
        if (req.method === "POST") {
          // Re-bootstrap from sibling shards
          const siblingShards = (this.env.SHARD_NAMES || "node-1,node-2,node-3")
            .split(",").map((s: string) => s.trim()).filter((s: string) => s && s !== this.shardName);
          const siblingUrls = siblingShards.map((s: string) => `${url.origin}/?shard=${s}`);
          const n = await this.gossipManager.bootstrapFromSeeds(siblingUrls);
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
          return this.json({ ok: true, discovered: n, peers: this.getActiveNodes() });
        }
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

      case "/admin/skip-to-round": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const skipRound = parseInt(url.searchParams.get("round") || "0");
        if (skipRound <= this.lastCommittedRound) return this.json({ error: "Round must be after current last_committed_round" }, 400);
        this.lastCommittedRound = skipRound;
        this.setKV("last_committed_round", skipRound.toString());
        return this.json({ ok: true, last_committed_round: skipRound });
      }

      case "/admin/try-commit": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        try {
          const activeCount = this.getActiveNodeCount();
          const activePubkeys = this.getActivePubkeys();
          const diagnostics: any[] = [];
          for (let r = this.lastCommittedRound + 2; r <= this.currentRound - 1 && diagnostics.length < 5; r += 2) {
            const existing = [...this.state.storage.sql.exec("SELECT round FROM dag_commits WHERE round = ?", r)];
            const verts = [...this.state.storage.sql.exec("SELECT hash, author, refs_json FROM dag_vertices WHERE round = ? OR round = ?", r, r + 1)] as any[];
            const leader = await selectLeader(r, activePubkeys);
            const roundVerts = verts.filter((v: any) => v.round === r);
            const nextVerts = verts.filter((v: any) => v.round === r + 1);
            const anchorExists = roundVerts.some((v: any) => v.author === leader);
            const refsToAnchor = anchorExists ? nextVerts.filter((v: any) => {
              const refs = JSON.parse(v.refs_json);
              return refs.some((ref: string) => roundVerts.find((rv: any) => rv.author === leader && rv.hash === ref));
            }).length : 0;
            diagnostics.push({
              round: r,
              already_committed: existing.length > 0,
              leader: leader.slice(0, 12),
              round_verts: roundVerts.length,
              next_round_verts: nextVerts.length,
              anchor_exists: anchorExists,
              refs_to_anchor: refsToAnchor,
              quorum: getQuorumSize(activeCount),
            });
          }
          const committed = await this.tryCommitRounds();
          return this.json({ ok: true, committed, last_committed_round: this.lastCommittedRound, activeCount, activePubkeys: activePubkeys.map((p: string) => p.slice(0, 12)), diagnostics });
        } catch (e: any) {
          return this.json({ ok: false, error: e.message, stack: e.stack });
        }
      }

      case "/admin/dag-stats": {
        const sql2 = this.state.storage.sql;
        const totalVerts = [...sql2.exec("SELECT COUNT(*) as cnt FROM dag_vertices")][0]?.cnt ?? 0;
        const minRound = [...sql2.exec("SELECT MIN(round) as r FROM dag_vertices")][0]?.r ?? null;
        const maxRound = [...sql2.exec("SELECT MAX(round) as r FROM dag_vertices")][0]?.r ?? null;
        const recentVerts = [...sql2.exec(
          "SELECT round, COUNT(*) as cnt FROM dag_vertices WHERE round >= ? GROUP BY round ORDER BY round ASC LIMIT 20",
          this.lastCommittedRound,
        )];
        return this.json({
          total_vertices: totalVerts,
          min_round: minRound,
          max_round: maxRound,
          current_round: this.currentRound,
          last_committed_round: this.lastCommittedRound,
          recent_vertices: recentVerts,
        });
      }

      case "/admin/set-round": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const setRound = parseInt(url.searchParams.get("round") || "0");
        if (setRound < this.lastCommittedRound) return this.json({ error: "Round must be >= last_committed_round" }, 400);
        const prevRound = this.currentRound;
        this.currentRound = setRound;
        this.setKV("current_round", setRound.toString());
        this.scheduleAlarm();
        return this.json({ ok: true, previous_round: prevRound, current_round: setRound });
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

      case "/admin/storage": {
        const sql = this.state.storage.sql;
        const tables = [
          "events", "pending_events", "dag_vertices", "dag_commits", "consensus_events",
          "blocks", "contracts", "contract_state", "roots", "zk_proofs", "block_headers",
          "anchors", "notes", "nullifiers", "accounts", "token_balances", "validators",
          "oracle_requests", "oracle_responses", "triggers", "gossip_peers", "active_nodes",
          "xshard_outbox", "xshard_inbox", "equivocation_evidence", "governance_votes",
          "proof_claims", "mpp_challenges", "mpp_receipts", "covenants", "private_state",
          "rate_limit_log", "network_config", "governance_proposals", "governance_proposal_votes",
          "network_config_history",
        ];
        const sizes: Record<string, number> = {};
        let totalRows = 0;
        for (const t of tables) {
          try {
            const rows = [...sql.exec(`SELECT COUNT(*) as c FROM ${t}`)];
            const count = (rows[0]?.c ?? 0) as number;
            sizes[t] = count;
            totalRows += count;
          } catch { sizes[t] = -1; }
        }
        // SQLite page-level stats (PRAGMA may not be supported on CF DO SQLite)
        let dbSizeBytes = 0;
        try {
          const pageCount = [...sql.exec("PRAGMA page_count")][0]?.page_count as number ?? 0;
          const pageSize = [...sql.exec("PRAGMA page_size")][0]?.page_size as number ?? 4096;
          dbSizeBytes = pageCount * pageSize;
        } catch { /* PRAGMA not available */ }
        return this.json({
          total_rows: totalRows,
          db_size_bytes: dbSizeBytes,
          db_size_mb: Math.round(dbSizeBytes / 1_048_576 * 100) / 100,
          limit_mb: 1024,
          usage_pct: Math.round(dbSizeBytes / (1024 * 1_048_576) * 10000) / 100,
          tables: sizes,
        });
      }

      case "/admin/config": {
        // GET: return all network config params
        const sql = this.state.storage.sql;
        const params = [...sql.exec("SELECT key, value, updated_at, updated_by FROM network_config ORDER BY key")] as any[];
        return this.json({ params: params.reduce((acc: any, r: any) => { acc[r.key] = { value: r.value, updated_at: r.updated_at, updated_by: r.updated_by }; return acc; }, {}) });
      }

      case "/admin/config/set": {
        // POST: admin-set a network param directly (bypasses governance)
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const { key, value } = await req.json() as any;
        if (!key || value === undefined) return this.json({ error: "Missing key or value" }, 400);
        const bounds = PersistiaWorldV4.GOVERNABLE_PARAMS[key];
        if (!bounds) return this.json({ error: `Unknown param: ${key}. Allowed: ${Object.keys(PersistiaWorldV4.GOVERNABLE_PARAMS).join(", ")}` }, 400);
        const numValue = parseInt(value);
        if (isNaN(numValue) || numValue < bounds.min || numValue > bounds.max) {
          return this.json({ error: `Value must be between ${bounds.min} and ${bounds.max}` }, 400);
        }
        this.setNetworkParam(key, numValue.toString(), "admin");
        return this.json({ ok: true, key, value: numValue });
      }

      case "/admin/adaptive": {
        // GET: return adaptive state. POST: enable/disable adaptive mode
        if (req.method === "POST") {
          const { enabled } = await req.json() as any;
          this._adaptiveEnabled = !!enabled;
          this.setKV("adaptive_enabled", this._adaptiveEnabled ? "1" : "0");
          return this.json({ ok: true, adaptive_enabled: this._adaptiveEnabled });
        }
        let latestProven = 0;
        try {
          const rows = [...sql.exec("SELECT MAX(block_number) as b FROM zk_proofs")];
          latestProven = (rows[0]?.b ?? 0) as number;
        } catch {}
        return this.json({
          adaptive_enabled: this._adaptiveEnabled,
          current_interval_ms: this.getNetworkParam("round_interval_ms", ROUND_INTERVAL_MS),
          current_max_events: this.getNetworkParam("max_events_per_vertex", MAX_EVENTS_PER_VERTEX),
          consecutive_empty_rounds: this._consecutiveEmptyRounds,
          pending_events: this.getPendingEventCount(),
          prover_lag: latestProven > 0 ? this.lastCommittedRound - latestProven : null,
          latest_proven_block: latestProven || null,
          last_committed_round: this.lastCommittedRound,
          utilization_history: this._utilizationHistory,
          smoothing_window: SMOOTHING_WINDOW,
          interval_bounds: PersistiaWorldV4.GOVERNABLE_PARAMS["round_interval_ms"],
          events_bounds: PersistiaWorldV4.GOVERNABLE_PARAMS["max_events_per_vertex"],
        });
      }

      case "/admin/config/history": {
        const sql = this.state.storage.sql;
        const history = [...sql.exec(
          "SELECT param_key, old_value, new_value, changed_by, proposal_id, round, changed_at FROM network_config_history ORDER BY changed_at DESC LIMIT 50"
        )] as any[];
        return this.json({ history });
      }

      case "/admin/governance/proposals": {
        const sql = this.state.storage.sql;
        const status = url.searchParams.get("status") || "pending";
        const proposals = [...sql.exec(
          "SELECT * FROM governance_proposals WHERE status = ? ORDER BY created_at DESC LIMIT 50", status
        )] as any[];
        // Attach vote counts
        for (const p of proposals) {
          const votes = [...sql.exec(
            "SELECT vote, COUNT(*) as cnt FROM governance_proposal_votes WHERE proposal_id = ? GROUP BY vote", p.id
          )] as any[];
          p.votes = votes.reduce((acc: any, v: any) => { acc[v.vote] = v.cnt; return acc; }, {});
        }
        return this.json({ proposals });
      }

      default:
        return this.json({ error: "Unknown admin endpoint" }, 404);
    }
  }

  // ─── Governance Routes ──────────────────────────────────────────────────

  private async handleGovernanceRoute(req: Request, url: URL): Promise<Response> {
    const sql = this.state.storage.sql;
    switch (url.pathname) {
      case "/governance/config": {
        const params = [...sql.exec("SELECT key, value, updated_at, updated_by FROM network_config ORDER BY key")] as any[];
        let latestProven = 0;
        try {
          const rows = [...sql.exec("SELECT MAX(block_number) as b FROM zk_proofs")];
          latestProven = (rows[0]?.b ?? 0) as number;
        } catch {}
        return this.json({
          params: params.reduce((acc: any, r: any) => { acc[r.key] = r.value; return acc; }, {}),
          adaptive: {
            enabled: this._adaptiveEnabled,
            consecutive_empty_rounds: this._consecutiveEmptyRounds,
            pending_events: this.getPendingEventCount(),
            prover_lag: latestProven > 0 ? this.lastCommittedRound - latestProven : null,
            latest_proven_block: latestProven || null,
            last_committed_round: this.lastCommittedRound,
            bounds: PersistiaWorldV4.GOVERNABLE_PARAMS["round_interval_ms"],
          },
        });
      }
      case "/governance/proposals": {
        const status = url.searchParams.get("status"); // null = all
        const query = status
          ? "SELECT * FROM governance_proposals WHERE status = ? ORDER BY created_at DESC LIMIT 50"
          : "SELECT * FROM governance_proposals ORDER BY created_at DESC LIMIT 50";
        const proposals = [...(status ? sql.exec(query, status) : sql.exec(query))] as any[];
        const now = Date.now();
        const MS_PER_DAY = 86_400_000;
        const activeRep = [...sql.exec("SELECT COALESCE(SUM(reputation), 0) as total FROM validators WHERE status = 'active'")] as any[];
        const totalReputation = (activeRep[0]?.total ?? 0) as number;
        const threshold = (totalReputation * 2) / 3;
        for (const p of proposals) {
          const votes = [...sql.exec(
            "SELECT vote, COUNT(*) as cnt FROM governance_proposal_votes WHERE proposal_id = ? GROUP BY vote", p.id
          )] as any[];
          p.votes = votes.reduce((acc: any, v: any) => { acc[v.vote] = v.cnt; return acc; }, {});
          const voters = [...sql.exec(
            "SELECT voter, vote, reputation, voted_at, staked_at FROM governance_proposal_votes WHERE proposal_id = ? ORDER BY voted_at", p.id
          )] as any[];
          // Calculate conviction weight per voter
          p.voter_list = voters.map((v: any) => {
            const daysStaked = (now - (v.staked_at || v.voted_at)) / MS_PER_DAY;
            return { ...v, conviction: Math.round(v.reputation * (1 + daysStaked) * 100) / 100 };
          });
          // Aggregate conviction by vote direction
          const yesConviction = p.voter_list.filter((v: any) => v.vote === "yes").reduce((s: number, v: any) => s + v.conviction, 0);
          const noConviction = p.voter_list.filter((v: any) => v.vote === "no").reduce((s: number, v: any) => s + v.conviction, 0);
          p.conviction = { yes: Math.round(yesConviction * 100) / 100, no: Math.round(noConviction * 100) / 100, threshold: Math.round(threshold * 100) / 100 };
        }
        return this.json({ proposals, current_round: this.currentRound, last_committed_round: this.lastCommittedRound });
      }
      case "/governance/propose": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as SignedEvent;
        body.type = "governance.propose";
        return this.json(await this.receiveClientEvent(body));
      }
      case "/governance/vote": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as SignedEvent;
        body.type = "governance.vote";
        return this.json(await this.receiveClientEvent(body));
      }
      case "/governance/history": {
        const history = [...sql.exec(
          "SELECT param_key, old_value, new_value, changed_by, proposal_id, round, changed_at FROM network_config_history ORDER BY changed_at DESC LIMIT 50"
        )] as any[];
        return this.json({ history });
      }
      default:
        return this.json({ error: "Unknown governance endpoint" }, 404);
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

      case "/contract/upgrade": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as SignedEvent;
        body.type = "contract.upgrade";
        return this.json(await this.receiveClientEvent(body));
      }

      case "/contract/lock": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as SignedEvent;
        body.type = "contract.lock";
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

      // ─── App upload endpoint ──────────────────────────────────────
      case "/contract/app/upload": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as SignedEvent;
        body.type = "app.upload";
        return this.json(await this.receiveClientEvent(body));
      }

      case "/contract/app/files": {
        const contract = url.searchParams.get("contract");
        if (!contract) return this.json({ error: "contract required" }, 400);
        const prefix = new TextEncoder().encode("_app/");
        const rows = [...this.state.storage.sql.exec(
          "SELECT key FROM contract_state WHERE contract_address = ? AND key >= ? AND key < ?",
          contract, prefix, new Uint8Array([...prefix.slice(0, -1), prefix[prefix.length - 1] + 1]),
        )];
        const files = rows.map((r: any) => {
          const keyBytes = r.key instanceof Uint8Array ? r.key : new Uint8Array(r.key);
          return new TextDecoder().decode(keyBytes).replace("_app/", "");
        });
        return this.json({ contract, files });
      }

      default:
        return this.json({ error: "Unknown contract endpoint" }, 404);
    }
  }

  // ─── On-Chain App Serving ──────────────────────────────────────────────

  private handleAppServe(_req: Request, url: URL): Response {
    const sql = this.state.storage.sql;

    // App registry listing
    if (url.searchParams.get("list")) {
      // Find all contracts that have _app/ keys
      const prefix = new TextEncoder().encode("_app/index.html");
      const rows = [...sql.exec(
        "SELECT DISTINCT contract_address FROM contract_state WHERE key = ?", prefix,
      )];
      const apps = rows.map((r: any) => {
        const info = this.contractExecutor.getContractInfo(r.contract_address);
        return {
          contract: r.contract_address,
          deployer: info?.deployer,
          url: `/app/${r.contract_address}/`,
        };
      });
      return this.json({ apps });
    }

    const contract = url.searchParams.get("contract");
    const rawPath = decodeURIComponent(url.searchParams.get("path") || "/index.html");

    if (!contract) return this.json({ error: "contract required" }, 400);

    // Sanitize path
    let filePath = rawPath.replace(/^\/+/, "") || "index.html";
    if (filePath === "" || filePath.endsWith("/")) filePath += "index.html";
    if (filePath.includes("..")) return this.json({ error: "Invalid path" }, 400);

    // Manifest request
    if (filePath === "_manifest") {
      const prefix = new TextEncoder().encode("_app/");
      const rows = [...sql.exec(
        "SELECT key, length(value) as size FROM contract_state WHERE contract_address = ? AND key >= ? AND key < ?",
        contract, prefix, new Uint8Array([...prefix.slice(0, -1), prefix[prefix.length - 1] + 1]),
      )];
      const files = rows.map((r: any) => {
        const keyBytes = r.key instanceof Uint8Array ? r.key : new Uint8Array(r.key);
        return { path: new TextDecoder().decode(keyBytes).replace("_app/", ""), size: r.size };
      });
      return this.json({ contract, files });
    }

    // Look up the file in contract state
    const stateKey = new TextEncoder().encode(`_app/${filePath}`);
    const rows = [...sql.exec(
      "SELECT value FROM contract_state WHERE contract_address = ? AND key = ?",
      contract, stateKey,
    )];

    if (rows.length === 0) {
      // SPA fallback: try index.html if specific path not found
      const indexKey = new TextEncoder().encode("_app/index.html");
      const indexRows = [...sql.exec(
        "SELECT value FROM contract_state WHERE contract_address = ? AND key = ?",
        contract, indexKey,
      )];
      if (indexRows.length > 0 && !filePath.includes(".")) {
        const data = (indexRows[0] as any).value;
        const body = data instanceof Uint8Array ? data : new Uint8Array(data);
        return new Response(body, {
          headers: { "Content-Type": "text/html;charset=utf-8", "Cache-Control": "public, max-age=60" },
        });
      }
      return new Response("Not Found", { status: 404 });
    }

    const data = (rows[0] as any).value;
    const body = data instanceof Uint8Array ? data : new Uint8Array(data);
    const contentType = this.mimeFromPath(filePath);

    return new Response(body, {
      headers: { "Content-Type": contentType, "Cache-Control": "public, max-age=60" },
    });
  }

  private mimeFromPath(path: string): string {
    const ext = path.split(".").pop()?.toLowerCase() || "";
    const mimeMap: Record<string, string> = {
      html: "text/html;charset=utf-8",
      css: "text/css;charset=utf-8",
      js: "application/javascript;charset=utf-8",
      mjs: "application/javascript;charset=utf-8",
      json: "application/json;charset=utf-8",
      png: "image/png",
      jpg: "image/jpeg",
      jpeg: "image/jpeg",
      gif: "image/gif",
      svg: "image/svg+xml",
      ico: "image/x-icon",
      woff: "font/woff",
      woff2: "font/woff2",
      ttf: "font/ttf",
      wasm: "application/wasm",
      txt: "text/plain;charset=utf-8",
      xml: "application/xml",
      webp: "image/webp",
    };
    return mimeMap[ext] || "application/octet-stream";
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
          || await generateStateProof(sql, key, this.stateTree.hashFunctionName);
        if (!proof) return this.json({ error: "key not found in state" }, 404);
        return this.json(proof);
      }

      case "/proof/verify": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const proof = await req.json();
        const valid = await verifyProof(proof);
        return this.json({ valid });
      }

      // ─── ZK Prover Block Data ────────────────────────────────────────
      // Returns block data in the format the Noir prover expects:
      // mutations as {key, new_value}, signatures with Schnorr fields,
      // and state root computed from the block's mutations.
      case "/proof/block": {
        const blockNum = parseInt(url.searchParams.get("block") || url.searchParams.get("round") || "0");
        if (!blockNum) return this.json({ error: "block parameter required" }, 400);

        // Get committed block data
        const commits = [...sql.exec(
          "SELECT anchor_hash, committed_at, signatures_json FROM dag_commits WHERE round = ?", blockNum
        )] as any[];
        if (commits.length === 0) return this.json({ error: "Block not committed" }, 404);

        // Get mutations for this block
        const mutations = [...sql.exec(
          "SELECT key, new_value, is_delete FROM block_mutations WHERE block_number = ?", blockNum
        )] as any[];

        // Format mutations as the prover expects: {key, new_value}
        const formattedMutations = mutations.map((m: any) => ({
          key: m.key,
          new_value: m.is_delete ? null : m.new_value,
        }));

        // Parse signatures from committed data, enriching with Schnorr fields
        let signatures: any[];
        try { signatures = JSON.parse(commits[0].signatures_json || "[]"); } catch { signatures = []; }

        // Enrich signatures with Grumpkin keys from active_nodes if missing
        for (const sig of signatures) {
          if (!sig.grumpkin_x || !sig.grumpkin_y) {
            const pubkey = sig.pubkey || sig.author;
            if (pubkey) {
              const rows = [...sql.exec(
                "SELECT grumpkin_x, grumpkin_y FROM active_nodes WHERE pubkey = ?", pubkey
              )] as any[];
              if (rows.length > 0 && rows[0].grumpkin_x && rows[0].grumpkin_y) {
                sig.grumpkin_x = rows[0].grumpkin_x;
                sig.grumpkin_y = rows[0].grumpkin_y;
              }
            }
          }
          // Ensure message field is present
          if (!sig.message) sig.message = `block:${blockNum}`;
        }

        // Get active_nodes count at commit time
        const vertices = [...sql.exec(
          "SELECT hash FROM dag_vertices WHERE round = ?", blockNum
        )] as any[];
        const activeNodes = Math.max(signatures.length, vertices.length, 1);

        return this.json({
          block_number: blockNum,
          committed_at: commits[0].committed_at,
          signatures,
          mutations: formattedMutations,
          active_nodes: activeNodes,
        });
      }

      // ─── ZK Proof Endpoints ──────────────────────────────────────────
      case "/proof/zk/submit": {
        // Accept a ZK proof from the prover sidecar
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        if (!body.block_number || !body.proof || !body.state_root) {
          return this.json({ error: "block_number, proof, and state_root required" }, 400);
        }

        // --- Consistency verification against node state ---
        // Verify that the proof's block_number corresponds to a committed block
        // and that public inputs (active_nodes, block_number) match node records.
        let verified = 0;
        const commitRows = [...sql.exec(
          "SELECT round, signatures_json FROM dag_commits WHERE round = ? LIMIT 1",
          body.block_number,
        )];
        if (commitRows.length === 0 && !body._relayed) {
          return this.json({ error: `Block ${body.block_number} not found in committed blocks` }, 400);
        }
        if (commitRows.length > 0) {
          // Cross-check public inputs if provided
          if (body.publicInputs && Array.isArray(body.publicInputs)) {
            // UltraHonk public inputs order: prev_state_root, new_state_root, block_number, active_nodes,
            // then StateTransitionOutput: state_root, block_number, proven_blocks, genesis_root
            // The new_state_root (index 1) should match body.state_root
            const piNewRoot = body.publicInputs[1];
            if (piNewRoot && piNewRoot !== body.state_root) {
              return this.json({ error: "publicInputs[1] (new_state_root) does not match body.state_root" }, 400);
            }
          }
          // Block mutations exist — proof is consistent with node state
          verified = 1;
        }

        // Decode proof bytes if provided (base64-encoded)
        let proofBytes: ArrayBuffer | null = null;
        if (body.proof_bytes_b64) {
          const raw = atob(body.proof_bytes_b64);
          const arr = new Uint8Array(raw.length);
          for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
          proofBytes = arr.buffer;

          // Store proof bytes in R2 if available (keep SQLite lean)
          if (this.env.BLOB_STORE && proofBytes) {
            await this.env.BLOB_STORE.put(`proofs/${body.block_number}`, proofBytes);
          }
        }
        sql.exec(
          `INSERT OR REPLACE INTO zk_proofs (block_number, proof_hex, state_root, proven_blocks, proof_type, submitted_at, verified, proof_bytes, public_values, genesis_root)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          body.block_number,
          body.proof,
          body.state_root,
          body.proven_blocks || 1,
          body.proof_type || "compressed",
          Date.now(),
          verified,
          this.env.BLOB_STORE ? null : proofBytes,  // skip inline storage if R2 available
          body.public_values ? JSON.stringify(body.public_values) : null,
          body.genesis_root || null,
        );
        this.broadcast({
          type: "zk.proof_submitted",
          block_number: body.block_number,
          state_root: body.state_root,
          proven_blocks: body.proven_blocks || 1,
          genesis_root: body.genesis_root || null,
          verified: !!verified,
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

        // Gossip proof to external peers via HTTP (reaches nodes on other Workers)
        if (!body._relayed && this.nodeIdentity) {
          const proofPayload = {
            block_number: body.block_number,
            proof: body.proof,
            state_root: body.state_root,
            proven_blocks: body.proven_blocks || 1,
            proof_type: body.proof_type || "compressed",
            public_values: body.public_values || null,
            genesis_root: body.genesis_root || null,
            // Omit proof_bytes_b64 from gossip to save bandwidth — peers can
            // fetch full proof via /proof/zk/download if needed for verification
          };
          this.gossipManager.createEnvelope("zk_proof", proofPayload)
            .then(env => this.gossipManager.flood(env))
            .catch(() => {});
        }

        return this.json({ ok: true, block_number: body.block_number, verified: !!verified });
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
        // Summary of ZK proof coverage with lineage tracking
        const latest = [...sql.exec(
          "SELECT MAX(block_number) as latest_block, MAX(proven_blocks) as max_chain_length FROM zk_proofs"
        )] as any[];
        const count = [...sql.exec("SELECT COUNT(*) as total FROM zk_proofs")] as any[];

        // Detect proof lineages: a new lineage starts when proven_blocks resets to a low value
        // or genesis_root changes. Group by genesis_root to find distinct chains.
        const lineages = [...sql.exec(
          `SELECT genesis_root, MIN(block_number) as first_block, MAX(block_number) as last_block,
                  MAX(proven_blocks) as chain_length, COUNT(*) as proof_count,
                  MIN(submitted_at) as started_at, MAX(submitted_at) as last_proof_at
           FROM zk_proofs GROUP BY genesis_root ORDER BY MAX(block_number) DESC`
        )] as any[];

        // Active lineage is the one with the highest last_block
        const active = lineages.length > 0 ? lineages[0] : null;

        return this.json({
          total_proofs: count[0]?.total || 0,
          latest_proven_block: latest[0]?.latest_block || null,
          max_chain_length: latest[0]?.max_chain_length || 0,
          last_committed_round: this.lastCommittedRound,
          proof_gap: (this.lastCommittedRound || 0) - (latest[0]?.latest_block || 0),
          lineages: lineages.map((l: any) => ({
            genesis_root: l.genesis_root || "unknown",
            first_block: l.first_block,
            last_block: l.last_block,
            chain_length: l.chain_length,
            proof_count: l.proof_count,
            started_at: l.started_at,
            last_proof_at: l.last_proof_at,
            active: l === active,
          })),
          active_lineage: active ? {
            genesis_root: active.genesis_root || "unknown",
            first_block: active.first_block,
            last_block: active.last_block,
            chain_length: active.chain_length,
            gap: (this.lastCommittedRound || 0) - (active.last_block || 0),
          } : null,
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

        // Try R2 first, then fall back to SQLite
        if (this.env.BLOB_STORE) {
          const obj = await this.env.BLOB_STORE.get(`proofs/${blockNum}`);
          if (obj) {
            const proofType = [...sql.exec("SELECT proof_type FROM zk_proofs WHERE block_number = ?", parseInt(blockNum))] as any[];
            return new Response(obj.body, {
              headers: {
                "Content-Type": "application/octet-stream",
                "Content-Disposition": `attachment; filename="proof_block_${blockNum}.bin"`,
                "X-Proof-Type": proofType[0]?.proof_type || "compressed",
              },
            });
          }
        }

        // Fallback: inline SQLite storage
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

      // ── SnarkFold Epoch Proof Aggregation ────────────────────────────────
      case "/proof/epoch/submit": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        if (!body.epoch || !body.block_start || !body.block_end || !body.proof) {
          return this.json({ error: "Missing epoch, block_start, block_end, or proof" }, 400);
        }
        sql.exec(
          `INSERT OR REPLACE INTO epoch_proofs (epoch, block_start, block_end, proof_count, proof_hex, proof_bytes, public_values, state_root, genesis_root, submitted_at, verified)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
          body.epoch, body.block_start, body.block_end,
          body.proof_count || (body.block_end - body.block_start + 1),
          body.proof, body.proof_bytes ? new Uint8Array(Buffer.from(body.proof_bytes, "base64")) : null,
          body.public_values ? JSON.stringify(body.public_values) : null,
          body.state_root || "", body.genesis_root || null, Date.now(),
        );
        return this.json({ ok: true, epoch: body.epoch, blocks: `${body.block_start}-${body.block_end}` });
      }
      case "/proof/epoch/latest": {
        const rows = [...sql.exec(
          "SELECT epoch, block_start, block_end, proof_count, state_root, genesis_root, submitted_at, verified FROM epoch_proofs ORDER BY epoch DESC LIMIT 1"
        )] as any[];
        if (rows.length === 0) return this.json({ epoch_proof: null });
        return this.json({ epoch_proof: rows[0] });
      }
      case "/proof/epoch/list": {
        const limit = parseInt(url.searchParams.get("limit") || "10");
        const rows = [...sql.exec(
          "SELECT epoch, block_start, block_end, proof_count, state_root, genesis_root, submitted_at, verified FROM epoch_proofs ORDER BY epoch DESC LIMIT ?",
          Math.min(limit, 50),
        )] as any[];
        return this.json({ epoch_proofs: rows });
      }
      case "/proof/epoch/download": {
        const epoch = parseInt(url.searchParams.get("epoch") || "0");
        if (!epoch) return this.json({ error: "epoch param required" }, 400);
        const rows = [...sql.exec("SELECT * FROM epoch_proofs WHERE epoch = ?", epoch)] as any[];
        if (rows.length === 0) return this.json({ error: "Epoch proof not found" }, 404);
        const ep = rows[0];
        return this.json({
          epoch: ep.epoch, block_start: ep.block_start, block_end: ep.block_end,
          proof_count: ep.proof_count, proof: ep.proof_hex,
          public_values: ep.public_values ? JSON.parse(ep.public_values) : null,
          state_root: ep.state_root, genesis_root: ep.genesis_root,
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

      // ─── Fraud Proof Challenge Protocol ──────────────────────────────
      case "/challenge/submit": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        if (!body.challenger || !body.block_number) {
          return this.json({ error: "Missing challenger or block_number" }, 400);
        }
        const result = await this.handleChallengeSubmit(
          body.challenger, body.block_number, body.claimed_invalid_root || null,
        );
        return this.json(result, result.ok ? 200 : 400);
      }
      case "/challenge/respond": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        if (!body.block_number || !body.proof_hash || !body.proof_state_root) {
          return this.json({ error: "Missing block_number, proof_hash, or proof_state_root" }, 400);
        }
        const result = this.handleChallengeRespond(body.block_number, body.proof_hash, body.proof_state_root);
        return this.json(result, result.ok ? 200 : 400);
      }
      case "/challenge/status": {
        const blockNum = parseInt(url.searchParams.get("block") || "0");
        if (!blockNum) return this.json({ error: "Missing block param" }, 400);
        const sql = this.state.storage.sql;
        const window = getChallengeWindow(sql, blockNum);
        const challenge = getActiveChallenge(sql, blockNum);
        return this.json({ window, challenge });
      }
      case "/challenge/witness": {
        const blockNum = parseInt(url.searchParams.get("block") || "0");
        if (!blockNum) return this.json({ error: "Missing block param" }, 400);
        const sql = this.state.storage.sql;
        // Gather block data for witness
        const headers = [...sql.exec(
          "SELECT state_root, prev_header_hash, validator_set_hash FROM block_headers WHERE block_number = ?", blockNum,
        )] as any[];
        if (headers.length === 0) return this.json({ error: "Block not found" }, 404);
        const prevHeaders = [...sql.exec(
          "SELECT state_root FROM block_headers WHERE block_number = ?", blockNum - 1,
        )] as any[];
        const prevStateRoot = prevHeaders.length > 0 ? prevHeaders[0].state_root as string : await sha256("genesis");
        const mutations = [...sql.exec(
          "SELECT key, new_value, is_delete FROM block_mutations WHERE block_number = ?", blockNum,
        )] as any[];
        const commitRow = [...sql.exec(
          "SELECT signatures_json FROM dag_commits WHERE round = ?", blockNum,
        )] as any[];
        const sigs = commitRow.length > 0 ? JSON.parse(commitRow[0].signatures_json) : [];
        // Get events from the committed vertex
        const vertexRows = [...sql.exec(
          "SELECT events_json FROM dag_vertices WHERE round = ?", blockNum,
        )] as any[];
        const events: any[] = [];
        const eventHashes: string[] = [];
        for (const vr of vertexRows) {
          try {
            const parsed = JSON.parse(vr.events_json || "[]");
            for (const e of parsed) { events.push(e); eventHashes.push(e.hash || ""); }
          } catch {}
        }
        const activeNodes = this.getActiveNodes().length;
        const witness = buildChallengeWitness({
          block_number: blockNum,
          prev_state_root: prevStateRoot,
          post_state_root: headers[0].state_root,
          events,
          event_hashes: eventHashes.filter(Boolean),
          mutations: mutations.map((m: any) => ({
            key: m.key, old_value: null, new_value: m.is_delete ? null : m.new_value,
          })),
          commit_signatures: sigs.map((s: any) => ({
            pubkey: s.pubkey, signature: s.signature, message: `block:${blockNum}`,
          })),
          active_nodes: activeNodes,
          prev_header_hash: headers[0].prev_header_hash,
          validator_set_hash: headers[0].validator_set_hash,
        });
        return this.json(witness);
      }
      case "/challenge/list": {
        const sql = this.state.storage.sql;
        const status = url.searchParams.get("status") || "challenged";
        const challenges = [...sql.exec(
          "SELECT * FROM fraud_challenges WHERE status = ? ORDER BY created_at DESC LIMIT 50", status,
        )];
        const windows = [...sql.exec(
          "SELECT * FROM challenge_windows WHERE status = 'open' ORDER BY block_number DESC LIMIT 50",
        )];
        return this.json({ challenges, windows });
      }

      // ─── Atomic Cross-Shard Settlement (2-Phase Commit) ─────────────
      // Phase 1: PREPARE — source shard locks funds/state, creates escrow
      // Phase 2: COMMIT/ABORT — target shard confirms receipt, source finalizes or rolls back
      case "/xshard/prepare": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        if (!body.tx_id || !body.target_shard || !body.operations) {
          return this.json({ error: "Missing tx_id, target_shard, or operations" }, 400);
        }
        // Lock operations (e.g., debit sender balance, hold in escrow)
        const escrowId = `escrow:${body.tx_id}`;
        try {
          for (const op of body.operations) {
            if (op.type === "token.lock") {
              const senderRows = [...sql.exec("SELECT address FROM accounts WHERE pubkey = ?", op.pubkey)];
              if (senderRows.length === 0) return this.json({ error: `Unknown sender: ${op.pubkey}` }, 400);
              const senderAddr = senderRows[0].address as string;
              const denom = op.denom || "PERSIST";
              const amount = BigInt(op.amount);
              const balRows = [...sql.exec("SELECT amount FROM token_balances WHERE address = ? AND denom = ?", senderAddr, denom)] as any[];
              const balance = BigInt(balRows[0]?.amount ?? "0");
              if (balance < amount) return this.json({ error: "Insufficient balance" }, 400);
              // Debit and hold in escrow
              sql.exec("UPDATE token_balances SET amount = ? WHERE address = ? AND denom = ?",
                (balance - amount).toString(), senderAddr, denom);
            }
          }
          // Record prepared transaction
          sql.exec(
            `INSERT INTO xshard_outbox (id, target_shard, message_json, status, created_at)
             VALUES (?, ?, ?, 'prepared', ?)`,
            escrowId, body.target_shard, JSON.stringify({ tx_id: body.tx_id, operations: body.operations }), Date.now(),
          );
          return this.json({ ok: true, tx_id: body.tx_id, status: "prepared" });
        } catch (e: any) {
          return this.json({ error: `Prepare failed: ${e.message}` }, 500);
        }
      }
      case "/xshard/commit": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const { tx_id } = await req.json() as any;
        const escrowId = `escrow:${tx_id}`;
        const rows = [...sql.exec("SELECT message_json FROM xshard_outbox WHERE id = ? AND status = 'prepared'", escrowId)] as any[];
        if (rows.length === 0) return this.json({ error: "No prepared transaction found" }, 404);
        // Finalize: mark as committed
        sql.exec("UPDATE xshard_outbox SET status = 'committed', delivered_at = ? WHERE id = ?", Date.now(), escrowId);
        return this.json({ ok: true, tx_id, status: "committed" });
      }
      case "/xshard/abort": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const { tx_id } = await req.json() as any;
        const escrowId = `escrow:${tx_id}`;
        const rows = [...sql.exec("SELECT message_json FROM xshard_outbox WHERE id = ? AND status = 'prepared'", escrowId)] as any[];
        if (rows.length === 0) return this.json({ error: "No prepared transaction found" }, 404);
        // Rollback: restore locked funds
        const txData = JSON.parse(rows[0].message_json);
        for (const op of txData.operations || []) {
          if (op.type === "token.lock") {
            const senderRows = [...sql.exec("SELECT address FROM accounts WHERE pubkey = ?", op.pubkey)] as any[];
            if (senderRows.length > 0) {
              const senderAddr = senderRows[0].address as string;
              const denom = op.denom || "PERSIST";
              const balRows = [...sql.exec("SELECT amount FROM token_balances WHERE address = ? AND denom = ?", senderAddr, denom)] as any[];
              const balance = BigInt(balRows[0]?.amount ?? "0");
              sql.exec("UPDATE token_balances SET amount = ? WHERE address = ? AND denom = ?",
                (balance + BigInt(op.amount)).toString(), senderAddr, denom);
            }
          }
        }
        sql.exec("UPDATE xshard_outbox SET status = 'aborted', delivered_at = ? WHERE id = ?", Date.now(), escrowId);
        return this.json({ ok: true, tx_id, status: "aborted" });
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

  /**
   * Execute a federated service request received from a peer.
   * Runs the AI inference locally, creates an attestation, and gossips the response.
   */
  // ─── Provider Marketplace Routes (/providers/*) ──────────────────────

  private async handleProviderRoute(req: Request, url: URL): Promise<Response> {
    const subpath = url.pathname.replace(/^\/providers\/?/, "");

    switch (subpath) {
      case "register": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        const result = await this.providerRegistry.register({
          owner_address: body.owner_address,
          endpoint_url: body.endpoint_url,
          service_type: body.service_type,
          model: body.model,
          price: BigInt(body.price || 0),
          bond_amount: BigInt(body.bond_amount || 0),
        });
        if (!result.ok) return this.json({ error: result.error }, 400);
        return this.json({
          ok: true,
          provider: {
            ...result.provider,
            price: result.provider!.price.toString(),
            bond: result.provider!.bond.toString(),
            total_earnings: result.provider!.total_earnings.toString(),
          },
        });
      }

      case "deactivate": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        const result = this.providerRegistry.deactivate(body.provider_id, body.owner_address);
        if (!result.ok) return this.json({ error: result.error }, 400);
        return this.json({ ok: true, refunded: result.refunded?.toString() });
      }

      case "update-price": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        const result = this.providerRegistry.updatePrice(body.provider_id, body.owner_address, BigInt(body.price || 0));
        if (!result.ok) return this.json({ error: result.error }, 400);
        return this.json({ ok: true });
      }

      case "update-endpoint": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        const result = this.providerRegistry.updateEndpoint(body.provider_id, body.owner_address, body.endpoint_url);
        if (!result.ok) return this.json({ error: result.error }, 400);
        return this.json({ ok: true });
      }

      case "claim": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        const result = this.providerRegistry.claimEarnings(body.provider_id, body.owner_address);
        if (!result.ok) return this.json({ error: result.error }, 400);
        return this.json({ ok: true, amount: result.amount?.toString() });
      }

      case "report-down": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const body = await req.json() as any;
        const report = this.providerRegistry.reportDown(body.provider_id, body.reporter_address);
        if (!report) return this.json({ error: "Provider not found, already reported, or inactive" }, 400);
        return this.json({ ok: true, report });
      }

      case "list": {
        const serviceType = url.searchParams.get("service_type") || "";
        const model = url.searchParams.get("model") || "";
        const providers = serviceType && model
          ? this.providerRegistry.getActive(serviceType, model)
          : this.providerRegistry.getAllActive();
        return this.json({
          providers: providers.map(p => ({
            ...p,
            price: p.price.toString(),
            bond: p.bond.toString(),
            total_earnings: p.total_earnings.toString(),
          })),
        });
      }

      case "models": {
        const models = this.providerRegistry.getAvailableModels();
        return this.json({
          models: models.map(m => ({
            ...m,
            cheapest: m.cheapest.toString(),
            most_expensive: m.most_expensive.toString(),
          })),
        });
      }

      case "stats": {
        const stats = this.providerRegistry.getStats();
        return this.json({
          ...stats,
          total_bond_locked: stats.total_bond_locked.toString(),
        });
      }

      case "my-providers": {
        const owner = url.searchParams.get("address") || "";
        if (!owner) return this.json({ error: "address param required" }, 400);
        const providers = this.providerRegistry.getByOwner(owner);
        return this.json({
          providers: providers.map(p => ({
            ...p,
            price: p.price.toString(),
            bond: p.bond.toString(),
            total_earnings: p.total_earnings.toString(),
          })),
        });
      }

      default:
        return this.json({ error: "Unknown provider route", routes: [
          "register", "deactivate", "update-price", "update-endpoint",
          "claim", "report-down", "list", "models", "stats", "my-providers",
        ] }, 404);
    }
  }

  private async handleFederatedServiceRequest(payload: ServiceRequestPayload): Promise<void> {
    if (!payload.input_body_b64) return;

    const bodyRaw = atob(payload.input_body_b64);
    const body = JSON.parse(bodyRaw);
    const modelId = body.model || payload.model;

    // Pre-commit
    const preCommit = await this.attestationMgr.preCommit(payload.service, modelId, bodyRaw);

    // Execute via AI binding
    const fakeRequest = new Request("https://internal/api/" + payload.service, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: bodyRaw,
    });

    const response = await dispatchApiRoute(
      "/api/" + payload.service,
      fakeRequest,
      this.env,
      null, // skip individual attestation wrapping — we do it manually
    );

    if (!response.ok) return;

    // Hash the output
    const outputClone = response.clone();
    const outputBytes = new Uint8Array(await outputClone.arrayBuffer());
    const outputHex = Array.from(outputBytes).map(b => b.toString(16).padStart(2, "0")).join("");
    const outputHash = await sha256(outputHex);

    // Create attestation
    const attestation = await this.attestationMgr.attest({
      service: payload.service,
      model: modelId,
      input_hash: preCommit.input_hash,
      output_bytes: outputBytes,
      pre_commitment: preCommit.pre_commitment,
      nonce: preCommit.nonce,
    });

    // Send response back via gossip
    await this.serviceFederation.sendResponse({
      request_id: payload.request_id,
      output_hash: outputHash,
      attestation_id: attestation.attestation_id,
    });
  }

  private async handleGossipRoute(req: Request, url: URL): Promise<Response> {
    switch (url.pathname) {
      case "/gossip/push": {
        // Receive a gossipped message (vertex or event)
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const envelope = expandEnvelope(await req.json()) as GossipEnvelope;

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

        // Store sender's Grumpkin public key if present
        if (envelope.grumpkin_x && envelope.grumpkin_y && envelope.sender_pubkey) {
          const sql = this.state.storage.sql;
          sql.exec("UPDATE gossip_peers SET grumpkin_x = ?, grumpkin_y = ? WHERE pubkey = ?",
            envelope.grumpkin_x, envelope.grumpkin_y, envelope.sender_pubkey);
          sql.exec("UPDATE active_nodes SET grumpkin_x = ?, grumpkin_y = ? WHERE pubkey = ?",
            envelope.grumpkin_x, envelope.grumpkin_y, envelope.sender_pubkey);
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
          case "zk_proof": {
            const proof = envelope.payload;
            if (!proof.block_number || !proof.proof || !proof.state_root) {
              return this.json({ error: "Invalid proof payload" }, 400);
            }
            // Check if we already have this proof
            const existing = [...this.state.storage.sql.exec(
              "SELECT block_number FROM zk_proofs WHERE block_number = ?", proof.block_number,
            )];
            if (existing.length > 0) {
              return this.json({ ok: true, already_have: true });
            }
            // Store the proof
            let proofBytes: ArrayBuffer | null = null;
            if (proof.proof_bytes_b64) {
              const raw = atob(proof.proof_bytes_b64);
              const arr = new Uint8Array(raw.length);
              for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
              proofBytes = arr.buffer;
            }
            this.state.storage.sql.exec(
              `INSERT OR IGNORE INTO zk_proofs (block_number, proof_hex, state_root, proven_blocks, proof_type, submitted_at, verified, proof_bytes, public_values, genesis_root)
               VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`,
              proof.block_number, proof.proof, proof.state_root,
              proof.proven_blocks || 1, proof.proof_type || "compressed",
              Date.now(), proofBytes,
              proof.public_values ? JSON.stringify(proof.public_values) : null,
              proof.genesis_root || null,
            );
            this.broadcast({
              type: "zk.proof_submitted",
              block_number: proof.block_number,
              state_root: proof.state_root,
              proven_blocks: proof.proven_blocks || 1,
              genesis_root: proof.genesis_root || null,
            });
            // Re-gossip to peers (excluding sender)
            const exclude = new Set([envelope.sender_pubkey]);
            this.gossipManager.flood(envelope, exclude).catch(() => {});
            return this.json({ ok: true });
          }
          case "service_request": {
            const payload = envelope.payload as ServiceRequestPayload;
            if (!this.serviceFederation?.shouldHandleRequest(payload)) {
              return this.json({ ok: false, reason: "not handling" });
            }
            // Execute the service locally and send response back via gossip
            this.handleFederatedServiceRequest(payload).catch(e =>
              console.error("Federation request failed:", e.message));
            return this.json({ ok: true, accepted: true });
          }
          case "service_response": {
            const payload = envelope.payload as ServiceResponsePayload;
            if (this.serviceFederation) {
              this.serviceFederation.handleResponse(payload);
            }
            return this.json({ ok: true });
          }
          default:
            return this.json({ error: "Unknown gossip type" }, 400);
        }
      }

      case "/gossip/sync": {
        // Rate-limit sync requests by IP — higher limit for bootstrapping nodes
        const syncCaller = req.headers.get("CF-Connecting-IP") || "unknown";
        if (!this.validatorRegistry.checkRateLimit(`sync:${syncCaller}`, 60_000, 30)) {
          return this.json({ error: "Sync rate limited" }, 429);
        }

        // Respond to sync requests from peers
        const afterRound = parseInt(url.searchParams.get("after_round") || "0");
        const limit = Math.min(parseInt(url.searchParams.get("limit") || "2000"), 2000);

        const vertices = [...this.state.storage.sql.exec(
          "SELECT hash, author, round, events_json, refs_json, signature, timestamp, schnorr_sig FROM dag_vertices WHERE round >= ? ORDER BY round ASC, hash ASC LIMIT ?",
          afterRound, limit,
        )].map((r: any) => ({
          hash: r.hash, author: r.author, round: r.round,
          event_hashes: (() => { try { return JSON.parse(r.events_json).map((e: any) => e.hash).filter(Boolean); } catch { return []; } })(),
          events: (() => { try { return JSON.parse(r.events_json); } catch { return []; } })(),
          refs: (() => { try { return JSON.parse(r.refs_json); } catch { return []; } })(),
          timestamp: r.timestamp,
          signature: r.signature,
          schnorr_sig: r.schnorr_sig ? (() => { try { return JSON.parse(r.schnorr_sig); } catch { return undefined; } })() : undefined,
        }));

        const commits = [...this.state.storage.sql.exec(
          "SELECT round, anchor_hash, committed_at FROM dag_commits WHERE round >= ? ORDER BY round ASC",
          afterRound,
        )];

        // Include ZK proof metadata (no proof bytes — peers fetch those separately)
        const proofs = [...this.state.storage.sql.exec(
          "SELECT block_number, proof_hex, state_root, proven_blocks, proof_type, genesis_root FROM zk_proofs ORDER BY block_number ASC LIMIT 200",
        )].map((r: any) => ({
          block_number: r.block_number, proof: r.proof_hex, state_root: r.state_root,
          proven_blocks: r.proven_blocks, proof_type: r.proof_type, genesis_root: r.genesis_root,
        }));

        // Include snapshot availability for new nodes
        const syncSnap = this.snapshotManager.getLatestSnapshot();

        return this.json({
          vertices,
          commits,
          proofs,
          latest_round: this.currentRound,
          adaptive_state: {
            round_interval_ms: this.getNetworkParam("round_interval_ms", ROUND_INTERVAL_MS),
            max_events_per_vertex: this.getNetworkParam("max_events_per_vertex", MAX_EVENTS_PER_VERTEX),
          },
          snapshot: syncSnap ? {
            anchor_id: syncSnap.anchor_id,
            finalized_seq: syncSnap.finalized_seq,
            snapshot_hash: syncSnap.snapshot_hash,
          } : undefined,
          // State checkpoint for fork detection — peers compare roots at same seq
          checkpoint: {
            finalized_seq: this.finalizedSeq,
            finalized_root: this.finalizedRoot,
            last_committed_round: this.lastCommittedRound,
          },
        } as SyncResponsePayload);
      }

      // ─── Delta Sync: hash-first protocol ─────────────────────────────
      // Step 1: GET /gossip/sync/hashes — returns only vertex hashes for a round range
      // Step 2: POST /gossip/sync/bodies — client sends missing hashes, gets full vertices
      case "/gossip/sync/hashes": {
        const afterRound = parseInt(url.searchParams.get("after_round") || "0");
        const limit = Math.min(parseInt(url.searchParams.get("limit") || "5000"), 5000);
        const hashes = [...sql.exec(
          "SELECT hash, round FROM dag_vertices WHERE round >= ? ORDER BY round ASC, hash ASC LIMIT ?",
          afterRound, limit,
        )].map((r: any) => ({ h: r.hash, r: r.round }));
        return this.json({
          hashes,
          latest_round: this.currentRound,
          checkpoint: {
            finalized_seq: this.finalizedSeq,
            finalized_root: this.finalizedRoot,
            last_committed_round: this.lastCommittedRound,
          },
        });
      }
      case "/gossip/sync/bodies": {
        if (req.method !== "POST") return this.json({ error: "POST required" }, 405);
        const { hashes: requestedHashes } = await req.json() as { hashes: string[] };
        if (!requestedHashes || !Array.isArray(requestedHashes) || requestedHashes.length > 500) {
          return this.json({ error: "Provide array of up to 500 hashes" }, 400);
        }
        const placeholders = requestedHashes.map(() => "?").join(",");
        const vertices = [...sql.exec(
          `SELECT hash, author, round, events_json, refs_json, signature, timestamp FROM dag_vertices WHERE hash IN (${placeholders})`,
          ...requestedHashes,
        )].map((r: any) => ({
          hash: r.hash, author: r.author, round: r.round,
          events: (() => { try { return JSON.parse(r.events_json); } catch { return []; } })(),
          refs: (() => { try { return JSON.parse(r.refs_json); } catch { return []; } })(),
          timestamp: r.timestamp, signature: r.signature,
        }));
        return this.json({ vertices });
      }

      // ─── Fork Resolution ──────────────────────────────────────────────
      case "/fork/weight": {
        // Return chain weight from a given seq for fork comparison.
        // Weight = total committed rounds × avg participating validators since fork point.
        const sinceSeq = parseInt(url.searchParams.get("since_seq") || "0");
        const commits = [...sql.exec(
          "SELECT round, signatures_json FROM dag_commits WHERE round >= ? ORDER BY round ASC",
          // Map seq to approximate round — commits table is indexed by round
          Math.max(0, this.lastCommittedRound - (this.finalizedSeq - sinceSeq)),
        )] as any[];
        let totalWeight = 0;
        for (const c of commits) {
          try {
            const sigs = JSON.parse(c.signatures_json || "[]");
            totalWeight += sigs.length; // each validator signature = 1 weight unit
          } catch { totalWeight += 1; }
        }
        return this.json({
          weight: totalWeight,
          commits: commits.length,
          finalized_seq: this.finalizedSeq,
          finalized_root: this.finalizedRoot,
          last_committed_round: this.lastCommittedRound,
          snapshot: this.snapshotManager.getLatestSnapshot() ? {
            anchor_id: this.snapshotManager.getLatestSnapshot()!.anchor_id,
            snapshot_hash: this.snapshotManager.getLatestSnapshot()!.snapshot_hash,
            finalized_seq: this.snapshotManager.getLatestSnapshot()!.finalized_seq,
          } : null,
        });
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
            const sql = this.state.storage.sql;
            for (const p of envelope.payload.peers) {
              if (p.pubkey && p.url) {
                this.gossipManager.addPeer(p.pubkey, p.url);
                // Store grumpkin keys from peer exchange
                if (p.grumpkin_x && p.grumpkin_y) {
                  sql.exec("UPDATE gossip_peers SET grumpkin_x = ?, grumpkin_y = ? WHERE pubkey = ?",
                    p.grumpkin_x, p.grumpkin_y, p.pubkey);
                  sql.exec("UPDATE active_nodes SET grumpkin_x = ?, grumpkin_y = ? WHERE pubkey = ?",
                    p.grumpkin_x, p.grumpkin_y, p.pubkey);
                }
              }
            }
          }
          // Auto-discover sender
          if (envelope.sender_pubkey && envelope.sender_url) {
            this.gossipManager.addPeer(envelope.sender_pubkey, envelope.sender_url);
          }
          // Store sender's Grumpkin keys from peer exchange envelope
          if (envelope.grumpkin_x && envelope.grumpkin_y && envelope.sender_pubkey) {
            const sql = this.state.storage.sql;
            sql.exec("UPDATE gossip_peers SET grumpkin_x = ?, grumpkin_y = ? WHERE pubkey = ?",
              envelope.grumpkin_x, envelope.grumpkin_y, envelope.sender_pubkey);
            sql.exec("UPDATE active_nodes SET grumpkin_x = ?, grumpkin_y = ? WHERE pubkey = ?",
              envelope.grumpkin_x, envelope.grumpkin_y, envelope.sender_pubkey);
          }
        }
        // Always return our peer list (with grumpkin keys)
        const sql = this.state.storage.sql;
        const myPeers = this.gossipManager.getHealthyPeers().map(p => {
          const gRows = [...sql.exec("SELECT grumpkin_x, grumpkin_y FROM gossip_peers WHERE pubkey = ?", p.pubkey)] as any[];
          return {
            pubkey: p.pubkey,
            url: p.url,
            grumpkin_x: gRows[0]?.grumpkin_x || undefined,
            grumpkin_y: gRows[0]?.grumpkin_y || undefined,
          };
        });
        // Include self
        if (this.nodeIdentity) {
          myPeers.push({
            pubkey: this.nodeIdentity.pubkey,
            url: this.nodeIdentity.url,
            grumpkin_x: this.nodeIdentity.grumpkinPublicKey ? "0x" + this.nodeIdentity.grumpkinPublicKey.x.toString(16).padStart(64, "0") : undefined,
            grumpkin_y: this.nodeIdentity.grumpkinPublicKey ? "0x" + this.nodeIdentity.grumpkinPublicKey.y.toString(16).padStart(64, "0") : undefined,
          });
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

  // ─── Service Attestation Routes ──────────────────────────────────────

  private async handleAttestationQuery(_req: Request, url: URL): Promise<Response> {
    const id = url.searchParams.get("id");
    if (id) {
      // Single attestation lookup
      const att = this.attestationMgr.getAttestation(id);
      if (!att) return this.json({ error: "Attestation not found" }, 404);
      // Also return chain context
      const chain = this.attestationMgr.getChain(id, 5);
      const challenges = this.attestationMgr.getChallenges(id);
      return this.json({ attestation: att, chain_depth: chain.length, challenges });
    }
    // List attestations
    const service = url.searchParams.get("service") || undefined;
    const after = url.searchParams.get("after");
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "50"), 200);
    const attestations = this.attestationMgr.listAttestations({
      service,
      limit,
      after: after ? parseInt(after) : undefined,
    });
    const stats = this.attestationMgr.getStats();
    return this.json({ attestations, stats });
  }

  private async handleAttestationVerify(_req: Request, url: URL): Promise<Response> {
    const id = url.searchParams.get("id");
    if (!id) return this.json({ error: "id required (?id=attestation_id)" }, 400);
    const result = await this.attestationMgr.verify(id);
    return this.json(result);
  }

  // ─── Snapshot Routes ───────────────────────────────────────────────────

  private async handleSnapshotRoute(req: Request, url: URL): Promise<Response> {
    switch (url.pathname) {
      case "/snapshot/latest": {
        const snap = this.snapshotManager.getLatestSnapshot();
        if (!snap) return this.json({ error: "No snapshot available" }, 404);
        return this.json(snap);
      }

      case "/snapshot/list": {
        const limit = parseInt(url.searchParams.get("limit") || "10");
        return this.json(this.snapshotManager.listSnapshots(limit));
      }

      case "/snapshot/download": {
        const anchorId = url.searchParams.get("anchor_id");
        if (!anchorId) {
          // Default to latest
          const latest = this.snapshotManager.getLatestSnapshot();
          if (!latest) return this.json({ error: "No snapshot available" }, 404);
          const res = await this.snapshotManager.streamSnapshot(latest.anchor_id);
          if (!res) return this.json({ error: "Snapshot not found in R2" }, 404);
          return res;
        }
        const res = await this.snapshotManager.streamSnapshot(anchorId);
        if (!res) return this.json({ error: "Snapshot not found" }, 404);
        return res;
      }

      default:
        return this.json({ error: "Unknown snapshot endpoint" }, 404);
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
        const latestSnap = this.snapshotManager.getLatestSnapshot();
        return this.json({
          bundle: latestForBootstrap.bundle,
          berachain_tx: latestForBootstrap.berachain_tx,
          snapshot: latestSnap ? {
            anchor_id: latestSnap.anchor_id,
            finalized_seq: latestSnap.finalized_seq,
            snapshot_hash: latestSnap.snapshot_hash,
            byte_size: latestSnap.byte_size,
          } : null,
          instructions: latestSnap
            ? "Download snapshot via /snapshot/download for fast bootstrap, then sync remaining events via /gossip/sync"
            : "No snapshot available — sync all events via /gossip/sync",
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
        const vertex: DAGVertex = {
          author: v.author,
          round: v.round,
          event_hashes: v.event_hashes || [],
          events: v.events || [],
          refs: v.refs || [],
          timestamp: v.timestamp || 0,
          signature: v.signature,
          schnorr_sig: v.schnorr_sig ? (typeof v.schnorr_sig === "string" ? JSON.parse(v.schnorr_sig) : v.schnorr_sig) : undefined,
        };
        await this.receiveVertex(vertex, true); // skip consensus during bulk sync
      },
      // Sync ZK proofs from peers
      async (proof: any) => {
        if (!proof.block_number || !proof.proof || !proof.state_root) return;
        const existing = [...this.state.storage.sql.exec(
          "SELECT block_number FROM zk_proofs WHERE block_number = ?", proof.block_number,
        )];
        if (existing.length > 0) return;
        this.state.storage.sql.exec(
          `INSERT OR IGNORE INTO zk_proofs (block_number, proof_hex, state_root, proven_blocks, proof_type, submitted_at, verified, genesis_root)
           VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
          proof.block_number, proof.proof, proof.state_root,
          proof.proven_blocks || 1, proof.proof_type || "compressed",
          Date.now(), proof.genesis_root || null,
        );
      },
      // Bootstrap adaptive params from peers (cold-start convergence)
      // Disabled: adaptive-bootstrap overwrites admin-set config on every deploy
      // since deploys reset runtime state (_utilizationHistory). The adaptive
      // system itself will converge to the right values after a few rounds.
      (_peerAdaptive: { round_interval_ms: number; max_events_per_vertex: number }) => {
        // No-op: rely on adaptive system to converge organically
      },
      // Divergence detection callback
      (peerPubkey, peerUrl, local, remote) => {
        console.error(
          `⚠ STATE DIVERGENCE DETECTED: peer ${peerPubkey.slice(0, 12)} at seq ${remote.seq} ` +
          `has root ${remote.root.slice(0, 12)} but we have ${local.root.slice(0, 12)}`,
        );
        // Record divergence evidence
        const sql = this.state.storage.sql;
        sql.exec(
          `CREATE TABLE IF NOT EXISTS divergence_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            peer_pubkey TEXT NOT NULL,
            peer_url TEXT NOT NULL,
            local_seq INTEGER NOT NULL,
            local_root TEXT NOT NULL,
            remote_seq INTEGER NOT NULL,
            remote_root TEXT NOT NULL,
            detected_at INTEGER NOT NULL,
            resolved INTEGER NOT NULL DEFAULT 0,
            resolution TEXT
          )`,
        );
        sql.exec(
          `INSERT INTO divergence_log (peer_pubkey, peer_url, local_seq, local_root, remote_seq, remote_root, detected_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          peerPubkey, peerUrl, local.seq, local.root, remote.seq, remote.root, Date.now(),
        );
        // Alert all connected clients
        this.broadcast({
          type: "divergence.detected",
          peer_pubkey: peerPubkey,
          local_root: local.root,
          remote_root: remote.root,
          at_seq: local.seq,
        });
        // Schedule async fork resolution
        this.resolveFork(peerUrl, local.seq).catch(e =>
          console.error(`Fork resolution failed: ${e.message}`),
        );
      },
      // Local checkpoint for comparison
      { finalized_seq: this.finalizedSeq, finalized_root: this.finalizedRoot },
    );

    // Run round advancement + commits once after all vertices are stored
    const maxSyncedRound = [...this.state.storage.sql.exec(
      "SELECT MAX(round) as mr FROM dag_vertices"
    )];
    const peerMaxRound = (maxSyncedRound[0]?.mr ?? this.currentRound) as number;

    if (peerMaxRound > this.currentRound) {
      // Try normal round advancement first
      const advanced = this.tryAdvanceRound();

      // If we're far behind, fast-forward the round counter to catch up.
      // Bounded: jump at most 2x ACTIVE_WINDOW per sync cycle to prevent malicious vertex injection
      // from catapulting us to an arbitrary round. Over multiple syncs we'll still converge.
      if (!advanced && peerMaxRound > this.currentRound + 2) {
        const maxJumpPerSync = ACTIVE_WINDOW * 2;
        const jumpTo = Math.min(peerMaxRound - 1, this.currentRound + maxJumpPerSync);
        console.log(`Fast-forward: round ${this.currentRound} → ${jumpTo} (peers at ${peerMaxRound}, cap ${maxJumpPerSync})`);
        this.currentRound = jumpTo;
        this.setKV("current_round", this.currentRound.toString());
        this.invalidateActiveCache();
      }

      // Replay committed rounds — capped to 3 per sync to stay within free-tier
      // SQLite and CPU limits. Rapid follow-up alarms handle the rest incrementally.
      const committed = await this.tryCommitRounds(3);
      if (advanced || committed) this.scheduleReactiveAlarm();
      this.broadcastToChannel("status", { type: "status.update", ...this.getConsensusStatus() });
    }
  }

  // ─── Fork Resolution ──────────────────────────────────────────────────

  /**
   * Heaviest-chain fork choice: when divergence is detected, query the peer's
   * chain weight and compare with ours. If the peer's fork has more cumulative
   * validator participation (commit signatures), we're on the minority fork and
   * should recover by downloading their snapshot.
   *
   * This is a soft fork choice — it doesn't force reorgs, but allows minority
   * partitions to converge to the majority chain after healing.
   */
  private async resolveFork(peerUrl: string, divergeSeq: number): Promise<void> {
    const sql = this.state.storage.sql;

    // 1. Get our local chain weight from the divergence point
    const localCommits = [...sql.exec(
      "SELECT round, signatures_json FROM dag_commits ORDER BY round ASC",
    )] as any[];
    let localWeight = 0;
    for (const c of localCommits) {
      try {
        const sigs = JSON.parse(c.signatures_json || "[]");
        localWeight += sigs.length;
      } catch { localWeight += 1; }
    }

    // 2. Query peer's chain weight
    let peerWeight = 0;
    let peerSnapshot: { anchor_id: string; snapshot_hash: string; finalized_seq: number } | null = null;
    try {
      const separator = peerUrl.includes("?") ? "&" : "?";
      const res = await fetch(
        `${peerUrl.replace(/\/$/, "")}/fork/weight${separator}since_seq=${divergeSeq}`,
        { signal: AbortSignal.timeout(5000) },
      );
      if (res.ok) {
        const data = await res.json() as any;
        peerWeight = data.weight || 0;
        peerSnapshot = data.snapshot || null;
      }
    } catch (e: any) {
      console.warn(`Fork weight query failed for ${peerUrl}: ${e.message}`);
      return;
    }

    console.log(`Fork resolution: local weight=${localWeight} (${localCommits.length} commits), peer weight=${peerWeight}`);

    // 3. If peer's fork is heavier, we're on the minority side
    if (peerWeight > localWeight && peerSnapshot) {
      console.warn(
        `⚠ LOCAL FORK IS LIGHTER (${localWeight} < ${peerWeight}). ` +
        `Recovering from peer snapshot at seq ${peerSnapshot.finalized_seq}`,
      );

      // Alert clients before recovery
      this.broadcast({
        type: "fork.recovery",
        action: "switching_to_heavier_fork",
        local_weight: localWeight,
        peer_weight: peerWeight,
        peer_snapshot_seq: peerSnapshot.finalized_seq,
      });

      // Apply peer's snapshot to recover
      const meta = await this.snapshotManager.applySnapshot(
        peerUrl, peerSnapshot.anchor_id, peerSnapshot.snapshot_hash,
      );
      if (meta) {
        // Reset our state to match the snapshot
        this.finalizedSeq = meta.finalized_seq;
        this.finalizedRoot = meta.finalized_root;
        this.lastCommittedRound = meta.last_committed_round;
        this.currentRound = meta.last_committed_round;
        this.setKV("finalized_seq", String(meta.finalized_seq));
        this.setKV("finalized_root", meta.finalized_root);
        this.setKV("last_committed_round", String(meta.last_committed_round));
        this.setKV("current_round", String(meta.last_committed_round));
        this.stateTree.invalidate();
        this.invalidateActiveCache();

        // Mark divergence as resolved
        sql.exec(
          `UPDATE divergence_log SET resolved = 1, resolution = 'snapshot_recovery' WHERE resolved = 0`,
        );

        console.log(`Fork recovery complete: now at seq=${meta.finalized_seq} round=${meta.last_committed_round}`);
        this.broadcast({
          type: "fork.recovered",
          finalized_seq: meta.finalized_seq,
          finalized_root: meta.finalized_root,
        });
      } else {
        console.error("Fork recovery failed: snapshot apply returned null");
      }
    } else if (peerWeight <= localWeight) {
      console.log("Local fork is heavier or equal — no action needed (peer should recover from us)");
      sql.exec(
        `UPDATE divergence_log SET resolved = 1, resolution = 'local_heavier' WHERE resolved = 0`,
      );
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

    // Create state snapshot at this anchor point (for fast node bootstrap)
    const snapshot = await this.snapshotManager.createSnapshot({
      anchorId: record.id,
      stateRoot: effectiveRoot,
      finalizedSeq: effectiveSeq,
      finalizedRoot: this.finalizedRoot || effectiveRoot,
      lastCommittedRound: this.lastCommittedRound,
      shardName: this.shardName,
    });

    // Broadcast anchor event
    this.broadcastToChannel("status", {
      type: "anchor.submitted",
      anchor_id: record.id,
      berachain_tx: record.berachain_tx,
      berachain_block: record.berachain_block,
      state_root: effectiveRoot,
      finalized_seq: effectiveSeq,
      snapshot_available: !!snapshot,
    });

    return record;
  }

  // ─── WebSocket (Hibernatable) ─────────────────────────────────────────────
  //
  // Uses Cloudflare Hibernatable WebSockets API. The DO can sleep between
  // messages, reducing duration billing. Tags encode channel subscriptions
  // and metadata: "ch:status", "ch:dag", "val:true", "pk:<pubkey>".

  private handleWebSocket(ws: WebSocket) {
    // Accept with Hibernation API — DO can sleep between messages
    this.state.acceptWebSocket(ws);
    this._wsRateLimit.set(ws, { msgCount: 0, msgWindowStart: Date.now() });
  }

  /** Called by CF runtime when a hibernatable WebSocket receives a message */
  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer) {
    try {
      // Rate limiting via lightweight WeakMap (survives hibernation wake-up)
      let rl = this._wsRateLimit.get(ws);
      if (!rl) {
        rl = { msgCount: 0, msgWindowStart: Date.now() };
        this._wsRateLimit.set(ws, rl);
      }
      const now = Date.now();
      if (now - rl.msgWindowStart > 1000) {
        rl.msgCount = 0;
        rl.msgWindowStart = now;
      }
      rl.msgCount++;
      if (rl.msgCount > 100) {
        ws.send(JSON.stringify({ type: "error", message: "Message rate exceeded (max 100/sec)" }));
        ws.close(4029, "Rate limit exceeded");
        return;
      }

      const msg = JSON.parse(typeof message === "string" ? message : new TextDecoder().decode(message));
      await this.handleWsMessage(ws, msg);
    } catch (e: any) {
      try { ws.send(JSON.stringify({ type: "error", message: e.message })); } catch {}
    }
  }

  /** Called by CF runtime when a hibernatable WebSocket is closed */
  webSocketClose(_ws: WebSocket, _code: number, _reason: string, _wasClean: boolean) {
    // WeakMap auto-cleans when ws is GC'd — no manual cleanup needed
  }

  /** Called by CF runtime when a hibernatable WebSocket errors */
  webSocketError(_ws: WebSocket, _error: unknown) {
    // WeakMap auto-cleans when ws is GC'd — no manual cleanup needed
  }

  /** Read WS metadata from hibernation tags */
  private _getWsTags(ws: WebSocket): { channels: Set<string>; isValidator: boolean; pubkey?: string } {
    try {
      const tags = this.state.getTags(ws);
      const channels = new Set<string>();
      let isValidator = false;
      let pubkey: string | undefined;
      for (const tag of tags) {
        if (tag.startsWith("ch:")) channels.add(tag.slice(3));
        if (tag === "val:true") isValidator = true;
        if (tag.startsWith("pk:")) pubkey = tag.slice(3);
      }
      return { channels, isValidator, pubkey };
    } catch {
      return { channels: new Set(), isValidator: false };
    }
  }

  private async handleWsMessage(ws: WebSocket, msg: any) {
    if (msg.type === "join") {
      if (msg.pubkey) {
        try {
          const existing = this._getWsTags(ws);
          const tags = Array.from(existing.channels).map(ch => `ch:${ch}`);
          if (existing.isValidator) tags.push("val:true");
          tags.push(`pk:${msg.pubkey}`);
          this.state.setTags(ws, tags);
        } catch {}
      }
      if (msg.pubkey) this.ensureStartingInventory(msg.pubkey);
      const blocks = [...this.state.storage.sql.exec("SELECT x, z, block_type FROM blocks")];
      const inventory = msg.pubkey ? this.getPlayerInventory(msg.pubkey) : {};
      // Include archived chunk regions so clients know about cold storage
      const archivedChunks = [...this.state.storage.sql.exec(
        "SELECT chunk_x, chunk_z, block_count FROM chunk_archive",
      )];

      ws.send(JSON.stringify({
        type: "state",
        blocks,
        inventory,
        archived_chunks: archivedChunks.length > 0 ? archivedChunks : undefined,
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
      if (Array.isArray(msg.channels)) {
        const existing = this._getWsTags(ws);
        for (const ch of msg.channels) {
          existing.channels.add(ch);
        }
        try {
          const tags = Array.from(existing.channels).map(ch => `ch:${ch}`);
          if (existing.isValidator) tags.push("val:true");
          if (existing.pubkey) tags.push(`pk:${existing.pubkey}`);
          this.state.setTags(ws, tags);
        } catch {}
        ws.send(JSON.stringify({ type: "subscribed", channels: Array.from(existing.channels) }));
      }
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
      // Persist validator status in tags
      try {
        const existing = this._getWsTags(ws);
        const tags = Array.from(existing.channels).map(ch => `ch:${ch}`);
        tags.push("val:true", `pk:${msg.pubkey}`);
        this.state.setTags(ws, tags);
      } catch {}
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
        "SELECT hash, author, round, events_json, refs_json, signature, received_at, schnorr_sig FROM dag_vertices WHERE round > ? ORDER BY round ASC, hash ASC LIMIT ?",
        afterRound, limit,
      )].map((r: any) => ({
        hash: r.hash, author: r.author, round: r.round,
        events_json: r.events_json, refs_json: r.refs_json, signature: r.signature,
        schnorr_sig: r.schnorr_sig || undefined,
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

    if (CONSENSUS_ENABLED && this.getActiveNodeCount() >= this.getNetworkParam("min_nodes_for_consensus", MIN_NODES_FOR_CONSENSUS)) {
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

      // Vertex creation is alarm-driven only — event-triggered vertex creation
      // causes runaway round advancement that outpaces the prover.

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

  private _lastVertexTime = 0;

  private async maybeCreateVertex() {
    if (!this.nodeIdentity) return;

    // Throttle vertex creation to at most once per round_interval_ms / 2
    // to prevent every accepted event from advancing the round
    const minInterval = this.getNetworkParam("round_interval_ms", ROUND_INTERVAL_MS) / 2;
    if (Date.now() - this._lastVertexTime < minInterval) return;

    // Don't create if we already have a vertex this round
    const existing = [...this.state.storage.sql.exec(
      "SELECT hash FROM dag_vertices WHERE author = ? AND round = ?",
      this.nodeIdentity.pubkey, this.currentRound,
    )];
    if (existing.length > 0) return;

    this._lastVertexTime = Date.now();
    await this.createAndBroadcastVertex();
  }

  private async createAndBroadcastVertex() {
    if (!this.nodeIdentity) return;
    const sql = this.state.storage.sql;

    // Expire stale pending events
    const pendingTtl = this.getNetworkParam("pending_event_ttl_ms", PENDING_EVENT_TTL_MS);
    const expiryCutoff = Date.now() - pendingTtl;
    const expired = [...sql.exec(
      "SELECT COUNT(*) as cnt FROM pending_events WHERE timestamp < ?", expiryCutoff,
    )];
    const expiredCount = (expired[0]?.cnt ?? 0) as number;
    if (expiredCount > 0) {
      sql.exec("DELETE FROM pending_events WHERE timestamp < ?", expiryCutoff);
      console.log(`Expired ${expiredCount} stale pending events (older than ${pendingTtl / 1000}s)`);
    }

    // Gather pending events (capped to keep vertices lightweight)
    const maxEvents = this.getNetworkParam("max_events_per_vertex", MAX_EVENTS_PER_VERTEX);
    const pendingRows = [...sql.exec(
      "SELECT hash, type, payload, pubkey, signature, timestamp FROM pending_events ORDER BY timestamp ASC LIMIT ?",
      maxEvents,
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

    // Schnorr-sign block message for ZK proving (Schnorr on Grumpkin curve)
    const blockMsg = new TextEncoder().encode(`block:${this.currentRound}`);
    const blockMsgHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", blockMsg),
    );
    const schnorrSig = signDataSchnorr(this.nodeIdentity, blockMsgHash);

    const vertex: DAGVertex = {
      author: this.nodeIdentity.pubkey,
      round: this.currentRound,
      event_hashes: eventHashes,
      events,
      refs,
      timestamp: Date.now(),
      signature: "",
      schnorr_sig: schnorrSig,
    };

    vertex.signature = await signVertex(this.nodeIdentity, vertex);
    const vHash = await computeVertexHash(vertex);

    // Store locally
    this.storeVertex(vHash, vertex);

    // Update self in active_nodes (receiveVertex does this for peer vertices, but not for self-created ones)
    const selfGrumpkinX = this.nodeIdentity!.grumpkinPublicKey ? "0x" + this.nodeIdentity!.grumpkinPublicKey.x.toString(16).padStart(64, "0") : null;
    const selfGrumpkinY = this.nodeIdentity!.grumpkinPublicKey ? "0x" + this.nodeIdentity!.grumpkinPublicKey.y.toString(16).padStart(64, "0") : null;
    sql.exec(
      `INSERT INTO active_nodes (pubkey, url, last_vertex_round, last_seen, is_self, grumpkin_x, grumpkin_y)
       VALUES (?, ?, ?, ?, 1, ?, ?)
       ON CONFLICT(pubkey) DO UPDATE SET last_vertex_round = MAX(last_vertex_round, ?), last_seen = ?, grumpkin_x = ?, grumpkin_y = ?`,
      this.nodeIdentity!.pubkey, this.nodeIdentity!.url, vertex.round, Date.now(), selfGrumpkinX, selfGrumpkinY,
      vertex.round, Date.now(), selfGrumpkinX, selfGrumpkinY,
    );
    this.invalidateActiveCache();

    // Clear pending events that were included (batch to avoid SQLite parameter limits)
    for (let i = 0; i < eventHashes.length; i += 100) {
      const batch = eventHashes.slice(i, i + 100);
      const placeholders = batch.map(() => "?").join(",");
      sql.exec(`DELETE FROM pending_events WHERE hash IN (${placeholders})`, ...batch);
    }

    // Try round advancement + commits
    const advanced = this.tryAdvanceRound();
    const committed = await this.tryCommitRounds();
    if (advanced || committed) this.scheduleReactiveAlarm();

    // Speculative execution: pre-apply our own events so commitAnchor can skip them.
    // Safe because these events already passed validation in receiveClientEvent.
    // If they get reordered or rejected during commit, the set is cleared.
    if (events.length > 0 && this._speculativeRound !== this.currentRound) {
      this._speculativelyApplied.clear();
      this._speculativeRound = this.currentRound;
    }
    for (let i = 0; i < events.length; i++) {
      try {
        await this.applyEvent(events[i].type, events[i].payload, events[i].pubkey);
        this._speculativelyApplied.add(eventHashes[i]);
      } catch { /* speculation failure is non-fatal */ }
    }

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

    // 2. Reject vertices from unregistered or suspended validators
    const authorStatus = this.validatorRegistry.getValidatorStatus(vertex.author);
    if (authorStatus === "suspended") {
      return { ok: false, error: "Vertex author is suspended (equivocation)" };
    }
    if (authorStatus === "stale") {
      return { ok: false, error: "Vertex author must re-register (inactive too long)" };
    }
    // Allow 'unknown' authors only during genesis bootstrapping (< MIN_NODES_FOR_CONSENSUS active)
    if (authorStatus === "unknown") {
      const activeCount = this.getActiveNodeCount();
      if (activeCount >= MIN_NODES_FOR_CONSENSUS) {
        return { ok: false, error: "Vertex author is not a registered validator" };
      }
    }

    // 3. Verify all contained events' signatures
    for (const event of vertex.events) {
      const validEvent = await this.verifySignature(event);
      if (!validEvent) return { ok: false, error: "Invalid event signature in vertex" };
    }

    // 3b. Reject vertices with unreasonable timestamps (clock skew protection)
    if (vertex.timestamp) {
      const now = Date.now();
      const MAX_FUTURE_MS = 30_000;    // 30s tolerance for clock drift
      const MAX_AGE_MS = 3_600_000;    // 1 hour — older vertices should come via sync, not live gossip
      if (vertex.timestamp > now + MAX_FUTURE_MS) {
        return { ok: false, error: `Vertex timestamp ${vertex.timestamp} is too far in the future` };
      }
      if (vertex.timestamp < now - MAX_AGE_MS && vertex.round > this.lastCommittedRound) {
        // Only reject stale timestamps on uncommitted rounds — historical sync is allowed
        return { ok: false, error: `Vertex timestamp is too old (${((now - vertex.timestamp) / 1000).toFixed(0)}s)` };
      }
    }

    // 4. Reject if too far ahead — bounded fast-forward
    const MAX_JUMP = ACTIVE_WINDOW * 2; // max round jump from a single vertex
    if (vertex.round > this.currentRound + ACTIVE_WINDOW) {
      if (vertex.round > this.currentRound + MAX_JUMP) {
        return { ok: false, error: `Vertex round too far ahead (${vertex.round} vs ${this.currentRound}, max jump ${MAX_JUMP})` };
      }
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
      "INSERT OR IGNORE INTO dag_vertices (hash, author, round, events_json, refs_json, signature, received_at, timestamp, schnorr_sig) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      hash,
      vertex.author,
      vertex.round,
      JSON.stringify(vertex.events.map((e, i) => ({ ...e, hash: vertex.event_hashes[i] }))),
      JSON.stringify(vertex.refs),
      vertex.signature,
      Date.now(),
      vertex.timestamp,
      vertex.schnorr_sig ? JSON.stringify(vertex.schnorr_sig) : null,
    );

    // dag_edges removed — topologicalSort uses in-memory refs_json
  }

  // ─── Round Advancement ──────────────────────────────────────────────────

  private tryAdvanceRound(): boolean {
    const activeCount = this.getActiveNodeCount();
    if (activeCount < this.getNetworkParam("min_nodes_for_consensus", MIN_NODES_FOR_CONSENSUS)) return false;

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

  private async tryCommitRounds(maxCommits: number = 10): Promise<boolean> {
    const minConsensus = this.getNetworkParam("min_nodes_for_consensus", MIN_NODES_FOR_CONSENSUS);
    const activeCount = this.getActiveNodeCount();
    const isCatchUp = (this.currentRound - this.lastCommittedRound) > ACTIVE_WINDOW;

    // In normal mode, need minimum active nodes. In catch-up mode, we derive
    // the active set from vertex authors in each round being committed.
    if (!isCatchUp && activeCount < minConsensus) return false;

    const sql = this.state.storage.sql;
    const startRound = this.lastCommittedRound + 1;
    const endRound = Math.min(this.currentRound - 1, startRound + maxCommits - 1);
    if (startRound > endRound) return false;

    // ── Pipelined execution: batch-load all vertex data for the commit range ──
    // One query covers rounds [startRound, endRound+1] (need +1 for commit check).
    // This replaces N per-round queries with a single range query.
    const allRows = [...sql.exec(
      "SELECT hash, author, round, events_json, refs_json FROM dag_vertices WHERE round >= ? AND round <= ?",
      startRound, endRound + 1,
    )] as any[];

    // Index vertices by round — parse JSON once, reuse across iterations
    const vertexCache = new Map<number, VertexNode[]>();
    for (const row of allRows) {
      let events: any[], refs: string[];
      try { events = JSON.parse(row.events_json); } catch { events = []; }
      try { refs = JSON.parse(row.refs_json); } catch { refs = []; }
      const node: VertexNode = {
        hash: row.hash,
        author: row.author,
        round: row.round,
        event_hashes: events.map((e: any) => e.hash),
        refs,
      };
      const list = vertexCache.get(row.round);
      if (list) list.push(node);
      else vertexCache.set(row.round, [node]);
    }

    // Batch-check already-committed rounds in the range
    const committedSet = new Set<number>(
      [...sql.exec(
        "SELECT round FROM dag_commits WHERE round >= ? AND round <= ?", startRound, endRound,
      )].map((r: any) => r.round as number),
    );

    // Pre-compute catch-up active set once (covers the entire range window)
    let catchUpAuthors: string[] | null = null;
    if (isCatchUp) {
      catchUpAuthors = [...sql.exec(
        "SELECT DISTINCT author FROM dag_vertices WHERE round >= ? AND round <= ?",
        Math.max(0, startRound - ACTIVE_WINDOW), endRound + 1,
      )].map((row: any) => row.author as string);
    }

    // Normal-mode active set (stable across the batch)
    const normalPubkeys = !isCatchUp ? this.getActivePubkeys() : [];

    // ── Pipeline: iterate rounds with pre-loaded data ──
    let commitsThisCycle = 0;
    for (let r = startRound; r <= endRound && commitsThisCycle < maxCommits; r++) {
      // Skip already-committed rounds (crash recovery)
      if (committedSet.has(r)) {
        if (r > this.lastCommittedRound) {
          this.lastCommittedRound = r;
          this.setKV("last_committed_round", r.toString());
        }
        continue;
      }

      // Build verticesByRound from cache (no SQL query needed)
      const verticesByRound = new Map<number, VertexNode[]>();
      verticesByRound.set(r, vertexCache.get(r) || []);
      verticesByRound.set(r + 1, vertexCache.get(r + 1) || []);

      let effectivePubkeys: string[];
      let effectiveCount: number;
      if (isCatchUp && catchUpAuthors) {
        effectivePubkeys = catchUpAuthors;
        effectiveCount = catchUpAuthors.length;
        if (effectiveCount < minConsensus) continue;
      } else {
        effectivePubkeys = normalPubkeys;
        effectiveCount = activeCount;
      }

      const leader = await selectLeader(r, effectivePubkeys);
      const result = checkCommit(r, leader, verticesByRound, effectiveCount);
      if (result.committed && result.anchorHash) {
        try {
          await this.commitAnchor(r, result.anchorHash);
          commitsThisCycle++;
          if (isCatchUp && commitsThisCycle % 50 === 0) {
            console.log(`Catch-up replay: committed ${commitsThisCycle} rounds (at round ${r})`);
          }
        } catch (e: any) {
          console.error(`commitAnchor failed at round ${r}: ${e.message}\n${e.stack}`);
        }
      }
    }
    return commitsThisCycle > 0;
  }

  private async commitAnchor(round: number, anchorHash: string) {
    const sql = this.state.storage.sql;

    // Collect vertex signatures + data for this round (persisted for ZK prover after pruning)
    const roundVertices = [...sql.exec(
      "SELECT hash, author, signature, round, events_json, refs_json, timestamp, schnorr_sig FROM dag_vertices WHERE round = ?", round
    )] as any[];
    // Build canonical block message for Schnorr signing
    const blockMsg = new TextEncoder().encode(`block:${round}`);
    const blockMsgHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", blockMsg),
    );

    // Pre-parse events/refs once and cache — avoids redundant JSON.parse later in vertexMap construction
    const eventsMap = new Map<string, any[]>();
    const refsMap = new Map<string, string[]>();
    for (const v of roundVertices as any[]) {
      try { eventsMap.set(v.hash, JSON.parse(v.events_json || "[]")); } catch { eventsMap.set(v.hash, []); }
      try { refsMap.set(v.hash, JSON.parse(v.refs_json || "[]")); } catch { refsMap.set(v.hash, []); }
    }

    // Batch-load grumpkin keys for all authors in one query (replaces N per-vertex lookups)
    const authorPubkeys = [...new Set(roundVertices.map((v: any) => v.author))];
    const grumpkinCache = new Map<string, { x: string; y: string }>();
    if (authorPubkeys.length > 0) {
      const placeholders = authorPubkeys.map(() => "?").join(",");
      const grumpkinRows = [...sql.exec(
        `SELECT pubkey, grumpkin_x, grumpkin_y FROM active_nodes WHERE pubkey IN (${placeholders}) AND grumpkin_x IS NOT NULL`,
        ...authorPubkeys,
      )] as any[];
      for (const r of grumpkinRows) {
        if (r.grumpkin_x && r.grumpkin_y) grumpkinCache.set(r.pubkey, { x: r.grumpkin_x, y: r.grumpkin_y });
      }
    }

    const commitSigs = JSON.stringify(roundVertices.map((v: any) => {
      const events = eventsMap.get(v.hash) || [];
      const eventHashes = events.map((e: any) => e.hash || "").filter(Boolean);
      const refs = refsMap.get(v.hash) || [];

      const entry: any = {
        pubkey: v.author,
        signature: v.signature,
        round: v.round,
        event_hashes: eventHashes,
        refs,
        timestamp: v.timestamp || 0,
      };

      // Use Schnorr signature stored in the vertex (created by each node at vertex creation time)
      if (v.schnorr_sig) {
        try {
          const stored = typeof v.schnorr_sig === "string" ? JSON.parse(v.schnorr_sig) : v.schnorr_sig;
          entry.schnorr_s = stored.schnorr_s;
          entry.schnorr_e = stored.schnorr_e;
          entry.grumpkin_x = stored.grumpkin_x;
          entry.grumpkin_y = stored.grumpkin_y;
        } catch {}
      }
      // Fallback: sign with own key if this is our vertex and no stored sig
      if (!entry.schnorr_s && v.author === this.nodeIdentity?.pubkey && this.nodeIdentity) {
        const schnorr = signDataSchnorr(this.nodeIdentity, blockMsgHash);
        entry.schnorr_s = schnorr.schnorr_s;
        entry.schnorr_e = schnorr.schnorr_e;
        entry.grumpkin_x = schnorr.grumpkin_x;
        entry.grumpkin_y = schnorr.grumpkin_y;
      }
      // Fallback: attach Grumpkin public key from active_nodes (for old vertices without schnorr_sig)
      if (!entry.grumpkin_x) {
        const cached = grumpkinCache.get(v.author);
        if (cached) {
          entry.grumpkin_x = cached.x;
          entry.grumpkin_y = cached.y;
        }
      }

      return entry;
    }));

    // Record commit with signatures
    sql.exec(
      "INSERT OR IGNORE INTO dag_commits (round, anchor_hash, committed_at, signatures_json) VALUES (?, ?, ?, ?)",
      round, anchorHash, Date.now(), commitSigs,
    );

    // Build vertex map for topological sort — load vertices within a bounded window
    // Only need vertices back to lastCommittedRound (older ones are already finalized)
    // Reuses eventsMap/refsMap populated above for current-round vertices; parses others once.
    const minRound = Math.max(0, this.lastCommittedRound - 2);
    const allVertices = [...sql.exec(
      "SELECT hash, author, round, events_json, refs_json FROM dag_vertices WHERE round >= ? AND round <= ?",
      minRound, round,
    )];
    const vertexMap = new Map<string, VertexNode>();
    for (const row of allVertices as any[]) {
      // Reuse cached parse for current-round vertices, parse once for others
      let events = eventsMap.get(row.hash);
      if (!events) {
        try { events = JSON.parse(row.events_json); } catch { events = []; }
        eventsMap.set(row.hash, events!);
      }
      let refs = refsMap.get(row.hash);
      if (!refs) {
        try { refs = JSON.parse(row.refs_json); } catch { refs = []; }
        refsMap.set(row.hash, refs!);
      }
      vertexMap.set(row.hash, {
        hash: row.hash,
        author: row.author,
        round: row.round,
        event_hashes: events!.map((e: any) => e.hash),
        refs: refs!,
      });
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
      if (!events || events.length === 0) continue;

      // Vertex-level skip: if all event hashes in this vertex are already finalized,
      // skip the entire inner loop (avoids per-event hash lookups + validateRules)
      if (events.every((e: any) => finalizedEventHashes.has(e.hash))) continue;

      for (const event of events) {
        const eventHash = event.hash || await computeEventHash(event);

        // Skip already finalized (in-memory set lookup, not DB query)
        if (finalizedEventHashes.has(eventHash)) continue;

        // Validate rules against current finalized state
        const ruleCheck = this.validateRules(event);
        if (!ruleCheck.ok) continue; // skip invalid

        // Apply to state — skip if speculatively pre-executed
        const payload = typeof event.payload === "string" ? JSON.parse(event.payload) : event.payload;
        if (!this._speculativelyApplied.has(eventHash)) {
          await this.applyEvent(event.type, payload, event.pubkey);
        }

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

    // ── Deferred state root computation ─────────────────────────────────────
    // Batch-compute the finalized root chain instead of per-event async SHA-256.
    // Single concatenation + one hash is ~N× faster than N individual hashes.
    if (newlyFinalizedHashes.length > 0) {
      let rootAccum = this.finalizedRoot;
      for (const h of newlyFinalizedHashes) {
        rootAccum = await sha256(rootAccum + h);
      }
      this.finalizedRoot = rootAccum;
    }

    // ── Persist per-block state mutations for ZK prover ─────────────────────
    // Capture dirty entries and clear them so next block starts fresh.
    const blockMutations = this.stateTree.getDirtyMutations();
    this.stateTree.clearDirtyKeys();
    if (blockMutations.length > 0) {
      // Cloudflare DO SQLite limits bind params; insert one row at a time
      for (const m of blockMutations) {
        sql.exec(
          `INSERT OR REPLACE INTO block_mutations (block_number, key, new_value, is_delete) VALUES (?, ?, ?, ?)`,
          round, m.key, m.value ?? "", m.value === null ? 1 : 0,
        );
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

    // Conviction voting: re-check pending proposals — time-accumulated conviction may now meet quorum
    this.recheckConviction();

    // Activate governance proposals that reached quorum and their target round
    this.activateGovernanceProposals(round);

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

    // ── Fraud Proof Challenge Window ──────────────────────────────────────
    // Open a challenge window for this block so validators can dispute it.
    {
      const challengeWindowSize = this.getNetworkParam("challenge_window_rounds", DEFAULT_CHALLENGE_WINDOW);
      const anchorVertex = vertexMap.get(anchorHash);
      const proposer = anchorVertex?.author || this.nodeIdentity?.pubkey || "";
      const cw = createChallengeWindow(round, proposer, this.finalizedRoot, this.currentRound, challengeWindowSize);
      insertChallengeWindow(sql, cw);
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

    // Distribute accumulated validator token rewards (reputation-weighted)
    this.feeSplitter.distributeValidatorRewards(round, "PERSIST");

    // ── Adaptive parameter adjustment (EIP-1559 style) ───────────────────
    this.adjustAdaptiveParams(round, finalizedBroadcasts.length);

    // Clear speculative cache after commit — speculated events are now finalized
    this._speculativelyApplied.clear();

    console.log(`Committed round=${round} anchor=${anchorHash.slice(0, 12)} seq=${this.finalizedSeq}`);
  }

  // ─── Peer Communication ─────────────────────────────────────────────────

  private async broadcastVertexToPeers(vertex: DAGVertex) {
    // Push to all validators connected via WebSocket (hibernatable + in-memory)
    const str = JSON.stringify({ type: "vertex.new", ...vertex });
    const valSockets = this.state.getWebSockets("val:true");
    for (const ws of valSockets) {
      try { ws.send(str); } catch {}
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
            schnorr_sig: v.schnorr_sig ? (typeof v.schnorr_sig === "string" ? JSON.parse(v.schnorr_sig) : v.schnorr_sig) : undefined,
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

  private getConsensusStatus(): ConsensusStatus & Record<string, any> {
    // In single-node / direct-apply mode, report latestSeq as finalized
    const effectiveSeq = this.finalizedSeq > 0 ? this.finalizedSeq : this.latestSeq;
    const effectiveRoot = this.finalizedRoot || this.currentRoot;
    let latestProvenCS = 0;
    try {
      const rows = [...this.state.storage.sql.exec("SELECT MAX(block_number) as b FROM zk_proofs")];
      latestProvenCS = (rows[0]?.b ?? 0) as number;
    } catch {}
    return {
      node_pubkey: this.nodeIdentity?.pubkey || "",
      current_round: this.currentRound,
      finalized_seq: effectiveSeq,
      finalized_root: effectiveRoot,
      last_committed_round: this.lastCommittedRound,
      active_nodes: this.getActiveNodeCount(),
      pending_events: this.getPendingEventCount(),
      round_interval_ms: this.getNetworkParam("round_interval_ms", ROUND_INTERVAL_MS),
      max_events_per_vertex: this.getNetworkParam("max_events_per_vertex", MAX_EVENTS_PER_VERTEX),
      grumpkin_x: this.nodeIdentity?.grumpkinPublicKey ? "0x" + this.nodeIdentity.grumpkinPublicKey.x.toString(16).padStart(64, "0") : undefined,
      grumpkin_y: this.nodeIdentity?.grumpkinPublicKey ? "0x" + this.nodeIdentity.grumpkinPublicKey.y.toString(16).padStart(64, "0") : undefined,
      adaptive: {
        enabled: this._adaptiveEnabled,
        prover_lag: latestProvenCS > 0 ? this.lastCommittedRound - latestProvenCS : null,
        consecutive_empty_rounds: this._consecutiveEmptyRounds,
      },
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
      case "app.upload": {
        if (!payload.contract) return { ok: false, error: "Missing contract address" };
        if (!payload.files || !Array.isArray(payload.files) || payload.files.length === 0) {
          return { ok: false, error: "Missing or empty files array" };
        }
        // Verify contract exists
        const contractRows = [...this.state.storage.sql.exec("SELECT deployer FROM contracts WHERE address = ?", payload.contract)];
        if (contractRows.length === 0) return { ok: false, error: "Contract not found" };
        // Only contract deployer can upload app files
        if ((contractRows[0] as any).deployer !== pubkey) {
          return { ok: false, error: "Only the contract deployer can upload app files" };
        }
        // Validate file paths
        for (const f of payload.files) {
          if (!f.path || !f.data_b64) return { ok: false, error: `Invalid file entry: missing path or data_b64` };
          if (f.path.includes("..") || f.path.startsWith("/")) return { ok: false, error: `Invalid path: ${f.path}` };
        }
        // Check total size
        let totalBytes = 0;
        for (const f of payload.files) {
          totalBytes += Math.ceil((f.data_b64.length * 3) / 4); // approximate decoded size
        }
        if (totalBytes > 2_097_152) return { ok: false, error: "Total app files exceed 2MB" };
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
      case "governance.propose": {
        if (!payload.param_key || payload.proposed_value === undefined || !payload.activate_at_round) {
          return { ok: false, error: "Missing param_key, proposed_value, or activate_at_round" };
        }
        const bounds = PersistiaWorldV4.GOVERNABLE_PARAMS[payload.param_key];
        if (!bounds) return { ok: false, error: `Unknown param: ${payload.param_key}` };
        const numVal = parseInt(payload.proposed_value);
        if (isNaN(numVal) || numVal < bounds.min || numVal > bounds.max) {
          return { ok: false, error: `Value must be between ${bounds.min} and ${bounds.max}` };
        }
        if (payload.activate_at_round <= this.lastCommittedRound + 10) {
          return { ok: false, error: "activate_at_round must be at least 10 rounds in the future" };
        }
        // Must be a registered validator
        const vRows = [...this.state.storage.sql.exec("SELECT 1 FROM validators WHERE pubkey = ? AND status = 'active'", pubkey)];
        if (vRows.length === 0) return { ok: false, error: "Only active validators can propose" };
        return { ok: true };
      }
      case "governance.vote": {
        if (!payload.proposal_id || !payload.vote) return { ok: false, error: "Missing proposal_id or vote" };
        if (!["yes", "no"].includes(payload.vote)) return { ok: false, error: "Vote must be 'yes' or 'no'" };
        // Proposal must exist and be pending
        const pRows = [...this.state.storage.sql.exec("SELECT status FROM governance_proposals WHERE id = ?", payload.proposal_id)];
        if (pRows.length === 0) return { ok: false, error: "Proposal not found" };
        if (pRows[0].status !== "pending") return { ok: false, error: "Proposal is not pending" };
        // Must be a registered validator
        const valRows = [...this.state.storage.sql.exec("SELECT 1 FROM validators WHERE pubkey = ? AND status = 'active'", pubkey)];
        if (valRows.length === 0) return { ok: false, error: "Only active validators can vote" };
        // Conviction voting: allow re-voting to change position (resets conviction timer)
        return { ok: true };
      }
      default:
        return { ok: false, error: `Unknown event type: ${event.type}` };
    }
  }

  // ─── State Expiry: Chunk Archive/Resurrect ──────────────────────────────

  private static CHUNK_SIZE = 64; // blocks per chunk dimension

  private chunkCoord(x: number, z: number): { cx: number; cz: number } {
    return {
      cx: Math.floor(x / PersistiaWorldV4.CHUNK_SIZE),
      cz: Math.floor(z / PersistiaWorldV4.CHUNK_SIZE),
    };
  }

  /**
   * Archive cold chunks to R2. Called from alarmPrune() every 10th cycle.
   * Chunks with no accessed_at update in 7 days are moved to R2 cold storage.
   */
  async archiveColdChunks(): Promise<number> {
    if (!this.env.BLOB_STORE) return 0;
    const sql = this.state.storage.sql;
    const sevenDaysAgo = Date.now() - 7 * 86_400_000;

    // Find chunks where all blocks are cold (accessed_at < 7 days or 0)
    // Group by chunk coordinates
    const coldBlocks = [...sql.exec(
      `SELECT x, z, block_type, placed_by FROM blocks
       WHERE accessed_at < ? OR accessed_at IS NULL
       ORDER BY x, z LIMIT 500`,
      sevenDaysAgo,
    )] as any[];

    if (coldBlocks.length === 0) return 0;

    // Group by chunk
    const chunks = new Map<string, any[]>();
    for (const b of coldBlocks) {
      const { cx, cz } = this.chunkCoord(b.x, b.z);
      const key = `${cx},${cz}`;
      if (!chunks.has(key)) chunks.set(key, []);
      chunks.get(key)!.push(b);
    }

    let archived = 0;
    for (const [key, blocks] of chunks) {
      const [cx, cz] = key.split(",").map(Number);
      // Don't re-archive already archived chunks
      const existing = [...sql.exec(
        "SELECT chunk_x FROM chunk_archive WHERE chunk_x = ? AND chunk_z = ?", cx, cz,
      )];
      if (existing.length > 0) continue;

      // Serialize chunk to JSON and upload to R2
      const r2Key = `chunks/${this.shardName}/${cx}_${cz}.json`;
      const data = JSON.stringify(blocks);
      await this.env.BLOB_STORE.put(r2Key, data, {
        customMetadata: { chunk_x: String(cx), chunk_z: String(cz), block_count: String(blocks.length) },
      });

      // Record archive and delete from SQLite
      sql.exec(
        "INSERT OR REPLACE INTO chunk_archive (chunk_x, chunk_z, r2_key, block_count, archived_at) VALUES (?, ?, ?, ?, ?)",
        cx, cz, r2Key, blocks.length, Date.now(),
      );
      for (const b of blocks) {
        sql.exec("DELETE FROM blocks WHERE x = ? AND z = ?", b.x, b.z);
      }
      archived += blocks.length;
    }

    if (archived > 0) {
      console.log(`State expiry: archived ${archived} blocks in ${chunks.size} chunks to R2`);
    }
    return archived;
  }

  /**
   * Resurrect an archived chunk from R2 back to SQLite.
   * Called on-demand when a player interacts with a block in an archived region.
   */
  async resurrectChunk(x: number, z: number): Promise<boolean> {
    if (!this.env.BLOB_STORE) return false;
    const sql = this.state.storage.sql;
    const { cx, cz } = this.chunkCoord(x, z);

    const rows = [...sql.exec(
      "SELECT r2_key FROM chunk_archive WHERE chunk_x = ? AND chunk_z = ?", cx, cz,
    )] as any[];
    if (rows.length === 0) return false; // not archived

    const obj = await this.env.BLOB_STORE.get(rows[0].r2_key);
    if (!obj) {
      console.warn(`Chunk ${cx},${cz} archive missing from R2`);
      sql.exec("DELETE FROM chunk_archive WHERE chunk_x = ? AND chunk_z = ?", cx, cz);
      return false;
    }

    const blocks = JSON.parse(await obj.text()) as any[];
    const now = Date.now();
    for (const b of blocks) {
      sql.exec(
        "INSERT OR IGNORE INTO blocks (x, z, block_type, placed_by, accessed_at) VALUES (?, ?, ?, ?, ?)",
        b.x, b.z, b.block_type, b.placed_by, now,
      );
    }

    // Remove archive record and R2 object
    sql.exec("DELETE FROM chunk_archive WHERE chunk_x = ? AND chunk_z = ?", cx, cz);
    await this.env.BLOB_STORE.delete(rows[0].r2_key);

    console.log(`Chunk ${cx},${cz} resurrected: ${blocks.length} blocks restored`);
    return true;
  }

  // ─── State Mutation ─────────────────────────────────────────────────────

  private async applyEvent(type: string, payload: any, pubkey: string) {
    const sql = this.state.storage.sql;
    switch (type) {
      case "place":
        // Resurrect archived chunk if needed before placing
        await this.resurrectChunk(payload.x, payload.z);
        sql.exec("INSERT OR REPLACE INTO blocks (x, z, block_type, placed_by, accessed_at) VALUES (?, ?, ?, ?, ?)",
          payload.x, payload.z, payload.block, pubkey, Date.now());
        this.addToInventory(pubkey, this.blockTypeToItem(payload.block), -1);
        this.stateTree.markDirty(`block:${payload.x},${payload.z}`, `${payload.block}:${pubkey}`);
        this.stateTree.markDirty(`inv:${pubkey}:${this.blockTypeToItem(payload.block)}`, null);
        await this.rewardGameAction(pubkey);
        break;
      case "break": {
        // Resurrect archived chunk if needed before breaking
        await this.resurrectChunk(payload.x, payload.z);
        const rows = [...sql.exec("SELECT block_type FROM blocks WHERE x = ? AND z = ?", payload.x, payload.z)];
        if (rows.length > 0) {
          sql.exec("DELETE FROM blocks WHERE x = ? AND z = ?", payload.x, payload.z);
          this.addToInventory(pubkey, this.blockTypeToItem(rows[0].block_type as number), 1);
          this.stateTree.markDirty(`block:${payload.x},${payload.z}`, null);
        }
        await this.rewardGameAction(pubkey);
        break;
      }
      case "transfer":
        sql.exec("UPDATE ownership SET owner_pubkey = ? WHERE asset_id = ?", payload.toPubkey, payload.assetId);
        break;
      case "craft":
        this.applyCraft(pubkey, payload.recipe);
        await this.rewardGameAction(pubkey);
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
      case "contract.upgrade": {
        const upgradeWasm = this.b64ToBytes(payload.wasm_b64);
        await this.contractExecutor.upgrade(payload.contract, upgradeWasm, pubkey);
        this.stateTree.markDirty(`deployed:${payload.contract}`, `${pubkey}:${payload.contract}:upgraded`);
        this.broadcast({ type: "contract.upgraded", address: payload.contract, deployer: pubkey });
        break;
      }
      case "contract.lock": {
        this.contractExecutor.lockContract(payload.contract, pubkey);
        this.stateTree.markDirty(`deployed:${payload.contract}`, `${pubkey}:${payload.contract}:locked`);
        this.broadcast({ type: "contract.locked", address: payload.contract, locked_by: pubkey });
        break;
      }
      case "app.upload": {
        // Store each file as contract state under _app/ prefix
        for (const f of payload.files) {
          const keyBytes = new TextEncoder().encode(`_app/${f.path}`);
          const valueBytes = Uint8Array.from(atob(f.data_b64), c => c.charCodeAt(0));
          sql.exec(
            "INSERT OR REPLACE INTO contract_state (contract_address, key, value) VALUES (?, ?, ?)",
            payload.contract, keyBytes, valueBytes,
          );
          this.stateTree.markDirty(`app:${payload.contract}:${f.path}`, `${f.path}:${valueBytes.length}`);
        }
        this.broadcast({ type: "app.uploaded", contract: payload.contract, files: payload.files.map((f: any) => f.path) });
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
        // Process any oracle/trigger/deploy requests emitted by the contract
        if (result.oracle_requests) {
          await this.processOracleEmits(payload.contract, result.oracle_requests);
        }
        if (result.trigger_requests) {
          await this.processTriggerEmits(payload.contract, pubkey, result.trigger_requests);
        }
        if (result.deploy_requests) {
          await this.processDeployEmits(result.deploy_requests);
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
        if (callResult.deploy_requests) {
          await this.processDeployEmits(callResult.deploy_requests);
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
      case "governance.propose": {
        const proposalId = await sha256(`gov:${pubkey}:${payload.param_key}:${payload.proposed_value}:${Date.now()}`);
        sql.exec(
          `INSERT INTO governance_proposals (id, param_key, proposed_value, activate_at_round, proposer, status, created_at)
           VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
          proposalId, payload.param_key, payload.proposed_value.toString(),
          payload.activate_at_round, pubkey, Date.now(),
        );
        this.broadcast({
          type: "governance.proposed",
          proposal_id: proposalId,
          param_key: payload.param_key,
          proposed_value: payload.proposed_value,
          activate_at_round: payload.activate_at_round,
          proposer: pubkey,
        });
        break;
      }
      case "governance.vote": {
        const repRows = [...sql.exec("SELECT reputation FROM validators WHERE pubkey = ?", pubkey)];
        const reputation = repRows.length > 0 ? (repRows[0].reputation as number) : 100;
        const now = Date.now();
        // Conviction voting: upsert — changing vote resets staked_at (conviction timer)
        const existingVote = [...sql.exec(
          "SELECT vote, staked_at FROM governance_proposal_votes WHERE proposal_id = ? AND voter = ?",
          payload.proposal_id, pubkey,
        )] as any[];
        if (existingVote.length > 0) {
          const sameVote = existingVote[0].vote === payload.vote;
          // Same vote: keep original staked_at (conviction continues growing)
          // Changed vote: reset staked_at (conviction restarts)
          sql.exec(
            `UPDATE governance_proposal_votes SET vote = ?, reputation = ?, voted_at = ?, staked_at = ?
             WHERE proposal_id = ? AND voter = ?`,
            payload.vote, reputation, now,
            sameVote ? existingVote[0].staked_at : now,
            payload.proposal_id, pubkey,
          );
        } else {
          sql.exec(
            `INSERT INTO governance_proposal_votes (proposal_id, voter, vote, reputation, voted_at, staked_at)
             VALUES (?, ?, ?, ?, ?, ?)`,
            payload.proposal_id, pubkey, payload.vote, reputation, now, now,
          );
        }
        this.checkProposalQuorum(payload.proposal_id);
        this.broadcast({
          type: "governance.voted",
          proposal_id: payload.proposal_id,
          voter: pubkey,
          vote: payload.vote,
          changed: existingVote.length > 0,
        });
        break;
      }
      case "fraud_proof.challenge": {
        // Consensus-ordered challenge — processed via handleChallengeSubmit
        await this.handleChallengeSubmit(pubkey, payload.block_number, payload.claimed_invalid_root || null);
        break;
      }
      case "fraud_proof.response": {
        // Consensus-ordered response with ZK proof
        this.handleChallengeRespond(payload.block_number, payload.proof_hash, payload.proof_state_root);
        break;
      }
    }
  }

  // ─── Governance ─────────────────────────────────────────────────────────

  /**
   * Conviction voting: weight = reputation × (1 + days_staked).
   * A vote held for 1 day counts 2x, 7 days counts 8x, etc.
   * Quorum threshold: total yes-conviction > 2/3 of max possible conviction.
   * Max possible = sum of all active validator reputations × their potential conviction.
   * For simplicity, threshold = 2/3 × (total active reputation × 2) — assumes ~1 day avg.
   */
  private checkProposalQuorum(proposalId: string) {
    const sql = this.state.storage.sql;
    const now = Date.now();
    const MS_PER_DAY = 86_400_000;

    // Get all yes votes with conviction weight
    const yesVotes = [...sql.exec(
      "SELECT reputation, staked_at FROM governance_proposal_votes WHERE proposal_id = ? AND vote = 'yes'",
      proposalId,
    )] as any[];

    let yesConviction = 0;
    for (const v of yesVotes) {
      const daysStaked = (now - (v.staked_at || now)) / MS_PER_DAY;
      yesConviction += (v.reputation as number) * (1 + daysStaked);
    }

    // Threshold: 2/3 of total active validator reputation (base, without time multiplier)
    // This means fresh unanimous votes pass immediately, but a minority can pass over time
    const activeRep = [...sql.exec(
      "SELECT COALESCE(SUM(reputation), 0) as total FROM validators WHERE status = 'active'"
    )] as any[];
    const totalReputation = (activeRep[0]?.total ?? 0) as number;
    if (totalReputation === 0) return;

    const threshold = (totalReputation * 2) / 3;
    if (yesConviction >= threshold) {
      sql.exec(
        "UPDATE governance_proposals SET quorum_reached_at = ? WHERE id = ? AND status = 'pending'",
        now, proposalId,
      );
      console.log(`Governance proposal ${proposalId.slice(0, 12)}... reached conviction quorum (${yesConviction.toFixed(1)}/${threshold.toFixed(1)})`);
    }
  }

  // ─── Fraud Proof Processing ──────────────────────────────────────────────

  /**
   * Periodic fraud proof processing: finalize unchallenged blocks
   * and resolve timed-out challenges.
   */
  private processFraudProofCycle() {
    const sql = this.state.storage.sql;

    // 1. Finalize expired unchallenged windows
    const finalized = finalizeExpiredWindows(sql, this.currentRound);
    if (finalized > 0) {
      console.log(`Fraud proofs: finalized ${finalized} unchallenged blocks`);
    }

    // 2. Resolve timed-out challenges (proposer failed to respond)
    const timedOut = findTimedOutChallenges(sql, this.currentRound);
    const challengeBond = BigInt(this.getNetworkParam("challenge_bond_amount", Number(DEFAULT_CHALLENGE_BOND)));
    for (const { challenge, window } of timedOut) {
      const resolution = resolveTimeout(challenge, window, challengeBond);
      // Slash proposer bond
      const proposerAddr = pubkeyB64ToAddress(resolution.slash_target);
      this.accountManager.placeHold(proposerAddr, "PERSIST", resolution.slash_amount, `fraud_slash:${challenge.id}`);
      // Release challenger bond + reward
      this.accountManager.releaseHold(challenge.bond_hold_id, 0n); // return full bond
      const challengerAddr = pubkeyB64ToAddress(resolution.reward_target);
      this.accountManager.mint(challengerAddr, "PERSIST", resolution.reward_amount);
      // Update records
      updateChallengeStatus(sql, challenge.id, "timeout", Date.now(), undefined, "timeout");
      updateWindowStatus(sql, challenge.block_number, "timeout");
      // Reputation penalty for proposer
      this.validatorRegistry.adjustReputation(resolution.slash_target, -50);
      // Reputation reward for challenger
      this.validatorRegistry.adjustReputation(resolution.reward_target, 25);
      console.log(`Fraud proofs: challenge ${challenge.id} resolved as TIMEOUT — proposer ${resolution.slash_target.slice(0, 12)}... slashed`);
      this.broadcast({
        type: "fraud_proof.resolved",
        challenge_id: challenge.id,
        block_number: challenge.block_number,
        outcome: "timeout",
      });
    }
  }

  /**
   * Handle a fraud proof challenge submission.
   */
  private async handleChallengeSubmit(challenger: string, blockNumber: number, claimedRoot: string | null): Promise<{ ok: boolean; error?: string; challenge_id?: string }> {
    const sql = this.state.storage.sql;
    const window = getChallengeWindow(sql, blockNumber);
    const isValidator = this.validatorRegistry.isRegistered(challenger);

    const validation = validateChallengeSubmission(
      { block_number: blockNumber, challenger, claimed_invalid_root: claimedRoot },
      window,
      this.currentRound,
      isValidator,
    );
    if (!validation.valid) return { ok: false, error: validation.error };

    // Check no existing active challenge
    const existing = getActiveChallenge(sql, blockNumber);
    if (existing) return { ok: false, error: "Block already has an active challenge" };

    // Place challenger bond
    const challengeBond = BigInt(this.getNetworkParam("challenge_bond_amount", Number(DEFAULT_CHALLENGE_BOND)));
    const challengerAddr = pubkeyB64ToAddress(challenger);
    const hold = this.accountManager.placeHold(challengerAddr, "PERSIST", challengeBond, `fraud_challenge:${blockNumber}`);
    if (!hold.ok) return { ok: false, error: `Bond placement failed: ${hold.error}` };

    // Create challenge record
    const responseWindow = this.getNetworkParam("challenge_response_rounds", DEFAULT_RESPONSE_WINDOW);
    const challengeId = await generateChallengeId(blockNumber, challenger);
    const record: ChallengeRecord = {
      id: challengeId,
      block_number: blockNumber,
      challenger,
      bond_hold_id: hold.hold_id!,
      claimed_invalid_root: claimedRoot,
      response_deadline_round: this.currentRound + responseWindow,
      status: "challenged",
      created_at: Date.now(),
      resolved_at: null,
      resolution_proof_hash: null,
      resolution_type: null,
    };
    insertChallenge(sql, record);
    updateWindowStatus(sql, blockNumber, "challenged");

    this.broadcast({
      type: "fraud_proof.challenged",
      challenge_id: challengeId,
      block_number: blockNumber,
      challenger,
      response_deadline_round: record.response_deadline_round,
    });

    return { ok: true, challenge_id: challengeId };
  }

  /**
   * Handle a fraud proof response (ZK proof submission).
   */
  private handleChallengeRespond(blockNumber: number, proofHash: string, proofStateRoot: string): { ok: boolean; error?: string; outcome?: string } {
    const sql = this.state.storage.sql;
    const challenge = getActiveChallenge(sql, blockNumber);
    if (!challenge) return { ok: false, error: "No active challenge for this block" };

    const window = getChallengeWindow(sql, blockNumber);
    if (!window) return { ok: false, error: "Challenge window not found" };

    const challengeBond = BigInt(this.getNetworkParam("challenge_bond_amount", Number(DEFAULT_CHALLENGE_BOND)));
    const resolution = resolveWithProof(challenge, window, proofStateRoot, challengeBond);

    if (resolution.outcome === "valid") {
      // Challenger was wrong — slash their bond
      this.accountManager.releaseHold(challenge.bond_hold_id, resolution.slash_amount);
      const proposerAddr = pubkeyB64ToAddress(resolution.reward_target);
      this.accountManager.mint(proposerAddr, "PERSIST", resolution.reward_amount);
      this.validatorRegistry.adjustReputation(challenge.challenger, -25);
      this.validatorRegistry.adjustReputation(window.proposer, 10);
      updateChallengeStatus(sql, challenge.id, "resolved_valid", Date.now(), proofHash, "zk_proof");
      updateWindowStatus(sql, blockNumber, "resolved_valid");
    } else {
      // Fraud confirmed — slash proposer
      const proposerAddr = pubkeyB64ToAddress(resolution.slash_target);
      this.accountManager.placeHold(proposerAddr, "PERSIST", resolution.slash_amount, `fraud_slash:${challenge.id}`);
      this.accountManager.releaseHold(challenge.bond_hold_id, 0n);
      const challengerAddr = pubkeyB64ToAddress(resolution.reward_target);
      this.accountManager.mint(challengerAddr, "PERSIST", resolution.reward_amount);
      this.validatorRegistry.adjustReputation(window.proposer, -100);
      this.validatorRegistry.adjustReputation(challenge.challenger, 50);
      updateChallengeStatus(sql, challenge.id, "resolved_fraud", Date.now(), proofHash, "zk_proof");
      updateWindowStatus(sql, blockNumber, "resolved_fraud");
    }

    this.broadcast({
      type: "fraud_proof.resolved",
      challenge_id: challenge.id,
      block_number: blockNumber,
      outcome: resolution.outcome,
    });

    return { ok: true, outcome: resolution.outcome };
  }

  /**
   * Re-check all pending proposals without quorum — conviction grows over time,
   * so a proposal may reach quorum between votes as stake duration increases.
   */
  private recheckConviction() {
    const sql = this.state.storage.sql;
    const pending = [...sql.exec(
      "SELECT id FROM governance_proposals WHERE status = 'pending' AND quorum_reached_at IS NULL"
    )] as any[];
    for (const p of pending) {
      this.checkProposalQuorum(p.id);
    }
  }

  /**
   * Called during commitAnchor to activate any governance proposals whose
   * activate_at_round has been reached and quorum was achieved.
   */
  private activateGovernanceProposals(round: number) {
    const sql = this.state.storage.sql;
    const ready = [...sql.exec(
      `SELECT id, param_key, proposed_value, proposer FROM governance_proposals
       WHERE status = 'pending' AND quorum_reached_at IS NOT NULL AND activate_at_round <= ?`,
      round,
    )] as any[];

    for (const proposal of ready) {
      const bounds = PersistiaWorldV4.GOVERNABLE_PARAMS[proposal.param_key];
      if (!bounds) continue; // param no longer governable

      const numVal = parseInt(proposal.proposed_value);
      if (isNaN(numVal) || numVal < bounds.min || numVal > bounds.max) {
        sql.exec("UPDATE governance_proposals SET status = 'rejected' WHERE id = ?", proposal.id);
        console.log(`Governance proposal ${proposal.id.slice(0, 12)}... rejected: value out of bounds`);
        continue;
      }

      this.setNetworkParam(proposal.param_key, proposal.proposed_value, "governance", proposal.id);
      sql.exec(
        "UPDATE governance_proposals SET status = 'activated', activated_at = ? WHERE id = ?",
        Date.now(), proposal.id,
      );
      console.log(`Governance activated: ${proposal.param_key} = ${proposal.proposed_value} (proposal ${proposal.id.slice(0, 12)}...)`);
      this.broadcast({
        type: "governance.activated",
        proposal_id: proposal.id,
        param_key: proposal.param_key,
        new_value: proposal.proposed_value,
        round,
      });
    }

    // Expire old proposals that passed their activation round without quorum
    sql.exec(
      `UPDATE governance_proposals SET status = 'expired'
       WHERE status = 'pending' AND quorum_reached_at IS NULL AND activate_at_round <= ?`,
      round,
    );
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
   * Process contract deploy requests emitted by a contract during execution.
   * Each deploy is compiled, stored, and cached — the child contract is immediately callable.
   */
  private async processDeployEmits(requests: DeployRequestEmit[]) {
    for (let i = 0; i < requests.length; i++) {
      const req = requests[i];
      try {
        const address = await this.contractExecutor.deploy(
          req.wasm_bytes, req.deployer, this.latestSeq * 1000 + i,
        );
        this.stateTree.markDirty(`deployed:${address}`, `${req.deployer}:${address}`);
        this.broadcast({ type: "contract.deployed", address, deployer: req.deployer, parent: req.contract });
        console.log(`Contract-initiated deploy: ${req.deployer.slice(0, 8)}... deployed child ${address.slice(0, 8)}...`);
      } catch (e: any) {
        console.warn(`Contract-initiated deploy failed: ${e.message}`);
      }
    }
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

    // Batch AI inference: group requests with same URL pattern for concurrent fetch
    // This reduces latency when multiple oracles hit the same API endpoint
    if (pending.length > 1) {
      const urlGroups = new Map<string, any[]>();
      for (const req of pending) {
        const baseUrl = req.url.split("?")[0]; // group by base URL
        const group = urlGroups.get(baseUrl);
        if (group) group.push(req);
        else urlGroups.set(baseUrl, [req]);
      }
      // Fetch all unique URLs concurrently (reduces sequential wait from N × latency to 1 × latency)
      const urlCache = new Map<string, string>();
      const fetchPromises = [...new Set(pending.map((r: any) => r.url))].map(async (url: string) => {
        try {
          const res = await fetchWithTimeout(url);
          urlCache.set(url, res);
        } catch { /* individual failures handled below */ }
      });
      await Promise.allSettled(fetchPromises);
      // Now process each request using cached responses
      for (const req of pending) {
        const cachedResponse = urlCache.get(req.url);
        if (cachedResponse !== undefined) {
          req._cachedResponse = cachedResponse;
        }
      }
    }

    for (const req of pending) {
      try {
        // Mark as fetching
        this.state.storage.sql.exec(
          "UPDATE oracle_requests SET status = 'fetching' WHERE id = ?", req.id,
        );

        // Fetch the data (use cached response from batch fetch if available)
        const rawResponse = req._cachedResponse ?? await fetchWithTimeout(req.url);
        const extracted = extractJsonPath(rawResponse, req.json_path);

        if (this.getActiveNodeCount() < this.getNetworkParam("min_nodes_for_consensus", MIN_NODES_FOR_CONSENSUS)) {
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
          // Multi-node mode: optimistic oracle with dispute escalation.
          // Accept the first response immediately with a dispute window.
          // If no peer disputes within the window, finalize. If disputed,
          // escalate to full BFT aggregation (require quorum agreement).
          const DISPUTE_WINDOW_MS = 30_000; // 30s dispute window
          const nodePubkey = this.nodeIdentity?.pubkey || "self";
          this.state.storage.sql.exec(
            `INSERT OR REPLACE INTO oracle_responses (request_id, node_pubkey, value, fetched_at)
             VALUES (?, ?, ?, ?)`,
            req.id, nodePubkey, extracted, Date.now(),
          );

          const responses = [...this.state.storage.sql.exec(
            "SELECT * FROM oracle_responses WHERE request_id = ?", req.id,
          )] as any[];

          if (responses.length === 1) {
            // First response: optimistically accept, mark with dispute window
            this.state.storage.sql.exec(
              "UPDATE oracle_requests SET status = 'optimistic', result_value = ?, result_sources = 1, delivered_at = ? WHERE id = ?",
              extracted, Date.now(), req.id,
            );
            // Deliver optimistically — contract gets the result immediately
            await this.applyEvent("oracle.response", {
              contract: req.contract,
              callback_method: req.callback_method,
              request_id: req.id,
              value: extracted,
              sources: 1,
              optimistic: true, // flag so contract knows this may be disputed
            }, "oracle:system");
            this.broadcast({ type: "oracle.optimistic", request_id: req.id, contract: req.contract, value: extracted });
          } else {
            // Subsequent responses: check for disputes
            const firstResponse = responses[0];
            const disputed = responses.some(r => r.value !== firstResponse.value);

            if (disputed) {
              // Dispute detected — escalate to full BFT aggregation
              const quorum = Math.ceil((this.getActiveNodeCount() * 2) / 3) + 1;
              const aggregated = aggregate(
                responses.map(r => ({
                  node_pubkey: r.node_pubkey, request_id: r.request_id,
                  value: r.value, fetched_at: r.fetched_at,
                })),
                req.aggregation as AggregationStrategy,
                quorum,
              );
              if (aggregated) {
                // If aggregated result differs from optimistic, send correction
                const needsCorrection = aggregated.value !== firstResponse.value;
                this.state.storage.sql.exec(
                  "UPDATE oracle_requests SET status = 'delivered', result_value = ?, result_sources = ?, delivered_at = ? WHERE id = ?",
                  aggregated.value, aggregated.sources, Date.now(), req.id,
                );
                if (needsCorrection) {
                  await this.applyEvent("oracle.correction", {
                    contract: req.contract, callback_method: req.callback_method,
                    request_id: req.id, value: aggregated.value,
                    sources: aggregated.sources, previous_value: firstResponse.value,
                  }, "oracle:system");
                  this.broadcast({ type: "oracle.corrected", request_id: req.id, old_value: firstResponse.value, new_value: aggregated.value });
                } else {
                  this.broadcast({ type: "oracle.confirmed", request_id: req.id });
                }
              } else {
                this.state.storage.sql.exec("UPDATE oracle_requests SET status = 'aggregating' WHERE id = ?", req.id);
              }
            } else {
              // No dispute — all responses agree, finalize
              const timeSinceFirst = Date.now() - firstResponse.fetched_at;
              if (timeSinceFirst >= DISPUTE_WINDOW_MS || responses.length >= this.getActiveNodeCount()) {
                this.state.storage.sql.exec(
                  "UPDATE oracle_requests SET status = 'delivered', result_sources = ? WHERE id = ?",
                  responses.length, req.id,
                );
                this.broadcast({ type: "oracle.confirmed", request_id: req.id });
              }
              // Otherwise: still within dispute window, wait for more responses
            }
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
          if (result.deploy_requests) {
            await this.processDeployEmits(result.deploy_requests);
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

  // ─── Game Action Rewards ────────────────────────────────────────────────

  private async rewardGameAction(pubkey: string) {
    try {
      const acct = await this.accountManager.getOrCreate(pubkey);
      this.accountManager.mint(acct.address, "PERSIST", 1n);
      this.stateTree.markDirty(`bal:${acct.address}:PERSIST`, null);
    } catch (e) {
      console.warn(`Failed to reward game action for ${pubkey}: ${e}`);
    }
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
    return { 1: "dirt", 2: "stone", 3: "wood", 4: "grass", 5: "house", 6: "wall", 7: "bridge" }[blockType] || "unknown";
  }

  private itemToBlockType(item: string): number {
    return { dirt: 1, stone: 2, wood: 3, grass: 4, house: 5, wall: 6, bridge: 7 }[item] || 0;
  }

  // ─── Broadcast ──────────────────────────────────────────────────────────

  // ─── Broadcast with backpressure ─────────────────────────────────────
  // Large messages (finalized_batch) are queued and sent via microtask
  // to avoid blocking the alarm handler. Per-client send failures cause
  // the socket to be closed rather than silently accumulating a backlog.
  private _broadcastQueue: string[] = [];
  private _broadcastDraining = false;
  private static BROADCAST_INLINE_LIMIT = 4096; // bytes — inline small messages

  private broadcast(msg: any, channel?: string) {
    const str = JSON.stringify(msg);
    if (str.length <= PersistiaWorldV4.BROADCAST_INLINE_LIMIT) {
      // Small message: send inline (no backpressure needed)
      const sockets = this.state.getWebSockets(channel ? `ch:${channel}` : undefined);
      for (const ws of sockets) {
        try { ws.send(str); } catch {}
      }
    } else {
      // Large message: queue and drain via microtask
      this._broadcastQueue.push(str);
      if (!this._broadcastDraining) {
        this._broadcastDraining = true;
        queueMicrotask(() => this._drainBroadcastQueue());
      }
    }
  }

  private _drainBroadcastQueue() {
    const sockets = this.state.getWebSockets();
    while (this._broadcastQueue.length > 0) {
      const msg = this._broadcastQueue.shift()!;
      for (const ws of sockets) {
        try { ws.send(msg); } catch {}
      }
    }
    this._broadcastDraining = false;
  }

  private broadcastToChannel(channel: string, msg: any) {
    const str = JSON.stringify(msg);
    const sockets = this.state.getWebSockets(`ch:${channel}`);
    for (const ws of sockets) {
      try { ws.send(str); } catch {}
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
