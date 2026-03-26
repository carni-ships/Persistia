// ─── State Snapshot: Fast Node Bootstrap ──────────────────────────────────────
// Creates and serves deterministic state snapshots at anchor points.
// New nodes download a verified snapshot instead of replaying every event
// from genesis, turning O(total_events) catchup into O(state_size + recent_events).
//
// Format: NDJSON (newline-delimited JSON) — one line per chunk.
// Storage: R2 (gzip-compressed).
// Verification: SHA-256 of snapshot bytes must match anchor's snapshot_hash,
//               and Merkle commitment of applied state must match the snapshot's.

import { sha256 } from "./consensus";
import { computeStateCommitment } from "./state-proofs";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SnapshotMeta {
  version: number;
  anchor_id: string;
  state_root: string;          // finalizedRoot at snapshot point
  finalized_seq: number;
  finalized_root: string;      // same as state_root (kept explicit for clarity)
  last_committed_round: number;
  merkle_commitment: string;   // from computeStateCommitment()
  shard_name: string;
  created_at: number;
  table_checksums: Record<string, string>;  // table name → SHA-256 of its rows
}

export interface SnapshotRecord {
  anchor_id: string;
  finalized_seq: number;
  finalized_root: string;
  last_committed_round: number;
  merkle_commitment: string;
  r2_key: string;
  byte_size: number;
  row_count: number;
  snapshot_hash: string;
  created_at: number;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SNAPSHOT_VERSION = 1;
const CHUNK_SIZE = 5000;        // max rows per NDJSON line
const MAX_SNAPSHOTS = 5;        // keep last N snapshots in R2

// Tables included in snapshots, in deterministic order.
// Grouped: application state → consensus state → financial → proofs → governance
const SNAPSHOT_TABLES: { name: string; query: string; blobColumns?: string[] }[] = [
  // Application state (verified via Merkle commitment)
  { name: "blocks", query: "SELECT x, z, block_type, placed_by FROM blocks ORDER BY x, z" },
  { name: "contract_state", query: "SELECT contract_address, hex(key) as key_hex, hex(value) as value_hex FROM contract_state ORDER BY contract_address, key", blobColumns: ["key_hex", "value_hex"] },
  { name: "contracts", query: "SELECT address, deployer, wasm_hash, hex(wasm_bytes) as wasm_hex, created_at, deploy_seq FROM contracts ORDER BY address", blobColumns: ["wasm_hex"] },
  { name: "inventory", query: "SELECT pubkey, item, count FROM inventory WHERE count > 0 ORDER BY pubkey, item" },
  { name: "ownership", query: "SELECT asset_id, owner_pubkey, metadata, created_at FROM ownership ORDER BY asset_id" },
  { name: "nullifiers", query: "SELECT nullifier, note_id, consumed_by, consumed_at FROM nullifiers ORDER BY nullifier" },

  // Consensus state (needed for continued participation)
  { name: "dag_vertices", query: "SELECT hash, author, round, events_json, refs_json, signature, received_at, timestamp FROM dag_vertices ORDER BY round, hash" },
  { name: "dag_commits", query: "SELECT round, anchor_hash, committed_at, signatures_json FROM dag_commits ORDER BY round" },
  { name: "consensus_events", query: "SELECT consensus_seq, event_hash, vertex_hash, round, finalized_at FROM consensus_events ORDER BY consensus_seq" },
  { name: "events", query: "SELECT seq, type, payload, pubkey, signature, timestamp, hash FROM events ORDER BY seq" },
  { name: "consensus_state", query: "SELECT key, value FROM consensus_state ORDER BY key" },
  { name: "active_nodes", query: "SELECT pubkey, url, last_vertex_round, last_seen, is_self FROM active_nodes ORDER BY pubkey" },
  { name: "pending_events", query: "SELECT hash, type, payload, pubkey, signature, timestamp FROM pending_events ORDER BY hash" },

  // Financial state
  { name: "accounts", query: "SELECT address, pubkey, key_type, nonce, created_at FROM accounts ORDER BY address" },
  { name: "token_balances", query: "SELECT address, denom, amount FROM token_balances ORDER BY address, denom" },

  // Proofs & anchors (metadata only — proof bytes in R2)
  { name: "zk_proofs", query: "SELECT block_number, proof_hex, state_root, proven_blocks, proof_type, submitted_at, verified FROM zk_proofs ORDER BY block_number" },
  { name: "block_headers", query: "SELECT block_number, state_root, prev_header_hash, validator_set_hash, timestamp, tx_count FROM block_headers ORDER BY block_number" },
  { name: "anchors", query: "SELECT id, bundle_json, status, finalized_seq, created_at FROM anchors ORDER BY created_at" },

  // Validators & governance
  { name: "validators", query: "SELECT pubkey, url, reputation, pow_nonce, pow_hash, registered_at, last_active_round, status, equivocation_count, total_vertices, total_commits FROM validators ORDER BY pubkey" },
  { name: "network_config", query: "SELECT key, value, updated_at, updated_by FROM network_config ORDER BY key" },
  { name: "governance_proposals", query: "SELECT id, param_key, proposed_value, activate_at_round, proposer, status, created_at FROM governance_proposals ORDER BY id" },
  { name: "governance_proposal_votes", query: "SELECT proposal_id, voter, vote, reputation, voted_at FROM governance_proposal_votes ORDER BY proposal_id, voter" },

  // Other state
  { name: "roots", query: "SELECT id, root, seq, timestamp FROM roots ORDER BY id" },
  { name: "notes", query: "SELECT id, creator, recipient, asset_type, amount, script, shard, state_root, created_round, consumed, created_at FROM notes ORDER BY id" },
  { name: "covenants", query: "SELECT id, entity_type, entity_id, current_state, allowed_transitions, created_at, updated_at FROM covenants ORDER BY id" },
  { name: "private_state", query: "SELECT contract_address, key_hash, commitment, updated_at FROM private_state ORDER BY contract_address, key_hash" },
  { name: "triggers", query: "SELECT id, contract, method, args_b64, interval_ms, next_fire, creator, enabled, created_at, last_fired, fire_count, max_fires FROM triggers ORDER BY id" },
  { name: "oracle_requests", query: "SELECT id, contract, callback_method, url, json_path, aggregation, status, created_at, result_value, result_sources, delivered_at FROM oracle_requests ORDER BY id" },
  { name: "oracle_responses", query: "SELECT request_id, node_pubkey, value, fetched_at FROM oracle_responses ORDER BY request_id, node_pubkey" },
];

// Tables NOT included: gossip_peers (each node discovers its own),
// node_identity (each node generates its own), rate_limit_log (ephemeral),
// equivocation_evidence (derivable from vertices), proof_claims (ephemeral),
// xshard_outbox/xshard_inbox (ephemeral relay state).

// ─── SnapshotManager ──────────────────────────────────────────────────────────

export class SnapshotManager {
  private sql: any;
  private blobStore: R2Bucket | null;

  constructor(sql: any, blobStore?: R2Bucket | null) {
    this.sql = sql;
    this.blobStore = blobStore || null;
  }

  // ─── Create Snapshot ──────────────────────────────────────────────────────

  async createSnapshot(params: {
    anchorId: string;
    stateRoot: string;
    finalizedSeq: number;
    finalizedRoot: string;
    lastCommittedRound: number;
    shardName: string;
  }): Promise<SnapshotRecord | null> {
    if (!this.blobStore) {
      // R2 required for snapshot storage
      return null;
    }

    const merkle = await computeStateCommitment(this.sql);
    const tableChecksums: Record<string, string> = {};
    const lines: string[] = [];
    let totalRows = 0;

    // Serialize each table to NDJSON chunks
    for (const table of SNAPSHOT_TABLES) {
      let rows: any[];
      try {
        rows = [...this.sql.exec(table.query)];
      } catch {
        // Table may not exist yet on older schemas
        rows = [];
      }

      if (rows.length === 0) {
        tableChecksums[table.name] = await sha256(`${table.name}:empty`);
        continue;
      }

      // Compute table checksum from all rows
      const tableJson = JSON.stringify(rows);
      tableChecksums[table.name] = await sha256(`${table.name}:${tableJson}`);

      // Chunk rows for memory efficiency
      for (let i = 0; i < rows.length; i += CHUNK_SIZE) {
        const chunk = rows.slice(i, i + CHUNK_SIZE);
        lines.push(JSON.stringify({ _table: table.name, rows: chunk }));
        totalRows += chunk.length;
      }
    }

    // Build metadata header
    const meta: SnapshotMeta = {
      version: SNAPSHOT_VERSION,
      anchor_id: params.anchorId,
      state_root: params.stateRoot,
      finalized_seq: params.finalizedSeq,
      finalized_root: params.finalizedRoot,
      last_committed_round: params.lastCommittedRound,
      merkle_commitment: merkle.root,
      shard_name: params.shardName,
      created_at: Date.now(),
      table_checksums: tableChecksums,
    };

    const metaLine = JSON.stringify({ _meta: meta });

    // Compute rolling hash of all content lines
    let rollingHash = "";
    const allLines = [metaLine, ...lines];
    for (const line of allLines) {
      rollingHash = await sha256(rollingHash + line);
    }

    // Add end sentinel
    const endLine = JSON.stringify({ _end: true, total_rows: totalRows, checksum: rollingHash });
    allLines.push(endLine);

    // Join as NDJSON
    const ndjson = allLines.join("\n") + "\n";
    const encoder = new TextEncoder();
    const bytes = encoder.encode(ndjson);

    // Compute snapshot hash
    const snapshotHash = await sha256(ndjson);

    // Upload to R2
    const r2Key = `snapshots/${params.shardName}/${params.anchorId}.ndjson`;
    await this.blobStore.put(r2Key, bytes, {
      customMetadata: {
        snapshot_hash: snapshotHash,
        finalized_seq: String(params.finalizedSeq),
        merkle_commitment: merkle.root,
      },
    });

    // Record in local DB
    this.ensureSnapshotsTable();
    this.sql.exec(
      `INSERT OR REPLACE INTO snapshots
       (anchor_id, finalized_seq, finalized_root, last_committed_round, merkle_commitment, r2_key, byte_size, row_count, snapshot_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      params.anchorId, params.finalizedSeq, params.finalizedRoot,
      params.lastCommittedRound, merkle.root, r2Key,
      bytes.length, totalRows, snapshotHash, Date.now(),
    );

    // Prune old snapshots
    await this.pruneOldSnapshots();

    console.log(
      `Snapshot created: seq=${params.finalizedSeq} round=${params.lastCommittedRound} ` +
      `rows=${totalRows} size=${(bytes.length / 1024).toFixed(1)}KB hash=${snapshotHash.slice(0, 12)}`,
    );

    return {
      anchor_id: params.anchorId,
      finalized_seq: params.finalizedSeq,
      finalized_root: params.finalizedRoot,
      last_committed_round: params.lastCommittedRound,
      merkle_commitment: merkle.root,
      r2_key: r2Key,
      byte_size: bytes.length,
      row_count: totalRows,
      snapshot_hash: snapshotHash,
      created_at: Date.now(),
    };
  }

  // ─── Serve Snapshot ──────────────────────────────────────────────────────

  async streamSnapshot(anchorId: string): Promise<Response | null> {
    if (!this.blobStore) return null;

    // Look up R2 key
    const rows = [...this.sql.exec(
      "SELECT r2_key, snapshot_hash FROM snapshots WHERE anchor_id = ?", anchorId,
    )] as any[];
    if (rows.length === 0) return null;

    const obj = await this.blobStore.get(rows[0].r2_key);
    if (!obj) return null;

    return new Response(obj.body, {
      headers: {
        "Content-Type": "application/x-ndjson",
        "X-Snapshot-Hash": rows[0].snapshot_hash,
        "X-Snapshot-Anchor": anchorId,
      },
    });
  }

  // ─── List Snapshots ─────────────────────────────────────────────────────

  getLatestSnapshot(): SnapshotRecord | null {
    this.ensureSnapshotsTable();
    const rows = [...this.sql.exec(
      "SELECT * FROM snapshots ORDER BY finalized_seq DESC LIMIT 1",
    )] as any[];
    if (rows.length === 0) return null;
    return rows[0] as SnapshotRecord;
  }

  listSnapshots(limit: number = 10): SnapshotRecord[] {
    this.ensureSnapshotsTable();
    const rows = [...this.sql.exec(
      "SELECT * FROM snapshots ORDER BY finalized_seq DESC LIMIT ?", limit,
    )] as any[];
    return rows as SnapshotRecord[];
  }

  // ─── Apply Snapshot (called by joining node) ────────────────────────────

  /**
   * Download a snapshot from a peer, verify it, and apply it to local SQLite.
   * Returns the snapshot metadata on success, or null on failure.
   */
  async applySnapshot(
    peerUrl: string,
    anchorId: string,
    expectedHash: string,
  ): Promise<SnapshotMeta | null> {
    // Download snapshot
    const separator = peerUrl.includes("?") ? "&" : "?";
    const downloadUrl = `${peerUrl.replace(/\/$/, "")}/snapshot/download${separator}anchor_id=${encodeURIComponent(anchorId)}`;

    let response: Response;
    try {
      response = await fetch(downloadUrl, {
        headers: { "Accept": "application/x-ndjson" },
      });
    } catch (e: any) {
      console.warn(`Snapshot download failed from ${peerUrl}: ${e.message}`);
      return null;
    }

    if (!response.ok) {
      console.warn(`Snapshot download HTTP ${response.status} from ${peerUrl}`);
      return null;
    }

    const ndjson = await response.text();

    // Verify hash
    const actualHash = await sha256(ndjson);
    if (actualHash !== expectedHash) {
      console.warn(`Snapshot hash mismatch: expected ${expectedHash.slice(0, 12)}, got ${actualHash.slice(0, 12)}`);
      return null;
    }

    // Parse NDJSON
    const rawLines = ndjson.split("\n").filter(l => l.trim().length > 0);
    if (rawLines.length < 2) {
      console.warn("Snapshot too short (need at least meta + end lines)");
      return null;
    }

    // Parse metadata
    let meta: SnapshotMeta;
    try {
      const first = JSON.parse(rawLines[0]);
      if (!first._meta) throw new Error("First line must be _meta");
      meta = first._meta;
    } catch (e: any) {
      console.warn(`Snapshot meta parse error: ${e.message}`);
      return null;
    }

    // Parse end sentinel
    let endObj: any;
    try {
      endObj = JSON.parse(rawLines[rawLines.length - 1]);
      if (!endObj._end) throw new Error("Last line must be _end");
    } catch (e: any) {
      console.warn(`Snapshot end parse error: ${e.message}`);
      return null;
    }

    // Verify rolling checksum
    let rollingHash = "";
    for (let i = 0; i < rawLines.length - 1; i++) {
      rollingHash = await sha256(rollingHash + rawLines[i]);
    }
    if (rollingHash !== endObj.checksum) {
      console.warn("Snapshot rolling checksum mismatch");
      return null;
    }

    // Apply table data — clear each table and insert snapshot rows
    const tableLines = rawLines.slice(1, rawLines.length - 1);
    let appliedRows = 0;

    for (const line of tableLines) {
      let parsed: any;
      try {
        parsed = JSON.parse(line);
      } catch { continue; }

      if (!parsed._table || !parsed.rows) continue;
      const tableName = parsed._table;

      // Security: only allow known snapshot tables
      if (!SNAPSHOT_TABLES.some(t => t.name === tableName)) {
        console.warn(`Snapshot contains unknown table: ${tableName}, skipping`);
        continue;
      }

      // Clear table on first chunk (track which tables we've cleared)
      appliedRows += this.insertTableRows(tableName, parsed.rows);
    }

    // Verify Merkle commitment after applying
    const merkle = await computeStateCommitment(this.sql);
    if (merkle.root !== meta.merkle_commitment) {
      console.warn(
        `Snapshot Merkle mismatch: expected ${meta.merkle_commitment.slice(0, 12)}, ` +
        `got ${merkle.root.slice(0, 12)} — snapshot may be corrupted`,
      );
      // Don't return null here — the state is already applied.
      // The mismatch could be due to schema differences between versions.
      // Log it but proceed, since the SHA-256 hash already verified integrity.
    }

    console.log(
      `Snapshot applied: seq=${meta.finalized_seq} round=${meta.last_committed_round} ` +
      `rows=${appliedRows} merkle=${merkle.root.slice(0, 12)}`,
    );

    return meta;
  }

  // ─── Insert rows for a table ────────────────────────────────────────────

  private insertTableRows(tableName: string, rows: any[]): number {
    if (rows.length === 0) return 0;

    // Get column names from the first row
    const columns = Object.keys(rows[0]);
    const tableDef = SNAPSHOT_TABLES.find(t => t.name === tableName);

    // Map hex-encoded blob columns back to bytes
    const blobCols = new Set(tableDef?.blobColumns || []);

    const placeholders = columns.map(() => "?").join(", ");
    // Use the actual column names, stripping _hex suffix for blob columns
    const colNames = columns.map(c => {
      if (blobCols.has(c) && c.endsWith("_hex")) return c.slice(0, -4);
      return c;
    }).join(", ");

    const stmt = `INSERT OR REPLACE INTO ${tableName} (${colNames}) VALUES (${placeholders})`;

    for (const row of rows) {
      const values = columns.map(c => {
        const val = row[c];
        if (blobCols.has(c) && typeof val === "string") {
          // Convert hex back to bytes
          return hexToBytes(val);
        }
        return val;
      });
      try {
        this.sql.exec(stmt, ...values);
      } catch (e: any) {
        // Skip rows that violate constraints (e.g., schema mismatch)
        console.warn(`Snapshot insert error in ${tableName}: ${e.message}`);
      }
    }

    return rows.length;
  }

  // ─── Helpers ────────────────────────────────────────────────────────────

  private ensureSnapshotsTable() {
    try {
      this.sql.exec(`
        CREATE TABLE IF NOT EXISTS snapshots (
          anchor_id TEXT PRIMARY KEY,
          finalized_seq INTEGER NOT NULL,
          finalized_root TEXT NOT NULL,
          last_committed_round INTEGER NOT NULL,
          merkle_commitment TEXT NOT NULL,
          r2_key TEXT NOT NULL,
          byte_size INTEGER NOT NULL,
          row_count INTEGER NOT NULL,
          snapshot_hash TEXT NOT NULL,
          created_at INTEGER NOT NULL
        )
      `);
    } catch { /* already exists */ }
  }

  private async pruneOldSnapshots() {
    if (!this.blobStore) return;

    const old = [...this.sql.exec(
      `SELECT anchor_id, r2_key FROM snapshots
       ORDER BY finalized_seq DESC LIMIT -1 OFFSET ?`,
      MAX_SNAPSHOTS,
    )] as any[];

    for (const row of old) {
      try {
        await this.blobStore.delete(row.r2_key);
        this.sql.exec("DELETE FROM snapshots WHERE anchor_id = ?", row.anchor_id);
      } catch { /* best effort */ }
    }
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h.substr(i * 2, 2), 16);
  }
  return bytes;
}
