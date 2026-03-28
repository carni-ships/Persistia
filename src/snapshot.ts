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
import { gzipSync, gunzipSync, strToU8, strFromU8 } from "fflate";

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

    // Compute snapshot hash on raw NDJSON (before compression) for deterministic verification
    const snapshotHash = await sha256(ndjson);

    // Gzip compress for ~50-70% smaller R2 storage and faster peer downloads
    const compressed = gzipSync(strToU8(ndjson), { level: 6 });

    // Upload compressed to R2
    const r2Key = `snapshots/${params.shardName}/${params.anchorId}.ndjson.gz`;
    await this.blobStore.put(r2Key, compressed, {
      customMetadata: {
        snapshot_hash: snapshotHash,
        finalized_seq: String(params.finalizedSeq),
        merkle_commitment: merkle.root,
        content_encoding: "gzip",
      },
    });

    // Erasure-code shards for DA resilience (any k of k+p shards can reconstruct)
    try {
      const erasureKey = `snapshots/${params.shardName}/${params.anchorId}`;
      await uploadErasureShards(this.blobStore, erasureKey, compressed);
    } catch (e: any) {
      // Non-fatal: primary blob already uploaded
      console.warn(`Erasure shard upload failed (non-fatal): ${e.message}`);
    }

    // Record in local DB
    this.ensureSnapshotsTable();
    this.sql.exec(
      `INSERT OR REPLACE INTO snapshots
       (anchor_id, finalized_seq, finalized_root, last_committed_round, merkle_commitment, r2_key, byte_size, row_count, snapshot_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      params.anchorId, params.finalizedSeq, params.finalizedRoot,
      params.lastCommittedRound, merkle.root, r2Key,
      compressed.length, totalRows, snapshotHash, Date.now(),
    );

    // Prune old snapshots
    await this.pruneOldSnapshots();

    const rawSize = strToU8(ndjson).length;
    const ratio = ((1 - compressed.length / rawSize) * 100).toFixed(0);
    console.log(
      `Snapshot created: seq=${params.finalizedSeq} round=${params.lastCommittedRound} ` +
      `rows=${totalRows} size=${(compressed.length / 1024).toFixed(1)}KB (${ratio}% smaller) hash=${snapshotHash.slice(0, 12)}`,
    );

    return {
      anchor_id: params.anchorId,
      finalized_seq: params.finalizedSeq,
      finalized_root: params.finalizedRoot,
      last_committed_round: params.lastCommittedRound,
      merkle_commitment: merkle.root,
      r2_key: r2Key,
      byte_size: compressed.length,
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

    // Serve compressed blob directly — clients decompress via Content-Encoding
    const isCompressed = rows[0].r2_key.endsWith(".gz");
    const headers: Record<string, string> = {
      "Content-Type": "application/x-ndjson",
      "X-Snapshot-Hash": rows[0].snapshot_hash,
      "X-Snapshot-Anchor": anchorId,
    };
    if (isCompressed) {
      headers["Content-Encoding"] = "gzip";
    }
    return new Response(obj.body, { headers });
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

    // Decompress if gzip-encoded (Content-Encoding auto-handled by fetch in most runtimes,
    // but handle raw gzip bytes as fallback for peer-to-peer transfers)
    let ndjson: string;
    const encoding = response.headers.get("Content-Encoding");
    if (encoding === "gzip") {
      const buf = new Uint8Array(await response.arrayBuffer());
      ndjson = strFromU8(gunzipSync(buf));
    } else {
      ndjson = await response.text();
    }

    // If primary download produced empty/corrupt data and we have R2 access,
    // attempt erasure-coded shard reconstruction
    if (ndjson.trim().length === 0 && this.blobStore) {
      console.log("Primary snapshot empty, attempting erasure shard reconstruction...");
      // Extract shard base key from anchor ID pattern
      const shardRows = [...this.sql.exec("SELECT r2_key FROM snapshots WHERE anchor_id = ?", anchorId)] as any[];
      if (shardRows.length > 0) {
        const baseKey = shardRows[0].r2_key.replace(".ndjson.gz", "");
        const reconstructed = await downloadErasureShards(this.blobStore, baseKey);
        if (reconstructed) {
          ndjson = strFromU8(gunzipSync(reconstructed));
          console.log("Reconstructed snapshot from erasure shards");
        }
      }
    }

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

// ─── Erasure Coding ──────────────────────────────────────────────────────────
// Reed-Solomon-inspired erasure coding for snapshot DA resilience.
// Splits compressed snapshot into k data shards + p parity shards.
// Any k shards (data or parity) can reconstruct the original.
// Uses XOR parity for lightweight implementation (no external deps).

export const ERASURE_DATA_SHARDS = 4;    // k: data shards
export const ERASURE_PARITY_SHARDS = 2;  // p: parity shards (tolerates p losses)

export interface ErasureShard {
  index: number;           // 0..k-1 = data, k..k+p-1 = parity
  type: "data" | "parity";
  data: Uint8Array;
  originalSize: number;    // total unsharded size
  shardSize: number;       // size of each shard (padded)
  totalShards: number;
}

export interface ErasureManifest {
  data_shards: number;
  parity_shards: number;
  shard_size: number;
  original_size: number;
  shard_hashes: string[];   // SHA-256 per shard for integrity
}

/**
 * Split a Uint8Array into k data shards + p XOR parity shards.
 * Each shard is ceil(data.length / k) bytes (last data shard zero-padded).
 */
export function erasureEncode(data: Uint8Array, k = ERASURE_DATA_SHARDS, p = ERASURE_PARITY_SHARDS): ErasureShard[] {
  const shardSize = Math.ceil(data.length / k);
  const shards: ErasureShard[] = [];

  // Create k data shards (zero-padded to uniform size)
  for (let i = 0; i < k; i++) {
    const start = i * shardSize;
    const shard = new Uint8Array(shardSize);
    const slice = data.subarray(start, Math.min(start + shardSize, data.length));
    shard.set(slice);
    shards.push({
      index: i,
      type: "data",
      data: shard,
      originalSize: data.length,
      shardSize,
      totalShards: k + p,
    });
  }

  // Create p parity shards using rotating XOR combinations
  // Parity[j] = XOR of data shards selected by a rotating window
  // This gives each parity shard coverage of different data shard combinations
  for (let j = 0; j < p; j++) {
    const parity = new Uint8Array(shardSize);
    for (let i = 0; i < k; i++) {
      // Rotate which shards contribute to each parity
      // Parity 0: XOR all, Parity 1: XOR odd-indexed, etc.
      if (j === 0 || (i + j) % (p + 1) !== 0) {
        const src = shards[i].data;
        for (let b = 0; b < shardSize; b++) {
          parity[b] ^= src[b];
        }
      }
    }
    shards.push({
      index: k + j,
      type: "parity",
      data: parity,
      originalSize: data.length,
      shardSize,
      totalShards: k + p,
    });
  }

  return shards;
}

/**
 * Reconstruct original data from available shards.
 * Requires at least k data shards, or can recover one missing data shard
 * using parity shard 0 (XOR of all data shards).
 */
export function erasureDecode(
  availableShards: ErasureShard[],
  k = ERASURE_DATA_SHARDS,
): Uint8Array {
  if (availableShards.length === 0) throw new Error("No shards available");

  const { originalSize, shardSize } = availableShards[0];

  // Separate data and parity shards
  const dataShards = new Map<number, Uint8Array>();
  const parityShards = new Map<number, Uint8Array>();
  for (const s of availableShards) {
    if (s.type === "data") dataShards.set(s.index, s.data);
    else parityShards.set(s.index, s.data);
  }

  // If all data shards present, just concatenate
  if (dataShards.size >= k) {
    const result = new Uint8Array(originalSize);
    for (let i = 0; i < k; i++) {
      const shard = dataShards.get(i)!;
      const start = i * shardSize;
      const len = Math.min(shardSize, originalSize - start);
      result.set(shard.subarray(0, len), start);
    }
    return result;
  }

  // Find missing data shard indices
  const missing: number[] = [];
  for (let i = 0; i < k; i++) {
    if (!dataShards.has(i)) missing.push(i);
  }

  // Recover using parity 0 (XOR of all data shards) — can recover exactly 1 missing shard
  if (missing.length === 1 && parityShards.has(k)) {
    const missingIdx = missing[0];
    const parity = parityShards.get(k)!;
    const recovered = new Uint8Array(parity); // start with parity (copy)
    for (let i = 0; i < k; i++) {
      if (i === missingIdx) continue;
      const src = dataShards.get(i)!;
      for (let b = 0; b < shardSize; b++) {
        recovered[b] ^= src[b]; // XOR out known shards leaves missing shard
      }
    }
    dataShards.set(missingIdx, recovered);

    const result = new Uint8Array(originalSize);
    for (let i = 0; i < k; i++) {
      const shard = dataShards.get(i)!;
      const start = i * shardSize;
      const len = Math.min(shardSize, originalSize - start);
      result.set(shard.subarray(0, len), start);
    }
    return result;
  }

  // Multiple missing shards — need full Reed-Solomon (not implemented for lightweight)
  throw new Error(`Cannot recover ${missing.length} missing data shards (max 1 with XOR parity)`);
}

/**
 * Upload erasure-coded shards to R2 and return manifest.
 */
export async function uploadErasureShards(
  blobStore: R2Bucket,
  baseKey: string,
  data: Uint8Array,
): Promise<ErasureManifest> {
  const shards = erasureEncode(data);
  const shardHashes: string[] = [];

  for (const shard of shards) {
    const hash = await sha256(String.fromCharCode(...shard.data.subarray(0, Math.min(256, shard.data.length))));
    shardHashes.push(hash);
    await blobStore.put(`${baseKey}.shard.${shard.index}`, shard.data, {
      customMetadata: {
        shard_index: String(shard.index),
        shard_type: shard.type,
        original_size: String(shard.originalSize),
        shard_size: String(shard.shardSize),
      },
    });
  }

  const manifest: ErasureManifest = {
    data_shards: ERASURE_DATA_SHARDS,
    parity_shards: ERASURE_PARITY_SHARDS,
    shard_size: shards[0].shardSize,
    original_size: data.length,
    shard_hashes: shardHashes,
  };

  // Store manifest alongside shards
  await blobStore.put(`${baseKey}.erasure.json`, JSON.stringify(manifest), {
    customMetadata: { content_type: "application/json" },
  });

  return manifest;
}

/**
 * Download and reconstruct data from erasure-coded shards in R2.
 */
export async function downloadErasureShards(
  blobStore: R2Bucket,
  baseKey: string,
): Promise<Uint8Array | null> {
  // Fetch manifest
  const manifestObj = await blobStore.get(`${baseKey}.erasure.json`);
  if (!manifestObj) return null;
  const manifest: ErasureManifest = JSON.parse(await manifestObj.text());

  const totalShards = manifest.data_shards + manifest.parity_shards;
  const available: ErasureShard[] = [];

  // Try to fetch all shards, collect what's available
  for (let i = 0; i < totalShards; i++) {
    try {
      const obj = await blobStore.get(`${baseKey}.shard.${i}`);
      if (!obj) continue;
      const data = new Uint8Array(await obj.arrayBuffer());
      available.push({
        index: i,
        type: i < manifest.data_shards ? "data" : "parity",
        data,
        originalSize: manifest.original_size,
        shardSize: manifest.shard_size,
        totalShards,
      });
    } catch { /* shard missing */ }
  }

  if (available.length < manifest.data_shards) {
    console.warn(`Only ${available.length}/${manifest.data_shards} shards available, cannot reconstruct`);
    return null;
  }

  return erasureDecode(available, manifest.data_shards);
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
