// ─── State Anchoring: Berachain ──────────────────────────────────────────────
// Posts state roots and ZK proofs to Berachain (EVM L1).
// This ensures the ledger survives any Cloudflare account deletion/ban.
//
// Berachain: EVM L1 with Proof of Liquidity. Posts anchor as calldata (HYTE format)
//            to the dead address, same pattern as HyberText Transport Protocol.
//            Optionally writes structured data to HyberDB contract.
//
// New nodes can bootstrap from the latest anchor instead of replaying the full history.

import { sha256 } from "./consensus";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AnchorBundle {
  // Core anchor data
  state_root: string;
  finalized_seq: number;
  last_committed_round: number;

  // ZK proof reference (if available)
  zk_proof_hash?: string;         // SHA-256 of the proof bytes
  zk_proven_block?: number;

  // Snapshot for bootstrap
  snapshot_hash: string;           // SHA-256 of the state snapshot JSON

  // Metadata
  shard_name: string;
  node_pubkey: string;
  timestamp: number;
  previous_anchor_id?: string;     // chain anchors together

  // Network info
  active_nodes: number;
  vertex_count: number;
}

export interface AnchorRecord {
  id: string;                      // SHA-256 of the bundle
  bundle: AnchorBundle;
  berachain_tx?: string;           // Berachain transaction hash
  berachain_block?: number;        // Berachain block number
  status: "pending" | "submitted" | "confirmed" | "failed";
  created_at: number;
  confirmed_at?: number;
}

export interface BerachainConfig {
  rpc_url: string;                 // e.g., "https://rpc.berachain.com"
  private_key?: string;            // Hex-encoded private key for signing txs
  hyberdb_address?: string;        // HyberDB contract address for structured anchors
  hyberdb_namespace?: string;      // HyberDB namespace for Persistia anchors
  chain_id: number;                // 80094 for Berachain mainnet
}

export interface AnchorConfig {
  berachain?: BerachainConfig;
  anchor_interval_seq: number;     // anchor every N finalized events (default: 100)
  anchor_interval_ms: number;      // minimum time between anchors (default: 300_000 = 5 min)
  snapshot_with_anchor: boolean;   // include full state snapshot in anchor (default: false for size)
}

// ─── Constants ───────────────────────────────────────────────────────────────

const DEAD_ADDRESS = "0x000000000000000000000000000000000000dEaD";
const HYTE_MAGIC = [0x48, 0x59, 0x54, 0x45]; // "HYTE"
const HYTE_VERSION = 0x01;
const HYTE_COMPRESSION_NONE = 0x00;
const HYTE_CONTENT_BLOB = 0x04;

// HyberDB ABI fragments (only what we need)
const HYBERDB_COMMIT_SIG = "0x5c36b186"; // commit(bytes32 namespace, bytes key, bytes value)

// ─── Defaults ─────────────────────────────────────────────────────────────────

const DEFAULT_CONFIG: AnchorConfig = {
  anchor_interval_seq: 100,
  anchor_interval_ms: 300_000,      // 5 minutes
  snapshot_with_anchor: false,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function utf8ToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Wrap data in HYTE format (same as HyberText Transport Protocol).
 * HYTE header: 4 bytes magic + 1 version + 1 compression + 1 content-type + 2 reserved
 */
function wrapHYTE(data: Uint8Array, contentType: number = HYTE_CONTENT_BLOB, compression: number = HYTE_COMPRESSION_NONE): Uint8Array {
  const header = new Uint8Array(9);
  header[0] = HYTE_MAGIC[0]; // H
  header[1] = HYTE_MAGIC[1]; // Y
  header[2] = HYTE_MAGIC[2]; // T
  header[3] = HYTE_MAGIC[3]; // E
  header[4] = HYTE_VERSION;
  header[5] = compression;
  header[6] = contentType;
  header[7] = 0x00; // reserved
  header[8] = 0x00; // reserved
  const result = new Uint8Array(header.length + data.length);
  result.set(header, 0);
  result.set(data, header.length);
  return result;
}

/**
 * Encode an unsigned EIP-1559 transaction as hex.
 * For CF Workers, we build raw transaction bytes and send via eth_sendRawTransaction.
 * If no private key is available, we use eth_sendTransaction (requires unlocked account).
 */
function encodeAnchorCalldata(bundle: AnchorBundle): string {
  const json = JSON.stringify(bundle);
  const payload = utf8ToBytes(json);
  const hyte = wrapHYTE(payload);
  return bytesToHex(hyte);
}

// ─── AnchorManager ────────────────────────────────────────────────────────────

export class AnchorManager {
  private sql: any;
  private config: AnchorConfig;
  private lastAnchorSeq: number = 0;
  private lastAnchorTime: number = 0;

  constructor(sql: any, config?: Partial<AnchorConfig>) {
    this.sql = sql;
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.loadState();
  }

  private loadState() {
    const rows = [...this.sql.exec(
      "SELECT finalized_seq, created_at FROM anchors ORDER BY created_at DESC LIMIT 1",
    )] as any[];
    if (rows.length > 0) {
      this.lastAnchorSeq = rows[0].finalized_seq || 0;
      this.lastAnchorTime = rows[0].created_at || 0;
    }
  }

  // ─── Should Anchor? ─────────────────────────────────────────────────────

  shouldAnchor(currentSeq: number): boolean {
    const seqDelta = currentSeq - this.lastAnchorSeq;
    const timeDelta = Date.now() - this.lastAnchorTime;

    return seqDelta >= this.config.anchor_interval_seq &&
           timeDelta >= this.config.anchor_interval_ms &&
           currentSeq > 0;
  }

  // ─── Create Anchor Bundle ──────────────────────────────────────────────

  async createBundle(params: {
    stateRoot: string;
    finalizedSeq: number;
    lastCommittedRound: number;
    shardName: string;
    nodePubkey: string;
    activeNodes: number;
    vertexCount: number;
    zkProofHash?: string;
    zkProvenBlock?: number;
    snapshotJson?: string;
  }): Promise<AnchorBundle> {
    const snapshotHash = params.snapshotJson
      ? await sha256(params.snapshotJson)
      : await sha256(`${params.stateRoot}:${params.finalizedSeq}`);

    // Get previous anchor ID for chaining
    const prevRows = [...this.sql.exec(
      "SELECT id FROM anchors ORDER BY created_at DESC LIMIT 1",
    )] as any[];
    const previousAnchorId = prevRows.length > 0 ? prevRows[0].id : undefined;

    return {
      state_root: params.stateRoot,
      finalized_seq: params.finalizedSeq,
      last_committed_round: params.lastCommittedRound,
      zk_proof_hash: params.zkProofHash,
      zk_proven_block: params.zkProvenBlock,
      snapshot_hash: snapshotHash,
      shard_name: params.shardName,
      node_pubkey: params.nodePubkey,
      timestamp: Date.now(),
      previous_anchor_id: previousAnchorId,
      active_nodes: params.activeNodes,
      vertex_count: params.vertexCount,
    };
  }

  // ─── Submit to Berachain ──────────────────────────────────────────────

  /**
   * Anchor state to Berachain using the HYTE format (same as HyberText Transport Protocol).
   * Sends anchor bundle as calldata to the dead address (0x...dEaD).
   * The transaction hash becomes a permanent, immutable reference to the anchor.
   *
   * If HyberDB is configured, also writes structured data for on-chain queryability.
   */
  async submitToBerachain(bundle: AnchorBundle): Promise<{ tx_hash: string; block_number: number } | null> {
    if (!this.config.berachain) return null;

    const bera = this.config.berachain;
    const calldata = encodeAnchorCalldata(bundle);

    try {
      // Method 1: Send HYTE-encoded calldata to dead address
      // This makes the anchor data permanently available via eth_getTransactionByHash,
      // using the same retrieval pattern as HBTP sites.
      const txHash = await this.sendBerachainTx(bera, {
        to: DEAD_ADDRESS,
        data: calldata,
        value: "0x0",
      });

      if (!txHash) return null;

      // Wait for receipt to get block number
      const receipt = await this.waitForReceipt(bera, txHash);
      const blockNumber = receipt?.blockNumber || 0;

      // Method 2 (optional): Also write to HyberDB for structured querying
      if (bera.hyberdb_address && bera.hyberdb_namespace) {
        await this.writeToHyberDB(bera, bundle, txHash);
      }

      return { tx_hash: txHash, block_number: blockNumber };
    } catch (e: any) {
      console.warn(`Berachain anchor failed: ${e.message}`);
      return null;
    }
  }

  private async sendBerachainTx(
    bera: BerachainConfig,
    tx: { to: string; data: string; value: string },
  ): Promise<string | null> {
    try {
      // Use eth_sendTransaction (requires an unlocked account or external signer)
      // In production, this would use a signing service or wallet API
      const res = await fetch(bera.rpc_url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: 1,
          jsonrpc: "2.0",
          method: "eth_sendTransaction",
          params: [{
            to: tx.to,
            data: tx.data,
            value: tx.value,
            chainId: "0x" + bera.chain_id.toString(16),
          }],
        }),
      });

      if (!res.ok) return null;
      const result = await res.json() as any;
      if (result.error) {
        console.warn(`Berachain tx error: ${result.error.message}`);
        return null;
      }
      return result.result as string;
    } catch (e: any) {
      console.warn(`Berachain tx send failed: ${e.message}`);
      return null;
    }
  }

  private async waitForReceipt(
    bera: BerachainConfig,
    txHash: string,
    maxAttempts: number = 10,
  ): Promise<{ blockNumber: number } | null> {
    for (let i = 0; i < maxAttempts; i++) {
      try {
        const res = await fetch(bera.rpc_url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            id: 1,
            jsonrpc: "2.0",
            method: "eth_getTransactionReceipt",
            params: [txHash],
          }),
        });

        if (!res.ok) continue;
        const result = await res.json() as any;
        if (result.result) {
          return { blockNumber: parseInt(result.result.blockNumber, 16) };
        }
      } catch {
        // retry
      }
      // Wait 2 seconds between attempts
      await new Promise(r => setTimeout(r, 2000));
    }
    return null;
  }

  /**
   * Write structured anchor data to HyberDB for on-chain queryability.
   * Uses the commit() function to write key-value pairs to a Persistia namespace.
   */
  private async writeToHyberDB(
    bera: BerachainConfig,
    bundle: AnchorBundle,
    calldataTxHash: string,
  ): Promise<void> {
    if (!bera.hyberdb_address || !bera.hyberdb_namespace) return;

    // Build commit calldata: commit(bytes32 namespace, bytes key, bytes value)
    // Key: "anchor:{seq}" → Value: JSON with state_root, round, tx_hash
    const key = `anchor:${bundle.finalized_seq}`;
    const value = JSON.stringify({
      state_root: bundle.state_root,
      round: bundle.last_committed_round,
      calldata_tx: calldataTxHash,
      zk_proof_hash: bundle.zk_proof_hash,
      active_nodes: bundle.active_nodes,
      timestamp: bundle.timestamp,
    });

    // ABI encode: commit(bytes32, bytes, bytes)
    const keyHex = bytesToHex(utf8ToBytes(key));
    const valueHex = bytesToHex(utf8ToBytes(value));

    // Simplified ABI encoding — in production use proper ABI encoder
    const calldata = HYBERDB_COMMIT_SIG +
      bera.hyberdb_namespace!.padStart(64, "0") +
      abiEncodeBytes(keyHex) +
      abiEncodeBytes(valueHex);

    try {
      await this.sendBerachainTx(bera, {
        to: bera.hyberdb_address,
        data: "0x" + calldata,
        value: "0x0",
      });
    } catch (e: any) {
      // Non-critical — the calldata anchor is the primary record
      console.warn(`HyberDB write failed (non-critical): ${e.message}`);
    }
  }

  // ─── Full Anchor Flow ───────────────────────────────────────────────────

  /**
   * Create anchor bundle, submit to configured backends, record in DB.
   */
  async anchor(params: {
    stateRoot: string;
    finalizedSeq: number;
    lastCommittedRound: number;
    shardName: string;
    nodePubkey: string;
    activeNodes: number;
    vertexCount: number;
    zkProofHash?: string;
    zkProvenBlock?: number;
    snapshotJson?: string;
  }): Promise<AnchorRecord> {
    const bundle = await this.createBundle(params);
    const anchorId = await sha256(JSON.stringify(bundle));

    // Store pending anchor
    this.sql.exec(
      `INSERT OR IGNORE INTO anchors (id, bundle_json, status, finalized_seq, created_at)
       VALUES (?, ?, 'pending', ?, ?)`,
      anchorId, JSON.stringify(bundle), params.finalizedSeq, Date.now(),
    );

    let berachainTx: string | undefined;
    let berachainBlock: number | undefined;

    // Submit to Berachain
    const beraResult = await this.submitToBerachain(bundle);
    if (beraResult) {
      berachainTx = beraResult.tx_hash;
      berachainBlock = beraResult.block_number;
      this.sql.exec(
        "UPDATE anchors SET celestia_height = ?, celestia_commitment = ? WHERE id = ?",
        berachainBlock, berachainTx, anchorId,
      );
    }

    // Update status
    const status = berachainTx ? "submitted" : "failed";
    this.sql.exec(
      "UPDATE anchors SET status = ? WHERE id = ?",
      status, anchorId,
    );

    // Update tracking
    this.lastAnchorSeq = params.finalizedSeq;
    this.lastAnchorTime = Date.now();

    const record: AnchorRecord = {
      id: anchorId,
      bundle,
      berachain_tx: berachainTx,
      berachain_block: berachainBlock,
      status,
      created_at: Date.now(),
    };

    console.log(
      `Anchored seq=${params.finalizedSeq} root=${params.stateRoot.slice(0, 12)}` +
      (berachainTx ? ` berachain=${berachainTx}` : ""),
    );

    return record;
  }

  // ─── Retrieval ──────────────────────────────────────────────────────────

  getLatestAnchor(): AnchorRecord | null {
    const rows = [...this.sql.exec(
      "SELECT id, bundle_json, celestia_height, celestia_commitment, status, created_at, confirmed_at FROM anchors ORDER BY created_at DESC LIMIT 1",
    )] as any[];

    if (rows.length === 0) return null;

    const row = rows[0];
    return {
      id: row.id,
      bundle: JSON.parse(row.bundle_json),
      berachain_tx: row.celestia_commitment || undefined,    // reusing column for backward compat
      berachain_block: row.celestia_height || undefined,
      status: row.status,
      created_at: row.created_at,
      confirmed_at: row.confirmed_at || undefined,
    };
  }

  getAnchorHistory(limit: number = 20): AnchorRecord[] {
    const rows = [...this.sql.exec(
      "SELECT id, bundle_json, celestia_height, celestia_commitment, status, created_at, confirmed_at FROM anchors ORDER BY created_at DESC LIMIT ?",
      limit,
    )] as any[];

    return rows.map((row: any) => ({
      id: row.id,
      bundle: JSON.parse(row.bundle_json),
      berachain_tx: row.celestia_commitment || undefined,
      berachain_block: row.celestia_height || undefined,
      status: row.status,
      created_at: row.created_at,
      confirmed_at: row.confirmed_at || undefined,
    }));
  }

  // ─── Verification ──────────────────────────────────────────────────────

  /**
   * Fetch and verify an anchor from Berachain by transaction hash.
   * Retrieves the tx calldata, strips the HYTE header, and parses the anchor bundle.
   */
  async verifyFromBerachain(txHash: string): Promise<{ valid: boolean; bundle?: AnchorBundle; error?: string }> {
    if (!this.config.berachain) return { valid: false, error: "Berachain not configured" };

    try {
      const res = await fetch(this.config.berachain.rpc_url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: 1,
          jsonrpc: "2.0",
          method: "eth_getTransactionByHash",
          params: [txHash],
        }),
      });

      if (!res.ok) return { valid: false, error: `HTTP ${res.status}` };

      const result = await res.json() as any;
      if (!result.result) return { valid: false, error: "Transaction not found" };

      const input = result.result.input;
      if (!input || input.length < 20) return { valid: false, error: "No calldata" };

      // Strip HYTE header (9 bytes = 18 hex chars + "0x" prefix)
      const dataHex = input.slice(2 + 18); // skip "0x" + 18 hex chars (9 bytes header)
      const dataBytes = hexToBytes(dataHex);
      const json = new TextDecoder().decode(dataBytes);
      const bundle = JSON.parse(json) as AnchorBundle;

      if (!bundle.state_root || !bundle.finalized_seq) {
        return { valid: false, error: "Invalid anchor data in calldata" };
      }

      return { valid: true, bundle };
    } catch (e: any) {
      return { valid: false, error: e.message };
    }
  }

  /**
   * Prune old confirmed anchors, keeping the most recent `keep` entries.
   */
  pruneOldAnchors(keep: number = 100) {
    this.sql.exec(
      `UPDATE anchors SET bundle_json = '{}' WHERE status = 'confirmed'
       AND id NOT IN (SELECT id FROM anchors WHERE status = 'confirmed' ORDER BY created_at DESC LIMIT ?)`,
      keep,
    );
  }
}

// ─── ABI Helpers ─────────────────────────────────────────────────────────────

/**
 * Minimal ABI encoding for a bytes parameter.
 * Returns hex string (no 0x prefix) for the offset + length + padded data.
 */
function abiEncodeBytes(hexData: string): string {
  const data = hexData.startsWith("0x") ? hexData.slice(2) : hexData;
  const byteLen = data.length / 2;
  const lenHex = byteLen.toString(16).padStart(64, "0");
  // Pad data to 32-byte boundary
  const paddedLen = Math.ceil(data.length / 64) * 64;
  const paddedData = data.padEnd(paddedLen, "0");
  return lenHex + paddedData;
}
