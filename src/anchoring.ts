// ─── State Anchoring: Arweave + Celestia ──────────────────────────────────────
// Posts state roots and ZK proofs to permanent off-platform storage.
// This ensures the ledger survives any Cloudflare account deletion/ban.
//
// Arweave: Pay-once permanent storage. Stores full anchor bundle (root, proof, metadata).
// Celestia: Data Availability layer. Posts blob for public verifiability.
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
  arweave_tx?: string;             // Arweave transaction ID
  celestia_height?: number;        // Celestia block height
  celestia_commitment?: string;    // Celestia blob commitment
  status: "pending" | "submitted" | "confirmed" | "failed";
  created_at: number;
  confirmed_at?: number;
}

export interface ArweaveConfig {
  gateway_url: string;             // e.g., "https://arweave.net" or "https://up.arweave.net"
  wallet_jwk?: any;                // Arweave wallet JWK for signing (optional — can use bundlr/irys)
  irys_url?: string;               // e.g., "https://node2.irys.xyz" (formerly Bundlr)
  irys_token?: string;             // Auth token for Irys
}

export interface CelestiaConfig {
  rpc_url: string;                 // e.g., "http://localhost:26658" or a public endpoint
  auth_token?: string;             // Bearer token for auth
  namespace: string;               // hex-encoded namespace (8 bytes)
}

export interface AnchorConfig {
  arweave?: ArweaveConfig;
  celestia?: CelestiaConfig;
  anchor_interval_seq: number;     // anchor every N finalized events (default: 100)
  anchor_interval_ms: number;      // minimum time between anchors (default: 300_000 = 5 min)
  snapshot_with_anchor: boolean;   // include full state snapshot in anchor (default: false for size)
}

// ─── Defaults ─────────────────────────────────────────────────────────────────

const DEFAULT_CONFIG: AnchorConfig = {
  anchor_interval_seq: 100,
  anchor_interval_ms: 300_000,      // 5 minutes
  snapshot_with_anchor: false,
};

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

  // ─── Submit to Arweave ──────────────────────────────────────────────────

  async submitToArweave(
    bundle: AnchorBundle,
    snapshotJson?: string,
  ): Promise<{ tx_id: string } | null> {
    if (!this.config.arweave) return null;

    const arweave = this.config.arweave;

    // Prepare the data to store
    const anchorData = JSON.stringify({
      bundle,
      snapshot: snapshotJson || null,
    });

    // Try Irys (formerly Bundlr) first — simpler API, instant finality
    if (arweave.irys_url && arweave.irys_token) {
      try {
        const res = await fetch(`${arweave.irys_url}/tx`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${arweave.irys_token}`,
            "x-tag-App-Name": "Persistia",
            "x-tag-Content-Type": "application/json",
            "x-tag-Shard": bundle.shard_name,
            "x-tag-State-Root": bundle.state_root,
            "x-tag-Seq": bundle.finalized_seq.toString(),
            "x-tag-Round": bundle.last_committed_round.toString(),
          },
          body: anchorData,
        });

        if (res.ok) {
          const result = await res.json() as any;
          return { tx_id: result.id || result.txId };
        }
      } catch (e: any) {
        console.warn(`Irys upload failed: ${e.message}`);
      }
    }

    // Fallback: direct Arweave gateway upload (requires wallet)
    if (arweave.gateway_url && arweave.wallet_jwk) {
      try {
        // Arweave transaction construction (simplified — real impl needs arweave-js)
        // For CF Workers, we use the gateway's upload endpoint
        const res = await fetch(`${arweave.gateway_url}/tx`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            data: btoa(anchorData),
            tags: [
              { name: "App-Name", value: "Persistia" },
              { name: "Content-Type", value: "application/json" },
              { name: "Shard", value: bundle.shard_name },
              { name: "State-Root", value: bundle.state_root },
              { name: "Seq", value: bundle.finalized_seq.toString() },
              { name: "Round", value: bundle.last_committed_round.toString() },
              { name: "Type", value: "state-anchor" },
            ],
          }),
        });

        if (res.ok) {
          const result = await res.json() as any;
          return { tx_id: result.id };
        }
      } catch (e: any) {
        console.warn(`Arweave upload failed: ${e.message}`);
      }
    }

    return null;
  }

  // ─── Submit to Celestia ─────────────────────────────────────────────────

  async submitToCelestia(bundle: AnchorBundle): Promise<{ height: number; commitment: string } | null> {
    if (!this.config.celestia) return null;

    const celestia = this.config.celestia;
    const blobData = JSON.stringify(bundle);
    const blobB64 = btoa(blobData);

    try {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (celestia.auth_token) {
        headers["Authorization"] = `Bearer ${celestia.auth_token}`;
      }

      // Celestia blob.Submit JSON-RPC
      const res = await fetch(celestia.rpc_url, {
        method: "POST",
        headers,
        body: JSON.stringify({
          id: 1,
          jsonrpc: "2.0",
          method: "blob.Submit",
          params: [
            [
              {
                namespace: celestia.namespace,
                data: blobB64,
                share_version: 0,
              },
            ],
            0.002, // gas price
          ],
        }),
      });

      if (!res.ok) return null;

      const result = await res.json() as any;
      if (result.error) {
        console.warn(`Celestia submit error: ${result.error.message}`);
        return null;
      }

      // Result contains the block height
      const height = result.result;

      // Get the blob commitment for verification
      const commitRes = await fetch(celestia.rpc_url, {
        method: "POST",
        headers,
        body: JSON.stringify({
          id: 2,
          jsonrpc: "2.0",
          method: "blob.Get",
          params: [height, celestia.namespace, blobB64],
        }),
      });

      let commitment = "";
      if (commitRes.ok) {
        const commitResult = await commitRes.json() as any;
        commitment = commitResult.result?.commitment || "";
      }

      return { height, commitment };
    } catch (e: any) {
      console.warn(`Celestia submit failed: ${e.message}`);
      return null;
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

    let arweaveTx: string | undefined;
    let celestiaHeight: number | undefined;
    let celestiaCommitment: string | undefined;

    // Submit to Arweave
    const arResult = await this.submitToArweave(bundle, params.snapshotJson);
    if (arResult) {
      arweaveTx = arResult.tx_id;
      this.sql.exec(
        "UPDATE anchors SET arweave_tx = ? WHERE id = ?",
        arweaveTx, anchorId,
      );
    }

    // Submit to Celestia
    const celResult = await this.submitToCelestia(bundle);
    if (celResult) {
      celestiaHeight = celResult.height;
      celestiaCommitment = celResult.commitment;
      this.sql.exec(
        "UPDATE anchors SET celestia_height = ?, celestia_commitment = ? WHERE id = ?",
        celestiaHeight, celestiaCommitment, anchorId,
      );
    }

    // Update status
    const status = (arweaveTx || celestiaHeight) ? "submitted" : "failed";
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
      arweave_tx: arweaveTx,
      celestia_height: celestiaHeight,
      celestia_commitment: celestiaCommitment,
      status,
      created_at: Date.now(),
    };

    console.log(
      `Anchored seq=${params.finalizedSeq} root=${params.stateRoot.slice(0, 12)}` +
      (arweaveTx ? ` arweave=${arweaveTx}` : "") +
      (celestiaHeight ? ` celestia=${celestiaHeight}` : ""),
    );

    return record;
  }

  // ─── Retrieval ──────────────────────────────────────────────────────────

  getLatestAnchor(): AnchorRecord | null {
    const rows = [...this.sql.exec(
      "SELECT id, bundle_json, arweave_tx, celestia_height, celestia_commitment, status, created_at, confirmed_at FROM anchors WHERE status IN ('submitted', 'confirmed') ORDER BY created_at DESC LIMIT 1",
    )] as any[];

    if (rows.length === 0) return null;

    const row = rows[0];
    return {
      id: row.id,
      bundle: JSON.parse(row.bundle_json),
      arweave_tx: row.arweave_tx || undefined,
      celestia_height: row.celestia_height || undefined,
      celestia_commitment: row.celestia_commitment || undefined,
      status: row.status,
      created_at: row.created_at,
      confirmed_at: row.confirmed_at || undefined,
    };
  }

  getAnchorHistory(limit: number = 20): AnchorRecord[] {
    const rows = [...this.sql.exec(
      "SELECT id, bundle_json, arweave_tx, celestia_height, celestia_commitment, status, created_at, confirmed_at FROM anchors ORDER BY created_at DESC LIMIT ?",
      limit,
    )] as any[];

    return rows.map((row: any) => ({
      id: row.id,
      bundle: JSON.parse(row.bundle_json),
      arweave_tx: row.arweave_tx || undefined,
      celestia_height: row.celestia_height || undefined,
      celestia_commitment: row.celestia_commitment || undefined,
      status: row.status,
      created_at: row.created_at,
      confirmed_at: row.confirmed_at || undefined,
    }));
  }

  // ─── Verification ──────────────────────────────────────────────────────

  /**
   * Fetch and verify an anchor from Arweave by transaction ID.
   */
  async verifyFromArweave(txId: string): Promise<{ valid: boolean; bundle?: AnchorBundle; error?: string }> {
    if (!this.config.arweave) return { valid: false, error: "Arweave not configured" };

    try {
      const gateway = this.config.arweave.gateway_url || "https://arweave.net";
      const res = await fetch(`${gateway}/${txId}`);
      if (!res.ok) return { valid: false, error: `HTTP ${res.status}` };

      const data = await res.json() as any;
      const bundle = data.bundle as AnchorBundle;

      if (!bundle || !bundle.state_root || !bundle.finalized_seq) {
        return { valid: false, error: "Invalid anchor data" };
      }

      // Verify the anchor ID matches
      const expectedId = await sha256(JSON.stringify(bundle));
      const storedAnchor = [...this.sql.exec("SELECT id FROM anchors WHERE arweave_tx = ?", txId)] as any[];

      if (storedAnchor.length > 0 && storedAnchor[0].id !== expectedId) {
        return { valid: false, error: "Anchor ID mismatch" };
      }

      return { valid: true, bundle };
    } catch (e: any) {
      return { valid: false, error: e.message };
    }
  }

  /**
   * Verify an anchor from Celestia by height and namespace.
   */
  async verifyFromCelestia(height: number): Promise<{ valid: boolean; bundle?: AnchorBundle; error?: string }> {
    if (!this.config.celestia) return { valid: false, error: "Celestia not configured" };

    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (this.config.celestia.auth_token) {
        headers["Authorization"] = `Bearer ${this.config.celestia.auth_token}`;
      }

      const res = await fetch(this.config.celestia.rpc_url, {
        method: "POST",
        headers,
        body: JSON.stringify({
          id: 1,
          jsonrpc: "2.0",
          method: "blob.GetAll",
          params: [height, [this.config.celestia.namespace]],
        }),
      });

      if (!res.ok) return { valid: false, error: `HTTP ${res.status}` };

      const result = await res.json() as any;
      if (result.error) return { valid: false, error: result.error.message };

      const blobs = result.result || [];
      for (const blob of blobs) {
        try {
          const data = JSON.parse(atob(blob.data));
          if (data.state_root && data.finalized_seq) {
            return { valid: true, bundle: data as AnchorBundle };
          }
        } catch {
          // not our blob
        }
      }

      return { valid: false, error: "No Persistia anchor found at this height" };
    } catch (e: any) {
      return { valid: false, error: e.message };
    }
  }

  // ─── Bootstrap ──────────────────────────────────────────────────────────

  /**
   * Find the latest anchor from Arweave for bootstrapping a new node.
   * Searches by tag to find the most recent Persistia anchor.
   */
  async findLatestArweaveAnchor(shardName: string): Promise<AnchorBundle | null> {
    if (!this.config.arweave) return null;

    try {
      const gateway = this.config.arweave.gateway_url || "https://arweave.net";

      // GraphQL query to find latest Persistia anchor by shard
      const query = `{
        transactions(
          tags: [
            { name: "App-Name", values: ["Persistia"] },
            { name: "Type", values: ["state-anchor"] },
            { name: "Shard", values: ["${shardName}"] }
          ],
          sort: HEIGHT_DESC,
          first: 1
        ) {
          edges {
            node {
              id
              tags { name value }
            }
          }
        }
      }`;

      const res = await fetch(`${gateway}/graphql`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query }),
      });

      if (!res.ok) return null;

      const data = await res.json() as any;
      const edges = data?.data?.transactions?.edges || [];
      if (edges.length === 0) return null;

      const txId = edges[0].node.id;

      // Fetch the anchor data
      const anchorRes = await fetch(`${gateway}/${txId}`);
      if (!anchorRes.ok) return null;

      const anchorData = await anchorRes.json() as any;
      return anchorData.bundle as AnchorBundle;
    } catch {
      return null;
    }
  }

  /**
   * Prune old confirmed anchors, keeping the most recent `keep` entries.
   * Removes bundle_json from older confirmed anchors to reclaim storage.
   */
  pruneOldAnchors(keep: number = 100) {
    // Null out bundle_json for old confirmed anchors beyond the retention window.
    // We keep the metadata (tx IDs, heights) for auditability but free the large payload.
    this.sql.exec(
      `UPDATE anchors SET bundle_json = '{}' WHERE status = 'confirmed'
       AND id NOT IN (SELECT id FROM anchors WHERE status = 'confirmed' ORDER BY created_at DESC LIMIT ?)`,
      keep,
    );
  }
}
