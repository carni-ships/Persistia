// ─── Service Attestation Protocol ─────────────────────────────────────────────
// Cryptographic commit-reveal attestations for verifiable AI compute.
//
// Flow:
//   1. Pre-commitment:  H(model || input_hash || nonce)   — committed before inference
//   2. AI inference runs on Workers AI
//   3. Post-commitment: sign(model, input_hash, output_hash, pre_commitment, nonce)
//   4. Attestation stored on-chain in hash chain → state root → L1 anchor
//
// Verification modes:
//   - Audit:     anyone can inspect the attestation + hash chain
//   - Challenge: re-run the same input on another node, compare outputs
//   - Multi-node: route to N nodes, require ≥2/3 agreement (uses oracle infra)

import { sha256 } from "./consensus";
import { signData, type NodeIdentity } from "./node-identity";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ServiceAttestation {
  attestation_id: string;
  prev_hash: string;           // hash of previous attestation (chain link)
  service: string;             // e.g. "llm", "tts"
  model: string;               // model ID used
  input_hash: string;          // H(request body)
  output_hash: string;         // H(response bytes)
  output_size: number;         // response size in bytes
  pre_commitment: string;      // H(model || input_hash || nonce) — committed before inference
  nonce: string;               // random nonce revealed after
  node_pubkey: string;         // attesting node's public key
  node_signature: string;      // Ed25519 sig over canonical attestation
  timestamp: number;
  receipt_id: string | null;   // linked MPP receipt
  challenge_status: "unchallenged" | "verified" | "disputed";
}

export interface ChallengeResult {
  attestation_id: string;
  challenger_node: string;
  original_output_hash: string;
  challenge_output_hash: string;
  match: boolean;
  timestamp: number;
}

// ─── Manager ──────────────────────────────────────────────────────────────────

export class ServiceAttestationManager {
  private sql: any;
  private identity: NodeIdentity | null;
  private lastHash: string = "genesis";

  constructor(sql: any, identity: NodeIdentity | null) {
    this.sql = sql;
    this.identity = identity;
  }

  /** Create tables for attestations and challenges. */
  static initTables(sql: any): void {
    sql.exec(`
      CREATE TABLE IF NOT EXISTS service_attestations (
        attestation_id TEXT PRIMARY KEY,
        prev_hash TEXT NOT NULL,
        service TEXT NOT NULL,
        model TEXT NOT NULL,
        input_hash TEXT NOT NULL,
        output_hash TEXT NOT NULL,
        output_size INTEGER NOT NULL DEFAULT 0,
        pre_commitment TEXT NOT NULL,
        nonce TEXT NOT NULL,
        node_pubkey TEXT NOT NULL,
        node_signature TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        receipt_id TEXT,
        challenge_status TEXT NOT NULL DEFAULT 'unchallenged'
      )
    `);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_sa_timestamp ON service_attestations(timestamp)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_sa_service ON service_attestations(service)`);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_sa_receipt ON service_attestations(receipt_id)`);

    sql.exec(`
      CREATE TABLE IF NOT EXISTS attestation_challenges (
        challenge_id TEXT PRIMARY KEY,
        attestation_id TEXT NOT NULL,
        challenger_node TEXT NOT NULL,
        original_output_hash TEXT NOT NULL,
        challenge_output_hash TEXT NOT NULL,
        match INTEGER NOT NULL,
        timestamp INTEGER NOT NULL
      )
    `);
    sql.exec(`CREATE INDEX IF NOT EXISTS idx_ac_attestation ON attestation_challenges(attestation_id)`);
  }

  /** Load the last attestation hash to continue the chain. */
  async init(): Promise<void> {
    const rows = [...this.sql.exec(
      "SELECT attestation_id FROM service_attestations ORDER BY timestamp DESC LIMIT 1"
    )];
    if (rows.length > 0) {
      this.lastHash = rows[0].attestation_id;
    }
  }

  // ─── Pre-commitment (before inference) ──────────────────────────────────

  /**
   * Create a pre-commitment before running inference.
   * Returns { pre_commitment, nonce, input_hash } to be used after inference completes.
   */
  async preCommit(
    service: string,
    model: string,
    inputBody: string,
  ): Promise<{ pre_commitment: string; nonce: string; input_hash: string }> {
    const nonce = await sha256(`nonce:${Date.now()}:${Math.random()}:${service}`);
    const input_hash = await sha256(inputBody);
    const pre_commitment = await sha256(`${model}||${input_hash}||${nonce}`);
    return { pre_commitment, nonce, input_hash };
  }

  // ─── Post-commitment (after inference) ──────────────────────────────────

  /**
   * Create and store a signed attestation after inference completes.
   * The attestation links to the previous one via prev_hash, forming a hash chain.
   */
  async attest(params: {
    service: string;
    model: string;
    input_hash: string;
    output_bytes: ArrayBuffer | Uint8Array | string;
    pre_commitment: string;
    nonce: string;
    receipt_id?: string;
  }): Promise<ServiceAttestation> {
    if (!this.identity) {
      throw new Error("Node identity not available for signing");
    }

    // Compute output hash
    let output_hash: string;
    let output_size: number;
    if (typeof params.output_bytes === "string") {
      output_hash = await sha256(params.output_bytes);
      output_size = new TextEncoder().encode(params.output_bytes).length;
    } else {
      const bytes = params.output_bytes instanceof Uint8Array
        ? params.output_bytes
        : new Uint8Array(params.output_bytes);
      output_size = bytes.length;
      // Hash the raw bytes via hex encoding
      const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
      output_hash = await sha256(hex);
    }

    const timestamp = Date.now();
    const prev_hash = this.lastHash;

    // Canonical form for signing (deterministic JSON key order)
    const canonical = JSON.stringify({
      prev_hash,
      service: params.service,
      model: params.model,
      input_hash: params.input_hash,
      output_hash,
      output_size,
      pre_commitment: params.pre_commitment,
      nonce: params.nonce,
      timestamp,
    });

    const node_signature = await signData(this.identity, canonical);
    const attestation_id = await sha256(`attestation:${canonical}:${node_signature}`);

    const attestation: ServiceAttestation = {
      attestation_id,
      prev_hash,
      service: params.service,
      model: params.model,
      input_hash: params.input_hash,
      output_hash,
      output_size,
      pre_commitment: params.pre_commitment,
      nonce: params.nonce,
      node_pubkey: this.identity.pubkey,
      node_signature,
      timestamp,
      receipt_id: params.receipt_id || null,
      challenge_status: "unchallenged",
    };

    // Store
    this.sql.exec(
      `INSERT INTO service_attestations
       (attestation_id, prev_hash, service, model, input_hash, output_hash, output_size,
        pre_commitment, nonce, node_pubkey, node_signature, timestamp, receipt_id, challenge_status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      attestation_id, prev_hash, params.service, params.model,
      params.input_hash, output_hash, output_size,
      params.pre_commitment, params.nonce,
      this.identity.pubkey, node_signature, timestamp,
      params.receipt_id || null, "unchallenged",
    );

    // Advance chain
    this.lastHash = attestation_id;

    return attestation;
  }

  // ─── Verification ───────────────────────────────────────────────────────

  /**
   * Verify an attestation's internal consistency:
   *   1. pre_commitment == H(model || input_hash || nonce)
   *   2. attestation_id == H(attestation:canonical:signature)
   *   3. Ed25519 signature is valid over the canonical form
   */
  async verify(attestation_id: string): Promise<{
    valid: boolean;
    checks: Record<string, boolean>;
    attestation?: ServiceAttestation;
  }> {
    const att = this.getAttestation(attestation_id);
    if (!att) return { valid: false, checks: { exists: false } };

    const checks: Record<string, boolean> = { exists: true };

    // Check pre-commitment
    const expected_pc = await sha256(`${att.model}||${att.input_hash}||${att.nonce}`);
    checks.pre_commitment = expected_pc === att.pre_commitment;

    // Check canonical + attestation_id
    const canonical = JSON.stringify({
      prev_hash: att.prev_hash,
      service: att.service,
      model: att.model,
      input_hash: att.input_hash,
      output_hash: att.output_hash,
      output_size: att.output_size,
      pre_commitment: att.pre_commitment,
      nonce: att.nonce,
      timestamp: att.timestamp,
    });
    const expected_id = await sha256(`attestation:${canonical}:${att.node_signature}`);
    checks.attestation_id = expected_id === att.attestation_id;

    // Check chain link
    if (att.prev_hash !== "genesis") {
      const prev = this.getAttestation(att.prev_hash);
      checks.chain_link = prev !== null;
    } else {
      checks.chain_link = true;
    }

    // Signature verification (Ed25519 via SubtleCrypto)
    try {
      const pubkeyBytes = Uint8Array.from(atob(att.node_pubkey), c => c.charCodeAt(0));
      const pubkey = await crypto.subtle.importKey(
        "raw", pubkeyBytes, { name: "Ed25519" }, false, ["verify"],
      );
      const sigBytes = Uint8Array.from(atob(att.node_signature), c => c.charCodeAt(0));
      const dataBytes = new TextEncoder().encode(canonical);
      checks.signature = await crypto.subtle.verify("Ed25519", pubkey, sigBytes, dataBytes);
    } catch {
      checks.signature = false;
    }

    const valid = Object.values(checks).every(Boolean);
    return { valid, checks, attestation: att };
  }

  // ─── Challenge ──────────────────────────────────────────────────────────

  /**
   * Record a challenge result: someone re-ran the same input and got a different (or same) output.
   */
  async recordChallenge(params: {
    attestation_id: string;
    challenger_node: string;
    challenge_output_hash: string;
  }): Promise<ChallengeResult> {
    const att = this.getAttestation(params.attestation_id);
    if (!att) throw new Error("Attestation not found");

    const match = att.output_hash === params.challenge_output_hash;
    const challenge_id = await sha256(
      `challenge:${params.attestation_id}:${params.challenger_node}:${Date.now()}`
    );
    const timestamp = Date.now();

    this.sql.exec(
      `INSERT INTO attestation_challenges
       (challenge_id, attestation_id, challenger_node, original_output_hash, challenge_output_hash, match, timestamp)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      challenge_id, params.attestation_id, params.challenger_node,
      att.output_hash, params.challenge_output_hash,
      match ? 1 : 0, timestamp,
    );

    // Update attestation status
    const new_status = match ? "verified" : "disputed";
    this.sql.exec(
      "UPDATE service_attestations SET challenge_status = ? WHERE attestation_id = ?",
      new_status, params.attestation_id,
    );

    return {
      attestation_id: params.attestation_id,
      challenger_node: params.challenger_node,
      original_output_hash: att.output_hash,
      challenge_output_hash: params.challenge_output_hash,
      match,
      timestamp,
    };
  }

  // ─── Queries ────────────────────────────────────────────────────────────

  getAttestation(id: string): ServiceAttestation | null {
    const rows = [...this.sql.exec(
      "SELECT * FROM service_attestations WHERE attestation_id = ?", id
    )];
    if (rows.length === 0) return null;
    return this.rowToAttestation(rows[0]);
  }

  /** Get recent attestations, optionally filtered by service. */
  listAttestations(opts: { service?: string; limit?: number; after?: number } = {}): ServiceAttestation[] {
    const limit = opts.limit || 50;
    if (opts.service) {
      const rows = [...this.sql.exec(
        "SELECT * FROM service_attestations WHERE service = ? ORDER BY timestamp DESC LIMIT ?",
        opts.service, limit,
      )];
      return rows.map(r => this.rowToAttestation(r));
    }
    if (opts.after) {
      const rows = [...this.sql.exec(
        "SELECT * FROM service_attestations WHERE timestamp > ? ORDER BY timestamp ASC LIMIT ?",
        opts.after, limit,
      )];
      return rows.map(r => this.rowToAttestation(r));
    }
    const rows = [...this.sql.exec(
      "SELECT * FROM service_attestations ORDER BY timestamp DESC LIMIT ?", limit,
    )];
    return rows.map(r => this.rowToAttestation(r));
  }

  /** Walk the hash chain backwards from a given attestation. */
  getChain(attestation_id: string, depth: number = 10): ServiceAttestation[] {
    const chain: ServiceAttestation[] = [];
    let current = attestation_id;
    for (let i = 0; i < depth; i++) {
      const att = this.getAttestation(current);
      if (!att) break;
      chain.push(att);
      if (att.prev_hash === "genesis") break;
      current = att.prev_hash;
    }
    return chain;
  }

  /** Get challenges for an attestation. */
  getChallenges(attestation_id: string): ChallengeResult[] {
    const rows = [...this.sql.exec(
      "SELECT * FROM attestation_challenges WHERE attestation_id = ? ORDER BY timestamp DESC",
      attestation_id,
    )];
    return rows.map(r => ({
      attestation_id: r.attestation_id,
      challenger_node: r.challenger_node,
      original_output_hash: r.original_output_hash,
      challenge_output_hash: r.challenge_output_hash,
      match: r.match === 1,
      timestamp: r.timestamp,
    }));
  }

  /** Summary stats. */
  getStats(): { total: number; unchallenged: number; verified: number; disputed: number } {
    const rows = [...this.sql.exec(
      `SELECT challenge_status, COUNT(*) as cnt FROM service_attestations GROUP BY challenge_status`
    )];
    const stats = { total: 0, unchallenged: 0, verified: 0, disputed: 0 };
    for (const r of rows) {
      const key = r.challenge_status as keyof typeof stats;
      if (key in stats) stats[key] = r.cnt;
      stats.total += r.cnt;
    }
    return stats;
  }

  private rowToAttestation(r: any): ServiceAttestation {
    return {
      attestation_id: r.attestation_id,
      prev_hash: r.prev_hash,
      service: r.service,
      model: r.model,
      input_hash: r.input_hash,
      output_hash: r.output_hash,
      output_size: r.output_size || 0,
      pre_commitment: r.pre_commitment,
      nonce: r.nonce,
      node_pubkey: r.node_pubkey,
      node_signature: r.node_signature,
      timestamp: r.timestamp,
      receipt_id: r.receipt_id,
      challenge_status: r.challenge_status || "unchallenged",
    };
  }
}
