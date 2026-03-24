// ─── Node Identity ────────────────────────────────────────────────────────────
// Manages the node's Ed25519 keypair (distinct from player keys).
// Used to sign DAG vertices and authenticate with peers.

import { sha256 } from "./consensus";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function bytesToB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface NodeIdentity {
  pubkey: string;      // base64 raw Ed25519 public key
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  url: string;
}

// ─── Key Management ───────────────────────────────────────────────────────────

/**
 * Load existing node identity from SQLite, or generate a new one.
 */
export async function loadOrCreateNodeIdentity(
  sql: any,
  nodeUrl: string,
): Promise<NodeIdentity> {
  const rows = [...sql.exec("SELECT pubkey, privkey_encrypted, node_url FROM node_identity LIMIT 1")];

  if (rows.length > 0) {
    const row = rows[0] as any;
    const pubBytes = b64ToBytes(row.pubkey);
    const privBytes = b64ToBytes(row.privkey_encrypted);

    const publicKey = await crypto.subtle.importKey("raw", pubBytes, "Ed25519", true, ["verify"]);
    const privateKey = await crypto.subtle.importKey("pkcs8", privBytes, "Ed25519", true, ["sign"]);

    // Update URL if changed
    if (row.node_url !== nodeUrl && nodeUrl) {
      sql.exec("UPDATE node_identity SET node_url = ?", nodeUrl);
    }

    return { pubkey: row.pubkey, privateKey, publicKey, url: nodeUrl || row.node_url };
  }

  // Generate new keypair
  const keyPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const pubRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  const privPkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

  const pubkeyB64 = bytesToB64(new Uint8Array(pubRaw));
  const privB64 = bytesToB64(new Uint8Array(privPkcs8));

  sql.exec(
    "INSERT INTO node_identity (pubkey, privkey_encrypted, node_url, created_at) VALUES (?, ?, ?, ?)",
    pubkeyB64, privB64, nodeUrl, Date.now(),
  );

  return {
    pubkey: pubkeyB64,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    url: nodeUrl,
  };
}

// ─── Signing ──────────────────────────────────────────────────────────────────

/**
 * Sign arbitrary data with the node's private key.
 */
export async function signData(identity: NodeIdentity, data: string): Promise<string> {
  const encoded = new TextEncoder().encode(data);
  const sig = await crypto.subtle.sign("Ed25519", identity.privateKey, encoded);
  return bytesToB64(new Uint8Array(sig));
}

/**
 * Sign a DAG vertex. The signature covers the canonical representation.
 */
export async function signVertex(
  identity: NodeIdentity,
  vertex: { author: string; round: number; event_hashes: string[]; refs: string[]; timestamp: number },
): Promise<string> {
  const canonical = JSON.stringify({
    author: vertex.author,
    round: vertex.round,
    event_hashes: [...vertex.event_hashes].sort(),
    refs: [...vertex.refs].sort(),
    timestamp: vertex.timestamp,
  });
  return signData(identity, canonical);
}

// ─── Verification ─────────────────────────────────────────────────────────────

/**
 * Verify a signature from any node given its public key.
 */
export async function verifyNodeSignature(
  pubkeyB64: string,
  signature: string,
  data: string,
): Promise<boolean> {
  try {
    const pubBytes = b64ToBytes(pubkeyB64);
    const sigBytes = b64ToBytes(signature);
    const dataBytes = new TextEncoder().encode(data);
    const key = await crypto.subtle.importKey("raw", pubBytes, "Ed25519", false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, sigBytes, dataBytes);
  } catch {
    return false;
  }
}

/**
 * Verify a DAG vertex's signature.
 */
export async function verifyVertexSignature(vertex: {
  author: string;
  round: number;
  event_hashes: string[];
  refs: string[];
  timestamp: number;
  signature: string;
}): Promise<boolean> {
  const canonical = JSON.stringify({
    author: vertex.author,
    round: vertex.round,
    event_hashes: [...vertex.event_hashes].sort(),
    refs: [...vertex.refs].sort(),
    timestamp: vertex.timestamp,
  });
  return verifyNodeSignature(vertex.author, vertex.signature, canonical);
}
