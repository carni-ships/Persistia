// ─── State Proofs: Merkle Proofs for Verifiable State ─────────────────────────
// Enables light clients and cross-shard verification by producing compact
// proofs that a given key-value pair exists in the ledger's state.
//
// Uses a simple SHA-256 binary Merkle tree over sorted state entries.
// Each leaf is SHA256(key || value). The root is the state commitment.

import { sha256 } from "./consensus";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface MerkleProof {
  key: string;           // the key being proved
  value: string;         // the value (hex-encoded bytes or string)
  leaf_hash: string;     // SHA256(key || value)
  siblings: string[];    // sibling hashes from leaf to root
  directions: number[];  // 0 = left, 1 = right (position of the proven leaf)
  root: string;          // expected root hash
}

export interface StateCommitment {
  root: string;
  entry_count: number;
  computed_at: number;
}

// ─── Merkle Tree ──────────────────────────────────────────────────────────────

/**
 * Compute the Merkle root of a set of leaf hashes.
 * Leaves must be sorted for deterministic results.
 */
export async function computeMerkleRoot(leafHashes: string[]): Promise<string> {
  if (leafHashes.length === 0) return sha256("empty");
  if (leafHashes.length === 1) return leafHashes[0];

  // Pad to power of 2 with duplicate of last element
  let level = [...leafHashes];
  while (level.length > 1 && (level.length & (level.length - 1)) !== 0) {
    level.push(level[level.length - 1]);
  }

  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1] || left; // handle odd count
      next.push(await sha256(left + right));
    }
    level = next;
  }

  return level[0];
}

/**
 * Compute a leaf hash from a key-value pair.
 */
export async function computeLeafHash(key: string, value: string): Promise<string> {
  return sha256(`leaf:${key}:${value}`);
}

/**
 * Generate a Merkle proof for a specific key.
 * Takes sorted leaf entries and returns the proof path from leaf to root.
 */
export async function generateProof(
  entries: { key: string; value: string }[],
  targetKey: string,
): Promise<MerkleProof | null> {
  // Sort entries by key for deterministic ordering
  const sorted = [...entries].sort((a, b) => a.key.localeCompare(b.key));

  // Find the target
  const targetIdx = sorted.findIndex(e => e.key === targetKey);
  if (targetIdx === -1) return null;

  const target = sorted[targetIdx];

  // Compute all leaf hashes
  const leafHashes: string[] = [];
  for (const e of sorted) {
    leafHashes.push(await computeLeafHash(e.key, e.value));
  }

  const leafHash = leafHashes[targetIdx];

  // Pad to power of 2
  let level = [...leafHashes];
  while (level.length > 1 && (level.length & (level.length - 1)) !== 0) {
    level.push(level[level.length - 1]);
  }

  // Build proof: collect siblings at each level
  const siblings: string[] = [];
  const directions: number[] = [];
  let idx = targetIdx;

  // Pad index tracking
  let currentLevel = [...level];
  while (currentLevel.length > 1) {
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    siblings.push(currentLevel[siblingIdx] || currentLevel[idx]);
    directions.push(idx % 2); // 0 = our node is on the left, 1 = on the right

    // Move up
    const nextLevel: string[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      const right = currentLevel[i + 1] || left;
      nextLevel.push(await sha256(left + right));
    }
    idx = Math.floor(idx / 2);
    currentLevel = nextLevel;
  }

  const root = currentLevel[0];

  return {
    key: target.key,
    value: target.value,
    leaf_hash: leafHash,
    siblings,
    directions,
    root,
  };
}

/**
 * Verify a Merkle proof against an expected root.
 * This is what a light client runs — no access to full state needed.
 */
export async function verifyProof(proof: MerkleProof): Promise<boolean> {
  // Recompute the leaf hash
  const leafHash = await computeLeafHash(proof.key, proof.value);
  if (leafHash !== proof.leaf_hash) return false;

  // Walk up the tree
  let current = leafHash;
  for (let i = 0; i < proof.siblings.length; i++) {
    const sibling = proof.siblings[i];
    if (proof.directions[i] === 0) {
      // Our node is on the left
      current = await sha256(current + sibling);
    } else {
      // Our node is on the right
      current = await sha256(sibling + current);
    }
  }

  return current === proof.root;
}

// ─── State Commitment (computed from SQLite tables) ───────────────────────────

/**
 * Compute the full state commitment from all contract_state entries + blocks + inventory.
 * Used by the node to periodically compute and store the state root.
 */
export async function computeStateCommitment(sql: any): Promise<StateCommitment> {
  const entries: { key: string; value: string }[] = [];

  // Contract state
  const contractRows = [...sql.exec("SELECT contract_address, key, value FROM contract_state ORDER BY contract_address, key")];
  for (const row of contractRows as any[]) {
    const k = `contract:${row.contract_address}:${bytesToHex(row.key)}`;
    const v = row.value instanceof Uint8Array ? bytesToHex(row.value) : String(row.value);
    entries.push({ key: k, value: v });
  }

  // Blocks (game state)
  const blockRows = [...sql.exec("SELECT x, z, block_type, placed_by FROM blocks ORDER BY x, z")];
  for (const row of blockRows as any[]) {
    entries.push({ key: `block:${row.x},${row.z}`, value: `${row.block_type}:${row.placed_by}` });
  }

  // Inventory
  const invRows = [...sql.exec("SELECT pubkey, item, count FROM inventory WHERE count > 0 ORDER BY pubkey, item")];
  for (const row of invRows as any[]) {
    entries.push({ key: `inv:${row.pubkey}:${row.item}`, value: String(row.count) });
  }

  // Contracts deployed
  const contractInfo = [...sql.exec("SELECT address, deployer, wasm_hash FROM contracts ORDER BY address")];
  for (const row of contractInfo as any[]) {
    entries.push({ key: `deployed:${row.address}`, value: `${row.deployer}:${row.wasm_hash}` });
  }

  // Compute leaf hashes and root
  const leafHashes: string[] = [];
  for (const e of entries) {
    leafHashes.push(await computeLeafHash(e.key, e.value));
  }

  const root = await computeMerkleRoot(leafHashes);

  return {
    root,
    entry_count: entries.length,
    computed_at: Date.now(),
  };
}

/**
 * Generate a proof for a specific state key.
 */
export async function generateStateProof(sql: any, stateKey: string): Promise<MerkleProof | null> {
  // Rebuild the full entry list (same as computeStateCommitment)
  const entries: { key: string; value: string }[] = [];

  const contractRows = [...sql.exec("SELECT contract_address, key, value FROM contract_state ORDER BY contract_address, key")];
  for (const row of contractRows as any[]) {
    const k = `contract:${row.contract_address}:${bytesToHex(row.key)}`;
    const v = row.value instanceof Uint8Array ? bytesToHex(row.value) : String(row.value);
    entries.push({ key: k, value: v });
  }

  const blockRows = [...sql.exec("SELECT x, z, block_type, placed_by FROM blocks ORDER BY x, z")];
  for (const row of blockRows as any[]) {
    entries.push({ key: `block:${row.x},${row.z}`, value: `${row.block_type}:${row.placed_by}` });
  }

  const invRows = [...sql.exec("SELECT pubkey, item, count FROM inventory WHERE count > 0 ORDER BY pubkey, item")];
  for (const row of invRows as any[]) {
    entries.push({ key: `inv:${row.pubkey}:${row.item}`, value: String(row.count) });
  }

  const contractInfo = [...sql.exec("SELECT address, deployer, wasm_hash FROM contracts ORDER BY address")];
  for (const row of contractInfo as any[]) {
    entries.push({ key: `deployed:${row.address}`, value: `${row.deployer}:${row.wasm_hash}` });
  }

  return generateProof(entries, stateKey);
}

// ─── Helper ───────────────────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array | any): string {
  if (bytes instanceof Uint8Array) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
  }
  return String(bytes);
}
