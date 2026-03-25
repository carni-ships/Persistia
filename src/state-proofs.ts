// ─── State Proofs: Incremental Merkle for Verifiable State ──────────────────
// Enables light clients and cross-shard verification by producing compact
// proofs that a given key-value pair exists in the ledger's state.
//
// Uses a SHA-256 binary Merkle tree over sorted state entries.
// Each leaf is SHA256("leaf:{key}:{value}"). The root is the state commitment.
//
// OPTIMIZATION: Maintains a cached leaf map and only recomputes changed leaves.
// Full rebuild from DB only happens on cold start; subsequent calls use dirty tracking.

import { sha256 } from "./consensus";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface MerkleProof {
  key: string;           // the key being proved
  value: string;         // the value (hex-encoded bytes or string)
  leaf_hash: string;     // SHA256("leaf:{key}:{value}")
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
      const right = level[i + 1] || left;
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
  const sorted = [...entries].sort((a, b) => a.key.localeCompare(b.key));

  const targetIdx = sorted.findIndex(e => e.key === targetKey);
  if (targetIdx === -1) return null;

  const target = sorted[targetIdx];

  const leafHashes: string[] = [];
  for (const e of sorted) {
    leafHashes.push(await computeLeafHash(e.key, e.value));
  }

  const leafHash = leafHashes[targetIdx];

  let level = [...leafHashes];
  while (level.length > 1 && (level.length & (level.length - 1)) !== 0) {
    level.push(level[level.length - 1]);
  }

  const siblings: string[] = [];
  const directions: number[] = [];
  let idx = targetIdx;

  let currentLevel = [...level];
  while (currentLevel.length > 1) {
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    siblings.push(currentLevel[siblingIdx] || currentLevel[idx]);
    directions.push(idx % 2);

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
  const leafHash = await computeLeafHash(proof.key, proof.value);
  if (leafHash !== proof.leaf_hash) return false;

  let current = leafHash;
  for (let i = 0; i < proof.siblings.length; i++) {
    const sibling = proof.siblings[i];
    if (proof.directions[i] === 0) {
      current = await sha256(current + sibling);
    } else {
      current = await sha256(sibling + current);
    }
  }

  return current === proof.root;
}

// ─── Incremental State Commitment ──────────────────────────────────────────

/**
 * Incremental Merkle tree for state commitment.
 * Caches leaf hashes and only recomputes when dirty keys change.
 * Full DB scan only on cold start; subsequent calls are O(dirty keys + log N).
 */
export class IncrementalStateTree {
  // key → leaf_hash
  private leafMap: Map<string, string> = new Map();
  // key → value (for proof generation without DB re-read)
  private valueMap: Map<string, string> = new Map();
  private cachedRoot: string | null = null;
  private dirtyKeys: Set<string> = new Set();
  private initialized = false;

  /**
   * Mark keys as dirty after a state mutation.
   * Call this from applyEvent() for every changed key.
   */
  markDirty(key: string, value: string | null) {
    this.dirtyKeys.add(key);
    if (value === null) {
      this.valueMap.delete(key);
    } else {
      this.valueMap.set(key, value);
    }
    this.cachedRoot = null; // invalidate
  }

  /**
   * Compute the state commitment, reusing cached leaves for unchanged keys.
   * On first call: full DB scan. On subsequent calls: only recompute dirty leaves.
   */
  async computeCommitment(sql: any): Promise<StateCommitment> {
    if (!this.initialized) {
      // Cold start: load everything from DB
      await this.fullRebuild(sql);
      this.initialized = true;
    } else if (this.dirtyKeys.size > 0) {
      // Incremental: only recompute dirty leaves
      await this.incrementalUpdate(sql);
    }

    if (!this.cachedRoot) {
      // Recompute root from sorted leaf hashes
      const sortedKeys = [...this.leafMap.keys()].sort();
      const leafHashes = sortedKeys.map(k => this.leafMap.get(k)!);
      this.cachedRoot = await computeMerkleRoot(leafHashes);
    }

    return {
      root: this.cachedRoot,
      entry_count: this.leafMap.size,
      computed_at: Date.now(),
    };
  }

  /**
   * Generate a proof for a specific key using cached state.
   */
  async generateProof(targetKey: string): Promise<MerkleProof | null> {
    if (!this.initialized) return null;

    const value = this.valueMap.get(targetKey);
    if (value === undefined) return null;

    const sortedKeys = [...this.valueMap.keys()].sort();
    const entries = sortedKeys.map(k => ({ key: k, value: this.valueMap.get(k)! }));
    return generateProof(entries, targetKey);
  }

  private async fullRebuild(sql: any) {
    this.leafMap.clear();
    this.valueMap.clear();

    const entries = collectStateEntries(sql);
    for (const e of entries) {
      const hash = await computeLeafHash(e.key, e.value);
      this.leafMap.set(e.key, hash);
      this.valueMap.set(e.key, e.value);
    }

    this.dirtyKeys.clear();
    this.cachedRoot = null;
  }

  private async incrementalUpdate(sql: any) {
    for (const key of this.dirtyKeys) {
      const value = this.valueMap.get(key);
      if (value === undefined) {
        // Deletion
        this.leafMap.delete(key);
      } else {
        // Insert or update
        const hash = await computeLeafHash(key, value);
        this.leafMap.set(key, hash);
      }
    }
    this.dirtyKeys.clear();
    this.cachedRoot = null; // force root recompute
  }

  /** Force a full rebuild from DB on next computeCommitment() */
  invalidate() {
    this.initialized = false;
    this.cachedRoot = null;
  }
}

// ─── Collect state entries from DB (used for full rebuild) ──────────────────

function collectStateEntries(sql: any): { key: string; value: string }[] {
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

  return entries;
}

// ─── Legacy API (backwards compatible) ──────────────────────────────────────

/**
 * Compute the full state commitment from all tables.
 * DEPRECATED: Use IncrementalStateTree.computeCommitment() instead.
 * Kept for backwards compatibility.
 */
export async function computeStateCommitment(sql: any): Promise<StateCommitment> {
  const entries = collectStateEntries(sql);

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
  const entries = collectStateEntries(sql);
  return generateProof(entries, stateKey);
}

// ─── Helper ───────────────────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array | any): string {
  if (bytes instanceof Uint8Array) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
  }
  return String(bytes);
}
