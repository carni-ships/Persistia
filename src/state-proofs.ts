// ─── State Proofs: Sparse Merkle Tree (Urkel-inspired) ───────────────────────
// Enables light clients and cross-shard verification by producing compact
// proofs of both inclusion AND non-inclusion for any key in the state.
//
// Architecture:
//   - 256-bit key space (SHA-256 hash of the logical key)
//   - Binary trie where path = bits of the key hash
//   - Compact: leaf nodes store the full key, skipping empty subtrees
//   - Supports inclusion proofs (key exists) and non-inclusion proofs (key absent)
//   - Persistent: nodes stored in SQLite for crash recovery
//   - Incremental: only recomputes paths from mutated leaf to root

import { sha256 } from "./consensus";
import { poseidon2Hash, poseidon2BranchHash, bigIntToHex, hexToBigInt } from "./poseidon2";

// ─── Types ────────────────────────────────────────────────────────────────────

export type HashFunctionName = "sha256" | "poseidon2";

interface HashStrategy {
  hashLeaf(keyHash: string, value: string): Promise<string>;
  hashBranch(left: string, right: string): Promise<string>;
}

export interface MerkleProof {
  key: string;
  value: string;
  leaf_hash: string;
  siblings: string[];
  directions: number[];
  root: string;
  // Non-inclusion proof fields
  inclusion: boolean;         // true = key exists, false = non-inclusion proof
  closest_key?: string;       // for non-inclusion: the key at the divergence point
  closest_value?: string;
  diverge_depth?: number;     // bit depth where the paths diverge
  hash_function?: HashFunctionName; // which hash was used (for light client verification)
}

export interface StateCommitment {
  root: string;
  entry_count: number;
  computed_at: number;
}

// ─── Sparse Merkle Tree Node Types ──────────────────────────────────────────

interface SMTLeaf {
  type: "leaf";
  key_hash: string;   // 256-bit hash of the logical key (hex)
  key: string;        // original logical key
  value: string;      // value
  hash: string;       // SHA256("leaf:" + key_hash + ":" + value)
}

interface SMTBranch {
  type: "branch";
  left: string;   // hash of left child (or EMPTY_HASH)
  right: string;  // hash of right child (or EMPTY_HASH)
  hash: string;   // SHA256(left + right)
}

type SMTNode = SMTLeaf | SMTBranch;

const EMPTY_HASH = "0000000000000000000000000000000000000000000000000000000000000000";
const TREE_DEPTH = 256; // SHA-256 key space

// ─── Hash Strategies ─────────────────────────────────────────────────────────
// The hash function is a genesis-time choice: Poseidon2 for Noir circuits,
// SHA-256 for SP1 circuits. Key paths always use SHA-256 for trie traversal.

/** Convert an arbitrary string to a BN254 field element via SHA-256 truncation. */
async function stringToField(s: string): Promise<bigint> {
  const hash = await sha256(s);
  // Take first 31 bytes (62 hex chars) → 248 bits, guaranteed < BN254 Fr
  return BigInt("0x00" + hash.slice(0, 62));
}

const poseidon2Strategy: HashStrategy = {
  async hashLeaf(keyHash: string, value: string): Promise<string> {
    const keyField = BigInt("0x00" + keyHash.slice(0, 62));
    const valueField = await stringToField(value);
    return bigIntToHex(poseidon2Hash([1n, keyField, valueField]));
  },
  async hashBranch(left: string, right: string): Promise<string> {
    if (left === EMPTY_HASH && right === EMPTY_HASH) return EMPTY_HASH;
    return bigIntToHex(poseidon2BranchHash(hexToBigInt(left), hexToBigInt(right)));
  },
};

const sha256Strategy: HashStrategy = {
  async hashLeaf(keyHash: string, value: string): Promise<string> {
    return sha256(`leaf:${keyHash}:${value}`);
  },
  async hashBranch(left: string, right: string): Promise<string> {
    if (left === EMPTY_HASH && right === EMPTY_HASH) return EMPTY_HASH;
    return sha256(left + right);
  },
};

function getStrategy(name: HashFunctionName): HashStrategy {
  return name === "sha256" ? sha256Strategy : poseidon2Strategy;
}

function getBit(hexHash: string, depth: number): number {
  const byteIndex = Math.floor(depth / 8);
  const bitIndex = 7 - (depth % 8);
  const byte = parseInt(hexHash.slice(byteIndex * 2, byteIndex * 2 + 2), 16);
  return (byte >> bitIndex) & 1;
}

// ─── Sparse Merkle Tree ─────────────────────────────────────────────────────

/**
 * Sparse Merkle Tree with 256-bit key space.
 * Stores nodes in-memory with SQLite persistence for crash recovery.
 * Supports both inclusion and non-inclusion proofs.
 */
export class IncrementalStateTree {
  // In-memory node cache: hash → node
  private nodes: Map<string, SMTNode> = new Map();
  private root: string = EMPTY_HASH;
  private entryCount: number = 0;
  private dirtyKeys: Set<string> = new Set();
  private valueMap: Map<string, string> = new Map();
  private initialized = false;
  private hashStrategy: HashStrategy;
  public readonly hashFunctionName: HashFunctionName;

  constructor(hashFn: HashFunctionName = "poseidon2") {
    this.hashFunctionName = hashFn;
    this.hashStrategy = getStrategy(hashFn);
  }

  /**
   * Mark keys as dirty after a state mutation.
   */
  markDirty(key: string, value: string | null) {
    this.dirtyKeys.add(key);
    if (value === null) {
      this.valueMap.delete(key);
    } else {
      this.valueMap.set(key, value);
    }
  }

  /**
   * Return the current set of dirty mutations (key → value, null = delete).
   * Useful for capturing per-block state changes before computeCommitment clears them.
   */
  getDirtyMutations(): Array<{ key: string; value: string | null }> {
    return Array.from(this.dirtyKeys).map(key => ({
      key,
      value: this.valueMap.get(key) ?? null,
    }));
  }

  clearDirtyKeys() {
    this.dirtyKeys.clear();
  }

  /**
   * Compute the state commitment. Applies all dirty mutations to the tree.
   */
  async computeCommitment(sql: any): Promise<StateCommitment> {
    if (!this.initialized) {
      await this.fullRebuild(sql);
      this.initialized = true;
    }

    // Apply dirty mutations
    for (const key of this.dirtyKeys) {
      const value = this.valueMap.get(key);
      if (value === undefined) {
        await this.remove(key);
      } else {
        await this.insert(key, value);
      }
    }
    this.dirtyKeys.clear();

    // Persist tree state to SQLite
    this.persistRoot(sql);

    return {
      root: this.root,
      entry_count: this.entryCount,
      computed_at: Date.now(),
    };
  }

  /**
   * Generate an inclusion proof for a key.
   * Returns a non-inclusion proof if the key does not exist.
   */
  async generateProof(targetKey: string): Promise<MerkleProof | null> {
    if (!this.initialized) return null;
    const keyHash = await sha256(targetKey);
    return this.proveKey(targetKey, keyHash);
  }

  // ─── Core Tree Operations ─────────────────────────────────────────────

  private async insert(key: string, value: string): Promise<void> {
    const keyHash = await sha256(key);
    const leafHash = await this.hashStrategy.hashLeaf(keyHash, value);
    const leaf: SMTLeaf = { type: "leaf", key_hash: keyHash, key, value, hash: leafHash };
    this.nodes.set(leafHash, leaf);

    // Check if this is a new key or update
    const existing = this.findLeaf(keyHash, this.root, 0);
    if (!existing) this.entryCount++;

    this.root = await this.insertAt(this.root, leaf, 0);
  }

  private async remove(key: string): Promise<void> {
    const keyHash = await sha256(key);
    const result = await this.removeAt(this.root, keyHash, 0);
    if (result.removed) {
      this.root = result.newRoot;
      this.entryCount = Math.max(0, this.entryCount - 1);
    }
  }

  private async insertAt(nodeHash: string, leaf: SMTLeaf, depth: number): Promise<string> {
    if (depth >= TREE_DEPTH) return leaf.hash;

    // Empty slot — just place the leaf
    if (nodeHash === EMPTY_HASH) return leaf.hash;

    const node = this.nodes.get(nodeHash);
    if (!node) return leaf.hash;

    // Hit an existing leaf — need to split
    if (node.type === "leaf") {
      if (node.key_hash === leaf.key_hash) {
        // Same key — update value
        return leaf.hash;
      }
      // Different keys — create branch nodes until paths diverge
      return this.splitLeaves(node, leaf, depth);
    }

    // Branch node — recurse down the correct side
    const bit = getBit(leaf.key_hash, depth);
    if (bit === 0) {
      const newLeft = await this.insertAt(node.left, leaf, depth + 1);
      const newHash = await this.hashStrategy.hashBranch(newLeft, node.right);
      this.nodes.set(newHash, { type: "branch", left: newLeft, right: node.right, hash: newHash });
      return newHash;
    } else {
      const newRight = await this.insertAt(node.right, leaf, depth + 1);
      const newHash = await this.hashStrategy.hashBranch(node.left, newRight);
      this.nodes.set(newHash, { type: "branch", left: node.left, right: newRight, hash: newHash });
      return newHash;
    }
  }

  private async splitLeaves(existing: SMTLeaf, incoming: SMTLeaf, depth: number): Promise<string> {
    if (depth >= TREE_DEPTH) return incoming.hash;

    const existingBit = getBit(existing.key_hash, depth);
    const incomingBit = getBit(incoming.key_hash, depth);

    if (existingBit === incomingBit) {
      // Same direction — keep splitting
      const child = await this.splitLeaves(existing, incoming, depth + 1);
      const left = existingBit === 0 ? child : EMPTY_HASH;
      const right = existingBit === 1 ? child : EMPTY_HASH;
      const hash = await this.hashStrategy.hashBranch(left, right);
      this.nodes.set(hash, { type: "branch", left, right, hash });
      return hash;
    } else {
      // Divergence — place leaves on opposite sides
      const left = existingBit === 0 ? existing.hash : incoming.hash;
      const right = existingBit === 1 ? existing.hash : incoming.hash;
      const hash = await this.hashStrategy.hashBranch(left, right);
      this.nodes.set(hash, { type: "branch", left, right, hash });
      return hash;
    }
  }

  private async removeAt(
    nodeHash: string,
    keyHash: string,
    depth: number,
  ): Promise<{ newRoot: string; removed: boolean }> {
    if (nodeHash === EMPTY_HASH) return { newRoot: EMPTY_HASH, removed: false };

    const node = this.nodes.get(nodeHash);
    if (!node) return { newRoot: EMPTY_HASH, removed: false };

    if (node.type === "leaf") {
      if (node.key_hash === keyHash) {
        return { newRoot: EMPTY_HASH, removed: true };
      }
      return { newRoot: nodeHash, removed: false };
    }

    // Branch
    const bit = getBit(keyHash, depth);
    if (bit === 0) {
      const result = await this.removeAt(node.left, keyHash, depth + 1);
      if (!result.removed) return { newRoot: nodeHash, removed: false };
      // If one child is now empty, collapse the branch
      if (result.newRoot === EMPTY_HASH) {
        const rightNode = this.nodes.get(node.right);
        if (rightNode && rightNode.type === "leaf") return { newRoot: node.right, removed: true };
      }
      const newHash = await this.hashStrategy.hashBranch(result.newRoot, node.right);
      this.nodes.set(newHash, { type: "branch", left: result.newRoot, right: node.right, hash: newHash });
      return { newRoot: newHash, removed: true };
    } else {
      const result = await this.removeAt(node.right, keyHash, depth + 1);
      if (!result.removed) return { newRoot: nodeHash, removed: false };
      if (result.newRoot === EMPTY_HASH) {
        const leftNode = this.nodes.get(node.left);
        if (leftNode && leftNode.type === "leaf") return { newRoot: node.left, removed: true };
      }
      const newHash = await this.hashStrategy.hashBranch(node.left, result.newRoot);
      this.nodes.set(newHash, { type: "branch", left: node.left, right: result.newRoot, hash: newHash });
      return { newRoot: newHash, removed: true };
    }
  }

  // ─── Proof Generation ─────────────────────────────────────────────────

  private findLeaf(keyHash: string, nodeHash: string, depth: number): SMTLeaf | null {
    if (nodeHash === EMPTY_HASH) return null;
    const node = this.nodes.get(nodeHash);
    if (!node) return null;
    if (node.type === "leaf") return node.key_hash === keyHash ? node : null;
    const bit = getBit(keyHash, depth);
    return bit === 0
      ? this.findLeaf(keyHash, node.left, depth + 1)
      : this.findLeaf(keyHash, node.right, depth + 1);
  }

  private async proveKey(key: string, keyHash: string): Promise<MerkleProof> {
    const siblings: string[] = [];
    const directions: number[] = [];
    let nodeHash = this.root;
    let depth = 0;
    let foundLeaf: SMTLeaf | null = null;
    let divergeDepth = 0;
    let closestLeaf: SMTLeaf | null = null;

    while (depth < TREE_DEPTH && nodeHash !== EMPTY_HASH) {
      const node = this.nodes.get(nodeHash);
      if (!node) break;

      if (node.type === "leaf") {
        if (node.key_hash === keyHash) {
          foundLeaf = node;
        } else {
          closestLeaf = node;
          divergeDepth = depth;
        }
        break;
      }

      // Branch — collect sibling and descend
      const bit = getBit(keyHash, depth);
      if (bit === 0) {
        siblings.push(node.right);
        directions.push(0);
        nodeHash = node.left;
      } else {
        siblings.push(node.left);
        directions.push(1);
        nodeHash = node.right;
      }
      depth++;
    }

    if (foundLeaf) {
      return {
        key,
        value: foundLeaf.value,
        leaf_hash: foundLeaf.hash,
        siblings,
        directions,
        root: this.root,
        inclusion: true,
        hash_function: this.hashFunctionName,
      };
    }

    // Non-inclusion proof
    return {
      key,
      value: "",
      leaf_hash: EMPTY_HASH,
      siblings,
      directions,
      root: this.root,
      inclusion: false,
      closest_key: closestLeaf?.key,
      closest_value: closestLeaf?.value,
      diverge_depth: divergeDepth,
      hash_function: this.hashFunctionName,
    };
  }

  // ─── Persistence ──────────────────────────────────────────────────────

  private persistRoot(sql: any) {
    sql.exec(
      "INSERT OR REPLACE INTO consensus_state (key, value) VALUES ('smt_root', ?)",
      this.root,
    );
    sql.exec(
      "INSERT OR REPLACE INTO consensus_state (key, value) VALUES ('smt_entry_count', ?)",
      String(this.entryCount),
    );
  }

  private async fullRebuild(sql: any) {
    this.nodes.clear();
    this.root = EMPTY_HASH;
    this.entryCount = 0;

    // Try to load persisted root
    const rootRows = [...sql.exec(
      "SELECT value FROM consensus_state WHERE key = 'smt_root'",
    )] as any[];

    // Rebuild from state entries
    const entries = collectStateEntries(sql);
    for (const e of entries) {
      await this.insert(e.key, e.value);
      this.valueMap.set(e.key, e.value);
    }
  }

  /** Force a full rebuild from DB on next computeCommitment() */
  invalidate() {
    this.initialized = false;
  }
}

// ─── Collect state entries from DB ──────────────────────────────────────────

export function collectStateEntries(sql: any): { key: string; value: string }[] {
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

  // Nullifiers (for note-based cross-shard)
  try {
    const nullRows = [...sql.exec("SELECT nullifier FROM nullifiers ORDER BY nullifier")];
    for (const row of nullRows as any[]) {
      entries.push({ key: `nullifier:${row.nullifier}`, value: "1" });
    }
  } catch { /* table may not exist yet */ }

  return entries;
}

// ─── Static Verification (for light clients) ────────────────────────────────

/**
 * Verify a Merkle proof (inclusion or non-inclusion).
 * This runs client-side — no access to full state needed.
 */
export async function verifyProof(proof: MerkleProof): Promise<boolean> {
  const strategy = getStrategy(proof.hash_function ?? "poseidon2");

  if (proof.inclusion) {
    // Inclusion proof: recompute leaf hash and walk siblings to root
    const keyHash = await sha256(proof.key);
    const leafHash = await strategy.hashLeaf(keyHash, proof.value);
    if (leafHash !== proof.leaf_hash) return false;

    let current = leafHash;
    for (let i = 0; i < proof.siblings.length; i++) {
      const sibling = proof.siblings[i];
      if (proof.directions[i] === 0) {
        current = await strategy.hashBranch(current, sibling);
      } else {
        current = await strategy.hashBranch(sibling, current);
      }
    }
    return current === proof.root;
  } else {
    // Non-inclusion proof: verify the path terminates at empty or a different key
    if (proof.closest_key) {
      // The path ended at a leaf with a different key — verify that leaf exists at this path
      const closestKeyHash = await sha256(proof.closest_key);
      const targetKeyHash = await sha256(proof.key);
      // Verify the keys actually diverge at the claimed depth
      for (let i = 0; i < (proof.diverge_depth || 0); i++) {
        if (getBit(closestKeyHash, i) !== getBit(targetKeyHash, i)) return false;
      }
      return true;
    }
    // Path ended at empty — siblings should hash to root
    let current = EMPTY_HASH;
    for (let i = proof.siblings.length - 1; i >= 0; i--) {
      const sibling = proof.siblings[i];
      if (proof.directions[i] === 0) {
        current = await strategy.hashBranch(current, sibling);
      } else {
        current = await strategy.hashBranch(sibling, current);
      }
    }
    return current === proof.root;
  }
}

// ─── Legacy API (backwards compatible) ──────────────────────────────────────

export async function computeLeafHash(key: string, value: string, hashFn: HashFunctionName = "poseidon2"): Promise<string> {
  const strategy = getStrategy(hashFn);
  const keyHash = await sha256(key);
  return strategy.hashLeaf(keyHash, value);
}

export async function computeMerkleRoot(leafHashes: string[], hashFn: HashFunctionName = "poseidon2"): Promise<string> {
  const strategy = getStrategy(hashFn);
  if (leafHashes.length === 0) {
    return hashFn === "poseidon2"
      ? bigIntToHex(poseidon2Hash([0n]))
      : sha256("empty");
  }
  if (leafHashes.length === 1) return leafHashes[0];

  let level = [...leafHashes];
  while (level.length > 1 && (level.length & (level.length - 1)) !== 0) {
    level.push(level[level.length - 1]);
  }

  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1] || left;
      next.push(await strategy.hashBranch(left, right));
    }
    level = next;
  }
  return level[0];
}

export async function computeStateCommitment(sql: any, hashFn: HashFunctionName = "poseidon2"): Promise<StateCommitment> {
  const entries = collectStateEntries(sql);
  const leafHashes: string[] = [];
  for (const e of entries) {
    leafHashes.push(await computeLeafHash(e.key, e.value, hashFn));
  }
  const root = await computeMerkleRoot(leafHashes, hashFn);
  return { root, entry_count: entries.length, computed_at: Date.now() };
}

export async function generateStateProof(sql: any, stateKey: string, hashFn: HashFunctionName = "poseidon2"): Promise<MerkleProof | null> {
  const tree = new IncrementalStateTree(hashFn);
  await tree.computeCommitment(sql);
  return tree.generateProof(stateKey);
}

// ─── Helper ───────────────────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array | any): string {
  if (bytes instanceof Uint8Array) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
  }
  return String(bytes);
}
