// Sparse Merkle Tree with Poseidon2 hashing (matches Noir incremental circuit).
//
// Maintains a persistent depth-20 tree where only non-default nodes are stored.
// Provides sibling paths for Merkle inclusion/update proofs.
//
// Storage: JSON file on disk for persistence across prover restarts.

import { Barretenberg } from "@aztec/bb.js";
import { readFileSync, writeFileSync, existsSync } from "fs";

const TREE_DEPTH = 20;

// --- Poseidon2 Hashing (via bb.js) ---

let _bb: Barretenberg | null = null;

async function getBb(): Promise<Barretenberg> {
  if (!_bb) _bb = await Barretenberg.new();
  return _bb;
}

function fieldToBytes(field: string | bigint): Uint8Array {
  const n = typeof field === "string" ? BigInt(field) : field;
  const hex = n.toString(16).padStart(64, "0");
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function poseidon2Hash(inputs: (string | bigint)[]): Promise<string> {
  const bb = await getBb();
  const fieldInputs = inputs.map(fieldToBytes);
  const { hash } = await bb.poseidon2Hash({ inputs: fieldInputs });
  return bytesToHex(hash);
}

async function poseidon2LeafHash(key: string, value: string): Promise<string> {
  return poseidon2Hash(["1", key, value]);
}

async function poseidon2NodeHash(left: string, right: string): Promise<string> {
  return poseidon2Hash(["2", left, right]);
}

async function poseidon2EmptyHash(): Promise<string> {
  return poseidon2Hash(["0"]);
}

// --- Sparse Merkle Tree ---

interface TreeState {
  root: string;
  // Nodes stored as { "level:index": hash }. Only non-default nodes stored.
  nodes: Record<string, string>;
  // Leaf values stored as { keyHex: valueHex }
  leaves: Record<string, string>;
}

export class SparseMerkleTree {
  private nodes: Map<string, string> = new Map();
  private leaves: Map<string, string> = new Map();
  private root: string = "";
  private defaultHashes: string[] = []; // defaultHashes[i] = default hash at level i
  private initialized = false;
  private persistPath: string | null;

  constructor(persistPath?: string) {
    this.persistPath = persistPath ?? null;
  }

  /** Initialize the tree. Must be called before any operations. */
  async init(): Promise<void> {
    if (this.initialized) return;

    // Compute default hashes for each level (empty subtree roots)
    const emptyLeaf = await poseidon2EmptyHash();
    this.defaultHashes = new Array(TREE_DEPTH + 1);
    this.defaultHashes[0] = emptyLeaf;
    for (let i = 1; i <= TREE_DEPTH; i++) {
      this.defaultHashes[i] = await poseidon2NodeHash(
        this.defaultHashes[i - 1],
        this.defaultHashes[i - 1],
      );
    }

    // Try to load from disk
    if (this.persistPath && existsSync(this.persistPath)) {
      const state: TreeState = JSON.parse(readFileSync(this.persistPath, "utf-8"));
      this.root = state.root;
      this.nodes = new Map(Object.entries(state.nodes));
      this.leaves = new Map(Object.entries(state.leaves));
      console.log(`Sparse Merkle tree loaded: ${this.leaves.size} leaves, root=${this.root.substring(0, 18)}...`);
    } else {
      // Empty tree: root is the default hash at the top level
      this.root = this.defaultHashes[TREE_DEPTH];
      console.log(`Sparse Merkle tree initialized (empty): root=${this.root.substring(0, 18)}...`);
    }

    this.initialized = true;
  }

  /** Save tree state to disk. */
  save(): void {
    if (!this.persistPath) return;
    const state: TreeState = {
      root: this.root,
      nodes: Object.fromEntries(this.nodes),
      leaves: Object.fromEntries(this.leaves),
    };
    writeFileSync(this.persistPath, JSON.stringify(state));
  }

  /** Get current root. */
  getRoot(): string {
    return this.root;
  }

  /** Get the number of non-empty leaves. */
  get size(): number {
    return this.leaves.size;
  }

  /** Get the value for a key, or "0" if not set. */
  getValue(keyHex: string): string {
    return this.leaves.get(keyHex) ?? "0";
  }

  /**
   * Get the key bits (little-endian) for path traversal.
   * The circuit uses Field.to_le_bits(), so we match that.
   */
  private keyToBits(keyHex: string): number[] {
    const n = BigInt(keyHex);
    const bits: number[] = [];
    for (let i = 0; i < TREE_DEPTH; i++) {
      bits.push(Number((n >> BigInt(i)) & 1n));
    }
    return bits;
  }

  /** Get the node hash at a given level and index, or the default hash for that level. */
  private getNode(level: number, index: bigint): string {
    const key = `${level}:${index}`;
    return this.nodes.get(key) ?? this.defaultHashes[level];
  }

  /** Set a node hash at a given level and index. */
  private setNode(level: number, index: bigint, hash: string): void {
    const key = `${level}:${index}`;
    if (hash === this.defaultHashes[level]) {
      this.nodes.delete(key); // Don't store defaults
    } else {
      this.nodes.set(key, hash);
    }
  }

  /**
   * Get sibling path for a key. Returns array of TREE_DEPTH sibling hashes.
   * siblings[i] is the sibling at level i (0 = leaf level).
   *
   * Tree indexing: at level i, a key's node index is (key >> i).
   * Its sibling is at index (key >> i) XOR 1.
   */
  getSiblings(keyHex: string): string[] {
    const keyVal = BigInt(keyHex) & ((1n << BigInt(TREE_DEPTH)) - 1n);
    const siblings: string[] = new Array(TREE_DEPTH);
    for (let level = 0; level < TREE_DEPTH; level++) {
      const posAtLevel = keyVal >> BigInt(level);
      const sibPos = posAtLevel ^ 1n;
      siblings[level] = this.getNode(level, sibPos);
    }
    return siblings;
  }

  /**
   * Update a key-value pair in the tree and recompute the root.
   * Returns the sibling path BEFORE the update (for the circuit witness).
   */
  async update(keyHex: string, newValueHex: string, isDelete: boolean): Promise<{
    oldValue: string;
    siblings: string[];
  }> {
    await this.init();

    const oldValue = this.getValue(keyHex);
    const siblings = this.getSiblings(keyHex);

    // Compute new leaf hash
    const emptyLeaf = this.defaultHashes[0];
    const newLeaf = isDelete ? emptyLeaf : await poseidon2LeafHash(keyHex, newValueHex);

    // Update leaf storage
    if (isDelete) {
      this.leaves.delete(keyHex);
    } else {
      this.leaves.set(keyHex, newValueHex);
    }

    // Set leaf node and recompute path to root
    const keyVal = BigInt(keyHex) & ((1n << BigInt(TREE_DEPTH)) - 1n);
    this.setNode(0, keyVal, newLeaf);

    let currentHash = newLeaf;
    const bits = this.keyToBits(keyHex);
    for (let level = 0; level < TREE_DEPTH; level++) {
      const posAtLevel = keyVal >> BigInt(level);
      const parentPos = posAtLevel >> 1n;
      const sibHash = siblings[level];

      let parentHash: string;
      if (bits[level] === 0) {
        parentHash = await poseidon2NodeHash(currentHash, sibHash);
      } else {
        parentHash = await poseidon2NodeHash(sibHash, currentHash);
      }

      this.setNode(level + 1, parentPos, parentHash);
      currentHash = parentHash;
    }

    this.root = currentHash;
    return { oldValue, siblings };
  }

  /**
   * Process a batch of mutations sequentially. Each mutation gets its sibling
   * path from the current tree state (after all prior mutations in the batch).
   * Returns the data needed for the circuit witness.
   */
  async applyMutations(mutations: { keyHex: string; newValueHex: string; isDelete: boolean }[]): Promise<{
    updates: { key: string; oldValue: string; newValue: string; siblings: string[]; isDelete: boolean }[];
    prevRoot: string;
    newRoot: string;
  }> {
    await this.init();
    const prevRoot = this.root;
    const updates: { key: string; oldValue: string; newValue: string; siblings: string[]; isDelete: boolean }[] = [];

    for (const mut of mutations) {
      const { oldValue, siblings } = await this.update(mut.keyHex, mut.newValueHex, mut.isDelete);
      updates.push({
        key: mut.keyHex,
        oldValue,
        newValue: mut.newValueHex,
        siblings,
        isDelete: mut.isDelete,
      });
    }

    this.save();
    return { updates, prevRoot, newRoot: this.root };
  }
}

/** Clean up the shared Barretenberg instance. */
export async function destroySmtBb(): Promise<void> {
  if (_bb) {
    await _bb.destroy();
    _bb = null;
  }
}
