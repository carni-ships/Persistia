// Incremental circuit witness generation for Persistia.
//
// Shared logic (Schnorr signing, Poseidon2, full-tree witness, test witness)
// is imported from zkMetal SDK. This file only contains incremental-circuit-
// specific code: sparse Merkle tree witness building with sibling paths.

import { createHash } from "crypto";

// Re-export shared types and functions from zkMetal SDK
export {
  buildMutationWitness,
  buildSingleBlockWitness,
  buildTestWitness,
  computePoseidon2MerkleRoot,
  emptyMutation,
  schnorrSign,
  destroyBb,
  setMaxMutations,
  getMaxMutations,
} from "zkmetal/witness";
export type { CircuitWitness } from "zkmetal/witness";

// =============================================================================
// Incremental Circuit Witness (sparse Merkle tree with sibling paths)
// =============================================================================

const MAX_VALIDATORS = 4;
const INCREMENTAL_MAX_MUTATIONS = 64;
const TREE_DEPTH = 20;
const VK_SIZE = 115;
const PROOF_SIZE = 449;
const PUBLIC_INPUTS_SIZE = 8;

// --- Types ---

interface NodeSignatureWitness {
  pubkey_x: string;
  pubkey_y: string;
  signature: number[];
  msg: number[];
  enabled: boolean;
}

interface StateMutationWitness {
  key: string;
  new_value: string;
  is_delete: boolean;
  enabled: boolean;
}

interface MerkleUpdateWitness {
  key: string;
  old_value: string;
  new_value: string;
  siblings: string[];   // [Field; TREE_DEPTH]
  is_delete: boolean;
  enabled: boolean;
}

export interface IncrementalCircuitWitness {
  updates: MerkleUpdateWitness[];
  mutation_count: number;
  signatures: NodeSignatureWitness[];
  sig_count: number;
  prev_proven_blocks: number;
  prev_genesis_root: string;
  prev_proof: string[];
  prev_vk: string[];
  prev_key_hash: string;
  prev_public_inputs: string[];
  prev_state_root: string;
  new_state_root: string;
  block_number: number;
  active_nodes: number;
}

// --- Helpers ---

function hexToBytes(hex: string): number[] {
  const bytes: number[] = [];
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  for (let i = 0; i < clean.length; i += 2) {
    bytes.push(parseInt(clean.substring(i, i + 2), 16));
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function sha256Hash(data: Buffer | Uint8Array): number[] {
  return Array.from(createHash("sha256").update(data).digest());
}

function padArray(arr: number[], targetLen: number): number[] {
  const result = [...arr];
  while (result.length < targetLen) result.push(0);
  return result.slice(0, targetLen);
}

// --- Schnorr Signing (for incremental witness) ---
// Import from bb.js directly since we need the internal getBb/dummy sig pattern

import { Barretenberg } from "@aztec/bb.js";

let _bb: Barretenberg | null = null;

async function getBb(): Promise<Barretenberg> {
  if (!_bb) _bb = await Barretenberg.new();
  return _bb;
}

let _dummySig: NodeSignatureWitness | null = null;

async function getDummySignature(): Promise<NodeSignatureWitness> {
  if (_dummySig) return _dummySig;
  const bb = await getBb();
  const dummyKey = new Uint8Array(32);
  dummyKey[31] = 0xff;
  const dummyMsg = new Uint8Array(32);
  const { publicKey } = await bb.schnorrComputePublicKey({ privateKey: dummyKey });
  const { s, e } = await bb.schnorrConstructSignature({ message: dummyMsg, privateKey: dummyKey });
  _dummySig = {
    pubkey_x: bytesToHex(publicKey.x),
    pubkey_y: bytesToHex(publicKey.y),
    signature: [...Array.from(s), ...Array.from(e)],
    msg: Array.from(dummyMsg),
    enabled: false,
  };
  return _dummySig;
}

// --- API Types ---

interface ApiSignature {
  pubkey: string;
  signature: string;
  message: string;
  schnorr_s?: string;
  schnorr_e?: string;
  grumpkin_x?: string;
  grumpkin_y?: string;
}

interface ApiMutation {
  key: string;
  old_value?: string;
  new_value?: string;
}

interface ApiBlock {
  block_number: number;
  state_root?: string;
  mutations: ApiMutation[];
  signatures: ApiSignature[];
  active_nodes: number;
}

// --- Incremental Witness Builders ---

async function buildSignatureWitness(sig: ApiSignature): Promise<NodeSignatureWitness> {
  const msgBytes = Buffer.from(sig.message, "utf-8");
  const msgHash = sha256Hash(msgBytes);

  if (sig.grumpkin_x && sig.grumpkin_y && sig.schnorr_s && sig.schnorr_e) {
    const s = hexToBytes(sig.schnorr_s);
    const e = hexToBytes(sig.schnorr_e);
    return {
      pubkey_x: sig.grumpkin_x,
      pubkey_y: sig.grumpkin_y,
      signature: [...padArray(s, 32), ...padArray(e, 32)],
      msg: msgHash,
      enabled: true,
    };
  }

  throw new Error(
    "Node must provide Schnorr signature fields (grumpkin_x, grumpkin_y, schnorr_s, schnorr_e). " +
    "Use buildTestWitness() for testing with generated keys."
  );
}

/**
 * Build a mutation witness for the incremental circuit.
 * Key is truncated to TREE_DEPTH bits (20) so it fits as a valid tree index.
 * Value remains a full field element.
 */
export function buildIncrementalMutationWitness(mut: ApiMutation): StateMutationWitness {
  const keyHash = createHash("sha256").update(mut.key).digest();
  const keyVal = ((keyHash[0] << 12) | (keyHash[1] << 4) | (keyHash[2] >> 4)) & 0xFFFFF;
  const keyField = "0x" + keyVal.toString(16);

  const isDelete = mut.new_value == null;
  const valueField = isDelete
    ? "0"
    : "0x00" + createHash("sha256").update(mut.new_value!).digest().subarray(0, 31).toString("hex");

  return {
    key: keyField,
    new_value: valueField,
    is_delete: isDelete,
    enabled: true,
  };
}

export function emptyMerkleUpdate(): MerkleUpdateWitness {
  return {
    key: "0",
    old_value: "0",
    new_value: "0",
    siblings: new Array(TREE_DEPTH).fill("0"),
    is_delete: false,
    enabled: false,
  };
}

/**
 * Build witness for the incremental circuit.
 * Requires pre-computed Merkle updates with sibling paths from a SparseMerkleTree.
 */
export async function buildIncrementalWitness(
  block: ApiBlock,
  merkleUpdates: { key: string; oldValue: string; newValue: string; siblings: string[]; isDelete: boolean }[],
  prevRoot: string,
  newRoot: string,
  opts?: {
    prevProvenBlocks?: number;
    prevGenesisRoot?: string;
    prevProof?: string[];
    prevVk?: string[];
    prevKeyHash?: string;
    prevPublicInputs?: string[];
  },
): Promise<IncrementalCircuitWitness> {
  // Build signature witnesses
  const sigs: NodeSignatureWitness[] = [];
  for (const sig of block.signatures) {
    if (sig.grumpkin_x && sig.grumpkin_y && sig.schnorr_s && sig.schnorr_e) {
      sigs.push(await buildSignatureWitness(sig));
    }
  }
  const dummy = await getDummySignature();
  while (sigs.length < MAX_VALIDATORS) sigs.push({ ...dummy });

  // Build Merkle update witnesses
  const updates: MerkleUpdateWitness[] = merkleUpdates.map(u => ({
    key: u.key,
    old_value: u.oldValue,
    new_value: u.newValue,
    siblings: u.siblings,
    is_delete: u.isDelete,
    enabled: true,
  }));
  while (updates.length < INCREMENTAL_MAX_MUTATIONS) updates.push(emptyMerkleUpdate());

  // Use Schnorr-capable node count for quorum check — nodes without Schnorr sigs
  // can't participate in ZK verification
  const schnorrCapableCount = sigs.filter(s => s.enabled).length;

  return {
    updates: updates.slice(0, INCREMENTAL_MAX_MUTATIONS),
    mutation_count: merkleUpdates.length,
    signatures: sigs.slice(0, MAX_VALIDATORS),
    sig_count: schnorrCapableCount,
    prev_proven_blocks: opts?.prevProvenBlocks ?? 0,
    prev_genesis_root: opts?.prevGenesisRoot ?? "0",
    prev_proof: opts?.prevProof ?? new Array(PROOF_SIZE).fill("0"),
    prev_vk: opts?.prevVk ?? new Array(VK_SIZE).fill("0"),
    prev_key_hash: opts?.prevKeyHash ?? "0",
    prev_public_inputs: opts?.prevPublicInputs ?? new Array(PUBLIC_INPUTS_SIZE).fill("0"),
    prev_state_root: prevRoot,
    new_state_root: newRoot,
    block_number: block.block_number,
    active_nodes: Math.max(schnorrCapableCount, 1),
  };
}
