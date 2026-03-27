// Witness generation for the Persistia Noir circuit.
//
// Transforms Persistia node API responses into the fixed-size witness
// format that the Noir circuit expects. All arrays are padded to their
// compile-time maximums with disabled sentinel entries.

import { createHash } from "crypto";

const MAX_VALIDATORS = 16;
const MAX_MUTATIONS = 128;
const MAX_BATCH_SIZE = 8;
const MAX_MSG_LEN = 512;

// ─── Types matching the Noir circuit structs ─────────────────────────────────

interface NodeSignatureWitness {
  pubkey: number[];       // [u8; 32]
  signature: number[];    // [u8; 64]
  message: number[];      // [u8; MAX_MSG_LEN]
  msg_len: number;
  enabled: boolean;
}

interface StateMutationWitness {
  key: number[];          // [u8; 32] — SHA-256 of logical key
  new_value: number[];    // [u8; 32] — SHA-256 of value
  is_delete: boolean;
  enabled: boolean;
}

interface BlockEvidenceWitness {
  block_number: number;
  new_state_root: number[];
  mutations: StateMutationWitness[];
  mutation_count: number;
  signatures: NodeSignatureWitness[];
  sig_count: number;
  active_nodes: number;
  enabled: boolean;
}

export interface CircuitWitness {
  // Private inputs
  mutations: StateMutationWitness[];
  mutation_count: number;
  signatures: NodeSignatureWitness[];
  sig_count: number;
  batch_blocks: BlockEvidenceWitness[];
  batch_count: number;
  recursive: boolean;
  prev_proven_blocks: number;
  prev_genesis_root: number[];
  // Public inputs
  prev_state_root: number[];
  new_state_root: number[];
  block_number: number;
  active_nodes: number;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): number[] {
  const bytes: number[] = [];
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  for (let i = 0; i < clean.length; i += 2) {
    bytes.push(parseInt(clean.substring(i, i + 2), 16));
  }
  return bytes;
}

function sha256Hash(data: Buffer | Uint8Array): number[] {
  return Array.from(createHash("sha256").update(data).digest());
}

function padArray(arr: number[], targetLen: number): number[] {
  const result = [...arr];
  while (result.length < targetLen) result.push(0);
  return result.slice(0, targetLen);
}

function emptySignature(): NodeSignatureWitness {
  return {
    pubkey: new Array(32).fill(0),
    signature: new Array(64).fill(0),
    message: new Array(MAX_MSG_LEN).fill(0),
    msg_len: 0,
    enabled: false,
  };
}

function emptyMutation(): StateMutationWitness {
  return {
    key: new Array(32).fill(0),
    new_value: new Array(32).fill(0),
    is_delete: false,
    enabled: false,
  };
}

function emptyBlockEvidence(): BlockEvidenceWitness {
  return {
    block_number: 0,
    new_state_root: new Array(32).fill(0),
    mutations: Array.from({ length: MAX_MUTATIONS }, emptyMutation),
    mutation_count: 0,
    signatures: Array.from({ length: MAX_VALIDATORS }, emptySignature),
    sig_count: 0,
    active_nodes: 0,
    enabled: false,
  };
}

// ─── API Types (from Persistia node) ─────────────────────────────────────────

interface ApiSignature {
  pubkey: string;      // hex
  signature: string;   // hex or base64
  message: string;     // JSON string
}

interface ApiMutation {
  key: string;         // logical key string
  old_value?: string;
  new_value?: string;
}

interface ApiBlock {
  block_number: number;
  state_root: string;
  mutations: ApiMutation[];
  signatures: ApiSignature[];
  active_nodes: number;
}

// ─── Witness Builders ────────────────────────────────────────────────────────

function buildSignatureWitness(sig: ApiSignature): NodeSignatureWitness {
  const pubkey = hexToBytes(sig.pubkey);
  const sigBytes = sig.signature.length === 128
    ? hexToBytes(sig.signature)  // hex-encoded
    : Array.from(Buffer.from(sig.signature, "base64")); // base64

  const msgBytes = Array.from(Buffer.from(sig.message, "utf-8"));

  return {
    pubkey: padArray(pubkey, 32),
    signature: padArray(sigBytes, 64),
    message: padArray(msgBytes, MAX_MSG_LEN),
    msg_len: msgBytes.length,
    enabled: true,
  };
}

function buildMutationWitness(mut: ApiMutation): StateMutationWitness {
  const keyHash = sha256Hash(Buffer.from(mut.key, "utf-8"));
  const isDelete = mut.new_value == null;
  const valueHash = isDelete
    ? new Array(32).fill(0)
    : sha256Hash(Buffer.from(mut.new_value!, "utf-8"));

  return {
    key: keyHash,
    new_value: valueHash,
    is_delete: isDelete,
    enabled: true,
  };
}

/** Build witness for a single-block proof. */
export function buildSingleBlockWitness(
  block: ApiBlock,
  prevStateRoot: string,
  opts?: { recursive?: boolean; prevProvenBlocks?: number; prevGenesisRoot?: string },
): CircuitWitness {
  const sigs = block.signatures.map(buildSignatureWitness);
  while (sigs.length < MAX_VALIDATORS) sigs.push(emptySignature());

  const muts = block.mutations.map(buildMutationWitness);
  while (muts.length < MAX_MUTATIONS) muts.push(emptyMutation());

  return {
    mutations: muts.slice(0, MAX_MUTATIONS),
    mutation_count: block.mutations.length,
    signatures: sigs.slice(0, MAX_VALIDATORS),
    sig_count: block.signatures.length,
    batch_blocks: Array.from({ length: MAX_BATCH_SIZE }, emptyBlockEvidence),
    batch_count: 0,
    recursive: opts?.recursive ?? false,
    prev_proven_blocks: opts?.prevProvenBlocks ?? 0,
    prev_genesis_root: opts?.prevGenesisRoot
      ? hexToBytes(opts.prevGenesisRoot)
      : new Array(32).fill(0),
    prev_state_root: hexToBytes(prevStateRoot),
    new_state_root: hexToBytes(block.state_root),
    block_number: block.block_number,
    active_nodes: block.active_nodes,
  };
}

/** Build witness for a batch proof (multiple blocks in one proof). */
export function buildBatchWitness(
  blocks: ApiBlock[],
  prevStateRoot: string,
  opts?: { recursive?: boolean; prevProvenBlocks?: number; prevGenesisRoot?: string },
): CircuitWitness {
  if (blocks.length > MAX_BATCH_SIZE) {
    throw new Error(`Batch too large: ${blocks.length} > ${MAX_BATCH_SIZE}`);
  }

  const batchBlocks: BlockEvidenceWitness[] = blocks.map((block) => {
    const sigs = block.signatures.map(buildSignatureWitness);
    while (sigs.length < MAX_VALIDATORS) sigs.push(emptySignature());

    const muts = block.mutations.map(buildMutationWitness);
    while (muts.length < MAX_MUTATIONS) muts.push(emptyMutation());

    return {
      block_number: block.block_number,
      new_state_root: hexToBytes(block.state_root),
      mutations: muts.slice(0, MAX_MUTATIONS),
      mutation_count: block.mutations.length,
      signatures: sigs.slice(0, MAX_VALIDATORS),
      sig_count: block.signatures.length,
      active_nodes: block.active_nodes,
      enabled: true,
    };
  });

  while (batchBlocks.length < MAX_BATCH_SIZE) {
    batchBlocks.push(emptyBlockEvidence());
  }

  const lastBlock = blocks[blocks.length - 1];

  return {
    mutations: Array.from({ length: MAX_MUTATIONS }, emptyMutation),
    mutation_count: 0,
    signatures: Array.from({ length: MAX_VALIDATORS }, emptySignature),
    sig_count: 0,
    batch_blocks: batchBlocks.slice(0, MAX_BATCH_SIZE),
    batch_count: blocks.length,
    recursive: opts?.recursive ?? false,
    prev_proven_blocks: opts?.prevProvenBlocks ?? 0,
    prev_genesis_root: opts?.prevGenesisRoot
      ? hexToBytes(opts.prevGenesisRoot)
      : new Array(32).fill(0),
    prev_state_root: hexToBytes(prevStateRoot),
    new_state_root: hexToBytes(lastBlock.state_root),
    block_number: lastBlock.block_number,
    active_nodes: lastBlock.active_nodes,
  };
}
