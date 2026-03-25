//! Shared types for Persistia ZK state proofs.
//!
//! Used by both the SP1 guest program and the host prover/verifier.

#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// A single state mutation: key changed from old_value to new_value.
/// If old_value is None, it's an insert. If new_value is None, it's a delete.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateMutation {
    pub key: Vec<u8>,
    pub old_value: Option<Vec<u8>>,
    pub new_value: Option<Vec<u8>>,
}

/// An Ed25519 signature over a block/vertex, plus the message that was signed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeSignature {
    pub pubkey: [u8; 32],
    pub signature: Vec<u8>,  // 64 bytes
    pub message: Vec<u8>,    // canonical JSON bytes that were signed
}

/// Input to the SP1 program: everything needed to prove one state transition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateTransitionInput {
    /// The previous state root (Poseidon Merkle root).
    pub prev_state_root: [u8; 32],

    /// The new state root after applying mutations.
    pub new_state_root: [u8; 32],

    /// Block/round number this transition corresponds to.
    pub block_number: u64,

    /// The state mutations applied in this block.
    pub mutations: Vec<StateMutation>,

    /// Quorum signatures on this block's vertex.
    pub signatures: Vec<NodeSignature>,

    /// Total active nodes (for quorum check: need 2f+1 where f = (n-1)/3).
    pub active_nodes: u32,

    /// Whether recursive verification should be performed.
    /// If true, the prover must supply the previous proof via stdin.write_proof().
    pub recursive: bool,

    /// Previous proof's public values (serialized StateTransitionOutput).
    /// Used to check chain integrity (prev state_root == our prev_state_root).
    pub prev_proof_public_values: Vec<u8>,

    /// Batch mode: if non-empty, proves multiple blocks in one proof.
    /// When set, the single-block fields (mutations, signatures, block_number,
    /// new_state_root, active_nodes) are ignored in favor of these.
    pub batch_blocks: Vec<BlockEvidence>,
}

/// Public output committed by the SP1 program.
/// This is what verifiers check — it summarizes the proven chain state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateTransitionOutput {
    /// The state root after this transition.
    pub state_root: [u8; 32],

    /// Block number proven up to.
    pub block_number: u64,

    /// Number of blocks recursively proven in this chain (1 for non-recursive).
    pub proven_blocks: u64,

    /// The genesis state root (anchors the proof chain).
    pub genesis_root: [u8; 32],
}

/// Evidence for a single block in a batch proof.
/// Contains all data needed to verify one block's state transition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockEvidence {
    pub block_number: u64,
    pub new_state_root: [u8; 32],
    pub mutations: Vec<StateMutation>,
    pub signatures: Vec<NodeSignature>,
    pub active_nodes: u32,
}

/// Maximum mutations per block that can be proven.
pub const MAX_MUTATIONS_PER_BLOCK: usize = 1024;

/// Maximum blocks in a single batch proof.
pub const MAX_BATCH_SIZE: usize = 32;

/// BFT quorum: need 2f+1 signatures where f = floor((n-1)/3).
pub fn required_quorum(active_nodes: u32) -> u32 {
    if active_nodes <= 1 {
        return 1;
    }
    let f = (active_nodes - 1) / 3;
    2 * f + 1
}

// ─── Client-Side Proving Types (Miden-inspired) ──────────────────────────────

/// A client-side proof that a single transaction is valid.
/// The user generates this proof locally; the block prover only verifies it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientProofEvidence {
    /// The transaction hash
    pub tx_hash: Vec<u8>,
    /// The user's public key
    pub sender_pubkey: [u8; 32],
    /// Pre-state root of the affected account/contract
    pub pre_state_root: [u8; 32],
    /// Post-state root after the transaction
    pub post_state_root: [u8; 32],
    /// Compressed proof bytes (SP1 compressed proof)
    pub proof_bytes: Vec<u8>,
    /// Public values from the client proof
    pub public_values: Vec<u8>,
}

/// Block evidence that includes client-side proofs instead of raw mutations.
/// Used when the block aggregator only needs to verify proofs, not re-execute.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedBlockEvidence {
    pub block_number: u64,
    pub new_state_root: [u8; 32],
    /// Client proofs for individual transactions in this block
    pub client_proofs: Vec<ClientProofEvidence>,
    /// BFT signatures on the block
    pub signatures: Vec<NodeSignature>,
    pub active_nodes: u32,
}

// ─── Tree-Structured Proof Aggregation (Miden-inspired) ──────────────────────

/// A node in the proof aggregation tree.
/// Leaf nodes contain block proofs; internal nodes aggregate children.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregationTreeNode {
    /// Tree level: 0 = leaf (individual block proof), higher = aggregation
    pub level: u32,
    /// Block range covered by this node
    pub block_start: u64,
    pub block_end: u64,
    /// State root at the end of this node's range
    pub state_root: [u8; 32],
    /// Number of blocks proven by this subtree
    pub proven_blocks: u64,
    /// Left child hash (for verification)
    pub left_child_hash: Option<Vec<u8>>,
    /// Right child hash (for verification)
    pub right_child_hash: Option<Vec<u8>>,
}

/// Input for tree-structured proof aggregation.
/// The prover combines two child proofs into one parent proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeAggregationInput {
    /// Left subtree's output (block range + state root)
    pub left: AggregationTreeNode,
    /// Right subtree's output (block range + state root)
    pub right: AggregationTreeNode,
    /// Whether to recursively verify child proofs
    pub verify_children: bool,
    /// Left child proof's public values
    pub left_public_values: Vec<u8>,
    /// Right child proof's public values
    pub right_public_values: Vec<u8>,
}

// ─── Sparse Merkle Tree Proof Types (Urkel-inspired) ─────────────────────────

/// A sparse Merkle proof that supports both inclusion and non-inclusion.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparseMerkleProof {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,    // None for non-inclusion proofs
    pub siblings: Vec<[u8; 32]>,
    pub directions: Vec<u8>,       // 0 = left, 1 = right
    pub root: [u8; 32],
    pub inclusion: bool,
    /// For non-inclusion: the closest existing key at the divergence point
    pub closest_key: Option<Vec<u8>>,
    pub diverge_depth: Option<u32>,
}

/// Nullifier for cross-shard note consumption (append-only, ZK-friendly).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullifierEntry {
    pub nullifier: [u8; 32],
    pub note_id: Vec<u8>,
    pub consumed_by: [u8; 32],
}
