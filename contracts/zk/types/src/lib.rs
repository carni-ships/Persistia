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
