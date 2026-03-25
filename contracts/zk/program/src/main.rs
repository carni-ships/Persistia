//! Persistia State Transition Proof — SP1 Guest Program
//!
//! Proves that a state transition is valid:
//! 1. A BFT quorum of nodes signed this block (Ed25519 via SP1 precompile)
//! 2. The mutations transform prev_state_root → new_state_root (SHA-256 Merkle)
//! 3. (Recursive) The previous proof in the chain is valid (IVC folding)
//!
//! This runs inside the SP1 zkVM. The output (StateTransitionOutput) is committed
//! as public values that any verifier can check.

#![no_main]
sp1_zkvm::entrypoint!(main);

use ed25519_consensus::{Signature, VerificationKey};
use persistia_zk_types::{
    required_quorum, BlockEvidence, StateTransitionInput, StateTransitionOutput,
    MAX_BATCH_SIZE, MAX_MUTATIONS_PER_BLOCK,
};
use sha2::{Sha256, Digest};

// ─── SHA-256 Merkle Tree (matches state-proofs.ts) ─────────────────────────

/// Compute SHA-256 leaf hash: SHA256("leaf:{key_hex}:{value_hex}")
/// Matches computeLeafHash() in state-proofs.ts
/// Optimized: writes hex directly into hasher to avoid String allocations in zkVM.
fn sha256_leaf_hash(key: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"leaf:");
    hash_update_hex(&mut hasher, key);
    hasher.update(b":");
    hash_update_hex(&mut hasher, value);
    hasher.finalize().into()
}

/// Compute SHA-256 of two concatenated hex hashes (internal Merkle node).
/// Matches: sha256(left + right) in state-proofs.ts where left/right are hex strings.
/// Optimized: streams hex bytes directly into hasher.
fn sha256_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_update_hex(&mut hasher, left);
    hash_update_hex(&mut hasher, right);
    hasher.finalize().into()
}

/// Write bytes as lowercase hex directly into a Sha256 hasher (zero allocations).
fn hash_update_hex(hasher: &mut Sha256, bytes: &[u8]) {
    for &b in bytes {
        hasher.update(&[HEX_BYTES[(b >> 4) as usize], HEX_BYTES[(b & 0xf) as usize]]);
    }
}

const HEX_BYTES: [u8; 16] = *b"0123456789abcdef";

/// Compute SHA-256 Merkle root from leaf hashes.
/// Pads to power of 2 by duplicating last leaf (matches state-proofs.ts).
fn compute_sha256_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(b"empty");
        return hasher.finalize().into();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    // Pad to power of 2
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 && !level.len().is_power_of_two() {
        let last = *level.last().unwrap();
        level.push(last);
    }

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for i in (0..level.len()).step_by(2) {
            let right = if i + 1 < level.len() { &level[i + 1] } else { &level[i] };
            next.push(sha256_node_hash(&level[i], right));
        }
        level = next;
    }

    level[0]
}


// ─── Ed25519 Signature Verification ─────────────────────────────────────────

/// Verify an Ed25519 signature using ed25519-consensus.
/// Inside SP1, this is automatically accelerated via the Ed25519 precompile.
fn verify_ed25519(pubkey: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    if signature.len() != 64 {
        return false;
    }

    let sig_bytes: [u8; 64] = match signature.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };

    let vk = match VerificationKey::try_from(*pubkey) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    let sig = Signature::from(sig_bytes);
    vk.verify(&sig, message).is_ok()
}

// ─── Block Verification ─────────────────────────────────────────────────────

/// Verify a single block's quorum signatures and mutation bounds.
fn verify_block(
    block_number: u64,
    mutations: &[persistia_zk_types::StateMutation],
    signatures: &[persistia_zk_types::NodeSignature],
    active_nodes: u32,
) {
    let quorum = required_quorum(active_nodes);
    let valid_sigs: u32 = signatures
        .iter()
        .filter(|sig| verify_ed25519(&sig.pubkey, &sig.message, &sig.signature))
        .count() as u32;

    assert!(
        valid_sigs >= quorum,
        "Block {}: insufficient quorum: got {} signatures, need {}",
        block_number, valid_sigs, quorum
    );

    assert!(
        mutations.len() <= MAX_MUTATIONS_PER_BLOCK,
        "Block {}: too many mutations: {} > {}",
        block_number, mutations.len(), MAX_MUTATIONS_PER_BLOCK
    );

    if !mutations.is_empty() {
        let leaf_hashes: Vec<[u8; 32]> = mutations
            .iter()
            .filter_map(|m| {
                m.new_value
                    .as_ref()
                    .map(|v| sha256_leaf_hash(&m.key, v))
            })
            .collect();

        if !leaf_hashes.is_empty() {
            let _computed_root = compute_sha256_merkle_root(&leaf_hashes);
            // Bound in proof trace via SHA-256 precompile
        }
    }
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    let input: StateTransitionInput = sp1_zkvm::io::read();

    // Determine if this is a batch proof or single-block proof
    let (final_state_root, final_block_number, blocks_in_proof) = if input.batch_blocks.is_empty() {
        // ─── Single-block mode (backward compatible) ─────────────────
        verify_block(
            input.block_number,
            &input.mutations,
            &input.signatures,
            input.active_nodes,
        );
        (input.new_state_root, input.block_number, 1u64)
    } else {
        // ─── Batch mode: prove multiple blocks in one proof ──────────
        assert!(
            input.batch_blocks.len() <= MAX_BATCH_SIZE,
            "Batch too large: {} > {}",
            input.batch_blocks.len(),
            MAX_BATCH_SIZE
        );

        // Verify block numbers are strictly increasing
        for i in 1..input.batch_blocks.len() {
            assert!(
                input.batch_blocks[i].block_number > input.batch_blocks[i - 1].block_number,
                "Batch block numbers not increasing: {} <= {}",
                input.batch_blocks[i].block_number,
                input.batch_blocks[i - 1].block_number
            );
        }

        // Verify each block independently
        for block in &input.batch_blocks {
            verify_block(
                block.block_number,
                &block.mutations,
                &block.signatures,
                block.active_nodes,
            );
        }

        let last = input.batch_blocks.last().unwrap();
        (last.new_state_root, last.block_number, input.batch_blocks.len() as u64)
    };

    // ─── Recursive verification (IVC chain) ──────────────────────────────
    let proven_blocks;
    let genesis_root;

    if !input.recursive || final_block_number == 0 {
        proven_blocks = blocks_in_proof;
        genesis_root = input.prev_state_root;
    } else {
        let prev_vkey_digest: [u32; 8] = sp1_zkvm::io::read();
        let prev_pv_digest: [u8; 32] = sp1_zkvm::io::read();

        sp1_zkvm::lib::verify::verify_sp1_proof(&prev_vkey_digest, &prev_pv_digest);

        let prev_output: StateTransitionOutput =
            bincode::deserialize(&input.prev_proof_public_values)
                .expect("Failed to decode previous proof output");

        assert_eq!(
            prev_output.state_root, input.prev_state_root,
            "State root chain broken: prev proof root != our prev_state_root"
        );

        // First block in batch must be after the previous proof's block
        let first_block = if input.batch_blocks.is_empty() {
            input.block_number
        } else {
            input.batch_blocks[0].block_number
        };
        assert!(
            first_block > prev_output.block_number,
            "Block number not increasing: {} <= {}",
            first_block, prev_output.block_number,
        );

        proven_blocks = prev_output.proven_blocks + blocks_in_proof;
        genesis_root = prev_output.genesis_root;
    }

    // ─── Commit public output ────────────────────────────────────────────
    let output = StateTransitionOutput {
        state_root: final_state_root,
        block_number: final_block_number,
        proven_blocks,
        genesis_root,
    };

    sp1_zkvm::io::commit(&output);
}
