# Persistia ZK Proofs -- Noir Circuit

Alternative ZK proof system using [Noir](https://noir-lang.org/) + Barretenberg UltraHonk backend.
Drop-in replacement for the SP1 prover at `../zk/`.

## Performance

| Metric | SP1 (current) | Noir (this) |
|--------|---------------|-------------|
| **Proving time** | ~60-90s/block | **0.84s** native, 5.3s WASM |
| **Proof size** | ~200KB (STARK) | **16 KB** (UltraHonk) |
| **Verification** | Requires Groth16 wrap | native verify built-in, 1.6s WASM |
| **On-chain verify** | Complex | Native Solidity verifier (2.4K LOC) |
| **Signatures** | Ed25519 | Schnorr on Grumpkin (~150 gates/sig) |
| **Merkle hash** | SHA-256 | Poseidon2 (~20 gates/hash) |
| **Circuit size** | N/A | 6,951 ACIR opcodes, 769K gates (with recursion) |
| **Speedup** | 1x | **~85x faster** (native) |

## Structure

```
zk-noir/
+-- Nargo.toml               # Noir project config
+-- src/
|   +-- main.nr               # The circuit (state transition proof)
+-- prover/
|   +-- package.json
|   +-- gen_test_witness.mjs   # Generate Prover.toml with Schnorr test sigs
|   +-- src/
|       +-- bench.mjs          # Benchmark script
|       +-- witness.ts         # Witness generation (Schnorr via @aztec/bb.js)
|       +-- prover.ts          # CLI prover
+-- target/
|   +-- PersistiaVerifier.sol  # Generated Solidity verifier
+-- README.md
```

## Prerequisites

```bash
# Install Noir toolchain (>= 1.0.0-beta.19)
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup

nargo --version
```

## Quick Start

```bash
# 1. Compile the circuit
cd contracts/zk-noir
nargo compile

# 2. Run tests (6 tests: quorum, Poseidon2 Merkle, Schnorr verification)
nargo test

# 3. Install prover dependencies
cd prover && npm install

# 4. Generate test witness with Schnorr signatures
node gen_test_witness.mjs && mv Prover.toml ../Prover.toml

# 5. Execute (witness solve, no proof)
cd .. && nargo execute

# 6. Prove with native bb CLI (bundled in @aztec/bb.js)
BB=prover/node_modules/@aztec/bb.js/build/arm64-macos/bb
$BB write_vk -b target/persistia_state_proof.json -o target/vk
$BB prove -b target/persistia_state_proof.json \
  -w target/persistia_state_proof.gz \
  -o target/proof -k target/vk/vk --verify

# 7. Benchmark (WASM)
cd prover && node src/bench.mjs
```

## Circuit Details

### What it proves

1. **BFT Quorum** -- Schnorr signatures on Grumpkin from >= 2f+1 validators
2. **State Merkle** -- Poseidon2 Merkle tree over state mutations (root verified against public input)
3. **Recursion** -- Previous proof in the IVC chain is valid via `std::verify_proof_with_type`

### Cryptographic primitives

| Primitive | Implementation | Cost |
|-----------|---------------|------|
| Signatures | Schnorr on Grumpkin (BN254 embedded) | ~150 gates/sig |
| Merkle hash | Poseidon2 sponge | ~20 gates/hash |
| Challenge derivation | Pedersen + BLAKE2s | native to Barretenberg |

### Fixed-Size Bounds

| Parameter | Value |
|-----------|-------|
| `MAX_VALIDATORS` | 4 |
| `MAX_MUTATIONS` | 32 |

Unused signature slots are padded with valid dummy Schnorr signatures (required
because Noir evaluates all circuit branches regardless of conditional logic).

## Solidity Verifier

```bash
# Generate EVM-targeted verifier
BB=prover/node_modules/@aztec/bb.js/build/arm64-macos/bb
$BB write_vk -b target/persistia_state_proof.json -o target/vk_evm -t evm
$BB write_solidity_verifier -k target/vk_evm/vk -o target/PersistiaVerifier.sol -t evm

# Deploy and call:
#   verifier.verify(proof, publicInputs)
```

## Optimization History

| Phase | Change | Opcodes | Gates | Prove Time |
|-------|--------|---------|-------|------------|
| Initial | ECDSA secp256k1 + SHA-256 (16 sigs, 64 muts) | 3.8M | N/A | OOM |
| Phase 0 | Right-size (4 sigs, 32 muts, no batch) | 288K | 2M | 8.6s |
| Phase 1 | Schnorr on Grumpkin (replaces ECDSA) | 288K | 2M | 8.6s |
| Phase 4a | Poseidon2 Merkle (replaces SHA-256) | **4,262** | **46K** | **0.45s** |
| Phase 3 | Recursive proof verification (IVC chain) | **6,951** | **769K** | **0.84s** native |

## Future Work

- **Batch mode**: Re-add batch proving with recursive sub-batch verification
- **Rolling Merkle**: Path-based updates instead of full tree recomputation
- **Node migration**: Update Persistia node to produce Schnorr/Grumpkin signatures
- **GPU/Metal acceleration**: Investigate Barretenberg Metal support for MSM on Apple Silicon
