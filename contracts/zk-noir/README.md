# Persistia ZK Proofs — Noir Circuit

Alternative ZK proof system using [Noir](https://noir-lang.org/) + Barretenberg backend.
Drop-in replacement for the SP1 prover at `../zk/`.

## Why Noir over SP1?

| | SP1 (current) | Noir (this) |
|---|---|---|
| **Proving time** | ~60-90s/block (local) | Target: 2-10s/block |
| **Proof size** | ~200KB (STARK) | ~few hundred bytes (SNARK) |
| **On-chain verify** | Requires Groth16 wrap | Native Solidity verifier |
| **Recursion** | IVC via RISC-V zkVM | Native `verify_proof` |
| **Flexibility** | Any Rust program | Fixed circuit (sufficient for us) |

## Structure

```
zk-noir/
├── Nargo.toml           # Noir project config
├── src/
│   └── main.nr          # The circuit (state transition proof)
├── prover/
│   ├── package.json
│   └── src/
│       ├── prover.ts    # CLI prover (replaces SP1 prover binary)
│       ├── witness.ts   # Witness generation from node API
│       └── gen-verifier.ts  # Solidity verifier codegen
└── README.md
```

## Prerequisites

```bash
# Install Noir toolchain
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup

# Verify
nargo --version
```

## Quick Start

```bash
# 1. Compile the circuit
cd contracts/zk-noir
nargo compile

# 2. Run tests
nargo test

# 3. Install prover dependencies
cd prover && npm install

# 4. Execute without proof (test witness generation)
npm run execute -- --node https://persistia.YOUR_DOMAIN --block 100

# 5. Generate a real proof
npm run prove -- --node https://persistia.YOUR_DOMAIN --block 100

# 6. Verify it
npm run verify -- --proof proof.json

# 7. Benchmark against SP1
npm run bench -- --node https://persistia.YOUR_DOMAIN --block 100
```

## Watch Mode (Continuous Proving)

```bash
# Single-block proofs, 10s poll interval
npm run watch -- --node https://persistia.YOUR_DOMAIN

# Batch 4 blocks per proof, 30s interval
npm run watch -- --node https://persistia.YOUR_DOMAIN --batch 4 --interval 30
```

## Solidity Verifier (On-Chain Anchoring)

```bash
# Generate the verifier contract
tsx prover/src/gen-verifier.ts --output contracts/PersistiaVerifier.sol

# Deploy to Berachain and call:
#   verifier.verify(proof, [prev_state_root, new_state_root, block_number, active_nodes])
```

## Circuit Details

The Noir circuit proves the same things as the SP1 guest program:

1. **BFT Quorum** — Verifies Ed25519 signatures from ≥2f+1 validators
2. **State Merkle** — SHA-256 Merkle tree over state mutations matches declared root
3. **Recursion** — Previous proof in the IVC chain is valid (when enabled)

### Fixed-Size Bounds

Noir circuits are fixed-size at compile time. Current bounds:

| Parameter | Value | Notes |
|-----------|-------|-------|
| `MAX_VALIDATORS` | 16 | Validator signatures per block |
| `MAX_MUTATIONS` | 128 | State mutations per block |
| `MAX_BATCH_SIZE` | 8 | Blocks per batch proof |
| `MAX_MSG_LEN` | 512 | Ed25519 message length |

Unused slots are padded with `enabled: false` sentinels and skipped in-circuit.

## Recursive Proofs

Noir supports native recursive verification via `std::verify_proof()`. The recursive
path in `main.nr` is scaffolded but commented out — it requires the circuit's
verification key, which is only available after first compilation.

To enable recursion:

1. Compile: `nargo compile`
2. Extract the verification key from the compiled artifact
3. Uncomment the `std::verify_proof()` call in `main.nr`
4. Pass `prev_verification_key` and `prev_proof` as witness inputs
5. Recompile

## Migration from SP1

The prover CLI mirrors the SP1 prover's interface:

| SP1 Command | Noir Equivalent |
|-------------|-----------------|
| `persistia-prover execute --block N` | `npm run execute -- --block N` |
| `persistia-prover prove --block N` | `npm run prove -- --block N` |
| `persistia-prover verify --proof X` | `npm run verify -- --proof X` |
| `persistia-prover watch` | `npm run watch` |

The node API endpoints (`/proof/block/N`, `/proof/zk/submit`) are unchanged.
