# Persistia: BFT Consensus at the Edge

**A decentralized ledger that runs on Cloudflare Workers, proves state with zero-knowledge proofs, and anchors to both Arweave and Celestia.**

---

Most blockchain infrastructure demands dedicated servers, significant capital for staking, and months of DevOps work before a single transaction is processed. Persistia takes a different path: it runs a full Byzantine Fault Tolerant consensus protocol on Cloudflare's edge network, using Durable Objects as validator nodes. No tokens to stake. No VMs to provision. Just deploy a Worker and you're running a validator.

This post covers the architecture, the design decisions behind it, and why it matters.

## The Problem with Infrastructure Lock-In

Every existing L1 requires operators to run full nodes — machines that store the complete chain state, execute every transaction, and participate in consensus. This creates a hardware floor that excludes most developers and concentrates validation power among well-funded operators.

We asked: what if the infrastructure layer was already solved? Cloudflare operates data centers in 300+ cities. Their Durable Objects provide strongly consistent, single-threaded execution with built-in persistence. Their Workers handle HTTP routing, WebSocket upgrades, and TLS termination globally. What if a consensus protocol could run *on top* of that?

## Architecture

### Bullshark DAG Consensus on Durable Objects

Persistia implements Bullshark, a DAG-based BFT consensus protocol. Each validator is a Cloudflare Durable Object — a stateful, single-threaded compute unit with a co-located SQLite database.

The protocol operates in rounds. Every 30 seconds, each validator:

1. Bundles pending events into a **DAG vertex** with cryptographic references to vertices from prior rounds
2. Broadcasts the vertex to peers via HTTP gossip
3. Checks if quorum (2f+1 of active validators) has been reached for the current round
4. On even-numbered rounds, evaluates the **commit rule**: if a round's leader vertex is referenced by quorum vertices in the next round, that anchor and all causally reachable vertices are finalized

This gives us the safety and liveness guarantees of Bullshark with the operational simplicity of a serverless deployment. The entire consensus state — vertices, events, commit history — lives in each Durable Object's embedded SQLite instance. No external database. No separate storage layer.

### Shard Routing

A single Cloudflare Worker acts as the HTTP gateway. Requests carry a `?shard=node-1` query parameter that routes to the corresponding Durable Object via `idFromName()`. This means every validator has a stable URL, cross-shard communication is just HTTP, and the network topology is decoupled from the physical infrastructure.

Cross-shard message relay is handled at the Worker layer: fetch outbox from source shard, deliver to target, acknowledge back. No custom networking protocols — just HTTP over Cloudflare's backbone.

### Tokenless Validation

Persistia has no native token and no staking requirement. Validators participate based on **reputation**, weighted by their consistency in producing vertices across recent rounds. The active set is computed from a sliding window of the last 10 rounds — if you've been producing vertices, you're in.

This eliminates the cold-start problem that plagues new networks: you don't need to bootstrap a token economy before you can bootstrap consensus. It also means the barrier to running a validator is deploying a Cloudflare Worker, not acquiring capital.

## Zero-Knowledge State Proofs

Every finalized block produces a state transition that can be proven in zero knowledge using [SP1](https://github.com/succinctlabs/sp1), a STARK-based zkVM.

### What the Proof Verifies

Each proof attests to three properties:

1. **BFT Quorum**: Ed25519 signatures from 2f+1 validators confirmed the block, verified inside the zkVM using SP1's Ed25519 precompile
2. **State Root Transition**: The SHA-256 Merkle root correctly transitions from `prev_state_root` to `new_state_root` given the block's mutations
3. **Proof Chain Continuity**: The previous proof in the chain is recursively verified via SP1's `verify_sp1_proof`, ensuring an unbroken chain of proofs back to genesis

### Batch Proving

Proving a single block at a time is expensive — STARK proofs have high fixed overhead. Persistia supports **batch proving**, where up to 32 blocks are verified in a single recursive proof. Each block in the batch is independently validated (quorum + state transitions), block numbers must be strictly increasing, and the final proof covers the entire range. This amortizes the STARK overhead across many blocks and keeps the proof chain from falling behind finalization.

### Incremental Merkle Trees

State commitments use an incremental Merkle tree with dirty-node tracking. Only the paths affected by mutations are recomputed — O(changed keys) rather than O(total state). This makes proof generation feasible even as state grows.

## WASM Smart Contracts

Persistia runs user-deployed smart contracts as WebAssembly modules, executed inside V8 isolates on Cloudflare Workers. The contract runtime follows the NEAR/CosmWasm model with a register-based ABI.

### How It Works

Contracts are deployed as WASM binaries (max 1MB). On deployment, the binary is validated:

- **Float opcodes are banned** (`f32.*`, `f64.*`) — floating-point arithmetic is non-deterministic across hardware. The validator scans the WASM bytecode and rejects any module containing these instructions.
- **WASI imports are banned** — no filesystem, no clock, no randomness. Execution must be fully deterministic.
- **Fuel metering is injected** — rather than relying on wall-clock timeouts (which differ across machines), Persistia instruments WASM binaries with a fuel counter at compile time. Every function call decrements fuel. When fuel runs out, the module traps deterministically with `unreachable`. All validators agree on exactly when execution stops.

State mutations are buffered during execution and flushed atomically on success. If the contract traps or exhausts fuel, nothing is written — all-or-nothing semantics without explicit transaction management.

### Cross-Contract Calls

Contracts can call other contracts synchronously, up to 10 levels deep. The execution context — mutations, fuel, call stack — is shared across the call chain. This means a top-level call that invokes three sub-contracts either commits all mutations or none. Fuel is also shared: a callee that burns all remaining fuel will cause the entire call chain to trap.

### CosmWasm Compatibility

We built a compatibility shim (`cosmwasm-compat`) that maps CosmWasm's message-passing model (`ExecuteMsg`, `QueryMsg`, `Response`) onto Persistia's register ABI. Contracts written for CosmWasm can be ported with minimal changes — swap the import from `cosmwasm_std` to `persistia_cosmwasm_compat`, adjust the entry point macro, and rebuild for `wasm32-unknown-unknown`.

This opens the door to porting existing CosmWasm applications — DEXs, lending protocols, NFT marketplaces — onto Persistia without rewriting business logic.

## Dual-Layer State Anchoring

Persistia doesn't rely on a single external chain for data availability. Finalized state is anchored to **both** Arweave (via Irys) and Celestia simultaneously.

- **Arweave**: Permanent storage. State proofs are bundled and submitted via Irys, producing an Arweave transaction ID that serves as a permanent receipt. Even if Persistia's validators all go offline, the state history is recoverable from Arweave.
- **Celestia**: Data availability sampling. State bundles are published to a dedicated namespace (`persistia`), enabling light clients to verify data availability without downloading the full state. The Celestia block height is stored for bootstrap syncing.

Running both in parallel hedges against single-chain downtime and gives operators a choice of verification path.

## The Dashboard: Real-Time DAG Visualization

Persistia ships with a live dashboard that renders the Bullshark DAG as it forms. Each round is a column, each validator a row, and vertices are drawn as nodes with edges showing cryptographic references. Committed anchors glow. Events stream in real-time over WebSocket.

This isn't a block explorer bolted on after the fact — it's a first-class view into the consensus process. You can watch quorum form, see which validators are active, track the ZK proof chain's progress, and monitor deployed contracts. It makes the abstract concrete: you see the DAG that textbooks describe.

## What's Novel

To summarize what makes Persistia different from existing approaches:

| Property | Persistia | Typical L1 |
|----------|-----------|-------------|
| **Infrastructure** | Cloudflare Workers + Durable Objects | Dedicated servers |
| **Validator requirement** | Deploy a Worker | Stake tokens + run hardware |
| **Consensus** | Bullshark DAG-BFT (30s rounds) | Various (Tendermint, HotStuff, Nakamoto) |
| **State proofs** | SP1 STARK recursive proofs | Optional or none |
| **Smart contracts** | WASM with fuel metering, no floats | EVM / WASM / Move |
| **Data availability** | Dual anchor (Arweave + Celestia) | Self-hosted or single DA layer |
| **Token** | None (reputation-based) | Required for staking/gas |
| **Operational cost** | Cloudflare free tier | $500–$5000+/month per validator |

## Try It

Persistia is live with a 3-validator cluster on Cloudflare's edge. The dashboard, consensus, gossip, ZK proofs, and contract runtime are all running on the free tier.

The codebase is structured as:
- `src/` — TypeScript: Durable Object consensus, gossip, contract executor, anchoring
- `contracts/zk/` — Rust: SP1 zkVM prover, guest program, shared types
- `contracts/persistia-sdk/` — Rust: SDK for writing smart contracts
- `contracts/cosmwasm-compat/` — Rust: CosmWasm compatibility layer
- `client/` — Dashboard and client library

We're actively working on expanding the contract ecosystem, improving proof generation throughput, and exploring cross-shard contract execution. If you're interested in building on infrastructure that doesn't require you to run infrastructure, Persistia is worth a look.

---

*Persistia is open source. Star the repo, deploy a validator, or port your CosmWasm contracts — contributions welcome.*
