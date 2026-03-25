# Persistia: BFT Consensus at the Edge

**A decentralized ledger that runs on Cloudflare Workers, proves state with zero-knowledge proofs, and anchors to Arweave and Berachain.**

---

Most blockchain infrastructure demands dedicated servers, significant capital for staking, and months of DevOps work before a single transaction is processed. Persistia takes a different path: it runs a full Byzantine Fault Tolerant consensus protocol on Cloudflare's edge network, using Durable Objects as validator nodes. No tokens to stake. No VMs to provision. Just deploy a Worker and you're running a validator.

This post covers the architecture, the design decisions behind it, and why it matters.

## The Problem with Infrastructure Lock-In

Every existing L1 requires operators to run full nodes — machines that store the complete chain state, execute every transaction, and participate in consensus. This creates a hardware floor that excludes most developers and concentrates validation power among well-funded operators.

We asked: what if the infrastructure layer was already solved? Cloudflare operates data centers in 300+ cities. Their Durable Objects provide strongly consistent, single-threaded execution with built-in persistence. Their Workers handle HTTP routing, WebSocket upgrades, and TLS termination globally. What if a consensus protocol could run *on top* of that?

## Architecture

### Bullshark DAG Consensus on Durable Objects

Persistia implements Bullshark, a DAG-based BFT consensus protocol. Each validator is a Cloudflare Durable Object — a stateful, single-threaded compute unit with a co-located SQLite database.

The protocol operates in rounds. Every 12 seconds, each validator:

1. Bundles pending events into a **DAG vertex** with cryptographic references to vertices from prior rounds
2. Broadcasts the vertex to peers via HTTP gossip
3. Checks if quorum (2f+1 of active validators) has been reached for the current round
4. On even-numbered rounds, evaluates the **commit rule**: if a round's leader vertex is referenced by quorum vertices in the next round, that anchor and all causally reachable vertices are finalized

This gives us the safety and liveness guarantees of Bullshark with the operational simplicity of a serverless deployment. The entire consensus state — vertices, events, commit history — lives in each Durable Object's embedded SQLite instance. No external database. No separate storage layer.

### Shard Routing

A single Cloudflare Worker acts as the HTTP gateway. Requests carry a `?shard=node-1` query parameter that routes to the corresponding Durable Object via `idFromName()`. This means every validator has a stable URL, cross-shard communication is just HTTP, and the network topology is decoupled from the physical infrastructure.

Cross-shard message relay is handled at the Worker layer: fetch outbox from source shard, deliver to target, acknowledge back. No custom networking protocols — just HTTP over Cloudflare's backbone.

### Tokenless Validation

Persistia has no native token and no staking requirement. Validators participate based on **reputation**, weighted by their consistency in producing vertices across recent rounds. The active set is computed from a sliding window — if you've been producing vertices, you're in.

This eliminates the cold-start problem that plagues new networks: you don't need to bootstrap a token economy before you can bootstrap consensus. It also means the barrier to running a validator is deploying a Cloudflare Worker, not acquiring capital.

## Finality

Persistia has five distinct finality stages, each with increasing guarantees. Understanding these levels is important for application developers choosing the right trade-off between speed and safety.

### Level 0: Optimistic — instant

When a client submits a signed event, the receiving node validates rules and adds it to the pending pool. A `pending` message is broadcast to all WebSocket clients immediately. The client can optimistically update its UI.

This is the fastest feedback loop, but provides no ordering guarantee. The event could be reverted if it fails validation at commit time or is never included in a vertex.

### Level 1: DAG Inclusion — ~12 seconds

On the next alarm cycle, the node bundles pending events into a DAG vertex (up to 500 events per vertex), signs it with its Ed25519 key, and gossips it to all peers. The vertex is now part of the DAG with causal references to prior rounds.

The event is in a signed vertex that all honest nodes will eventually see. But the vertex hasn't been committed — a Byzantine author could equivocate (produce two conflicting vertices for the same round).

### Level 2: BFT Commit — ~24–36 seconds

This is the core finality guarantee. Bullshark's commit rule works on even-numbered rounds:

1. **Round R** (even): The deterministically-elected leader creates an **anchor vertex**
2. **Round R+1**: Validators create vertices that reference the anchor
3. **Commit check**: If >= 2f+1 distinct validators in round R+1 reference the anchor, the anchor is committed

On commit, all causally reachable vertices are collected via topological sort, their events are applied to state in deterministic order, and the finalized state root is updated.

This is BFT-safe finality — the same guarantee as Tendermint or HotStuff. The event ordering cannot be reverted unless more than one-third of active validators are Byzantine.

### Level 3: ZK Proven — minutes

The SP1 prover watches committed rounds and generates STARK proofs that attest to three properties: BFT quorum signatures were valid, the Merkle state root transition is correct, and the previous proof in the chain verifies (recursive IVC). Any third party can verify the proof without trusting the validators. The proof chain is continuous back to genesis.

With batch proving (up to 32 blocks per proof), the amortized proving cost drops to ~1–3 minutes per block on consumer hardware.

### Level 4: DA Anchored — minutes

State roots and metadata are anchored to **Arweave** (permanent, immutable storage) and **Berachain** (EVM-compatible L1 with Proof of Liquidity consensus). Even if every Persistia validator disappears, the state history is recoverable. This is the strongest finality: independently verifiable and permanently stored outside Persistia's own infrastructure.

### Finality Comparison

| Level | Name | Latency | Revertible? |
|-------|------|---------|-------------|
| 0 | Optimistic | instant | Yes — not ordered yet |
| 1 | DAG Inclusion | ~12s | Yes — vertex not committed |
| 2 | **BFT Commit** | ~24–36s | No (unless >1/3 Byzantine) |
| 3 | ZK Proven | ~5–15 min | No (cryptographic) |
| 4 | DA Anchored | ~5–10 min | No (permanent external storage) |

For context: Ethereum reaches finality in ~12 minutes (2 epochs). Cosmos chains finalize in ~6 seconds. Persistia's ~24–36 second BFT finality is practical for most applications, running on $0 infrastructure. The round interval is tunable — at 2s rounds, finality drops to ~4–6 seconds but requires faster proof generation to keep up.

## Throughput

Persistia's throughput is shaped by Cloudflare's execution model rather than traditional blockchain bottlenecks like block size or gas limits.

### Single-Shard Throughput

Each Durable Object processes events sequentially. The binding constraints:

- **Alarm interval**: 12 seconds (tunable; currently set to match prover throughput)
- **Events per vertex**: Up to 500 events bundled per vertex per round
- **Reactive rescheduling**: When consensus advances, the alarm fires within 100ms instead of waiting for the next tick

On the current configuration with 3 validators, each producing a vertex with up to 500 events per round at 12-second intervals, the baseline throughput is **~42 transactions per second**. Events are accepted continuously via WebSocket and HTTP; the alarm interval only gates vertex creation and commit finalization, not event ingestion. SQL commits are batched (2 bulk INSERTs instead of N individual ones), and WebSocket broadcasts are batched into a single message per commit cycle.

At the faster 2-second round interval, throughput reaches **~250 TPS** per shard. The current 12s interval is tuned so a single ZK prover running batch-32 mode can keep pace with block production.

### Horizontal Scaling via Sharding

Persistia's shard routing (`?shard=X`) means each shard is an independent consensus domain running in its own Durable Object. Throughput scales linearly:

| Configuration | Shards | Estimated TPS |
|--------------|--------|---------------|
| Current (12s rounds, free tier) | 1 | ~42 |
| Fast rounds (2s) | 1 | ~250 |
| Optimized (2s + pipelining) | 1 | ~500–750 |
| Advanced (multi-vertex) | 1 | ~1,000–3,000 |
| Paid + 10 shards | 10 | ~10,000 |
| Paid + 100 shards | 100 | ~100,000 |

Cross-shard transactions add one round of latency per shard hop but don't reduce per-shard throughput. The Worker layer handles relay transparently.

### The Unusual Economics

Most chains measure cost-per-transaction against validator hardware. Persistia's validators run on Cloudflare's free tier — the operational cost is effectively zero for small deployments. On the paid plan ($5/month), you get access to higher CPU limits and faster alarm scheduling that unlock the higher throughput tiers. This makes Persistia's cost-per-transaction structure fundamentally different from chains that require dedicated infrastructure.

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

## State Anchoring: Arweave + Berachain

Persistia doesn't rely on a single external chain for data availability and state verification. Finalized state is anchored to **both** Arweave and Berachain.

- **Arweave**: Permanent storage. State proofs are bundled and submitted via Irys, producing an Arweave transaction ID that serves as a permanent receipt. Even if Persistia's validators all go offline, the state history is recoverable from Arweave.
- **Berachain**: EVM-compatible L1 secured by Proof of Liquidity. State roots and ZK proof commitments are published on-chain, enabling smart contracts on Berachain to verify Persistia state transitions. This creates a trust bridge: Berachain contracts can act on Persistia-proven state, and Persistia can reference Berachain finality as an external checkpoint.

Running both in parallel provides redundancy (permanent archival via Arweave, active verification via Berachain) and connects Persistia to the broader EVM ecosystem.

## The Dashboard: Real-Time DAG Visualization

Persistia ships with a live dashboard that renders the Bullshark DAG as it forms. Each round is a column, each validator a row, and vertices are drawn as nodes with edges showing cryptographic references. Committed anchors glow. Events stream in real-time over WebSocket.

This isn't a block explorer bolted on after the fact — it's a first-class view into the consensus process. You can watch quorum form, see which validators are active, track the ZK proof chain's progress, and monitor deployed contracts. It makes the abstract concrete: you see the DAG that textbooks describe.

## No Indexer Required: SQL Over the Chain

Most blockchains store state in a Merkle trie optimized for proof generation, not queries. Want to find all NFTs owned by an address? All events emitted by a contract? Transaction history for a wallet? You need an **indexer** — a separate service (The Graph, Helius, Goldsky) that replays every block, denormalizes data into a queryable database, and serves it via GraphQL or REST. This adds infrastructure, cost, latency, and a trust dependency on the indexer operator.

Persistia doesn't have this problem. Each validator node runs SQLite as its primary state store. The chain state *is* a relational database. And we expose it directly:

```
GET /query?q=SELECT author, COUNT(*) as vertices FROM dag_vertices GROUP BY author
GET /query?q=SELECT * FROM contracts WHERE deployer = 'abc...'
GET /query?q=SELECT * FROM token_balances WHERE amount != '0'
GET /schema  -- returns all tables and indexes
```

Any `SELECT`, `PRAGMA`, or `EXPLAIN` query runs directly against the node's SQLite instance. Mutations are rejected — the query endpoint is read-only. No separate indexing service. No subgraph deployment. No sync lag.

### What You Can Query

| Table | Contents |
|-------|----------|
| `dag_vertices` | Every vertex in the DAG with author, round, events, references |
| `dag_commits` | Committed rounds with anchor hashes and validator signatures |
| `consensus_events` | Finalized event log with ordering and vertex attribution |
| `contracts` | Deployed WASM contracts with deployer, hash, and bytecode |
| `contract_state` | Key-value state for each contract |
| `token_balances` | Token balances by address and denomination |
| `blocks` | Game world state (block placements) |
| `inventory` | Player inventories |
| `zk_proofs` | ZK proof chain with block ranges and verification status |

### Comparison

| Query | Ethereum | Persistia |
|-------|----------|-----------|
| Events by contract | Deploy a subgraph, wait for sync | `SELECT * FROM consensus_events WHERE ...` |
| NFTs owned by address | Alchemy NFT API ($) | `SELECT * FROM ownership WHERE owner_pubkey = ?` |
| Token balance | `eth_call` + ABI decode | `SELECT * FROM token_balances WHERE address = ?` |
| Transaction history | Etherscan API | `SELECT * FROM events WHERE pubkey = ? ORDER BY seq` |
| Contract storage | Multicall + slot math | `SELECT * FROM contract_state WHERE contract_address = ?` |
| Custom aggregation | Write a custom indexer | Write a SQL query |

This is possible because Persistia chose SQLite over a Merkle trie as the primary state representation. The Merkle tree exists for proof generation (incremental, dirty-node tracking), but the authoritative state lives in relational tables that support arbitrary queries natively.

For cross-shard aggregation — querying state across multiple independent consensus domains — you'd query each shard's `/query` endpoint and merge results client-side. Within a single shard, the node *is* the indexer.

## What's Novel

To summarize what makes Persistia different from existing approaches:

| Property | Persistia | Typical L1 |
|----------|-----------|-------------|
| **Infrastructure** | Cloudflare Workers + Durable Objects | Dedicated servers |
| **Validator requirement** | Deploy a Worker | Stake tokens + run hardware |
| **Consensus** | Bullshark DAG-BFT | Various (Tendermint, HotStuff, Nakamoto) |
| **BFT finality** | ~24–36s (12s rounds) / ~4–6s (2s rounds) | 6s–12min depending on chain |
| **Throughput** | ~42 TPS (12s) / ~250 TPS (2s) to ~100k TPS (sharded) | 15–4000 TPS |
| **State proofs** | SP1 STARK recursive proofs | Optional or none |
| **Smart contracts** | WASM with fuel metering, no floats | EVM / WASM / Move |
| **State anchoring** | Arweave + Berachain | Self-hosted or single DA layer |
| **State queries** | SQL over HTTP (`/query`) | Requires external indexer |
| **Token** | None (reputation-based) | Required for staking/gas |
| **Operational cost** | Cloudflare free tier ($0) | $500–$5000+/month per validator |

## Try It

Persistia is live with a 3-validator cluster on Cloudflare's edge. The dashboard, consensus, gossip, ZK proofs, and contract runtime are all running on the free tier.

The codebase is structured as:
- `src/` — TypeScript: Durable Object consensus, gossip, contract executor, anchoring
- `contracts/zk/` — Rust: SP1 zkVM prover, guest program, shared types
- `contracts/persistia-sdk/` — Rust: SDK for writing smart contracts
- `contracts/cosmwasm-compat/` — Rust: CosmWasm compatibility layer
- `client/` — Dashboard, wallet, and client library

We're actively working on expanding the contract ecosystem, improving proof generation throughput, and building the Berachain verification bridge. If you're interested in building on infrastructure that doesn't require you to run infrastructure, Persistia is worth a look.

---

*Persistia is open source. Star the repo, deploy a validator, or port your CosmWasm contracts — contributions welcome.*
