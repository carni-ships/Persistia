# Persistia: BFT Consensus at the Edge

**A decentralized ledger that runs on Cloudflare Workers, proves state with zero-knowledge proofs, and anchors to Berachain.**

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

The SP1 prover watches committed rounds and generates **STARK proofs** that attest to three properties: BFT quorum signatures were valid, the Merkle state root transition is correct, and the previous proof in the chain verifies. Any third party can verify the proof without trusting the validators.

#### Recursive Proofs (IVC)

The key design choice is **Incrementally Verifiable Computation (IVC)**: each proof includes a verification of the *previous* proof as part of its circuit. This creates a cryptographic chain stretching back to genesis — proof N attests to the validity of all state transitions from block 0 through block N.

This recursion has three major benefits:

1. **Constant verification cost.** A verifier only needs to check the latest proof. It doesn't matter whether the chain has 100 blocks or 10 million — the verification time and proof size are the same (~200ms, ~few KB). This is what makes the light client practical: verify one proof, trust the entire history.

2. **No trusted checkpoints.** Traditional light clients bootstrap from a trusted recent state (Ethereum's sync committees, Cosmos's trusted height). With a recursive proof chain, the genesis block *is* the trust root, and the latest proof cryptographically covers every state transition since then. There's nothing to trust except math.

3. **Composable bridging.** A Berachain smart contract that can verify one SP1 proof can verify the entire Persistia chain. This makes the anchoring bridge trustless: the contract checks the proof, extracts the state root, and knows it's valid without relying on any multisig, oracle, or committee.

#### Batch Proving

The prover supports batch mode (up to 32 blocks per proof), amortizing the fixed overhead of proof generation. On consumer hardware, this brings the amortized cost to ~1–3 minutes per block. The batch boundary is also the IVC step boundary — each batch proof verifies the previous batch proof, maintaining the recursive chain.

### Level 4: DA Anchored — minutes

State roots and metadata are anchored to **Berachain** (EVM-compatible L1 with Proof of Liquidity consensus). Even if every Persistia validator disappears, the state history is recoverable from the Berachain anchor transactions. This is the strongest finality: independently verifiable and permanently stored on an external EVM L1.

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

## Autonomous Execution: Contracts That Wake Themselves Up

On nearly every blockchain, smart contracts are inert. They sit in storage until an externally owned account (EOA) submits a transaction that invokes them. A lending protocol can't liquidate an undercollateralized position on its own — it needs a keeper bot watching off-chain and submitting a transaction at the right moment. A subscription service can't charge monthly fees without someone calling the `charge()` function. A game can't advance its world state without a crank-turner.

This is such a fundamental constraint that entire businesses exist to work around it: Chainlink Automation (formerly Keepers), Gelato Network, OpenZeppelin Defender. These are centralized or semi-centralized services that monitor conditions off-chain and submit transactions on behalf of contracts. They add latency, cost, and a trust dependency on a third party.

Persistia doesn't have this limitation. Contracts can register **triggers** — scheduled method calls that the infrastructure executes autonomously, without any external transaction.

### How Triggers Work

A contract calls the `trigger_manage` host function to register a trigger:

```
{
  "action": "create",
  "method": "update_prices",      // method to call
  "interval_ms": 60000,           // every 60 seconds
  "max_fires": 0                  // 0 = unlimited
}
```

The trigger is stored in the `triggers` table. On every alarm cycle (~12 seconds), the Durable Object checks for due triggers:

1. `getDueTriggers()` — find all triggers where `next_fire <= now`
2. `contractExecutor.call()` — execute the contract method, with the trigger ID as the caller identity
3. `markFired()` — advance `next_fire` by the interval, increment the fire count, disable if `max_fires` reached
4. Process any emitted side effects — the triggered call can itself create new triggers or request oracle data

The DO alarm scheduler adapts: `scheduleAlarm()` picks `min(next_round_time, next_trigger_fire)`, so triggers aren't bottlenecked by the consensus round interval. A trigger with a 10-second interval will fire at approximately 10-second intervals, not 12.

### What This Enables

- **Self-liquidating lending**: The contract checks collateral ratios on its own schedule and liquidates when conditions are met — no keeper bot
- **Subscription billing**: A SaaS contract charges users every month by calling its own `charge()` method
- **Game loops**: A world contract advances NPC behavior, weather, resource regeneration every N seconds
- **Recurring oracle refreshes**: A trigger calls `refresh_price()` which emits an oracle request, and the oracle callback updates the price feed — fully autonomous data pipeline
- **Self-destruct timers**: A contract schedules its own cleanup after an expiration period

### Composability: Triggers + Oracles

Triggered calls can emit oracle requests, and oracle callbacks can create new triggers. This creates autonomous feedback loops:

```
Trigger fires every 60s → contract calls refresh_price()
  → emits oracle_request("https://api.coingecko.com/...")
  → oracle system fetches with multi-node consensus
  → callback delivers price to contract
  → contract updates state, checks thresholds
  → if price crossed threshold → emits new trigger for emergency action
```

No human in the loop. No keeper bot. No Gelato subscription. The contract drives its own execution lifecycle.

### Constraints

- Minimum interval: 10 seconds (prevents alarm spam)
- Maximum interval: 24 hours
- Per-contract limit: 10 active triggers
- Fuel metering applies: triggered calls consume fuel like any contract call
- Only the creator can remove a trigger

The key insight is architectural: because Persistia validators are Durable Objects with a built-in alarm scheduler, autonomous execution is free. It's not a service bolted on — it's a consequence of running consensus on infrastructure that already has a cron primitive.

## Reading Web2 Data: Native Oracles

On Ethereum, if your contract needs an off-chain data point — a price, a weather reading, an API response — you have three options: deploy a Chainlink oracle network ($$$), run your own relay bot (centralized), or use a commit-reveal scheme (complex, slow). The problem is fundamental: EVM execution is deterministic and isolated. Contracts can't call `fetch()`.

Persistia contracts can. The oracle system is a native host function, not an external service.

### How It Works

A contract calls the `oracle_request` host function with a URL, a callback method, an aggregation strategy, and an optional JSON path:

```
oracle_request(
  url: "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd",
  callback: "on_price_received",
  aggregation: "median",
  json_path: "ethereum.usd"
)
```

The request is emitted as a side effect during contract execution and stored in the `oracle_requests` table. On the next alarm cycle, `processPendingOracles()` picks it up:

**Single-node mode:** The node fetches the URL, extracts the value at the JSON path, and delivers it directly to the contract's callback method.

**Multi-node mode:** Each validator independently fetches the URL and stores its result. When enough responses arrive (quorum = 2f+1), the results are aggregated and the consensus value is delivered to the contract callback. This prevents any single node from injecting false data.

### Aggregation Strategies

| Strategy | Behavior | Use Case |
|----------|----------|----------|
| `identical` | All nodes must return the exact same value | Deterministic APIs (block heights, hashes) |
| `median` | Numeric median of all responses | Price feeds, temperature readings |
| `majority` | Most common value if it meets quorum | Enum data, status checks |

### The Callback Pattern

The oracle delivers data by calling the contract's specified callback method with the result as input. The contract processes it like any other call — it can update storage, emit events, create triggers, or make further oracle requests:

```rust
#[no_mangle]
pub extern "C" fn on_price_received() {
    let data = input();  // oracle delivers: { value: "3521.42", sources: 3 }
    let price: f64 = parse_price(&data);
    storage_write(b"eth_price", &price.to_le_bytes());

    // React to the data autonomously
    if price < threshold() {
        // emit another oracle request, create a trigger, etc.
    }
}
```

### Why This Is Different

On Ethereum, Chainlink nodes are a separate network with their own token economics, their own consensus, and their own trust assumptions. The data path is: Chainlink nodes fetch → aggregate off-chain → submit on-chain transaction → your contract reads the result. It's an entire parallel infrastructure.

On Persistia, the validators *are* the oracle nodes. They already run 24/7, they already have BFT consensus, and they already execute contract callbacks. The oracle is just another host function — `fetch()` with consensus. No additional network, no additional token, no additional trust assumption beyond what you already trust for consensus itself.

This makes data-driven contracts economically viable at any scale. A contract that needs a price feed every minute doesn't need to pay Chainlink's fee per update — it registers a trigger and an oracle request, and the infrastructure handles the rest at zero marginal cost.

### JSON Path Extraction

The `json_path` parameter supports dot-notation traversal (`data.price`, `items.0.name`), extracting nested values from complex API responses without burdening the contract with JSON parsing. The extraction happens node-side before aggregation.

## State Anchoring: Berachain

Persistia anchors finalized state to **Berachain**, an EVM-compatible L1 secured by Proof of Liquidity consensus.

State roots and ZK proof commitments are published on-chain as HYTE-encoded calldata sent to the dead address (`0x...dEaD`), making them permanently retrievable via `eth_getTransactionByHash`. Optionally, structured data is also written to a HyberDB contract for on-chain queryability.

This creates a trust bridge: Berachain contracts can act on Persistia-proven state, and Persistia can reference Berachain finality as an external checkpoint. Even if every Persistia validator goes offline, the full state history is recoverable from Berachain anchor transactions.

## Machine Payment Protocol (MPP): HTTP 402 for the Machine Economy

APIs are increasingly consumed by autonomous agents — LLMs calling tools, bots executing workflows, IoT devices requesting data. These machine-to-machine interactions need a payment layer that works at HTTP speed, without human intervention, browser redirects, or API key provisioning.

Persistia implements **MPP (Machine Payment Protocol)**, a native HTTP 402-based payment flow built directly into the consensus layer:

1. **Client requests a protected resource** → server responds `402 Payment Required` with a `WWW-Authenticate: Payment` header containing the challenge (amount, recipient address, denomination, expiry).
2. **Client pays on-chain** → submits a `token.transfer` event to Persistia targeting the specified recipient address with the required amount.
3. **Client retries with credential** → includes `Authorization: Payment <base64-credential>` header containing the challenge ID, transaction hash, and payer address.
4. **Server verifies on-chain** → checks that a matching transfer event exists in the finalized ledger, marks the challenge consumed, and serves the resource with a `Payment-Receipt` header.

The entire flow is machine-readable. No OAuth, no API keys, no billing dashboards. An LLM agent that encounters a 402 can parse the challenge, execute the payment, and retry — all programmatically.

### Why This Matters

Most payment-for-API solutions today involve Stripe subscriptions, prepaid credits, or centralized billing APIs — all designed for humans clicking through UIs. The 402 status code has existed since HTTP/1.1 but was "reserved for future use" because there was no good way to make it work without a payment rail native to the web.

Persistia provides that rail. Token transfers finalize in ~24 seconds (BFT commit), the challenge-response flow uses standard HTTP headers, and the payment verification happens against the same consensus layer that serves the data. There's no external payment processor in the loop.

This enables:

- **Paid API endpoints** on any Persistia-hosted service, with per-request pricing
- **Agent-to-agent commerce** — autonomous programs buying data, compute, or services from each other
- **Micropayments** — sub-cent payments are practical because there are no gas fees inside Persistia
- **Metered access** — pay-per-query for oracle data, contract state reads, or premium chain analytics

Routes are configured declaratively — specify a URL prefix, price, and denomination, and MPP handles challenge generation, credential verification, and receipt issuance automatically.

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

## HTTP-Native Light Clients

Most blockchains require specialized libraries to verify state — ethers.js for Ethereum, cosmjs for Cosmos, custom RPC clients for Solana. Light clients are separate binaries that must implement the chain's wire protocol, handle peer discovery, and maintain header sync. Building one is a multi-month engineering effort.

Persistia doesn't need a separate light client implementation. The HTTP API *is* the light client protocol.

### Verifying State in Three Requests

Any environment with `fetch()` and an Ed25519 library can trustlessly verify Persistia state:

**1. Get the latest header with its BFT certificate**

```
GET /headers/latest?shard=node-1
```

Returns the block header (state root, previous header hash, validator set hash, timestamp) plus a `bft_certificate` — an array of Ed25519 signatures from the validators who committed this round:

```json
{
  "block_number": 5180,
  "state_root": "e3b0c44298fc1c...",
  "prev_header_hash": "a7ffb7eb4a743c...",
  "validator_set_hash": "3c06073acb525c...",
  "bft_certificate": [
    { "pubkey": "J90nWC...", "signature": "Om7yr+...", "round": 5180 },
    { "pubkey": "ME5YS9...", "signature": "Iuoh3Y...", "round": 5180 },
    { "pubkey": "GhZuLr...", "signature": "My6eIx...", "round": 5180 }
  ]
}
```

Verify: check that the Ed25519 signatures are valid, the signers are in the known validator set, and the count meets quorum (2f+1). If all three checks pass, the state root is consensus-approved.

**2. Request a Merkle proof for any state key**

```
GET /proof/generate?key=contract:abc123:count
```

Returns a sparse Merkle tree proof — the sibling hashes along the path from the leaf to the root, plus a direction array indicating left/right at each level:

```json
{
  "key": "contract:abc123:count",
  "value": "0x0500000000000000",
  "siblings": ["a1b2c3...", "d4e5f6...", ...],
  "directions": [0, 1, 1, 0, ...],
  "root": "e3b0c44298fc1c...",
  "inclusion": true
}
```

**3. Verify locally**

Recompute the Merkle root from the leaf hash and sibling path. If it matches the state root from the BFT-certified header, the value is proven — no trust in any individual node required.

```javascript
// ~30 lines of verification logic
let hash = sha256("leaf:" + sha256(key) + ":" + value);
for (let i = 0; i < siblings.length; i++) {
  hash = directions[i] === 0
    ? sha256(hash + siblings[i])
    : sha256(siblings[i] + hash);
}
assert(hash === header.state_root); // proven
```

The entire verification runs client-side. The node could be malicious — it can't forge a proof that passes verification against a BFT-certified root.

### Non-Inclusion Proofs

The sparse Merkle tree also supports **non-inclusion proofs**: cryptographic proof that a key does *not* exist in the state. The proof shows where the path diverges from any existing leaf, with a `closest_key` and `diverge_depth`. This lets a light client prove negative facts — "this contract has no key called X" — which is impossible with most Merkle Patricia tries without scanning the entire trie.

### Cross-Checking Against External Anchors

For the highest assurance, light clients can verify the state root against Persistia's Berachain anchor:

- **Berachain**: Fetch the anchor transaction via `eth_getTransactionByHash` and decode the HYTE-formatted calldata. The state root is embedded in an EVM L1 transaction, verifiable by any Ethereum-compatible client.

If the state root in the BFT-certified header matches the root anchored to Berachain, the client has two independent confirmations: validator consensus and an EVM L1 chain.

### Why This Matters

Traditional light clients exist to avoid downloading the full chain. But they still require: a specialized binary, a peer discovery mechanism, a header sync protocol, and often a trusted checkpoint. Persistia collapses all of this into standard HTTP endpoints.

This means:
- **Mobile apps** can verify state with a single network request + local hash computation
- **Browser extensions** can prove token balances without running a node
- **IoT devices** can verify contract state with minimal compute
- **Cross-chain bridges** can verify Persistia state from any environment that supports HTTP and SHA-256
- **CI/CD pipelines** can assert on-chain state as part of deployment verification

No library to install. No protocol to implement. No peers to discover. Just `fetch()`, `sha256()`, and `ed25519.verify()`.

## Fully On-Chain Applications

Most "decentralized apps" aren't. The smart contract runs on-chain, but the frontend is hosted on Vercel, the backend talks to a centralized API, and the governance is a Discord vote. The app isn't on-chain — just the settlement layer is.

Persistia is different because the consensus network **is** an HTTP server. Cloudflare Workers serve web requests at the edge, and Durable Objects provide persistent state. This means a Persistia node can serve a complete web application — HTML, CSS, JavaScript — directly from contract state, with no external hosting.

### How It Works

1. **Deploy a WASM contract** with your business logic (storage, token mechanics, access control)
2. **Upload frontend files** to the contract's state via `app.upload` events — HTML, CSS, JS stored as key-value pairs under the `_app/` prefix
3. **Visit `/app/{contract_address}/`** — the node reads frontend files from contract state and serves them with proper MIME types
4. **The frontend calls its own contract** via `/contract/query` and `/contract/call` endpoints, signing transactions with Ed25519 keys

The entire application — frontend, backend logic, state, payments, governance — lives on the consensus network.

### The Full Stack

Every layer of a traditional web application has an on-chain equivalent in Persistia:

| Layer | Traditional | Persistia On-Chain |
|-------|------------|-------------------|
| **Frontend** | Vercel, Netlify, S3 | Contract state served at `/app/{addr}/` |
| **Backend Logic** | Express, Django, Rails | WASM smart contracts with cross-contract calls |
| **Database** | PostgreSQL, MongoDB | Contract KV storage + SQL over the chain |
| **Authentication** | OAuth, JWT, sessions | Ed25519 signatures on every request |
| **Payments** | Stripe, PayPal | MPP (HTTP 402) with on-chain token transfers |
| **Cron Jobs** | AWS Lambda, crontab | Triggers (DO alarms with configurable intervals) |
| **External Data** | API calls, webhooks | Oracles (multi-node consensus on off-chain data) |
| **CDN / Hosting** | Cloudflare, AWS | Consensus network IS the CDN (300+ edge locations) |
| **Governance** | Discord votes, multisig | Reputation-weighted on-chain voting |
| **State Proofs** | Trust the server | Merkle proofs + recursive ZK proof chain |
| **Cross-Service** | REST APIs, gRPC | Cross-shard messaging with nullifier-based atomicity |
| **Privacy** | Hope the DB isn't leaked | Commitment-based private state, notes + nullifiers |

### Developer Experience

The `PersistiaApp` SDK (served at `/app/sdk.js`) provides a client-side library:

```javascript
const app = new PersistiaApp({ contract: "abc123..." });

// Read state (no signature needed)
const count = await app.query("get_count");

// Mutate state (requires Ed25519 keypair)
const keypair = await PersistiaApp.generateKeypair();
await app.call("increment", new Uint8Array(), keypair);

// Real-time updates via WebSocket
app.connect();
app.on("contract.called", (msg) => console.log("State changed:", msg));
```

### Why This Matters

When your frontend, contracts, payments, governance, and data all live on the same consensus network, you get properties that are impossible with the typical dApp architecture:

- **Atomic deploys**: Frontend + contract upgrade in one signed event
- **No DNS dependency**: Apps are addressable by contract address
- **MPP-gated apps**: The entire app can be behind a paywall, verified on-chain
- **Provable state**: Every piece of data the UI shows is backed by a Merkle proof
- **No vendor lock-in**: Any Persistia node can serve the app — there's no single hosting provider to depend on

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
| **State anchoring** | Berachain (EVM L1) | Self-hosted or single DA layer |
| **State queries** | SQL over HTTP (`/query`) | Requires external indexer |
| **Token** | None (reputation-based) | Required for staking/gas |
| **Light client** | 3 HTTP requests + local hash verification | Dedicated binary or trusted RPC |
| **Operational cost** | Cloudflare free tier ($0) | $500–$5000+/month per validator |

## Try It

Persistia is live with a 3-validator cluster on Cloudflare's edge. The dashboard, consensus, gossip, ZK proofs, and contract runtime are all running on the free tier.

The codebase is structured as:
- `src/` — TypeScript: Durable Object consensus, gossip, contract executor, anchoring
- `contracts/zk/` — Rust: SP1 zkVM prover, guest program, shared types
- `contracts/persistia-sdk/` — Rust: SDK for writing smart contracts
- `contracts/cosmwasm-compat/` — Rust: CosmWasm compatibility layer
- `client/` — Dashboard, wallet, and client library

## What's Next: Appchain Rollup Framework

Persistia today is a single network. The next step is making it a **framework** — so anyone can deploy their own BFT chain with a single command, secured by restaked tokens, with built-in cross-chain services.

Three interlocking products:

- **Appchain Rollups.** Fork Persistia, configure your consensus parameters (round time, staking token, anchor chain), and `npx wrangler deploy`. You get BFT consensus, WASM contracts, oracles, cron, payments, and frontend hosting — all for $0 on Cloudflare's free tier. No other rollup framework offers this: OP Stack and Cosmos SDK require dedicated servers and weeks of setup. Persistia collapses that to minutes.

- **Cross-Chain Execution Runtime.** Persistia validators already run 24/7 on Cloudflare's edge, fetch external data with multi-node consensus, and execute scheduled tasks. The leap: instead of only serving Persistia contracts, these validators can execute tasks for *any* chain — oracle data feeds, automated liquidations, verified off-chain computation, cross-chain message relay. Same capabilities as Chainlink's CRE, but with BFT consensus on every output and ZK proofs for trustless verification.

- **Restaking Security.** Rather than bootstrapping a new token for each appchain, validators can stake existing tokens (ETH, BERA, any ERC-20) on L1. Persistia observes the stake via its oracle system, admits the validator with proportional weight, and slashes via ZK-proven misbehavior evidence submitted to the L1 staking contract. One restaked position can secure multiple appchains simultaneously.

These create a flywheel: more appchains deployed means more validators needed, which increases restaking demand, which improves oracle security, which attracts more external chains, which drives more appchain demand. The infrastructure layer is already built — what comes next is making it composable.

---

*Persistia is open source. Star the repo, deploy a validator, or port your CosmWasm contracts — contributions welcome.*
