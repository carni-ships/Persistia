# Persistia

A decentralized BFT consensus ledger running on Cloudflare Workers with zero-knowledge state proofs, WASM smart contracts, and dual-layer state anchoring.

## Architecture

- **Consensus**: Bullshark DAG-based BFT with 12s rounds, quorum-gated advancement, leader-based commit rule
- **Infrastructure**: Cloudflare Workers + Durable Objects — each validator is a DO shard
- **Smart Contracts**: WASM runtime with register-based ABI, fuel metering, float ban, cross-contract calls
- **ZK Proofs**: SP1 STARK recursive proof chain with batch proving (up to 32 blocks per proof)
- **Anchoring**: Dual-layer to Arweave (via Irys) and Berachain (EVM L1)
- **Wallet**: Ed25519 keys with Bech32 addresses (`persistia1...`), token transfers, nonce-based replay protection
- **MPP**: Machine Payment Protocol (HTTP 402) for paid API access

## Quick Start

```bash
npm install
npx wrangler deploy
```

### Multi-Node Setup

Deploy and register a 3-node cluster:

```bash
BASE="https://your-worker.workers.dev"

# Register peers (full mesh)
curl -X POST "$BASE/addNode?shard=node-1" -H "Content-Type: application/json" \
  -d '{"url":"'$BASE'/?shard=node-2"}'
curl -X POST "$BASE/addNode?shard=node-1" -H "Content-Type: application/json" \
  -d '{"url":"'$BASE'/?shard=node-3"}'
# Repeat for node-2 and node-3...
```

Consensus activates automatically when 3+ nodes are registered and producing vertices.

### Dashboard

Visit `https://your-worker.workers.dev/dashboard?shard=node-1` for real-time DAG visualization, validator status, ZK proof progress, and contract deployments.

### Wallet

Visit `https://your-worker.workers.dev/wallet` to manage Ed25519 keys, view balances, and send token transfers. Use the faucet endpoint to get test tokens.

### Join an Existing Network

See [`join/README.md`](join/README.md) to deploy your own validator node and connect to the live network.

## Project Structure

```
src/
  PersistiaDO.ts          # Main Durable Object — consensus, events, routing
  consensus.ts            # Pure consensus functions (quorum, leader, topological sort, commit rule)
  gossip.ts               # Node-to-node gossip protocol
  node-identity.ts        # Ed25519 key management and signing
  wallet.ts               # Bech32 addresses, account model, token transfers
  contract-executor.ts    # WASM smart contract runtime
  state-proofs.ts         # Incremental Merkle tree and state commitments
  anchoring.ts            # Arweave + Berachain state anchoring
  cross-shard.ts          # Cross-shard message relay (notes + nullifiers)
  mpp.ts                  # Machine Payment Protocol (HTTP 402)
  oracle.ts               # Decentralized oracle with multi-node aggregation
  triggers.ts             # Scheduled contract execution (cron)
  validator-registry.ts   # PoW-based Sybil resistance and reputation tracking
  types.ts                # Shared type definitions
  index.ts                # Worker entry point and HTTP routing

client/
  dashboard.html          # Real-time DAG explorer and chain monitor
  wallet.html             # Key management, balances, and transfers
  game.html               # Minecraft-lite game client
  script.js               # Game client library

contracts/
  persistia-sdk/          # Rust SDK for writing smart contracts
  cosmwasm-compat/        # CosmWasm compatibility layer
  example-counter/        # Example counter contract
  zk/
    program/              # SP1 guest program (what the proof verifies)
    prover/               # SP1 prover binary (generates proofs)
    types/                # Shared Rust types for ZK system

join/
  README.md               # How to join the network
  setup.sh                # Automated node setup script
  wrangler.toml           # Wrangler config for external nodes

blog/
  introducing-persistia.md  # Technical blog post
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/dag/status` | GET | Chain status (round, active nodes, finalized seq) |
| `/dag/vertices?round=N` | GET | Vertices at a specific round |
| `/event` | POST | Submit a signed event |
| `/sync?after=N` | GET | Fetch finalized events after sequence N |
| `/state` | GET | Full state snapshot |
| `/wallet/info?pubkey=X` | GET | Account info and balances |
| `/wallet/address?pubkey=X` | GET | Derive Bech32 address from pubkey |
| `/wallet/balance?address=X` | GET | Token balances |
| `/wallet/faucet` | POST | Mint test tokens |
| `/contract/deploy` | POST | Deploy WASM contract |
| `/contract/call` | POST | Call contract method |
| `/contract/query` | GET | Read-only contract query |
| `/proof/zk/status` | GET | ZK proof chain status |
| `/proof/zk/submit` | POST | Submit a ZK proof |
| `/admin/peers` | GET | Active validator list |
| `/addNode` | POST | Register a gossip peer |
| `/gossip/sync` | GET | Pull vertices from peer |
| `/anchor/latest` | GET | Latest state anchor |
| `/network` | GET | Node identity and capabilities |
| `/join` | POST | Register an external node with seed shards |
| `/validator/register` | POST | Register as validator (with PoW) |
| `/validator/list` | GET | Active validators and quorum info |
| `/mpp/info` | GET | Payment requirements for protected routes |
| `/mpp/receipts?payer=X` | GET | Payment receipts for an address |
| `/headers/latest` | GET | Latest light client block header |
| `/notes/create` | POST | Create a cross-shard note |
| `/notes/consume` | POST | Consume a note (with nullifier) |
| `/covenant/create` | POST | Create a covenant state machine |

## Smart Contracts

Contracts are written in Rust, compiled to `wasm32-unknown-unknown`, and deployed as signed events.

```rust
use persistia_sdk::*;

#[no_mangle]
pub extern "C" fn increment() {
    let key = b"count";
    let current: u64 = storage_read(key)
        .map(|v| u64::from_le_bytes(v.try_into().unwrap_or([0; 8])))
        .unwrap_or(0);
    storage_write(key, &(current + 1).to_le_bytes());
    set_return(&(current + 1).to_le_bytes());
}
```

Build and deploy:
```bash
cd contracts/example-counter
cargo build --target wasm32-unknown-unknown --release
# Then POST the .wasm binary (base64-encoded) to /contract/deploy
```

CosmWasm contracts can be ported using the `cosmwasm-compat` crate — swap imports and rebuild.

## ZK Prover

Run the prover against a live node:

```bash
cd contracts/zk/prover
./run-local.sh watch --node "https://your-worker.workers.dev/?shard=node-1"
```

The prover watches for new committed rounds, generates SP1 STARK proofs, and submits them back to the chain. Supports batch mode (`--batch N`) for amortizing proof overhead.

## Key Design Decisions

- **No native token**: Validators participate based on reputation, not stake
- **Bech32 addresses**: Compatible with Cosmos ecosystem address format (`persistia1...`)
- **Deterministic execution**: No floats, no WASI, fuel-metered WASM
- **Dual anchoring**: Arweave (permanent) + Berachain (EVM L1) for redundancy
- **Edge-native**: Runs entirely on Cloudflare's free tier
