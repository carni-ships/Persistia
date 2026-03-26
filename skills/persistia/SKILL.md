---
name: persistia
description: Set up, join, and interact with the Persistia decentralized ledger network on Cloudflare Workers
version: 0.5.0
author: carni-ships
tags: [blockchain, cloudflare-workers, bft-consensus, wasm-contracts, web3]
---

# Persistia Network Skill

Help users set up, deploy, join, and interact with the Persistia decentralized BFT consensus ledger running on Cloudflare Workers.

## What is Persistia?

Persistia is a decentralized BFT consensus ledger on Cloudflare Workers with:
- **Bullshark DAG-based BFT consensus** (12s rounds, quorum-gated)
- **WASM smart contracts** (Rust SDK, register-based ABI, fuel metering)
- **SP1 STARK recursive ZK proofs** (IVC, batch proving up to 32 blocks)
- **Berachain state anchoring** (EVM L1 via HYTE-encoded calldata)
- **On-chain app hosting** (frontends served from contract state)
- **Ed25519 wallet** with Bech32 addresses (`persistia1...`)
- **Decentralized oracles**, scheduled triggers, cross-shard relay, Machine Payment Protocol

## Live Network

| Seed Node | URL |
|-----------|-----|
| node-1 | `https://persistia.carnation-903.workers.dev/?shard=node-1` |
| node-2 | `https://persistia.carnation-903.workers.dev/?shard=node-2` |
| node-3 | `https://persistia.carnation-903.workers.dev/?shard=node-3` |

Discovery endpoint: `GET https://persistia.carnation-903.workers.dev/network?shard=node-1`

## Prerequisites

- Node.js 18+
- npm
- A Cloudflare account (free tier works)
- `npx wrangler login` completed (Cloudflare authentication)

## Setup & Join the Network

### Step 1: Clone and install

```bash
git clone https://github.com/carni-ships/Persistia && cd Persistia
npm install
```

### Step 2: Authenticate with Cloudflare

```bash
npx wrangler login
npx wrangler whoami  # verify it shows your account
```

### Step 3: Configure your node

Edit `join/wrangler.toml` and uncomment/set `NODE_URL` to your worker URL:

```toml
[vars]
NODE_URL = "https://persistia-node.YOUR_SUBDOMAIN.workers.dev"
SEED_NODES = "https://persistia.carnation-903.workers.dev/?shard=node-1,https://persistia.carnation-903.workers.dev/?shard=node-2,https://persistia.carnation-903.workers.dev/?shard=node-3"
```

The subdomain is your Cloudflare workers subdomain (visible in `npx wrangler whoami` output or Cloudflare dashboard).

### Step 4: Deploy

```bash
npx wrangler deploy -c join/wrangler.toml
```

### Step 5: Join the network

Register your node with the seed nodes:

```bash
curl -X POST https://persistia.carnation-903.workers.dev/join \
  -H "Content-Type: application/json" \
  -d '{"url":"https://persistia-node.YOUR_SUBDOMAIN.workers.dev","shard":"global-world"}'
```

### Step 6: Verify

```bash
curl https://persistia-node.YOUR_SUBDOMAIN.workers.dev/dag/status
# Should show active_nodes >= 3 and current_round advancing
```

### Automated setup (alternative)

Instead of steps 3-6, run the automated script:

```bash
cd join && chmod +x setup.sh && ./setup.sh
```

## Using the CLI

The CLI is at `cli/persistia.ts`. Run via:

```bash
npm run cli -- <command> [args] [--node <url>]
```

Or set the node URL via environment variable:

```bash
export PERSISTIA_NODE="https://persistia-node.YOUR_SUBDOMAIN.workers.dev"
```

### Key commands

| Command | Description |
|---------|-------------|
| `status` | Node status and info |
| `keys` | Show or generate Ed25519 keypair (stored at `~/.persistia/keys.json`) |
| `consensus` | DAG consensus status (current round, active nodes, finality) |
| `peers` | List known peers |
| `deploy <contract.wasm>` | Deploy a WASM smart contract |
| `call <address> <method> [args]` | Call a contract method (creates consensus event) |
| `query <address> <method> [args]` | Read-only contract query (no event) |
| `info <address>` | Get contract metadata |
| `trigger-create <addr> <method> <ms>` | Create a cron trigger for scheduled execution |
| `trigger-list <address>` | List triggers for a contract |
| `oracle-request <addr> <cb> <url>` | Request oracle data fetch |
| `register <peer_url>` | Register a peer node |
| `zk-status` | ZK proof coverage status |
| `zk-latest` | Latest ZK proof info |
| `zk-get <block>` | Get ZK proof for a specific block |

## Writing Smart Contracts

Contracts are written in Rust using the Persistia SDK. Example counter contract:

```bash
cd contracts/example-counter
cargo build --target wasm32-unknown-unknown --release
npm run cli -- deploy target/wasm32-unknown-unknown/release/counter.wasm
npm run cli -- call <address> increment
npm run cli -- query <address> get_count
```

Contract templates available in `contracts/`:
- `example-counter/` — Simple counter
- `example-oracle/` — Oracle request example
- `token-standard/` — Token/NFT standard
- `cosmwasm-compat/` — CosmWasm compatibility layer
- `persistia-sdk/` — Rust SDK for writing contracts

## Web Dashboards

| Dashboard | Path | Description |
|-----------|------|-------------|
| Game World | `/` | Minecraft-lite game client |
| DAG Visualizer | `/dashboard` | Real-time DAG consensus visualization |
| ZK Verifier | `/verifier` | Verify ZK proof chain integrity |
| Wallet | `/wallet` | Key management and token transfers |

## HTTP API Reference

### Node status
- `GET /` — Node info
- `GET /dag/status` — Consensus status (round, nodes, finality)
- `GET /network` — Node identity + peer list
- `GET /validator/list` — Active validators

### Contracts
- `POST /contract/deploy` — Deploy WASM contract (signed)
- `POST /contract/call` — Call contract method (signed, creates event)
- `GET /contract/query?address=X&method=Y` — Read-only query
- `GET /contract/info?address=X` — Contract metadata

### Gossip & peering
- `POST /join` — Register a new node with the network
- `POST /gossip/push` — Push DAG vertices to peer
- `POST /gossip/sync` — Sync DAG state with peer
- `GET /admin/peers` — List known peers
- `POST /admin/register` — Register peer (signed)

### ZK proofs
- `GET /proof/zk/status` — Proof coverage status
- `GET /proof/zk/latest` — Latest proof
- `GET /proof/zk/get?block=N` — Proof for specific block

### On-chain apps
- `GET /app/{address}/` — Serve frontend from contract state
- `GET /app/{address}/{path}` — Serve specific file

## Architecture Notes

- Each node is a **Cloudflare Durable Object** with SQLite state
- Nodes gossip via HTTP (`/gossip/push`, `/gossip/sync`) and WebSocket for real-time
- Consensus: Bullshark DAG-BFT with 12s rounds, leader-based commit, quorum-gated
- Keys: Ed25519 PKCS8 stored at `~/.persistia/keys.json`, auto-generated on first CLI use
- Addresses: Bech32 with `persistia1` prefix derived from Ed25519 public key
- All state-changing operations require Ed25519 signatures

## Troubleshooting

- **"Not authenticated"**: Run `npx wrangler login` and retry
- **Node not syncing**: Check that `SEED_NODES` in wrangler.toml points to live seed nodes, and that your `NODE_URL` is correct
- **Deploy fails**: Ensure wasm is built for `wasm32-unknown-unknown` target
- **Consensus not advancing**: Need 3+ active nodes; check `/dag/status` for `active_nodes` count
- **Keys not found**: CLI auto-generates on first use; check `~/.persistia/keys.json`

## Local Development

```bash
npm install
npm run dev  # starts local wrangler dev server at http://localhost:8787
```

For multi-node local testing, use the provided config files:

```bash
npx wrangler dev --config local-node-a.toml &
npx wrangler dev --config local-node-b.toml --port 8788 &
```
