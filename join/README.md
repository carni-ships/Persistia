# Join the Persistia Network

Run your own Persistia validator node on Cloudflare Workers (free tier).

## Quick Start

```bash
git clone <repo-url> persistia && cd persistia
npm install
cd join
chmod +x setup.sh
./setup.sh
```

The script will:
1. Install dependencies
2. Authenticate with Cloudflare (`npx wrangler login` if needed)
3. Deploy your node as a CF Worker
4. Register with the seed nodes
5. Start syncing

## Manual Setup

### 1. Deploy

Edit `join/wrangler.toml` — uncomment and set `NODE_URL` to your worker URL:

```toml
[vars]
NODE_URL = "https://persistia-node.YOUR_SUBDOMAIN.workers.dev"
SEED_NODES = "https://persistia.carnation-903.workers.dev/?shard=node-1,..."
```

Deploy from the repo root:

```bash
npx wrangler deploy -c join/wrangler.toml
```

### 2. Join the Network

Register your node with the seed nodes:

```bash
curl -X POST https://persistia.carnation-903.workers.dev/join \
  -H "Content-Type: application/json" \
  -d '{"url":"https://persistia-node.YOUR_SUBDOMAIN.workers.dev"}'
```

### 3. Verify

```bash
# Check your node status
curl https://persistia-node.YOUR_SUBDOMAIN.workers.dev/dag/status

# Should show active_nodes >= 3 and current_round advancing
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Game world UI |
| `/dashboard` | DAG consensus visualizer |
| `/dag/status` | Consensus status JSON |
| `/network` | Node identity + peer list |
| `/validator/list` | Active validators |

## Architecture

Each node is a Cloudflare Durable Object with:
- **BFT consensus** — Bullshark DAG with 12s rounds
- **Gossip protocol** — Automatic peer discovery and vertex propagation
- **State proofs** — Sparse Merkle Tree with ZK-provable state roots
- **WASM contracts** — Deploy and call smart contracts

Nodes sync via HTTP gossip (`/gossip/push`, `/gossip/sync`) and WebSocket for real-time updates.

## Network Info

| Seed Node | URL |
|-----------|-----|
| node-1 | `https://persistia.carnation-903.workers.dev/?shard=node-1` |
| node-2 | `https://persistia.carnation-903.workers.dev/?shard=node-2` |
| node-3 | `https://persistia.carnation-903.workers.dev/?shard=node-3` |

Discovery: `GET https://persistia.carnation-903.workers.dev/network?shard=node-1`
