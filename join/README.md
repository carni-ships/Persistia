# Join the Persistia Network

Run your own Persistia node on Cloudflare Workers (free tier) and join the existing chain.

Your node syncs state from the seed nodes via HTTP gossip, participates in BFT consensus by creating DAG vertices, and serves the full dashboard/game UI.

## Quick Start

```bash
git clone https://github.com/carni-ships/Persistia && cd Persistia
npm install
cd join
chmod +x setup.sh
./setup.sh
```

The script will:
1. Authenticate with Cloudflare (`npx wrangler login` if needed)
2. Deploy your node as a CF Worker
3. Register with the seed nodes via `POST /join`
4. Begin syncing chain state

## Manual Setup

### 1. Configure

Edit `join/wrangler.toml` — uncomment and set `NODE_URL`:

```toml
[vars]
NODE_URL = "https://persistia-node.YOUR_SUBDOMAIN.workers.dev"
SEED_NODES = "https://persistia.carnation-903.workers.dev/?shard=node-1,..."
```

### 2. Deploy

```bash
# From the repo root:
npx wrangler deploy -c join/wrangler.toml
```

### 3. Join the network

Register your node with the seed nodes:

```bash
curl -X POST https://persistia.carnation-903.workers.dev/join \
  -H "Content-Type: application/json" \
  -d '{"url":"https://persistia-node.YOUR_SUBDOMAIN.workers.dev"}'
```

Your node will automatically:
- Bootstrap peers from `SEED_NODES` via `/gossip/peers`
- Sync DAG history via `/gossip/sync`
- Start creating vertices once it has enough peers

### 4. Register as Validator (optional)

To participate in consensus as a validator (not just a syncing node), you need to solve a Proof-of-Work and register:

```bash
# Check PoW difficulty
curl https://persistia.carnation-903.workers.dev/validator/registration-info?shard=node-1

# Register on your own node
curl -X POST https://YOUR_NODE/validator/register \
  -H "Content-Type: application/json" \
  -d '{"pubkey":"<your_pubkey>","url":"https://YOUR_NODE","pow_nonce":"<nonce>","signature":"<sig>"}'

# Register on the seeds (so they accept your vertices for consensus)
curl -X POST https://persistia.carnation-903.workers.dev/join \
  -H "Content-Type: application/json" \
  -d '{"url":"https://YOUR_NODE","pubkey":"<pubkey>","pow_nonce":"<nonce>","signature":"<sig>"}'
```

### 5. Verify

```bash
# Check your node status
curl https://YOUR_NODE/dag/status

# Should show:
#   - current_round advancing
#   - active_nodes >= 3
#   - last_committed_round advancing (consensus is working)
```

## How It Works

1. **Gossip is HTTP** — all node-to-node communication uses standard HTTP endpoints (`/gossip/push`, `/gossip/sync`, `/gossip/peers`). No special transport layer needed.
2. **Peer discovery** — your node reads `SEED_NODES` on startup, calls `bootstrapFromSeeds()` to discover peer identities and URLs, then syncs DAG vertices.
3. **State sync** — `/gossip/sync?after_round=N` returns up to 2000 vertices per request. Your node catches up incrementally over multiple alarm cycles.
4. **Vertex creation** — each round (~60s), your node creates a DAG vertex containing pending events and references to prior vertices, then gossips it to all known peers.
5. **Consensus** — Bullshark DAG consensus commits rounds when a quorum of validators reference the round leader's vertex. Your node's vertices contribute to quorum.

## Architecture

```
Your CF Worker                     Seed CF Worker
┌──────────────────┐              ┌──────────────────────────────┐
│ PersistiaWorldV4 │◄──── HTTP ──►│ node-1 │ node-2 │ node-3    │
│ (single DO)      │  /gossip/*   │ (3 DOs on same Worker)       │
│                  │  /validator/* │                              │
│ NODE_URL set     │  /join       │ Shard routing via ?shard=    │
└──────────────────┘              └──────────────────────────────┘
```

External nodes run a single DO (no shard routing). The seed nodes run multiple DOs on one Worker with `?shard=` routing. Gossip works the same way in both cases — it's just HTTP fetch to peer URLs.

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Game world UI |
| `/dashboard` | DAG consensus visualizer |
| `/dag/status` | Consensus status JSON |
| `/network` | Node identity + peer list |
| `/gossip/peers` | Peer exchange |
| `/gossip/sync?after_round=N` | Bulk vertex sync |
| `/validator/list` | Active validators |
| `/validator/registration-info` | PoW difficulty for registration |
| `/governance/config` | Current network parameters |
| `/governance/proposals` | Active governance proposals |

## Network Info

| Seed Node | URL |
|-----------|-----|
| node-1 | `https://persistia.carnation-903.workers.dev/?shard=node-1` |
| node-2 | `https://persistia.carnation-903.workers.dev/?shard=node-2` |
| node-3 | `https://persistia.carnation-903.workers.dev/?shard=node-3` |

Discovery: `GET https://persistia.carnation-903.workers.dev/network?shard=node-1`

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Node stuck at round 0 | Check `SEED_NODES` is set correctly. Hit `/dag/status` — `active_nodes` should be > 0 |
| "Sync rate limited" | Normal during bulk catch-up. Your node retries automatically each alarm cycle |
| No commits advancing | Need quorum (>2/3 of active validators). Check `/validator/list` on a seed node |
| Node URL wrong | Set `NODE_URL` in wrangler.toml to your exact `*.workers.dev` URL and redeploy |
