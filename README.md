# Persistia PoC v0.1 — Decentralized Minecraft-lite on Cloudflare

## Quick Start
1. `npm install`
2. `wrangler deploy` (uses your Cloudflare account)
3. Open `client/index.html` (or deploy to Cloudflare Pages)
4. Play! Build, transfer items, craft.

To add a second node (true decentralization):
- Deploy the same code to another Cloudflare account
- Paste the new Worker URL into the first client's console: `addNode("https://other-worker...")`

World state survives account deletion because the Merkle root can be anchored (see anchor.js).

Next steps (we'll do these together):
- Upgrade to Godot 4 + godot_voxel
- Full SP1 recursive zk proofs
- Real Arweave anchoring
- Multi-zone spatial sharding

Enjoy the persistent universe!