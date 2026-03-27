// ─── Standalone Persistia HTTP Server ────────────────────────────────────────
// Express + ws wrapper around StandaloneNode, exposing the same API surface
// as the Cloudflare DO so that dashboards, provers, and wallets work unchanged.
//
// Usage:
//   tsx src/server.ts --port 3000 --seed-nodes https://persistia.carnation-903.workers.dev?shard=node-1
//   tsx src/server.ts --data-dir ./data --port 8080

import express from "express";
import { WebSocketServer, WebSocket } from "ws";
import { createServer } from "http";
import { StandaloneNode, type NodeConfig } from "./node.ts";

// CJS interop for root src modules
import * as _wallet from "../../src/wallet.ts";
const { pubkeyB64ToAddress } = _wallet;

// ─── CLI Args ────────────────────────────────────────────────────────────────

function parseArgs(): NodeConfig {
  const args = process.argv.slice(2);
  let port = 3000;
  let dataDir = "./data";
  let seedNodes: string[] = [];
  let nodeUrl = "";
  let roundIntervalMs = 60_000;

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--port":
      case "-p":
        port = parseInt(args[++i]) || 3000;
        break;
      case "--data-dir":
      case "-d":
        dataDir = args[++i] || "./data";
        break;
      case "--seed-nodes":
      case "-s":
        seedNodes = (args[++i] || "").split(",").filter(Boolean);
        break;
      case "--node-url":
      case "-u":
        nodeUrl = args[++i] || "";
        break;
      case "--round-interval":
      case "-r":
        roundIntervalMs = parseInt(args[++i]) || 60_000;
        break;
      case "--help":
      case "-h":
        console.log(`
Persistia Standalone Validator Node

Usage: tsx src/server.ts [options]

Options:
  --port, -p          HTTP port (default: 3000)
  --data-dir, -d      SQLite data directory (default: ./data)
  --seed-nodes, -s    Comma-separated seed node URLs
  --node-url, -u      Public URL of this node (auto-detected if omitted)
  --round-interval, -r  Consensus round interval in ms (default: 60000)
  --help, -h          Show this help
`);
        process.exit(0);
    }
  }

  if (!nodeUrl) {
    nodeUrl = `http://localhost:${port}`;
  }

  return { port, dataDir, seedNodes, nodeUrl, roundIntervalMs };
}

// ─── Server ──────────────────────────────────────────────────────────────────

async function main() {
  const config = parseArgs();
  const node = new StandaloneNode(config);

  console.log("╔═══════════════════════════════════════════════╗");
  console.log("║       Persistia Standalone Validator Node     ║");
  console.log("╚═══════════════════════════════════════════════╝");
  console.log(`  Port:       ${config.port}`);
  console.log(`  Data dir:   ${config.dataDir}`);
  console.log(`  Node URL:   ${config.nodeUrl}`);
  console.log(`  Seeds:      ${config.seedNodes.length > 0 ? config.seedNodes.join(", ") : "(none)"}`);
  console.log();

  await node.init();

  const app = express();
  app.use(express.json({ limit: "10mb" }));

  // ─── Helper ──────────────────────────────────────────────────────────

  function json(res: express.Response, data: any, status = 200) {
    res.status(status).json(data);
  }

  function bigintSerializer(_key: string, value: any): any {
    return typeof value === "bigint" ? value.toString() : value;
  }

  function jsonSafe(res: express.Response, data: any, status = 200) {
    res.status(status).type("json").send(JSON.stringify(data, bigintSerializer));
  }

  // ─── Network / Status (default route) ────────────────────────────────

  app.get("/network", (_req, res) => {
    json(res, node.getStatus());
  });

  app.get("/", (_req, res) => {
    json(res, node.getStatus());
  });

  // ─── Gossip Routes (/gossip/*) ───────────────────────────────────────

  app.post("/gossip/push", async (req, res) => {
    try {
      const result = await node.handleGossipPush(req.body);
      json(res, result, result.ok ? 200 : 400);
    } catch (e: any) {
      json(res, { error: e.message }, 500);
    }
  });

  app.get("/gossip/sync", (req, res) => {
    try {
      const afterRound = parseInt(req.query.after_round as string || "0");
      const limit = Math.min(parseInt(req.query.limit as string || "2000"), 2000);
      const syncResp = node.getSyncResponse(afterRound, limit);
      json(res, syncResp);
    } catch (e: any) {
      json(res, { error: e.message }, 500);
    }
  });

  app.get("/gossip/peers", (_req, res) => {
    const peers = node.gossipManager.getHealthyPeers();
    json(res, {
      peers: peers.map(p => ({ pubkey: p.pubkey, url: p.url })),
      node_pubkey: node.nodeIdentity.pubkey,
      node_url: config.nodeUrl,
    });
  });

  app.post("/gossip/peers", async (req, res) => {
    try {
      const envelope = req.body;
      const valid = await node.gossipManager.verifyEnvelope(envelope);
      if (valid && envelope.payload?.peers) {
        for (const p of envelope.payload.peers) {
          if (p.pubkey && p.url) {
            node.gossipManager.addPeer(p.pubkey, p.url);
          }
        }
      }
      if (envelope.sender_pubkey && envelope.sender_url) {
        node.gossipManager.addPeer(envelope.sender_pubkey, envelope.sender_url);
      }
      const peers = node.gossipManager.getHealthyPeers();
      json(res, {
        peers: peers.map(p => ({ pubkey: p.pubkey, url: p.url })),
        node_pubkey: node.nodeIdentity.pubkey,
        node_url: config.nodeUrl,
      });
    } catch (e: any) {
      json(res, { error: e.message }, 500);
    }
  });

  // ─── DAG Routes (/dag/*) ─────────────────────────────────────────────

  app.get("/dag/status", (_req, res) => {
    json(res, {
      current_round: node.currentRound,
      finalized_seq: node.finalizedSeq,
      finalized_root: node.finalizedRoot,
      last_committed_round: node.lastCommittedRound,
      active_nodes: node.getStatus().active_nodes,
      gossip_peers: node.gossipManager.getHealthyPeers().length,
    });
  });

  app.post("/dag/vertex", async (req, res) => {
    try {
      const result = await node.receiveVertex(req.body);
      json(res, result, result.ok ? 200 : 400);
    } catch (e: any) {
      json(res, { error: e.message }, 500);
    }
  });

  app.get("/dag/sync", (req, res) => {
    try {
      const afterRound = parseInt(req.query.after_round as string || "0");
      const limit = Math.min(parseInt(req.query.limit as string || "500"), 500);
      const afterSeq = parseInt(req.query.after_seq as string || "0");

      const vertices = node.sql.exec(
        "SELECT hash, author, round, events_json, refs_json, signature, received_at FROM dag_vertices WHERE round > ? ORDER BY round ASC, hash ASC LIMIT ?",
        afterRound, limit,
      ).map((r: any) => ({
        hash: r.hash, author: r.author, round: r.round,
        events_json: r.events_json, refs_json: r.refs_json, signature: r.signature,
      }));

      const commits = node.sql.exec(
        "SELECT round, anchor_hash, committed_at FROM dag_commits WHERE round >= ? ORDER BY round ASC",
        afterRound,
      );

      const recentEvents = node.sql.exec(
        "SELECT seq, type, payload, pubkey, timestamp FROM events WHERE seq > ? ORDER BY seq ASC LIMIT ?",
        afterSeq, limit,
      ).map((r: any) => ({
        seq: r.seq, type: r.type,
        payload: typeof r.payload === "string" ? r.payload : JSON.stringify(r.payload),
        pubkey: r.pubkey, timestamp: r.timestamp,
      }));

      json(res, {
        vertices, commits, recent_events: recentEvents,
        latest_round: node.currentRound,
        finalized_seq: node.finalizedSeq,
        finalized_root: node.finalizedRoot,
      });
    } catch (e: any) {
      json(res, { error: e.message }, 500);
    }
  });

  app.get("/dag/block", (req, res) => {
    try {
      const round = parseInt(req.query.round as string || "0");
      if (!round) return json(res, { error: "round parameter required" }, 400);

      const commits = node.sql.exec(
        "SELECT anchor_hash, committed_at, signatures_json FROM dag_commits WHERE round = ?", round,
      );
      if (commits.length === 0) return json(res, { error: "Round not committed" }, 404);

      const anchor = commits[0] as any;
      const vertices = node.sql.exec(
        "SELECT hash, author, round, events_json, refs_json, signature FROM dag_vertices WHERE round = ?", round,
      );

      let signatures: any[];
      if (anchor.signatures_json && anchor.signatures_json !== "[]") {
        try { signatures = JSON.parse(anchor.signatures_json); } catch { signatures = []; }
      } else {
        signatures = vertices.map((v: any) => ({ pubkey: v.author, signature: v.signature }));
      }

      const anchorVertex = vertices.find((v: any) => v.hash === anchor.anchor_hash);
      let events: any[] = [];
      if ((anchorVertex as any)?.events_json) {
        try { events = JSON.parse((anchorVertex as any).events_json); } catch {}
      }

      json(res, {
        round, block_number: round, hash: anchor.anchor_hash,
        committed_at: anchor.committed_at,
        signatures: signatures.map((s: any) => ({ ...s, message: `block:${round}` })),
        events,
        mutations: events.filter((e: any) => e.type === "state_mutation"),
        vertex_count: vertices.length,
        active_nodes: Math.max(signatures.length, vertices.length, 1),
      });
    } catch (e: any) {
      json(res, { error: e.message }, 500);
    }
  });

  app.get("/dag/next_committed", (req, res) => {
    const afterRound = parseInt(req.query.after as string || "0");
    const rows = node.sql.exec(
      "SELECT round FROM dag_commits WHERE round > ? ORDER BY round ASC LIMIT 1", afterRound,
    );
    json(res, { round: rows.length > 0 ? (rows[0] as any).round : null });
  });

  app.get("/dag/vertices", (req, res) => {
    const round = parseInt(req.query.round as string || "0");
    if (!round) return json(res, { error: "round parameter required" }, 400);

    const verts = node.sql.exec(
      "SELECT hash, author, round, events_json, refs_json, signature, timestamp FROM dag_vertices WHERE round = ?", round,
    );
    json(res, verts.map((v: any) => {
      let event_hashes: string[] = [];
      try { event_hashes = JSON.parse(v.events_json).map((e: any) => e.hash).filter(Boolean); } catch {}
      let refs: string[] = [];
      try { refs = JSON.parse(v.refs_json); } catch {}
      return { hash: v.hash, author: v.author, round: v.round, event_hashes, refs, timestamp: v.timestamp, signature: v.signature };
    }));
  });

  app.get("/dag/snapshot", (_req, res) => {
    const blocks = node.sql.exec("SELECT x, z, block_type, placed_by FROM blocks");
    const ownership = node.sql.exec("SELECT asset_id, owner_pubkey, metadata, created_at FROM ownership");
    const inventory = node.sql.exec("SELECT pubkey, item, count FROM inventory WHERE count > 0");
    json(res, {
      finalized_root: node.finalizedRoot,
      finalized_seq: node.finalizedSeq,
      last_committed_round: node.lastCommittedRound,
      state: { blocks, ownership, inventory },
    });
  });

  // ─── Wallet Routes (/wallet/*) ───────────────────────────────────────

  app.get("/wallet/info", (req, res) => {
    const pubkey = req.query.pubkey as string || "";
    if (!pubkey) return json(res, { error: "pubkey required" }, 400);
    const address = pubkeyB64ToAddress(pubkey);
    const balances = node.accountManager.getAllBalances(address);
    const available = node.accountManager.getAvailableBalance(address, "PERSIST");
    json(res, { address, pubkey, balances, available_PERSIST: available.toString() });
  });

  app.get("/wallet/balance", (req, res) => {
    const address = req.query.address as string || "";
    const denom = req.query.denom as string || "PERSIST";
    if (!address) return json(res, { error: "address required" }, 400);
    const balance = node.accountManager.getBalance(address, denom);
    const available = node.accountManager.getAvailableBalance(address, denom);
    json(res, { address, denom, balance: balance.toString(), available: available.toString() });
  });

  app.get("/wallet/address", (req, res) => {
    const pubkey = req.query.pubkey as string || "";
    if (!pubkey) return json(res, { error: "pubkey required" }, 400);
    json(res, { address: pubkeyB64ToAddress(pubkey) });
  });

  app.post("/wallet/faucet", async (req, res) => {
    try {
      const { pubkey, denom, amount } = req.body;
      if (!pubkey) return json(res, { error: "pubkey required" }, 400);
      const acct = await node.accountManager.getOrCreate(pubkey);
      const mintDenom = denom || "PERSIST";
      const mintAmount = BigInt(amount || 1000);
      node.accountManager.mint(acct.address, mintDenom, mintAmount);
      const balance = node.accountManager.getBalance(acct.address, mintDenom);
      json(res, { ok: true, address: acct.address, balance: balance.toString() });
    } catch (e: any) {
      json(res, { error: e.message }, 500);
    }
  });

  // ─── Transfer ────────────────────────────────────────────────────────

  app.post("/transfer", async (req, res) => {
    try {
      const { from, to, denom, amount } = req.body;
      if (!from || !to || !amount) return json(res, { error: "from, to, amount required" }, 400);
      node.accountManager.transfer(from, to, denom || "PERSIST", BigInt(amount));
      json(res, { ok: true });
    } catch (e: any) {
      json(res, { error: e.message }, 400);
    }
  });

  // ─── Economics ───────────────────────────────────────────────────────

  app.get("/economics", (_req, res) => {
    try {
      // Sum all PERSIST balances for total supply proxy
      const rows = node.sql.exec("SELECT COALESCE(SUM(CAST(amount AS INTEGER)), 0) as total FROM token_balances WHERE denom = 'PERSIST'");
      const total = BigInt((rows[0] as any)?.total || 0);
      const burnRows = node.sql.exec("SELECT COALESCE(SUM(CAST(amount AS INTEGER)), 0) as total FROM burn_log WHERE denom = 'PERSIST'");
      const burned = BigInt((burnRows[0] as any)?.total || 0);
      json(res, {
        denom: "PERSIST",
        total_supply: total.toString(),
        total_burned: burned.toString(),
        circulating: (total - burned).toString(),
      });
    } catch {
      json(res, { denom: "PERSIST", total_supply: "0", total_burned: "0", circulating: "0" });
    }
  });

  // ─── Provider Routes (/providers/*) ──────────────────────────────────

  app.post("/providers/register", async (req, res) => {
    try {
      const body = req.body;
      const result = await node.providerRegistry.register({
        owner_address: body.owner_address,
        endpoint_url: body.endpoint_url,
        service_type: body.service_type,
        model: body.model,
        price: BigInt(body.price || 0),
        bond_amount: BigInt(body.bond_amount || 0),
      });
      if (!result.ok) return json(res, { error: result.error }, 400);
      jsonSafe(res, { ok: true, provider: result.provider });
    } catch (e: any) {
      json(res, { error: e.message }, 500);
    }
  });

  app.post("/providers/deactivate", (req, res) => {
    const { provider_id, owner_address } = req.body;
    const result = node.providerRegistry.deactivate(provider_id, owner_address);
    if (!result.ok) return json(res, { error: result.error }, 400);
    json(res, { ok: true, refunded: result.refunded?.toString() });
  });

  app.post("/providers/update-price", (req, res) => {
    const { provider_id, owner_address, price } = req.body;
    const result = node.providerRegistry.updatePrice(provider_id, owner_address, BigInt(price || 0));
    if (!result.ok) return json(res, { error: result.error }, 400);
    json(res, { ok: true });
  });

  app.post("/providers/update-endpoint", (req, res) => {
    const { provider_id, owner_address, endpoint_url } = req.body;
    const result = node.providerRegistry.updateEndpoint(provider_id, owner_address, endpoint_url);
    if (!result.ok) return json(res, { error: result.error }, 400);
    json(res, { ok: true });
  });

  app.post("/providers/claim", (req, res) => {
    const { provider_id, owner_address } = req.body;
    const result = node.providerRegistry.claimEarnings(provider_id, owner_address);
    if (!result.ok) return json(res, { error: result.error }, 400);
    json(res, { ok: true, amount: result.amount?.toString() });
  });

  app.post("/providers/report-down", (req, res) => {
    const { provider_id, reporter_address } = req.body;
    const report = node.providerRegistry.reportDown(provider_id, reporter_address);
    if (!report) return json(res, { error: "Provider not found, already reported, or inactive" }, 400);
    json(res, { ok: true, report });
  });

  app.get("/providers/list", (req, res) => {
    const serviceType = req.query.service_type as string || "";
    const model = req.query.model as string || "";
    const providers = serviceType && model
      ? node.providerRegistry.getActive(serviceType, model)
      : node.providerRegistry.getAllActive();
    jsonSafe(res, { providers });
  });

  app.get("/providers/models", (_req, res) => {
    const models = node.providerRegistry.getAvailableModels();
    jsonSafe(res, { models });
  });

  app.get("/providers/stats", (_req, res) => {
    const stats = node.providerRegistry.getStats();
    jsonSafe(res, stats);
  });

  app.get("/providers/my-providers", (req, res) => {
    const address = req.query.address as string || "";
    if (!address) return json(res, { error: "address param required" }, 400);
    const providers = node.providerRegistry.getByOwner(address);
    jsonSafe(res, { providers });
  });

  // ─── API Gateway (/api/*) ────────────────────────────────────────────
  // Standalone nodes have no local Workers AI — route everything to external providers

  app.all("/api/federation", (_req, res) => {
    const stats = node.serviceFederation?.getStats() || { pending: 0, active_nodes: 0, federation_capable: false };
    const networkServices = node.validatorRegistry.getNetworkServices();
    const proxyStats = node.providerProxy?.getStats() || { external_providers: 0, available_models: 0, pending_settlements: 0, pending_settlement_amount: 0n };
    jsonSafe(res, {
      federation: stats,
      network_services: networkServices,
      marketplace: {
        ...proxyStats,
        providers: node.providerRegistry.getAvailableModels(),
      },
    });
  });

  app.all("/api/:service", async (req, res) => {
    try {
      const serviceId = req.params.service;
      const model = req.body?.model || "";
      const buyerAddress = "";
      const requestBody = JSON.stringify(req.body || {});

      const proxyResult = await node.providerProxy.routeToProvider({
        serviceType: serviceId,
        model,
        requestBody,
        buyerAddress,
      });

      if (!proxyResult) {
        return json(res, {
          error: "No external providers available for this service",
          service: serviceId,
          hint: "Register a provider via /providers/register or connect to a seed node with providers",
        }, 503);
      }

      // Forward the provider response
      const responseBody = await proxyResult.response.text();
      const contentType = proxyResult.response.headers.get("content-type") || "application/json";
      res.status(proxyResult.response.status)
        .type(contentType)
        .set("X-Provider", proxyResult.provider?.provider_id || "unknown")
        .send(responseBody);
    } catch (e: any) {
      json(res, { error: e.message }, 500);
    }
  });

  // ─── Event Submission ────────────────────────────────────────────────

  app.post("/event", async (req, res) => {
    try {
      const event = req.body;
      if (!event.hash) {
        // Compute hash if not provided
        const { computeEventHash } = await import("../../src/consensus.ts");
        event.hash = await computeEventHash(event);
      }
      node.sql.exec(
        `INSERT OR IGNORE INTO pending_events (hash, type, payload, pubkey, signature, timestamp)
         VALUES (?, ?, ?, ?, ?, ?)`,
        event.hash, event.type || "", JSON.stringify(event.payload || {}),
        event.pubkey || "", event.signature || "", event.timestamp || Date.now(),
      );
      json(res, { ok: true, hash: event.hash });
    } catch (e: any) {
      json(res, { error: e.message }, 500);
    }
  });

  // ─── Add Node (peer discovery) ───────────────────────────────────────

  app.post("/addNode", async (req, res) => {
    try {
      const { url: peerUrl, pubkey: peerPubkey } = req.body;
      if (!peerUrl) return json(res, { error: "url required" }, 400);

      let resolvedPubkey = peerPubkey;
      if (!peerPubkey) {
        try {
          const networkUrl = peerUrl.includes("?")
            ? peerUrl.replace("?", "/network?")
            : peerUrl.replace(/\/?$/, "/network");
          const resp = await fetch(networkUrl);
          if (resp.ok) {
            const info = await resp.json() as any;
            if (info.node_pubkey) {
              resolvedPubkey = info.node_pubkey;
              node.gossipManager.addPeer(info.node_pubkey, peerUrl);
            }
          }
        } catch {}
      } else {
        node.gossipManager.addPeer(peerPubkey, peerUrl);
      }

      if (resolvedPubkey) {
        node.sql.exec(
          `INSERT INTO active_nodes (pubkey, url, last_vertex_round, last_seen, is_self)
           VALUES (?, ?, 0, ?, 0)
           ON CONFLICT(pubkey) DO UPDATE SET url = ?, last_seen = ?`,
          resolvedPubkey, peerUrl, Date.now(), peerUrl, Date.now(),
        );
      }

      json(res, { ok: true, peers: node.gossipManager.getPeers() });
    } catch (e: any) {
      json(res, { error: e.message }, 500);
    }
  });

  // ─── Admin Routes ────────────────────────────────────────────────────

  app.get("/admin/peers", (_req, res) => {
    json(res, {
      gossip_peers: node.gossipManager.getPeers(),
      active_nodes: node.sql.exec(
        "SELECT pubkey, url, last_vertex_round, last_seen, is_self FROM active_nodes ORDER BY last_seen DESC",
      ),
    });
  });

  app.get("/admin/dag-stats", (_req, res) => {
    const totalVertices = node.sql.exec("SELECT COUNT(*) as cnt FROM dag_vertices");
    const totalCommits = node.sql.exec("SELECT COUNT(*) as cnt FROM dag_commits");
    const totalEvents = node.sql.exec("SELECT COUNT(*) as cnt FROM events");
    const pendingEvents = node.sql.exec("SELECT COUNT(*) as cnt FROM pending_events");
    json(res, {
      total_vertices: (totalVertices[0] as any)?.cnt || 0,
      total_commits: (totalCommits[0] as any)?.cnt || 0,
      total_events: (totalEvents[0] as any)?.cnt || 0,
      pending_events: (pendingEvents[0] as any)?.cnt || 0,
      current_round: node.currentRound,
      last_committed_round: node.lastCommittedRound,
    });
  });

  // ─── Query / State ───────────────────────────────────────────────────

  app.get("/state", (_req, res) => {
    const blocks = node.sql.exec("SELECT x, z, block_type, placed_by FROM blocks");
    json(res, {
      blocks, seq: node.finalizedSeq, root: node.finalizedRoot,
      current_round: node.currentRound,
    });
  });

  app.post("/query", (req, res) => {
    try {
      const { sql: query, params } = req.body;
      if (!query) return json(res, { error: "sql required" }, 400);
      // Only allow SELECT queries for safety
      if (!query.trim().toUpperCase().startsWith("SELECT")) {
        return json(res, { error: "Only SELECT queries allowed" }, 403);
      }
      const rows = params ? node.sql.exec(query, ...params) : node.sql.exec(query);
      json(res, { rows });
    } catch (e: any) {
      json(res, { error: e.message }, 400);
    }
  });

  // ─── ZK Proofs ───────────────────────────────────────────────────────

  app.get("/proof/commitment", (_req, res) => {
    const latestProof = node.sql.exec(
      "SELECT MAX(block_number) as b FROM zk_proofs",
    );
    json(res, {
      latest_proven_block: (latestProof[0] as any)?.b || 0,
      current_round: node.currentRound,
      last_committed_round: node.lastCommittedRound,
    });
  });

  // ─── Create HTTP server + WebSocket ──────────────────────────────────

  const server = createServer(app);

  const wss = new WebSocketServer({ server, path: "/ws" });
  const wsClients = new Map<WebSocket, { pubkey?: string; channels: Set<string> }>();

  wss.on("connection", (ws) => {
    const clientState = { pubkey: undefined as string | undefined, channels: new Set<string>() };
    wsClients.set(ws, clientState);

    ws.on("message", (data) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === "subscribe" && msg.channel) {
          clientState.channels.add(msg.channel);
          ws.send(JSON.stringify({ type: "subscribed", channel: msg.channel }));
        } else if (msg.type === "unsubscribe" && msg.channel) {
          clientState.channels.delete(msg.channel);
        } else if (msg.type === "auth" && msg.pubkey) {
          clientState.pubkey = msg.pubkey;
          ws.send(JSON.stringify({ type: "authenticated", pubkey: msg.pubkey }));
        }
      } catch {}
    });

    ws.on("close", () => {
      wsClients.delete(ws);
    });

    // Send welcome
    ws.send(JSON.stringify({
      type: "welcome",
      node: node.nodeIdentity.pubkey,
      runtime: "standalone",
    }));
  });

  // Broadcast helper — used by consensus tick to notify connected clients
  function broadcast(msg: any) {
    const payload = JSON.stringify(msg);
    for (const [ws, client] of wsClients) {
      if (ws.readyState === WebSocket.OPEN) {
        // Send to all or matching channel subscribers
        if (client.channels.size === 0 || client.channels.has(msg.type) || client.channels.has("*")) {
          ws.send(payload);
        }
      }
    }
  }

  // Expose broadcast on the node so consensus ticks can push updates
  (node as any).broadcast = broadcast;

  // ─── Start ─────────────────────────────────────────────────────────

  server.listen(config.port, () => {
    console.log(`\nHTTP server listening on port ${config.port}`);
    console.log(`WebSocket available at ws://localhost:${config.port}/ws`);
    console.log(`Node status: http://localhost:${config.port}/network\n`);

    // Start consensus loop
    node.startConsensus();
  });

  // ─── Graceful Shutdown ─────────────────────────────────────────────

  process.on("SIGINT", () => {
    console.log("\nShutting down...");
    node.shutdown();
    wss.close();
    server.close(() => process.exit(0));
  });

  process.on("SIGTERM", () => {
    node.shutdown();
    wss.close();
    server.close(() => process.exit(0));
  });
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
