import { PersistiaWorld } from "./PersistiaDO";
import DASHBOARD_HTML from "../client/dashboard.html";
import GAME_HTML from "../client/game.html";
export { PersistiaWorld };

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

const MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024; // 2MB — reject oversized payloads before they reach the DO

export default {
  async fetch(request: Request, env: any): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // Reject oversized request bodies early (before forwarding to Durable Object)
    const contentLength = request.headers.get("Content-Length");
    if (contentLength && parseInt(contentLength) > MAX_REQUEST_BODY_BYTES) {
      return corsResponse(JSON.stringify({ error: "Request body too large (max 2MB)" }), 413);
    }

    const url = new URL(request.url);

    // ─── Cross-shard relay ──────────────────────────────────────────────
    // POST /relay — Worker picks up outbox messages from source shard
    // and delivers them to the target shard's /xshard/receive endpoint.
    if (url.pathname === "/relay" && request.method === "POST") {
      const { source_shard, target_shard } = await request.json() as any;
      if (!source_shard || !target_shard) {
        return corsResponse(JSON.stringify({ error: "source_shard and target_shard required" }), 400);
      }

      // 1. Get pending outbox messages from source shard
      const sourceId = env.PERSISTIA_WORLD.idFromName(source_shard);
      const sourceStub = env.PERSISTIA_WORLD.get(sourceId);
      const outboxRes = await sourceStub.fetch(new Request(`${url.origin}/xshard/outbox?status=pending`));
      const outbox = await outboxRes.json() as any;

      if (!outbox.messages || outbox.messages.length === 0) {
        return corsResponse(JSON.stringify({ relayed: 0 }));
      }

      // 2. Deliver each message to the target shard
      let relayed = 0;
      for (const row of outbox.messages) {
        if (row.target_shard !== target_shard) continue;

        const msg = typeof row.message_json === "string" ? JSON.parse(row.message_json) : row.message_json;
        const targetId = env.PERSISTIA_WORLD.idFromName(target_shard);
        const targetStub = env.PERSISTIA_WORLD.get(targetId);

        const deliverRes = await targetStub.fetch(new Request(`${url.origin}/xshard/receive`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(msg),
        }));
        const receipt = await deliverRes.json() as any;

        // 3. Acknowledge delivery on source shard
        await sourceStub.fetch(new Request(`${url.origin}/xshard/ack`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message_id: row.id, status: receipt.status || "delivered" }),
        }));

        relayed++;
      }

      return corsResponse(JSON.stringify({ relayed }));
    }

    // ─── WebSocket upgrade — forward directly to DO ────────────────
    if (request.headers.get("Upgrade") === "websocket") {
      const shardName = url.searchParams.get("shard") || "global-world";
      const id = env.PERSISTIA_WORLD.idFromName(shardName);
      const stub = env.PERSISTIA_WORLD.get(id);
      const headers = new Headers(request.headers);
      headers.set("X-Shard-Name", shardName);
      return stub.fetch(new Request(request.url, { method: request.method, headers, body: request.body }));
    }

    // ─── Game UI ──────────────────────────────────────────────────────
    if (url.pathname === "/" || url.pathname === "/game" || url.pathname === "/game.html") {
      return new Response(GAME_HTML, {
        headers: { "Content-Type": "text/html;charset=utf-8", ...CORS_HEADERS },
      });
    }

    // ─── Dashboard ─────────────────────────────────────────────────────
    if (url.pathname === "/dashboard" || url.pathname === "/dashboard.html") {
      return new Response(DASHBOARD_HTML, {
        headers: { "Content-Type": "text/html;charset=utf-8", ...CORS_HEADERS },
      });
    }

    // ─── List shards ────────────────────────────────────────────────────
    if (url.pathname === "/shards") {
      return corsResponse(JSON.stringify({
        note: "Shards are created on demand via ?shard= parameter",
        default: "global-world",
      }));
    }

    // ─── Network discovery ──────────────────────────────────────────────
    // GET /network — public endpoint listing this node's identity + known peers
    // Used by other nodes to discover and bootstrap into the network.
    if (url.pathname === "/network") {
      const shardName = url.searchParams.get("shard") || "global-world";
      const id = env.PERSISTIA_WORLD.idFromName(shardName);
      const stub = env.PERSISTIA_WORLD.get(id);
      const infoRes = await stub.fetch(new Request(`${url.origin}/gossip/peers`));
      const peers = await infoRes.json() as any;

      const nodeRes = await stub.fetch(new Request(url.origin));
      const nodeInfo = await nodeRes.json() as any;

      return corsResponse(JSON.stringify({
        node_pubkey: nodeInfo.node_pubkey,
        node_url: nodeInfo.node_url,
        version: nodeInfo.version,
        shard: shardName,
        gossip_peers: peers.peers || [],
        endpoints: {
          gossip_push: "/gossip/push",
          gossip_sync: "/gossip/sync",
          gossip_peers: "/gossip/peers",
          add_node: "/addNode",
          anchor_latest: "/anchor/latest",
          anchor_bootstrap: "/anchor/bootstrap",
        },
      }));
    }

    // ─── Standard routing to shard DO ───────────────────────────────────
    const shardName = url.searchParams.get("shard") || "global-world";
    const id = env.PERSISTIA_WORLD.idFromName(shardName);
    const stub = env.PERSISTIA_WORLD.get(id);

    // Pass shard name as header so the DO knows its identity
    const headers = new Headers(request.headers);
    headers.set("X-Shard-Name", shardName);
    const proxiedRequest = new Request(request.url, {
      method: request.method,
      headers,
      body: request.body,
    });

    const response = await stub.fetch(proxiedRequest);

    const newResponse = new Response(response.body, response);
    for (const [k, v] of Object.entries(CORS_HEADERS)) {
      newResponse.headers.set(k, v);
    }
    return newResponse;
  },
};

function corsResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}
