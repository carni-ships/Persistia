import { PersistiaWorldV4 } from "./PersistiaDO";
import { PersistiaAgent } from "./persistia-agent";
import { routeAgentRequest } from "agents";
import { APP_SDK_JS } from "./app-sdk";
export { PersistiaWorldV4, PersistiaAgent };

// ─── Types ────────────────────────────────────────────────────────────────────

interface Env {
  PERSISTIA_WORLD: DurableObjectNamespace;
  PERSISTIA_AGENT: DurableObjectNamespace;
  BLOB_STORE?: R2Bucket;
  RELAY_QUEUE?: Queue;
  ASSETS?: { fetch: (req: Request) => Promise<Response> };
  AI?: any;
  BROWSER?: any;
  [key: string]: any;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

const MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024; // 2MB

// Cache TTLs for read-heavy endpoints (seconds)
const CACHE_TTL_STATUS = 5;         // /dag/status — changes each round
const CACHE_TTL_CHAIN = 30;         // /proof/zk/chain — changes per proof
const CACHE_TTL_GOV_CONFIG = 30;    // /governance/config — changes rarely
const CACHE_TTL_VALIDATOR = 15;     // /validator/list — changes on join/leave

// Endpoints eligible for edge caching (GET only, matched by prefix)
const CACHEABLE_ENDPOINTS: Record<string, number> = {
  "/dag/status": CACHE_TTL_STATUS,
  "/proof/zk/chain": CACHE_TTL_CHAIN,
  "/proof/zk/status": CACHE_TTL_CHAIN,
  "/governance/config": CACHE_TTL_GOV_CONFIG,
  "/validator/list": CACHE_TTL_VALIDATOR,
  "/network": CACHE_TTL_STATUS,
  "/snapshot/latest": CACHE_TTL_GOV_CONFIG,  // changes per anchor (~5 min)
  "/snapshot/list": CACHE_TTL_GOV_CONFIG,
  "/api/catalog": 300,  // service catalog changes rarely
};

// Static HTML routes served from Workers Static Assets
const STATIC_ROUTES: Record<string, string> = {
  "/": "/game.html",
  "/game": "/game.html",
  "/game.html": "/game.html",
  "/dashboard": "/dashboard.html",
  "/dashboard.html": "/dashboard.html",
  "/verifier": "/verifier.html",
  "/verifier.html": "/verifier.html",
  "/wallet": "/wallet.html",
  "/wallet.html": "/wallet.html",
  "/services": "/services.html",
  "/services.html": "/services.html",
  "/oracle": "/oracle.html",
  "/oracle.html": "/oracle.html",
};

// ─── Worker ───────────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const contentLength = request.headers.get("Content-Length");
    if (contentLength && parseInt(contentLength) > MAX_REQUEST_BODY_BYTES) {
      return corsResponse(JSON.stringify({ error: "Request body too large (max 2MB)" }), 413);
    }

    const url = new URL(request.url);

    // ─── MCP Agent routing (/agents/*) ─────────────────────────────────
    const agentResponse = await routeAgentRequest(request, env);
    if (agentResponse) return agentResponse;

    // ─── Static HTML via Workers Static Assets (CDN edge) ──────────────
    const staticFile = STATIC_ROUTES[url.pathname];
    if (staticFile && request.method === "GET") {
      if (env.ASSETS) {
        const assetReq = new Request(new URL(staticFile, url.origin), request);
        const res = await env.ASSETS.fetch(assetReq);
        const response = new Response(res.body, res);
        response.headers.set("Cache-Control", "public, max-age=3600");
        for (const [k, v] of Object.entries(CORS_HEADERS)) {
          response.headers.set(k, v);
        }
        return response;
      }
      // Fallback: assets binding not available (dev mode or external nodes)
      // Let it fall through to DO routing which won't match — return 404
    }

    // ─── Edge Cache for read-heavy GET endpoints ───────────────────────
    if (request.method === "GET") {
      const cacheTtl = CACHEABLE_ENDPOINTS[url.pathname];
      if (cacheTtl) {
        const cache = caches.default;
        const cacheKey = new Request(url.toString(), request);
        const cached = await cache.match(cacheKey);
        if (cached) return cached;

        // Fetch from DO, cache the response
        const doResponse = await routeToDO(request, url, env);
        if (doResponse.ok) {
          const cacheable = new Response(doResponse.body, doResponse);
          cacheable.headers.set("Cache-Control", `public, max-age=${cacheTtl}`);
          for (const [k, v] of Object.entries(CORS_HEADERS)) {
            cacheable.headers.set(k, v);
          }
          ctx.waitUntil(cache.put(cacheKey, cacheable.clone()));
          return cacheable;
        }
        return doResponse;
      }
    }

    // ─── Cross-shard relay via Queue ──────────────────────────────────
    if (url.pathname === "/relay" && request.method === "POST") {
      const { source_shard, target_shard } = await request.json() as any;
      if (!source_shard || !target_shard) {
        return corsResponse(JSON.stringify({ error: "source_shard and target_shard required" }), 400);
      }

      if (env.RELAY_QUEUE) {
        // Async relay via Queue — non-blocking
        await env.RELAY_QUEUE.send({ source_shard, target_shard });
        return corsResponse(JSON.stringify({ queued: true, source_shard, target_shard }));
      }

      // Fallback: synchronous relay (Queue not configured)
      return await synchronousRelay(url, env, source_shard, target_shard);
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

    // ─── List shards ────────────────────────────────────────────────────
    if (url.pathname === "/shards") {
      return corsResponse(JSON.stringify({
        note: "Shards are created on demand via ?shard= parameter",
        default: "global-world",
      }));
    }

    // ─── Join network ─────────────────────────────────────────────────
    if (url.pathname === "/join" && request.method === "POST") {
      const body = await request.json() as any;
      const joinerUrl = body.url;
      const joinerShard = body.shard || "global-world";
      if (!joinerUrl) {
        return corsResponse(JSON.stringify({ error: "url required (your node's public URL)" }), 400);
      }

      const peerUrl = joinerShard === "global-world"
        ? joinerUrl
        : `${joinerUrl}/?shard=${joinerShard}`;

      const shards = ["node-1", "node-2", "node-3"];
      const results: any[] = [];
      for (const seed of shards) {
        try {
          const seedId = env.PERSISTIA_WORLD.idFromName(seed);
          const seedStub = env.PERSISTIA_WORLD.get(seedId);

          const addRes = await seedStub.fetch(new Request(`${url.origin}/addNode?shard=${seed}`, {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Shard-Name": seed },
            body: JSON.stringify({ url: peerUrl, pubkey: body.pubkey }),
          }));
          const r = await addRes.json() as any;
          const seedResult: any = { shard: seed, peer: r.ok ?? true };

          if (body.pubkey && body.pow_nonce && body.signature) {
            try {
              const valRes = await seedStub.fetch(new Request(`${url.origin}/validator/register?shard=${seed}`, {
                method: "POST",
                headers: { "Content-Type": "application/json", "X-Shard-Name": seed },
                body: JSON.stringify({
                  pubkey: body.pubkey,
                  url: peerUrl,
                  pow_nonce: body.pow_nonce,
                  signature: body.signature,
                }),
              }));
              const vr = await valRes.json() as any;
              seedResult.validator = vr.ok ?? false;
              if (vr.error) seedResult.validator_error = vr.error;
            } catch (e: any) {
              seedResult.validator = false;
              seedResult.validator_error = e.message;
            }
          }

          results.push(seedResult);
        } catch (e: any) {
          results.push({ shard: seed, peer: false, error: e.message });
        }
      }

      const seedUrls = shards.map(s => `${url.origin}/?shard=${s}`);
      return corsResponse(JSON.stringify({
        ok: true,
        message: body.pow_nonce
          ? "Node registered as peer and validator on seed shards."
          : "Node registered as peer. To become a validator, include pubkey + pow_nonce + signature.",
        seed_nodes: seedUrls,
        results,
      }));
    }

    // ─── Network discovery ──────────────────────────────────────────────
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
          snapshot_latest: "/snapshot/latest",
          snapshot_download: "/snapshot/download",
        },
      }));
    }

    // ─── App SDK ──────────────────────────────────────────────────────
    if (url.pathname === "/app/sdk.js") {
      return new Response(APP_SDK_JS, {
        headers: {
          "Content-Type": "application/javascript;charset=utf-8",
          "Cache-Control": "public, max-age=300",
          ...CORS_HEADERS,
        },
      });
    }

    // ─── On-Chain App Serving ────────────────────────────────────────
    const appMatch = url.pathname.match(/^\/app\/([a-f0-9]{16,64})(\/.*)?$/);
    if (appMatch) {
      const contractAddress = appMatch[1];
      const filePath = appMatch[2] || "/index.html";
      const appShardName = url.searchParams.get("shard") || "global-world";
      const appId = env.PERSISTIA_WORLD.idFromName(appShardName);
      const appStub = env.PERSISTIA_WORLD.get(appId);

      const appHeaders = new Headers(request.headers);
      appHeaders.set("X-Shard-Name", appShardName);
      const appRes = await appStub.fetch(new Request(
        `${url.origin}/app-serve?contract=${contractAddress}&path=${encodeURIComponent(filePath)}`,
        { method: "GET", headers: appHeaders },
      ));

      const appResponse = new Response(appRes.body, appRes);
      for (const [k, v] of Object.entries(CORS_HEADERS)) {
        appResponse.headers.set(k, v);
      }
      return appResponse;
    }

    // ─── App Registry ────────────────────────────────────────────────
    if (url.pathname === "/apps") {
      const appsShardName = url.searchParams.get("shard") || "global-world";
      const appsId = env.PERSISTIA_WORLD.idFromName(appsShardName);
      const appsStub = env.PERSISTIA_WORLD.get(appsId);
      const appsHeaders = new Headers(request.headers);
      appsHeaders.set("X-Shard-Name", appsShardName);
      const appsRes = await appsStub.fetch(new Request(`${url.origin}/app-serve?list=1`, { headers: appsHeaders }));
      const appsResponse = new Response(appsRes.body, appsRes);
      for (const [k, v] of Object.entries(CORS_HEADERS)) {
        appsResponse.headers.set(k, v);
      }
      return appsResponse;
    }

    // ─── Standard routing to shard DO ───────────────────────────────────
    return routeToDO(request, url, env);
  },

  // ─── Queue Consumer (async cross-shard relay) ────────────────────────
  async queue(batch: MessageBatch<{ source_shard: string; target_shard: string }>, env: Env): Promise<void> {
    for (const msg of batch.messages) {
      try {
        const { source_shard, target_shard } = msg.body;
        const origin = "https://persistia.workers.dev"; // internal origin for DO routing

        const sourceId = env.PERSISTIA_WORLD.idFromName(source_shard);
        const sourceStub = env.PERSISTIA_WORLD.get(sourceId);
        const outboxRes = await sourceStub.fetch(new Request(`${origin}/xshard/outbox?status=pending`));
        const outbox = await outboxRes.json() as any;

        if (!outbox.messages || outbox.messages.length === 0) {
          msg.ack();
          continue;
        }

        for (const row of outbox.messages) {
          if (row.target_shard !== target_shard) continue;

          const msgBody = typeof row.message_json === "string" ? JSON.parse(row.message_json) : row.message_json;
          const targetId = env.PERSISTIA_WORLD.idFromName(target_shard);
          const targetStub = env.PERSISTIA_WORLD.get(targetId);

          const deliverRes = await targetStub.fetch(new Request(`${origin}/xshard/receive`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(msgBody),
          }));
          const receipt = await deliverRes.json() as any;

          await sourceStub.fetch(new Request(`${origin}/xshard/ack`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message_id: row.id, status: receipt.status || "delivered" }),
          }));
        }

        msg.ack();
      } catch (e) {
        console.error("Queue relay error:", e);
        msg.retry();
      }
    }
  },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function routeToDO(request: Request, url: URL, env: Env): Promise<Response> {
  const shardName = url.searchParams.get("shard") || "global-world";
  const id = env.PERSISTIA_WORLD.idFromName(shardName);
  const stub = env.PERSISTIA_WORLD.get(id);

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
}

async function synchronousRelay(url: URL, env: Env, source_shard: string, target_shard: string): Promise<Response> {
  const sourceId = env.PERSISTIA_WORLD.idFromName(source_shard);
  const sourceStub = env.PERSISTIA_WORLD.get(sourceId);
  const outboxRes = await sourceStub.fetch(new Request(`${url.origin}/xshard/outbox?status=pending`));
  const outbox = await outboxRes.json() as any;

  if (!outbox.messages || outbox.messages.length === 0) {
    return corsResponse(JSON.stringify({ relayed: 0 }));
  }

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

    await sourceStub.fetch(new Request(`${url.origin}/xshard/ack`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message_id: row.id, status: receipt.status || "delivered" }),
    }));

    relayed++;
  }

  return corsResponse(JSON.stringify({ relayed }));
}

function corsResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}
