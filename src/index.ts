import { PersistiaWorldV4 } from "./PersistiaDO";
import DASHBOARD_HTML from "../client/dashboard.html";
import GAME_HTML from "../client/game.html";
import VERIFIER_HTML from "../client/verifier.html";
import WALLET_HTML from "../client/wallet.html";
import { APP_SDK_JS } from "./app-sdk";
export { PersistiaWorldV4 };

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

    // ─── Verifier ─────────────────────────────────────────────────────
    if (url.pathname === "/verifier" || url.pathname === "/verifier.html") {
      return new Response(VERIFIER_HTML, {
        headers: { "Content-Type": "text/html;charset=utf-8", ...CORS_HEADERS },
      });
    }

    // ─── Wallet ──────────────────────────────────────────────────────
    if (url.pathname === "/wallet" || url.pathname === "/wallet.html") {
      return new Response(WALLET_HTML, {
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

    // ─── Join network ─────────────────────────────────────────────────
    // POST /join — External node announces itself to all seed shards.
    // Body: { "url": "https://my-node.example.workers.dev", "shard": "global-world",
    //         "pubkey": "...", "pow_nonce": "...", "signature": "..." }
    // The seed nodes add the joiner as a peer. If pubkey + pow_nonce are provided,
    // also registers as a validator on each shard.
    if (url.pathname === "/join" && request.method === "POST") {
      const body = await request.json() as any;
      const joinerUrl = body.url;
      const joinerShard = body.shard || "global-world";
      if (!joinerUrl) {
        return corsResponse(JSON.stringify({ error: "url required (your node's public URL)" }), 400);
      }

      // Determine the effective peer URL for this joiner
      // External nodes use their root URL directly (no shard routing)
      const peerUrl = joinerShard === "global-world"
        ? joinerUrl
        : `${joinerUrl}/?shard=${joinerShard}`;

      // Register joiner on all seed shards
      const shards = ["node-1", "node-2", "node-3"];
      const results: any[] = [];
      for (const seed of shards) {
        try {
          const seedId = env.PERSISTIA_WORLD.idFromName(seed);
          const seedStub = env.PERSISTIA_WORLD.get(seedId);

          // Add as peer
          const addRes = await seedStub.fetch(new Request(`${url.origin}/addNode?shard=${seed}`, {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Shard-Name": seed },
            body: JSON.stringify({ url: peerUrl, pubkey: body.pubkey }),
          }));
          const r = await addRes.json() as any;
          const seedResult: any = { shard: seed, peer: r.ok ?? true };

          // Register as validator if PoW provided
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

      // Tell the joiner about the seed nodes (reverse peering)
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

    // ─── App SDK ──────────────────────────────────────────────────────
    if (url.pathname === "/app/sdk.js") {
      return new Response(APP_SDK_JS, {
        headers: { "Content-Type": "application/javascript;charset=utf-8", "Cache-Control": "public, max-age=300", ...CORS_HEADERS },
      });
    }

    // ─── On-Chain App Serving ────────────────────────────────────────
    // Routes: /app/{contract_address}/...filepath
    // Serves frontend files stored in contract state under _app/ prefix
    const appMatch = url.pathname.match(/^\/app\/([a-f0-9]{16,64})(\/.*)?$/);
    if (appMatch) {
      const contractAddress = appMatch[1];
      const filePath = appMatch[2] || "/index.html";
      const appShardName = url.searchParams.get("shard") || "global-world";
      const appId = env.PERSISTIA_WORLD.idFromName(appShardName);
      const appStub = env.PERSISTIA_WORLD.get(appId);

      // Proxy to DO's /app-serve endpoint
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
