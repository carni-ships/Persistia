// ─── Persistia MCP Agent ─────────────────────────────────────────────────────
// Exposes the Persistia ledger as an MCP server via Cloudflare Agents SDK.
// AI agents can query balances, submit transactions, deploy contracts, and more.

import { McpAgent } from "agents/mcp";
import { z } from "zod";

interface Env {
  PERSISTIA_WORLD: DurableObjectNamespace;
  AI?: any;
  [key: string]: any;
}

// Helper: route a request to the shard DO and return JSON
async function queryDO(env: Env, shard: string, path: string, method = "GET", body?: any): Promise<any> {
  const id = env.PERSISTIA_WORLD.idFromName(shard);
  const stub = env.PERSISTIA_WORLD.get(id);
  const origin = "https://persistia.internal";
  const opts: RequestInit = {
    method,
    headers: { "Content-Type": "application/json", "X-Shard-Name": shard },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await stub.fetch(new Request(`${origin}${path}`, opts));
  return res.json();
}

// ─── MCP Agent ───────────────────────────────────────────────────────────────

export class PersistiaAgent extends McpAgent<Env> {
  server = this.createServer({
    name: "persistia",
    version: "1.0.0",
  });

  async init() {
    const env = this.env;
    const defaultShard = "node-1";

    // ─── Resources ──────────────────────────────────────────────────────

    // Service catalog (static resource)
    this.server.resource(
      "service-catalog",
      "persistia://services/catalog",
      { description: "AI services catalog with pricing" },
      async () => {
        const data = await queryDO(env, defaultShard, `/api/catalog?shard=${defaultShard}`);
        return { contents: [{ uri: "persistia://services/catalog", text: JSON.stringify(data, null, 2), mimeType: "application/json" }] };
      },
    );

    // ─── Tools ──────────────────────────────────────────────────────────

    // Query account balance
    this.server.tool(
      "get_balance",
      "Get token balance for an address",
      { address: z.string().describe("Persistia address (hex)"), denom: z.string().default("PERSIST").describe("Token denomination"), shard: z.string().default(defaultShard) },
      async ({ address, denom, shard }) => {
        const data = await queryDO(env, shard, `/balance/${address}?denom=${denom}&shard=${shard}`);
        return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
      },
    );

    // Transfer tokens
    this.server.tool(
      "transfer",
      "Transfer tokens between addresses (requires signed transaction)",
      {
        from: z.string().describe("Sender address"),
        to: z.string().describe("Recipient address"),
        denom: z.string().default("PERSIST"),
        amount: z.string().describe("Amount as string (bigint)"),
        signature: z.string().describe("Schnorr signature over transfer payload"),
        pubkey: z.string().describe("Sender's public key"),
        shard: z.string().default(defaultShard),
      },
      async ({ from, to, denom, amount, signature, pubkey, shard }) => {
        const event = {
          type: "transfer",
          payload: JSON.stringify({ from, to, denom, amount }),
          pubkey,
          signature,
          timestamp: Date.now(),
        };
        const data = await queryDO(env, shard, `/event?shard=${shard}`, "POST", event);
        return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
      },
    );

    // Query DAG status
    this.server.tool(
      "dag_status",
      "Get current consensus DAG status (round, finalized seq, node count)",
      { shard: z.string().default(defaultShard) },
      async ({ shard }) => {
        const data = await queryDO(env, shard, `/dag/status?shard=${shard}`);
        return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
      },
    );

    // List validators
    this.server.tool(
      "list_validators",
      "List all registered validators and their status",
      { shard: z.string().default(defaultShard) },
      async ({ shard }) => {
        const data = await queryDO(env, shard, `/validator/list?shard=${shard}`);
        return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
      },
    );

    // Query contract info
    this.server.tool(
      "get_contract",
      "Get info about a deployed smart contract",
      { address: z.string().describe("Contract address (hex hash)"), shard: z.string().default(defaultShard) },
      async ({ address, shard }) => {
        const data = await queryDO(env, shard, `/contract/info/${address}?shard=${shard}`);
        return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
      },
    );

    // Call contract (read-only)
    this.server.tool(
      "call_contract",
      "Call a smart contract method (read-only view call, no state changes)",
      {
        address: z.string().describe("Contract address"),
        method: z.string().describe("Method name to call"),
        args: z.string().default("{}").describe("JSON-encoded arguments"),
        shard: z.string().default(defaultShard),
      },
      async ({ address, method, args, shard }) => {
        const data = await queryDO(env, shard, `/contract/call?shard=${shard}`, "POST", {
          address, method, args: JSON.parse(args), caller: "mcp-agent",
        });
        return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
      },
    );

    // Deploy contract
    this.server.tool(
      "deploy_contract",
      "Deploy a WASM smart contract (requires signed transaction)",
      {
        wasm_base64: z.string().describe("Base64-encoded WASM binary"),
        pubkey: z.string().describe("Deployer's public key"),
        signature: z.string().describe("Schnorr signature over WASM hash"),
        shard: z.string().default(defaultShard),
      },
      async ({ wasm_base64, pubkey, signature, shard }) => {
        const event = {
          type: "contract.deploy",
          payload: JSON.stringify({ wasm: wasm_base64 }),
          pubkey,
          signature,
          timestamp: Date.now(),
        };
        const data = await queryDO(env, shard, `/event?shard=${shard}`, "POST", event);
        return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
      },
    );

    // Get game world state (blocks at coordinates)
    this.server.tool(
      "get_world",
      "Query game world blocks in a region",
      {
        x_min: z.number().default(-50),
        x_max: z.number().default(50),
        z_min: z.number().default(-50),
        z_max: z.number().default(50),
        shard: z.string().default(defaultShard),
      },
      async ({ x_min, x_max, z_min, z_max, shard }) => {
        const data = await queryDO(env, shard, `/world?x_min=${x_min}&x_max=${x_max}&z_min=${z_min}&z_max=${z_max}&shard=${shard}`);
        return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
      },
    );

    // Get inventory
    this.server.tool(
      "get_inventory",
      "Get a player's inventory",
      { pubkey: z.string().describe("Player's public key"), shard: z.string().default(defaultShard) },
      async ({ pubkey, shard }) => {
        const data = await queryDO(env, shard, `/inventory/${pubkey}?shard=${shard}`);
        return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
      },
    );

    // Query recent events
    this.server.tool(
      "get_events",
      "Query recent ledger events with optional type filter",
      {
        type: z.string().optional().describe("Event type filter (e.g. 'transfer', 'place', 'contract.deploy')"),
        limit: z.number().default(20).describe("Max events to return"),
        shard: z.string().default(defaultShard),
      },
      async ({ type, limit, shard }) => {
        const typeParam = type ? `&type=${type}` : "";
        const data = await queryDO(env, shard, `/events?limit=${limit}${typeParam}&shard=${shard}`);
        return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
      },
    );

    // Token economics stats
    this.server.tool(
      "economics",
      "Get token economics stats (burns, fee splits, validator rewards)",
      { shard: z.string().default(defaultShard) },
      async ({ shard }) => {
        const data = await queryDO(env, shard, `/economics?shard=${shard}`);
        return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
      },
    );

    // Faucet — request test tokens
    this.server.tool(
      "faucet",
      "Request test PERSIST tokens from the faucet",
      {
        address: z.string().describe("Recipient address"),
        shard: z.string().default(defaultShard),
      },
      async ({ address, shard }) => {
        const data = await queryDO(env, shard, `/faucet?shard=${shard}`, "POST", { address });
        return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
      },
    );

    // AI service call (proxied through MPP)
    this.server.tool(
      "ai_service",
      "Call an AI service (LLM, TTS, image gen, etc). Requires MPP payment.",
      {
        service: z.enum(["llm", "tts", "stt", "image", "embed", "translate", "vision", "classify", "summarize", "code"]).describe("Service name"),
        input: z.string().describe("JSON-encoded service input"),
        authorization: z.string().optional().describe("MPP payment receipt (Authorization header value)"),
        shard: z.string().default(defaultShard),
      },
      async ({ service, input, authorization, shard }) => {
        const id = env.PERSISTIA_WORLD.idFromName(shard);
        const stub = env.PERSISTIA_WORLD.get(id);
        const headers: Record<string, string> = {
          "Content-Type": "application/json",
          "X-Shard-Name": shard,
        };
        if (authorization) headers["Authorization"] = authorization;
        const res = await stub.fetch(new Request(`https://persistia.internal/api/${service}?shard=${shard}`, {
          method: "POST",
          headers,
          body: input,
        }));
        // Handle binary responses (audio, images)
        const ct = res.headers.get("content-type") || "";
        if (ct.startsWith("audio/") || ct.startsWith("image/")) {
          const buf = await res.arrayBuffer();
          const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
          return { content: [{ type: "text" as const, text: JSON.stringify({ content_type: ct, data_base64: b64 }) }] };
        }
        const data = await res.json();
        return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
      },
    );

    // Network info
    this.server.tool(
      "network_info",
      "Get network topology: peers, endpoints, node identity",
      { shard: z.string().default(defaultShard) },
      async ({ shard }) => {
        const [peers, status] = await Promise.all([
          queryDO(env, shard, `/gossip/peers?shard=${shard}`),
          queryDO(env, shard, `/dag/status?shard=${shard}`),
        ]);
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({ peers: peers.peers, round: status.round, finalized: status.finalized_seq, validators: status.validator_count }, null, 2),
          }],
        };
      },
    );

    // ZK proof status
    this.server.tool(
      "zk_proof_status",
      "Get ZK proof chain status and latest proofs",
      { shard: z.string().default(defaultShard) },
      async ({ shard }) => {
        const data = await queryDO(env, shard, `/proof/zk/chain?shard=${shard}`);
        return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
      },
    );

    // Governance config
    this.server.tool(
      "governance_config",
      "Get current governance parameters",
      { shard: z.string().default(defaultShard) },
      async ({ shard }) => {
        const data = await queryDO(env, shard, `/governance/config?shard=${shard}`);
        return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
      },
    );
  }
}
