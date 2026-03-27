#!/usr/bin/env -S npx tsx
// High-throughput event generator for prover stress testing.
// Runs multiple agents in parallel hammering the node.

const NODE = process.argv.includes("--node")
  ? process.argv[process.argv.indexOf("--node") + 1]
  : "https://persistia.carnation-903.workers.dev";

const SHARD = process.argv.includes("--shard")
  ? process.argv[process.argv.indexOf("--shard") + 1]
  : "node-1";

const NUM_AGENTS = process.argv.includes("--agents")
  ? parseInt(process.argv[process.argv.indexOf("--agents") + 1])
  : 5;

const INTERVAL_MS = process.argv.includes("--interval")
  ? parseInt(process.argv[process.argv.indexOf("--interval") + 1])
  : 50;

function shardUrl(path: string): string {
  const sep = path.includes("?") ? "&" : "?";
  return `${NODE}${path}${sep}shard=${SHARD}`;
}

function bytesToB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

async function createAgent(name: string) {
  const keyPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const pubRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  return {
    name,
    pubkey: bytesToB64(new Uint8Array(pubRaw)),
    privateKey: keyPair.privateKey,
  };
}

async function sign(privateKey: CryptoKey, data: any): Promise<string> {
  const encoded = new TextEncoder().encode(JSON.stringify(data));
  const sig = await crypto.subtle.sign("Ed25519", privateKey, encoded);
  return bytesToB64(new Uint8Array(sig));
}

async function post(path: string, body: any): Promise<any> {
  try {
    const res = await fetch(shardUrl(path), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return await res.json().catch(() => ({ ok: false }));
  } catch {
    return { ok: false };
  }
}

async function get(path: string): Promise<any> {
  const res = await fetch(shardUrl(path));
  return res.json();
}

const BLOCK_NAMES = ["dirt", "stone", "wood", "grass"];
let totalOk = 0, totalErr = 0, totalSent = 0;

async function agentLoop(agent: { name: string; pubkey: string; privateKey: CryptoKey }, intervalMs: number) {
  let x = Math.floor(Math.random() * 100);
  let z = Math.floor(Math.random() * 100);
  let count = 0;

  while (true) {
    const timestamp = Date.now();
    const action = count % 4 === 3 ? "break" : "place";
    let res: any;

    if (action === "place") {
      const blockType = BLOCK_NAMES[count % BLOCK_NAMES.length];
      const y = 1 + (count % 10);
      const payload = { x, z, block: y, block_type: blockType };
      const signature = await sign(agent.privateKey, { type: "place", payload, timestamp });
      res = await post("/event", { type: "place", payload, pubkey: agent.pubkey, signature, timestamp });
      x = (x + 1) % 200;
      if (x === 0) z = (z + 1) % 200;
    } else {
      const payload = { x: Math.floor(Math.random() * 200), z: Math.floor(Math.random() * 200) };
      const signature = await sign(agent.privateKey, { type: "break", payload, timestamp });
      res = await post("/event", { type: "break", payload, pubkey: agent.pubkey, signature, timestamp });
    }

    if (res.ok) totalOk++;
    else totalErr++;
    totalSent++;
    count++;

    await new Promise(r => setTimeout(r, intervalMs));
  }
}

async function main() {
  console.log(`Starting ${NUM_AGENTS} agents at ${INTERVAL_MS}ms intervals each (~${Math.floor(NUM_AGENTS * 1000 / INTERVAL_MS)}/s target)`);

  const agents = await Promise.all(
    Array.from({ length: NUM_AGENTS }, (_, i) => createAgent(`agent-${i}`))
  );

  // Register and seed all agents
  for (const agent of agents) {
    await post("/players/register", { pubkey: agent.pubkey, name: agent.name + '-' + (Date.now() % 10000) });
    await post("/seed", { pubkey: agent.pubkey, amount: 100000 });
  }
  console.log(`All ${NUM_AGENTS} agents seeded`);

  const startTime = Date.now();

  // Stats printer
  setInterval(async () => {
    const elapsed = (Date.now() - startTime) / 1000;
    const rate = totalSent / elapsed;
    let info: any = {};
    try { info = await get("/dag/status"); } catch {}
    console.log(
      `[${Math.floor(elapsed)}s] sent=${totalSent} ok=${totalOk} err=${totalErr} ` +
      `rate=${rate.toFixed(1)}/s round=${info.current_round ?? '?'} committed=${info.last_committed_round ?? '?'} ` +
      `pending=${info.pending_events ?? '?'}`
    );
  }, 10000);

  // Launch all agent loops in parallel with staggered start
  await Promise.all(agents.map((agent, i) =>
    new Promise<void>(resolve => setTimeout(() => { agentLoop(agent, INTERVAL_MS); resolve(); }, i * 10))
  ));
}

main().catch(console.error);
