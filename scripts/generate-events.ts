#!/usr/bin/env -S npx tsx
// ─── Persistia Procedural Builder ────────────────────────────────────────────
// Generates events that build visible structures in the world:
// villages, roads, towers, trees, walls, and terrain patches.
// Usage: npx tsx scripts/generate-events.ts [--node URL] [--interval MS] [--agents N]

const NODE = process.argv.includes("--node")
  ? process.argv[process.argv.indexOf("--node") + 1]
  : process.env.PERSISTIA_NODE || "https://persistia.carnation-903.workers.dev";

const SHARD = process.argv.includes("--shard")
  ? process.argv[process.argv.indexOf("--shard") + 1]
  : process.env.PERSISTIA_SHARD || "node-1";

const INTERVAL = process.argv.includes("--interval")
  ? parseInt(process.argv[process.argv.indexOf("--interval") + 1])
  : 2000;

const NUM_AGENTS = process.argv.includes("--agents")
  ? parseInt(process.argv[process.argv.indexOf("--agents") + 1])
  : 3;

// ─── Block IDs ───────────────────────────────────────────────────────────────
const DIRT = 1, STONE = 2, WOOD = 3, GRASS = 4;
const BLOCK_NAMES: Record<number, string> = { 1: "dirt", 2: "stone", 3: "wood", 4: "grass" };

// ─── Crypto ──────────────────────────────────────────────────────────────────

function bytesToB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

interface Agent {
  name: string;
  pubkey: string;
  privateKey: CryptoKey;
  inventory: Record<string, number>;
  buildQueue: { x: number; z: number; block: number }[];
}

async function createAgent(name: string): Promise<Agent> {
  const keyPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const pubRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  return {
    name,
    pubkey: bytesToB64(new Uint8Array(pubRaw)),
    privateKey: keyPair.privateKey,
    inventory: {},
    buildQueue: [],
  };
}

async function sign(privateKey: CryptoKey, data: any): Promise<string> {
  const encoded = new TextEncoder().encode(JSON.stringify(data));
  const sig = await crypto.subtle.sign("Ed25519", privateKey, encoded);
  return bytesToB64(new Uint8Array(sig));
}

// ─── API ─────────────────────────────────────────────────────────────────────

function shardUrl(path: string): string {
  const sep = path.includes("?") ? "&" : "?";
  return `${NODE}${path}${sep}shard=${SHARD}`;
}

async function post(path: string, body: any): Promise<any> {
  try {
    const res = await fetch(shardUrl(path), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    return text ? JSON.parse(text) : { ok: false, error: `Empty response (${res.status})` };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

async function get(path: string): Promise<any> {
  try {
    const res = await fetch(shardUrl(path));
    const text = await res.text();
    return text ? JSON.parse(text) : {};
  } catch (e: any) {
    return {};
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

async function seedInventory(agent: Agent, amount = 500): Promise<void> {
  const result = await post("/seed", { pubkey: agent.pubkey, amount });
  if (result.inventory) agent.inventory = result.inventory;
}

async function placeBlock(agent: Agent, x: number, z: number, block: number): Promise<boolean> {
  const item = BLOCK_NAMES[block];
  if ((agent.inventory[item] || 0) <= 0) return false;

  const timestamp = Date.now();
  const payload = { x, z, block, block_type: item };
  const signature = await sign(agent.privateKey, { type: "place", payload, timestamp });
  const result = await post("/event", { type: "place", payload, pubkey: agent.pubkey, signature, timestamp });

  if (result.ok) {
    agent.inventory[item] = (agent.inventory[item] || 0) - 1;
    return true;
  }
  return false;
}

async function breakBlock(agent: Agent, x: number, z: number): Promise<boolean> {
  const timestamp = Date.now();
  const payload = { x, z };
  const signature = await sign(agent.privateKey, { type: "break", payload, timestamp });
  const result = await post("/event", { type: "break", payload, pubkey: agent.pubkey, signature, timestamp });
  return !!result.ok;
}

// ─── Structure Generators ────────────────────────────────────────────────────
// Each returns an array of {x, z, block} for the agent to build sequentially.

function generateHouse(cx: number, cz: number, w: number, h: number): { x: number; z: number; block: number }[] {
  const blocks: { x: number; z: number; block: number }[] = [];

  // Floor
  for (let x = cx; x < cx + w; x++) {
    for (let z = cz; z < cz + h; z++) {
      blocks.push({ x, z, block: WOOD });
    }
  }
  // Walls
  for (let x = cx; x < cx + w; x++) {
    blocks.push({ x, z: cz, block: STONE });
    blocks.push({ x, z: cz + h - 1, block: STONE });
  }
  for (let z = cz + 1; z < cz + h - 1; z++) {
    blocks.push({ x: cx, z, block: STONE });
    blocks.push({ x: cx + w - 1, z, block: STONE });
  }
  // Door (remove one wall block — leave wood floor)
  const doorX = cx + Math.floor(w / 2);
  blocks.push({ x: doorX, z: cz + h - 1, block: DIRT });

  return blocks;
}

function generateTower(cx: number, cz: number, radius: number): { x: number; z: number; block: number }[] {
  const blocks: { x: number; z: number; block: number }[] = [];
  for (let dx = -radius; dx <= radius; dx++) {
    for (let dz = -radius; dz <= radius; dz++) {
      const dist = Math.sqrt(dx * dx + dz * dz);
      if (dist <= radius + 0.5) {
        if (dist >= radius - 0.8) {
          blocks.push({ x: cx + dx, z: cz + dz, block: STONE });
        } else {
          blocks.push({ x: cx + dx, z: cz + dz, block: DIRT });
        }
      }
    }
  }
  return blocks;
}

function generateTree(cx: number, cz: number): { x: number; z: number; block: number }[] {
  const blocks: { x: number; z: number; block: number }[] = [];
  // Trunk
  blocks.push({ x: cx, z: cz, block: WOOD });
  // Canopy (cross pattern)
  for (const [dx, dz] of [[0, -1], [0, -2], [-1, -1], [1, -1], [-1, 0], [1, 0], [0, 1], [-2, 0], [2, 0], [-1, -2], [1, -2]]) {
    blocks.push({ x: cx + dx, z: cz + dz, block: GRASS });
  }
  return blocks;
}

function generateRoad(x1: number, z1: number, x2: number, z2: number, width = 1): { x: number; z: number; block: number }[] {
  const blocks: { x: number; z: number; block: number }[] = [];
  const dx = Math.sign(x2 - x1);
  const dz = Math.sign(z2 - z1);
  let x = x1, z = z1;

  // L-shaped path: go horizontal first, then vertical
  while (x !== x2) {
    for (let w = -Math.floor(width / 2); w <= Math.floor(width / 2); w++) {
      blocks.push({ x, z: z + w, block: DIRT });
    }
    x += dx;
  }
  while (z !== z2) {
    for (let w = -Math.floor(width / 2); w <= Math.floor(width / 2); w++) {
      blocks.push({ x: x + w, z, block: DIRT });
    }
    z += dz;
  }
  return blocks;
}

function generateWall(x1: number, z1: number, x2: number, z2: number): { x: number; z: number; block: number }[] {
  const blocks: { x: number; z: number; block: number }[] = [];
  const dx = Math.sign(x2 - x1);
  const dz = Math.sign(z2 - z1);
  let x = x1, z = z1;

  while (x !== x2 || z !== z2) {
    blocks.push({ x, z, block: STONE });
    if (x !== x2) x += dx;
    else z += dz;
  }
  blocks.push({ x: x2, z: z2, block: STONE });
  return blocks;
}

function generateGarden(cx: number, cz: number, size: number): { x: number; z: number; block: number }[] {
  const blocks: { x: number; z: number; block: number }[] = [];
  // Grass patch with scattered pattern
  for (let dx = 0; dx < size; dx++) {
    for (let dz = 0; dz < size; dz++) {
      if ((dx + dz) % 2 === 0) {
        blocks.push({ x: cx + dx, z: cz + dz, block: GRASS });
      }
    }
  }
  return blocks;
}

function generateSpiral(cx: number, cz: number, turns: number): { x: number; z: number; block: number }[] {
  const blocks: { x: number; z: number; block: number }[] = [];
  const steps = turns * 20;
  for (let i = 0; i < steps; i++) {
    const angle = (i / steps) * turns * Math.PI * 2;
    const r = 1 + (i / steps) * turns * 2;
    const x = cx + Math.round(Math.cos(angle) * r);
    const z = cz + Math.round(Math.sin(angle) * r);
    blocks.push({ x, z, block: i % 3 === 0 ? STONE : WOOD });
  }
  return blocks;
}

function generatePyramid(cx: number, cz: number, size: number): { x: number; z: number; block: number }[] {
  const blocks: { x: number; z: number; block: number }[] = [];
  // Concentric squares from outside in, alternating materials
  for (let layer = 0; layer < Math.ceil(size / 2); layer++) {
    const s = size - layer * 2;
    const ox = cx + layer;
    const oz = cz + layer;
    const block = layer % 2 === 0 ? STONE : DIRT;
    for (let dx = 0; dx < s; dx++) {
      for (let dz = 0; dz < s; dz++) {
        if (dx === 0 || dx === s - 1 || dz === 0 || dz === s - 1) {
          blocks.push({ x: ox + dx, z: oz + dz, block });
        }
      }
    }
  }
  // Center cap
  blocks.push({ x: cx + Math.floor(size / 2), z: cz + Math.floor(size / 2), block: WOOD });
  return blocks;
}

// ─── Village Generator ───────────────────────────────────────────────────────

interface Village {
  name: string;
  cx: number;
  cz: number;
  structures: { x: number; z: number; block: number }[];
}

function generateVillage(name: string, cx: number, cz: number): Village {
  const all: { x: number; z: number; block: number }[] = [];

  // 3-5 houses around a center
  const numHouses = 3 + Math.floor(Math.random() * 3);
  const housePositions: { x: number; z: number }[] = [];

  for (let i = 0; i < numHouses; i++) {
    const angle = (i / numHouses) * Math.PI * 2 + (Math.random() - 0.5) * 0.4;
    const dist = 8 + Math.random() * 6;
    const hx = cx + Math.round(Math.cos(angle) * dist);
    const hz = cz + Math.round(Math.sin(angle) * dist);
    const w = 4 + Math.floor(Math.random() * 3);
    const h = 4 + Math.floor(Math.random() * 3);
    all.push(...generateHouse(hx, hz, w, h));
    housePositions.push({ x: hx + Math.floor(w / 2), z: hz + h });
  }

  // Roads connecting houses to center
  for (const hp of housePositions) {
    all.push(...generateRoad(hp.x, hp.z, cx, cz, 1));
  }

  // Central feature — tower or garden
  if (Math.random() > 0.5) {
    all.push(...generateTower(cx, cz, 2));
  } else {
    all.push(...generateGarden(cx - 2, cz - 2, 5));
  }

  // Trees around outskirts
  const numTrees = 5 + Math.floor(Math.random() * 8);
  for (let i = 0; i < numTrees; i++) {
    const angle = Math.random() * Math.PI * 2;
    const dist = 18 + Math.random() * 10;
    const tx = cx + Math.round(Math.cos(angle) * dist);
    const tz = cz + Math.round(Math.sin(angle) * dist);
    all.push(...generateTree(tx, tz));
  }

  // Perimeter wall (partial)
  if (Math.random() > 0.4) {
    const r = 22;
    const wallStart = Math.random() * Math.PI * 2;
    const wallArc = Math.PI * (0.8 + Math.random() * 0.8);
    const steps = Math.floor(wallArc * r / 2);
    for (let i = 0; i <= steps; i++) {
      const a = wallStart + (i / steps) * wallArc;
      const wx = cx + Math.round(Math.cos(a) * r);
      const wz = cz + Math.round(Math.sin(a) * r);
      all.push({ x: wx, z: wz, block: STONE });
    }
  }

  return { name, cx, cz, structures: all };
}

function generateLandmark(cx: number, cz: number): { x: number; z: number; block: number }[] {
  const type = Math.floor(Math.random() * 4);
  switch (type) {
    case 0: return generatePyramid(cx, cz, 7 + Math.floor(Math.random() * 4));
    case 1: return generateSpiral(cx, cz, 2 + Math.random() * 2);
    case 2: return generateTower(cx, cz, 3 + Math.floor(Math.random() * 2));
    case 3: {
      // Stone circle
      const blocks: { x: number; z: number; block: number }[] = [];
      const r = 5 + Math.floor(Math.random() * 4);
      for (let i = 0; i < 12; i++) {
        const a = (i / 12) * Math.PI * 2;
        blocks.push({ x: cx + Math.round(Math.cos(a) * r), z: cz + Math.round(Math.sin(a) * r), block: STONE });
      }
      return blocks;
    }
    default: return [];
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`Persistia Procedural Builder`);
  console.log(`  Node:     ${NODE}`);
  console.log(`  Shard:    ${SHARD}`);
  console.log(`  Interval: ${INTERVAL}ms`);
  console.log(`  Agents:   ${NUM_AGENTS}`);
  console.log();

  // Check node
  try {
    const status = await get("/dag/status");
    console.log(`Node: round=${status.current_round}, seq=${status.finalized_seq}, nodes=${status.active_nodes}`);
  } catch (e: any) {
    console.error(`Cannot reach node: ${e.message}`);
    process.exit(1);
  }

  // Create agents
  const agents: Agent[] = [];
  for (let i = 0; i < NUM_AGENTS; i++) {
    const agent = await createAgent(`builder-${i + 1}`);
    agents.push(agent);
    console.log(`Created ${agent.name} (${agent.pubkey.slice(0, 12)}...)`);
  }
  console.log();

  // Seed large inventories for building
  for (const agent of agents) {
    await seedInventory(agent, 2000);
    const total = Object.values(agent.inventory).reduce((a, b) => a + b, 0);
    console.log(`  [${agent.name}] Inventory: ${total} items`);
  }
  console.log();

  // ─── Generate build plans ─────────────────────────────────────────────

  // Place 3-4 villages at different locations
  const VILLAGE_NAMES = ["Oakvale", "Stonekeep", "Thornfield", "Ironhaven", "Willowmere", "Duskhollow"];
  const villages: Village[] = [];
  const numVillages = 3 + Math.floor(Math.random() * 2);

  for (let i = 0; i < numVillages; i++) {
    const angle = (i / numVillages) * Math.PI * 2 + (Math.random() - 0.5) * 0.3;
    const dist = 30 + Math.random() * 20;
    const vx = Math.round(Math.cos(angle) * dist);
    const vz = Math.round(Math.sin(angle) * dist);
    const name = VILLAGE_NAMES[i % VILLAGE_NAMES.length];
    const v = generateVillage(name, vx, vz);
    villages.push(v);
    console.log(`  Village "${name}" at (${vx}, ${vz}) — ${v.structures.length} blocks`);
  }

  // Roads between villages
  const interVillageRoads: { x: number; z: number; block: number }[] = [];
  for (let i = 0; i < villages.length - 1; i++) {
    const from = villages[i];
    const to = villages[i + 1];
    interVillageRoads.push(...generateRoad(from.cx, from.cz, to.cx, to.cz, 2));
  }
  // Close the loop
  if (villages.length > 2) {
    const first = villages[0];
    const last = villages[villages.length - 1];
    interVillageRoads.push(...generateRoad(last.cx, last.cz, first.cx, first.cz, 2));
  }
  console.log(`  Inter-village roads: ${interVillageRoads.length} blocks`);

  // Landmarks scattered around
  const landmarks: { x: number; z: number; block: number }[] = [];
  for (let i = 0; i < 4; i++) {
    const lx = Math.round((Math.random() - 0.5) * 80);
    const lz = Math.round((Math.random() - 0.5) * 80);
    landmarks.push(...generateLandmark(lx, lz));
  }
  console.log(`  Landmarks: ${landmarks.length} blocks`);

  // Forest patches
  const trees: { x: number; z: number; block: number }[] = [];
  for (let i = 0; i < 15; i++) {
    const tx = Math.round((Math.random() - 0.5) * 100);
    const tz = Math.round((Math.random() - 0.5) * 100);
    trees.push(...generateTree(tx, tz));
  }
  console.log(`  Scattered trees: ${trees.length} blocks`);

  // Assign all work to agents round-robin
  const allBlocks = [
    ...interVillageRoads,  // Roads first (foundation)
    ...villages.flatMap(v => v.structures),
    ...landmarks,
    ...trees,
  ];

  // Deduplicate — later blocks overwrite earlier ones at same position
  const seen = new Map<string, { x: number; z: number; block: number }>();
  for (const b of allBlocks) {
    seen.set(`${b.x},${b.z}`, b);
  }
  const dedupedBlocks = [...seen.values()];

  console.log(`\nTotal unique blocks to place: ${dedupedBlocks.length}`);

  // Distribute to agents
  for (let i = 0; i < dedupedBlocks.length; i++) {
    agents[i % agents.length].buildQueue.push(dedupedBlocks[i]);
  }
  for (const a of agents) {
    console.log(`  ${a.name}: ${a.buildQueue.length} blocks queued`);
  }
  console.log();

  // ─── Build loop ───────────────────────────────────────────────────────

  let placed = 0;
  const total = dedupedBlocks.length;
  console.log(`Building world (Ctrl+C to stop)...\n`);

  const interval = setInterval(async () => {
    // Find an agent with work
    const agent = agents.find(a => a.buildQueue.length > 0);
    if (!agent) {
      console.log(`\nAll ${placed} blocks placed! World complete.`);
      // Start organic activity phase
      console.log(`Switching to organic activity mode...\n`);
      clearInterval(interval);
      startOrganicPhase(agents);
      return;
    }

    // Reseed if low
    const totalInv = Object.values(agent.inventory).reduce((a, b) => a + b, 0);
    if (totalInv < 100) {
      await seedInventory(agent, 2000);
    }

    const next = agent.buildQueue.shift()!;
    const ok = await placeBlock(agent, next.x, next.z, next.block);
    if (ok) {
      placed++;
      if (placed % 50 === 0) {
        const pct = ((placed / total) * 100).toFixed(1);
        process.stdout.write(`  Progress: ${placed}/${total} (${pct}%) — ${agent.name} placing ${BLOCK_NAMES[next.block]} at (${next.x},${next.z})\n`);
      }
    }
  }, INTERVAL);

  process.on("SIGINT", () => {
    clearInterval(interval);
    console.log(`\nStopped. Placed ${placed}/${total} blocks.`);
    process.exit(0);
  });
}

// ─── Organic Phase ───────────────────────────────────────────────────────────
// After building, agents wander and make small changes to keep activity going.

function startOrganicPhase(agents: Agent[]) {
  let tick = 0;

  const interval = setInterval(async () => {
    tick++;
    const agent = agents[tick % agents.length];

    // Reseed occasionally
    const totalInv = Object.values(agent.inventory).reduce((a, b) => a + b, 0);
    if (totalInv < 50) {
      await seedInventory(agent, 500);
    }

    // Small random actions: extend roads, add trees, place decorative blocks, break blocks
    const roll = Math.random();
    if (roll < 0.3) {
      // Add a tree somewhere
      const tx = Math.round((Math.random() - 0.5) * 120);
      const tz = Math.round((Math.random() - 0.5) * 120);
      const tree = generateTree(tx, tz);
      for (const b of tree) {
        await placeBlock(agent, b.x, b.z, b.block);
        await sleep(500);
      }
      console.log(`  [${agent.name}] Planted tree at (${tx}, ${tz})`);
    } else if (roll < 0.5) {
      // Add a small stone/dirt patch
      const px = Math.round((Math.random() - 0.5) * 100);
      const pz = Math.round((Math.random() - 0.5) * 100);
      const block = Math.random() > 0.5 ? STONE : GRASS;
      const size = 2 + Math.floor(Math.random() * 2);
      for (let dx = 0; dx < size; dx++) {
        for (let dz = 0; dz < size; dz++) {
          if (Math.random() > 0.4) {
            await placeBlock(agent, px + dx, pz + dz, block);
            await sleep(500);
          }
        }
      }
      console.log(`  [${agent.name}] Created ${BLOCK_NAMES[block]} patch at (${px}, ${pz})`);
    } else if (roll < 0.7) {
      // Extend a road from a random spot
      const rx = Math.round((Math.random() - 0.5) * 80);
      const rz = Math.round((Math.random() - 0.5) * 80);
      const len = 3 + Math.floor(Math.random() * 5);
      const horizontal = Math.random() > 0.5;
      for (let i = 0; i < len; i++) {
        const x = horizontal ? rx + i : rx;
        const z = horizontal ? rz : rz + i;
        await placeBlock(agent, x, z, DIRT);
        await sleep(500);
      }
      console.log(`  [${agent.name}] Extended road at (${rx}, ${rz})`);
    } else {
      // Break some blocks in a random area (clearing, demolition)
      const bx = Math.round((Math.random() - 0.5) * 100);
      const bz = Math.round((Math.random() - 0.5) * 100);
      const count = 1 + Math.floor(Math.random() * 4);
      let broken = 0;
      for (let i = 0; i < count; i++) {
        const dx = Math.round((Math.random() - 0.5) * 4);
        const dz = Math.round((Math.random() - 0.5) * 4);
        if (await breakBlock(agent, bx + dx, bz + dz)) broken++;
        await sleep(500);
      }
      console.log(`  [${agent.name}] Cleared ${broken} blocks near (${bx}, ${bz})`);
    }

    if (tick % 20 === 0) {
      try {
        const status = await get("/dag/status");
        console.log(`\n── Tick ${tick} | Round ${status.current_round} | Seq ${status.finalized_seq} | Nodes ${status.active_nodes} ──\n`);
      } catch {}
    }
  }, 10000);

  process.on("SIGINT", () => {
    clearInterval(interval);
    console.log(`\nOrganic phase stopped after ${tick} ticks.`);
    process.exit(0);
  });
}

main().catch(console.error);
