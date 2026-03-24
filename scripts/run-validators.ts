#!/usr/bin/env -S npx tsx
// ─── Persistia Validator Simulator (WebSocket) ──────────────────────────────
// Runs N simulated validator nodes over persistent WebSocket connections.
// Zero HTTP polling — all communication via WS push/pull.
//
// Usage: npx tsx scripts/run-validators.ts [--node URL] [--validators N]

import WebSocket from "ws";

const NODE = process.argv.includes("--node")
  ? process.argv[process.argv.indexOf("--node") + 1]
  : process.env.PERSISTIA_NODE || "https://persistia.carnation-903.workers.dev";

const NUM_VALIDATORS = process.argv.includes("--validators")
  ? parseInt(process.argv[process.argv.indexOf("--validators") + 1])
  : 3;

// ─── Crypto Helpers ──────────────────────────────────────────────────────────

function bytesToB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

async function sha256(data: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

interface ValidatorNode {
  name: string;
  pubkey: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  ws: WebSocket | null;
  currentRound: number;
  parentHashes: string[];
  submittedRounds: Set<number>;
}

async function createValidator(name: string): Promise<ValidatorNode> {
  const keyPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const pubRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  return {
    name,
    pubkey: bytesToB64(new Uint8Array(pubRaw)),
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    ws: null,
    currentRound: 0,
    parentHashes: [],
    submittedRounds: new Set(),
  };
}

async function signData(privateKey: CryptoKey, data: string): Promise<string> {
  const encoded = new TextEncoder().encode(data);
  const sig = await crypto.subtle.sign("Ed25519", privateKey, encoded);
  return bytesToB64(new Uint8Array(sig));
}

// ─── Vertex Creation ─────────────────────────────────────────────────────────

interface DAGVertex {
  author: string;
  round: number;
  event_hashes: string[];
  events: any[];
  refs: string[];
  timestamp: number;
  signature: string;
}

async function signVertex(
  privateKey: CryptoKey,
  vertex: { author: string; round: number; event_hashes: string[]; refs: string[]; timestamp: number },
): Promise<string> {
  const canonical = JSON.stringify({
    author: vertex.author,
    round: vertex.round,
    event_hashes: [...vertex.event_hashes].sort(),
    refs: [...vertex.refs].sort(),
    timestamp: vertex.timestamp,
  });
  return signData(privateKey, canonical);
}

// ─── WebSocket Connection ────────────────────────────────────────────────────

function connectValidator(node: ValidatorNode): Promise<void> {
  return new Promise((resolve, reject) => {
    const wsUrl = NODE.replace(/^http/, "ws");
    const ws = new WebSocket(wsUrl);
    node.ws = ws;

    ws.on("open", async () => {
      console.log(`  [${node.name}] WS connected`);

      // Register as validator
      const regData = JSON.stringify({ pubkey: node.pubkey, url: "" });
      const signature = await signData(node.privateKey, regData);
      ws.send(JSON.stringify({
        type: "register",
        pubkey: node.pubkey,
        url: "",
        signature,
      }));

      // Subscribe to DAG and status channels
      ws.send(JSON.stringify({
        type: "subscribe",
        channels: ["dag", "status"],
      }));

      // Request initial sync
      ws.send(JSON.stringify({
        type: "sync",
        after_round: 0,
        limit: 500,
      }));
    });

    ws.on("message", async (data) => {
      try {
        const msg = JSON.parse(data.toString());
        await handleMessage(node, msg);
      } catch (e: any) {
        console.error(`  [${node.name}] Message error: ${e.message}`);
      }
    });

    ws.on("close", () => {
      console.log(`  [${node.name}] WS disconnected, reconnecting in 5s...`);
      node.ws = null;
      setTimeout(() => connectValidator(node).catch(() => {}), 5000);
    });

    ws.on("error", (err) => {
      console.error(`  [${node.name}] WS error: ${err.message}`);
    });

    // Resolve after a short delay to let registration complete
    setTimeout(resolve, 2000);
  });
}

async function handleMessage(node: ValidatorNode, msg: any) {
  switch (msg.type) {
    case "register.result":
      if (msg.ok) {
        console.log(`  [${node.name}] Registered (${node.pubkey.slice(0, 16)}...)`);
      } else {
        console.error(`  [${node.name}] Registration failed: ${msg.error}`);
      }
      break;

    case "sync.result":
      // Process initial sync data — extract parent hashes for current round
      if (msg.vertices && msg.vertices.length > 0) {
        let maxRound = 0;
        const hashesByRound = new Map<number, string[]>();
        for (const v of msg.vertices) {
          const round = v.round;
          if (round > maxRound) maxRound = round;
          if (!hashesByRound.has(round)) hashesByRound.set(round, []);
          hashesByRound.get(round)!.push(v.hash);
        }
        // Use the DO's current round (which is the round expecting vertices)
        node.currentRound = msg.latest_round || maxRound;
        node.parentHashes = hashesByRound.get(node.currentRound - 1) || [];
      } else {
        // No vertices yet — start at the DO's current round
        node.currentRound = msg.latest_round || 0;
        node.parentHashes = [];
      }
      // Submit a vertex for the current round
      await maybeSubmitVertex(node);
      break;

    case "status.update": {
      const newRound = msg.current_round || 0;
      if (newRound > node.currentRound) {
        // Reset refs for the new round — we'll get fresh vertex.new messages
        // Keep recent hashes that might be from the previous round
        node.parentHashes = node.parentHashes.slice(-20);
        node.currentRound = newRound;
        scheduleVertexSubmission(node);
      }
      break;
    }

    case "vertex.new": {
      // Use the hash from the broadcast directly
      const vHash = msg.hash || await sha256(JSON.stringify({
        author: msg.author, round: msg.round,
        event_hashes: [...(msg.event_hashes || [])].sort(),
        refs: [...(msg.refs || [])].sort(),
        timestamp: msg.timestamp,
      }));
      // Only track vertices from the most recent rounds as refs
      // (the commit rule checks that round r+1 vertices reference the anchor at round r)
      if (msg.round >= node.currentRound - 1) {
        if (!node.parentHashes.includes(vHash)) {
          node.parentHashes.push(vHash);
        }
      }
      break;
    }

    case "vertex.result":
      if (!msg.ok && msg.error && !msg.error.includes("Equivocation") && !msg.error.includes("duplicate")) {
        console.error(`  [${node.name}] Vertex rejected: ${msg.error}`);
      }
      break;

    case "commit":
      // Log commits
      break;
  }
}

// Debounce vertex submission — wait 500ms to accumulate parent refs
const submitTimers = new Map<string, ReturnType<typeof setTimeout>>();
function scheduleVertexSubmission(node: ValidatorNode) {
  const existing = submitTimers.get(node.pubkey);
  if (existing) clearTimeout(existing);
  submitTimers.set(node.pubkey, setTimeout(() => {
    submitTimers.delete(node.pubkey);
    maybeSubmitVertex(node);
  }, 500));
}

async function maybeSubmitVertex(node: ValidatorNode) {
  if (!node.ws || node.ws.readyState !== WebSocket.OPEN) return;
  if (node.submittedRounds.has(node.currentRound)) return;

  node.submittedRounds.add(node.currentRound);

  // Clean old rounds from tracking set
  if (node.submittedRounds.size > 100) {
    const minKeep = node.currentRound - 50;
    for (const r of node.submittedRounds) {
      if (r < minKeep) node.submittedRounds.delete(r);
    }
  }

  const vertex: DAGVertex = {
    author: node.pubkey,
    round: node.currentRound,
    event_hashes: [],
    events: [],
    refs: [...new Set(node.parentHashes)].slice(-20), // latest unique refs
    timestamp: Date.now(),
    signature: "",
  };

  vertex.signature = await signVertex(node.privateKey, vertex);

  node.ws.send(JSON.stringify({ type: "vertex", ...vertex }));
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`Persistia Validator Simulator (WebSocket)`);
  console.log(`  Node:       ${NODE}`);
  console.log(`  Validators: ${NUM_VALIDATORS} (+ 1 DO node = ${NUM_VALIDATORS + 1} total)`);
  console.log(`  Protocol:   WebSocket push (zero HTTP polling)`);
  console.log();

  // Create validators
  const validators: ValidatorNode[] = [];
  for (let i = 0; i < NUM_VALIDATORS; i++) {
    validators.push(await createValidator(`validator-${i + 1}`));
  }

  // Connect all validators via WebSocket
  console.log(`Connecting ${NUM_VALIDATORS} validators via WebSocket...`);
  for (const node of validators) {
    await connectValidator(node);
  }

  console.log(`\nAll validators connected. Running (Ctrl+C to stop)...\n`);

  // Status logging every 30s
  setInterval(() => {
    for (const v of validators) {
      const connected = v.ws?.readyState === WebSocket.OPEN ? "connected" : "disconnected";
      console.log(`  [${v.name}] ${connected} | round=${v.currentRound} | submitted=${v.submittedRounds.size}`);
    }
  }, 30000);

  // Graceful shutdown
  process.on("SIGINT", () => {
    console.log(`\nShutting down validators...`);
    for (const v of validators) {
      v.ws?.close();
    }
    process.exit(0);
  });
}

main().catch(console.error);
