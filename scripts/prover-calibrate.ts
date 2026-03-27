#!/usr/bin/env -S npx tsx
// Prover calibration: gradually increase block rate and monitor prover lag

const NODE = "https://persistia.carnation-903.workers.dev";
const SHARD = "node-1";

function url(path: string): string {
  const sep = path.includes("?") ? "&" : "?";
  return `${NODE}${path}${sep}shard=${SHARD}`;
}

async function getJson(path: string): Promise<any> {
  const res = await fetch(url(path));
  return res.json();
}

async function postJson(path: string, body?: any): Promise<any> {
  const res = await fetch(url(path), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return res.json();
}

async function setParam(key: string, value: number): Promise<void> {
  await postJson("/admin/set-param", { key, value: String(value) });
}

async function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

// Test phases: reactive alarm delay in ms (lower = faster blocks)
const PHASES = [
  { delay: 10000, duration: 90, label: "1 block / 10s" },
  { delay: 7000,  duration: 90, label: "1 block / 7s" },
  { delay: 5000,  duration: 90, label: "1 block / 5s" },
  { delay: 3000,  duration: 90, label: "1 block / 3s" },
  { delay: 2000,  duration: 90, label: "1 block / 2s" },
  { delay: 1000,  duration: 90, label: "1 block / 1s" },
  { delay: 500,   duration: 90, label: "2 blocks / 1s" },
  { delay: 200,   duration: 60, label: "5 blocks / 1s" },
];

async function main() {
  console.log("=== Prover Calibration Test ===\n");

  // Also start event generator inline (10 agents) to ensure blocks have content
  const agents = await Promise.all(
    Array.from({ length: 10 }, async (_, i) => {
      const keyPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
      const pubRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
      const pubkey = Buffer.from(new Uint8Array(pubRaw)).toString("base64");
      await postJson("/players/register", { pubkey, name: `cal-${i}-${Date.now() % 10000}` });
      await postJson("/seed", { pubkey, amount: 100000 });
      return { pubkey, privateKey: keyPair.privateKey };
    })
  );
  console.log("10 event agents ready\n");

  // Background event loop
  let eventsOk = 0, eventsErr = 0, running = true;
  const eventLoop = async () => {
    let idx = 0;
    while (running) {
      const agent = agents[idx % agents.length];
      const payload = { x: idx % 200, z: Math.floor(idx / 200) % 200, block: 1 + (idx % 10), block_type: "stone" };
      const encoded = new TextEncoder().encode(JSON.stringify({ type: "place", payload, timestamp: Date.now() }));
      const sig = await crypto.subtle.sign("Ed25519", agent.privateKey, encoded);
      const signature = Buffer.from(new Uint8Array(sig)).toString("base64");
      try {
        const res = await postJson("/event", { type: "place", payload, pubkey: agent.pubkey, signature, timestamp: Date.now() });
        if (res.ok) eventsOk++; else eventsErr++;
      } catch { eventsErr++; }
      idx++;
      await sleep(100); // 10/s target
    }
  };
  eventLoop();

  for (const phase of PHASES) {
    console.log(`\n--- Phase: ${phase.label} (delay=${phase.delay}ms, ${phase.duration}s) ---`);
    await setParam("reactive_alarm_delay_ms", phase.delay);

    const startStatus = await getJson("/proof/zk/status");
    const startRound = startStatus.last_committed_round;
    const startProven = startStatus.latest_proven_block;
    const startGap = startStatus.proof_gap;
    const startEvents = eventsOk;

    console.log(`Start: committed=${startRound} proven=${startProven} gap=${startGap}`);

    // Monitor at intervals
    const samples: { t: number; round: number; proven: number; gap: number; events: number }[] = [];
    const t0 = Date.now();

    for (let elapsed = 0; elapsed < phase.duration; elapsed += 15) {
      await sleep(15000);
      const status = await getJson("/proof/zk/status");
      const dagStats = await getJson("/admin/dag-stats");
      const t = Math.round((Date.now() - t0) / 1000);
      const round = dagStats.current_round;
      const committed = dagStats.last_committed_round;
      const proven = status.latest_proven_block;
      const gap = status.proof_gap;
      const ev = eventsOk - startEvents;

      samples.push({ t, round, proven, gap, events: ev });
      console.log(
        `  +${t}s: round=${round} committed=${committed} proven=${proven} gap=${gap} events_ok=${ev}`
      );

      // If gap grows by more than 50 in a phase, prover can't keep up
      if (gap - startGap > 50) {
        console.log(`  ** PROVER FALLING BEHIND (gap grew by ${gap - startGap}) **`);
      }
    }

    // Summary
    const endStatus = await getJson("/proof/zk/status");
    const roundsProduced = endStatus.last_committed_round - startRound;
    const proofsGenerated = endStatus.latest_proven_block - startProven;
    const gapDelta = endStatus.proof_gap - startGap;
    const blockRate = roundsProduced / phase.duration;
    const proofRate = proofsGenerated / phase.duration;

    console.log(`  Summary: blocks=${roundsProduced} (${blockRate.toFixed(2)}/s) proofs=${proofsGenerated} (${proofRate.toFixed(2)}/s) gap_delta=${gapDelta > 0 ? "+" : ""}${gapDelta}`);

    if (gapDelta > 20) {
      console.log(`\n=== PROVER LIMIT FOUND ===`);
      console.log(`Prover can't sustain ${phase.label} — gap grew by ${gapDelta}`);
      console.log(`Sustainable rate is somewhere between this and the previous phase.`);
      console.log(`Proof rate: ${proofRate.toFixed(3)} proofs/s = ~${(proofRate * 60).toFixed(1)} proofs/min`);

      // Test one more phase to confirm
      continue;
    }
  }

  running = false;
  console.log("\n=== Calibration complete ===");
  const finalStatus = await getJson("/proof/zk/status");
  console.log(`Final: proven=${finalStatus.latest_proven_block} gap=${finalStatus.proof_gap}`);
  console.log(`Events: ${eventsOk} accepted, ${eventsErr} rejected`);
}

main().catch(console.error);
