#!/usr/bin/env npx tsx
/**
 * Test Berachain anchoring for Persistia.
 *
 * Two modes:
 *   1. --gateway  : Publish through HBTP's existing MCP gateway (no private key needed)
 *   2. --direct   : Sign and send raw transaction via viem (requires BERACHAIN_PRIVATE_KEY env var)
 *
 * Usage:
 *   BERACHAIN_PRIVATE_KEY=0x... npx tsx scripts/test-anchor.ts --direct
 *   npx tsx scripts/test-anchor.ts --gateway
 *   npx tsx scripts/test-anchor.ts --verify 0x<txhash>
 */

import { createPublicClient, createWalletClient, defineChain, http, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

// ─── Berachain chain definition (same as HBTP) ─────────────────────────────

const berachain = defineChain({
  id: 80094,
  name: "Berachain",
  nativeCurrency: { name: "BERA", symbol: "BERA", decimals: 18 },
  rpcUrls: {
    default: { http: ["https://rpc.berachain.com"] },
  },
  blockExplorers: {
    default: { name: "Berascan", url: "https://berascan.com" },
  },
});

const DEAD_ADDRESS = "0x000000000000000000000000000000000000dEaD" as `0x${string}`;
const PERSISTIA_BASE = "https://persistia.carnation-903.workers.dev";
const HBTP_GATEWAY = "https://hybertext-mcp.carnation-903.workers.dev";

// ─── HYTE format ────────────────────────────────────────────────────────────

function wrapHYTE(data: Uint8Array): Uint8Array {
  const header = new Uint8Array([
    0x48, 0x59, 0x54, 0x45, // HYTE magic
    0x01,                     // version
    0x00,                     // no compression
    0x04,                     // content type: blob
    0x00, 0x00,               // reserved
  ]);
  const result = new Uint8Array(header.length + data.length);
  result.set(header, 0);
  result.set(data, header.length);
  return result;
}

function stripHYTE(data: Uint8Array): Uint8Array {
  // Verify HYTE magic
  if (data[0] === 0x48 && data[1] === 0x59 && data[2] === 0x54 && data[3] === 0x45) {
    return data.slice(9);
  }
  return data; // not HYTE-wrapped
}

// ─── Fetch chain state ──────────────────────────────────────────────────────

async function fetchChainState(shard: string = "node-1") {
  const statusRes = await fetch(`${PERSISTIA_BASE}/dag/status?shard=${shard}`);
  const status = await statusRes.json() as any;

  const stateRes = await fetch(`${PERSISTIA_BASE}/state?shard=${shard}`);
  const state = await stateRes.json() as any;

  return {
    state_root: status.finalized_root,
    finalized_seq: status.finalized_seq,
    last_committed_round: status.last_committed_round,
    current_round: status.current_round,
    active_nodes: status.active_nodes,
    node_pubkey: status.node_pubkey,
    vertex_count: state?.dag?.total_vertices || 0,
    shard_name: shard,
    timestamp: Date.now(),
    snapshot_hash: status.finalized_root, // simplified
  };
}

// ─── Mode 1: Direct send via viem ───────────────────────────────────────────

async function directAnchor() {
  const privateKey = process.env.BERACHAIN_PRIVATE_KEY;
  if (!privateKey) {
    console.error("Set BERACHAIN_PRIVATE_KEY env var (hex with 0x prefix)");
    process.exit(1);
  }

  console.log("Fetching Persistia chain state...");
  const bundle = await fetchChainState();
  console.log("Chain state:", JSON.stringify(bundle, null, 2));

  // Wrap in HYTE
  const json = JSON.stringify(bundle);
  const payload = new TextEncoder().encode(json);
  const hyte = wrapHYTE(payload);
  const calldata = toHex(hyte);

  console.log(`\nAnchor calldata: ${calldata.length} hex chars (${hyte.length} bytes)`);

  // Sign and send
  const account = privateKeyToAccount(privateKey as `0x${string}`);
  console.log(`Signing with account: ${account.address}`);

  const walletClient = createWalletClient({
    account,
    chain: berachain,
    transport: http(),
  });

  const publicClient = createPublicClient({
    chain: berachain,
    transport: http(),
  });

  // Check balance
  const balance = await publicClient.getBalance({ address: account.address });
  console.log(`Balance: ${Number(balance) / 1e18} BERA`);

  if (balance === 0n) {
    console.error("Account has no BERA for gas. Fund it first.");
    process.exit(1);
  }

  console.log("\nSending anchor transaction to dead address...");
  const txHash = await walletClient.sendTransaction({
    to: DEAD_ADDRESS,
    data: calldata as `0x${string}`,
    value: 0n,
  });

  console.log(`Transaction sent: ${txHash}`);
  console.log(`Berascan: https://berascan.com/tx/${txHash}`);

  // Wait for receipt
  console.log("Waiting for confirmation...");
  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
  console.log(`Confirmed in block ${receipt.blockNumber}, status: ${receipt.status}`);

  // Now submit the anchor back to Persistia
  console.log("\nSubmitting anchor record to Persistia...");
  try {
    const submitRes = await fetch(`${PERSISTIA_BASE}/anchor/submit?shard=node-1`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        berachain_tx: txHash,
        berachain_block: Number(receipt.blockNumber),
        bundle,
      }),
    });
    const submitResult = await submitRes.json();
    console.log("Persistia anchor record:", submitResult);
  } catch (e: any) {
    console.warn(`Failed to submit to Persistia (non-critical): ${e.message}`);
  }

  return { txHash, blockNumber: Number(receipt.blockNumber), bundle };
}

// ─── Mode 2: Publish through HBTP gateway ───────────────────────────────────

async function gatewayAnchor() {
  console.log("Fetching Persistia chain state...");
  const bundle = await fetchChainState();
  console.log("Chain state:", JSON.stringify(bundle, null, 2));

  // Create a minimal HTML page with the anchor data embedded
  const html = `<!DOCTYPE html>
<html>
<head><title>Persistia Anchor #${bundle.finalized_seq}</title>
<meta name="persistia:state_root" content="${bundle.state_root}">
<meta name="persistia:finalized_seq" content="${bundle.finalized_seq}">
<meta name="persistia:round" content="${bundle.last_committed_round}">
</head>
<body>
<h1>Persistia State Anchor</h1>
<pre id="anchor-data">${JSON.stringify(bundle, null, 2)}</pre>
<script>window.__PERSISTIA_ANCHOR__ = ${JSON.stringify(bundle)};</script>
</body>
</html>`;

  // Build a ZIP containing index.html using fflate (or manual ZIP)
  // The HBTP gateway requires multipart/form-data with a ZIP file
  const { Blob } = await import("buffer");
  const fflate = await import("fflate");

  const zipData = fflate.zipSync({
    "index.html": fflate.strToU8(html),
    "anchor.json": fflate.strToU8(JSON.stringify(bundle, null, 2)),
  });

  console.log(`\nPublishing anchor page through HBTP gateway...`);
  console.log(`Gateway: ${HBTP_GATEWAY}/publish`);
  console.log(`ZIP size: ${zipData.length} bytes`);

  // Build multipart form data with the ZIP
  const formData = new FormData();
  const blob = new globalThis.Blob([zipData], { type: "application/zip" });
  formData.append("file", blob, "persistia-anchor.zip");

  const res = await fetch(`${HBTP_GATEWAY}/publish`, {
    method: "POST",
    body: formData,
  });

  const text = await res.text();
  console.log(`\nGateway response (${res.status}): ${text}`);

  if (!res.ok) {
    console.error("Gateway publish failed");
    process.exit(1);
  }

  let result: any;
  try { result = JSON.parse(text); } catch { result = { raw: text }; }

  if (result.txHash) {
    console.log(`\nBerachain TX: ${result.txHash}`);
    console.log(`Berascan: https://berascan.com/tx/${result.txHash}`);
    console.log(`Gateway URL: ${result.url || `${HBTP_GATEWAY}/${result.txHash}/`}`);
  }

  return result;
}

// ─── Mode 3: Verify an existing anchor from Berachain ───────────────────────

async function verifyAnchor(txHash: string) {
  console.log(`Verifying anchor from Berachain tx: ${txHash}`);

  const publicClient = createPublicClient({
    chain: berachain,
    transport: http(),
  });

  const tx = await publicClient.getTransaction({ hash: txHash as `0x${string}` });

  if (!tx) {
    console.error("Transaction not found");
    process.exit(1);
  }

  console.log(`From: ${tx.from}`);
  console.log(`To: ${tx.to}`);
  console.log(`Block: ${tx.blockNumber}`);
  console.log(`Input length: ${tx.input.length} hex chars`);

  // Decode the calldata
  const inputBytes = hexToBytes(tx.input.slice(2));

  // Check for HYTE header
  if (inputBytes[0] === 0x48 && inputBytes[1] === 0x59 && inputBytes[2] === 0x54 && inputBytes[3] === 0x45) {
    console.log("\nHYTE header detected:");
    console.log(`  Version: ${inputBytes[4]}`);
    console.log(`  Compression: ${inputBytes[5]}`);
    console.log(`  Content type: ${inputBytes[6]}`);

    const payload = inputBytes.slice(9);
    const text = new TextDecoder().decode(payload);

    try {
      const data = JSON.parse(text);
      console.log("\nDecoded anchor data:");
      console.log(JSON.stringify(data, null, 2));

      if (data.state_root) {
        console.log("\n✓ Valid Persistia anchor bundle");
        console.log(`  State root: ${data.state_root}`);
        console.log(`  Finalized seq: ${data.finalized_seq}`);
        console.log(`  Round: ${data.last_committed_round}`);
        console.log(`  Nodes: ${data.active_nodes}`);
      }
    } catch {
      console.log("\nRaw payload (not JSON):");
      console.log(text.slice(0, 500));
    }
  } else {
    console.log("\nNo HYTE header — raw calldata");
    const text = new TextDecoder().decode(inputBytes);
    console.log(text.slice(0, 500));
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// ─── CLI ────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const mode = args[0] || "--gateway";

(async () => {
  try {
    if (mode === "--direct") {
      await directAnchor();
    } else if (mode === "--gateway") {
      await gatewayAnchor();
    } else if (mode === "--verify") {
      const txHash = args[1];
      if (!txHash) {
        console.error("Usage: --verify 0x<txhash>");
        process.exit(1);
      }
      await verifyAnchor(txHash);
    } else {
      console.log("Usage:");
      console.log("  npx tsx scripts/test-anchor.ts --gateway           # Publish through HBTP gateway");
      console.log("  npx tsx scripts/test-anchor.ts --direct            # Send directly (needs BERACHAIN_PRIVATE_KEY)");
      console.log("  npx tsx scripts/test-anchor.ts --verify 0x<hash>   # Verify existing anchor tx");
    }
  } catch (e: any) {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  }
})();
