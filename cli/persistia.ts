#!/usr/bin/env -S npx tsx
// ─── Persistia CLI ────────────────────────────────────────────────────────────
// Developer tool for deploying contracts, calling methods, managing triggers,
// and interacting with Persistia nodes.

import { readFileSync, existsSync } from "fs";
import { resolve } from "path";

// ─── Config ───────────────────────────────────────────────────────────────────

const DEFAULT_NODE = process.env.PERSISTIA_NODE || "http://localhost:8787";

function getNode(): string {
  const idx = process.argv.indexOf("--node");
  if (idx !== -1 && process.argv[idx + 1]) return process.argv[idx + 1];
  return DEFAULT_NODE;
}

// ─── Key Management ───────────────────────────────────────────────────────────

const KEY_FILE = resolve(process.env.HOME || "~", ".persistia", "keys.json");

interface KeyPair {
  pub: string;   // base64 raw Ed25519 public key
  priv: string;  // base64 PKCS8 Ed25519 private key
}

async function loadOrCreateKeys(): Promise<{ keys: KeyPair; privateKey: CryptoKey; publicKey: CryptoKey }> {
  const dir = resolve(process.env.HOME || "~", ".persistia");
  const { mkdirSync } = await import("fs");
  const { writeFileSync } = await import("fs");

  if (existsSync(KEY_FILE)) {
    const stored = JSON.parse(readFileSync(KEY_FILE, "utf8")) as KeyPair;
    const pubBytes = b64ToBytes(stored.pub);
    const privBytes = b64ToBytes(stored.priv);
    const publicKey = await crypto.subtle.importKey("raw", pubBytes, "Ed25519", true, ["verify"]);
    const privateKey = await crypto.subtle.importKey("pkcs8", privBytes, "Ed25519", true, ["sign"]);
    return { keys: stored, privateKey, publicKey };
  }

  mkdirSync(dir, { recursive: true });
  const keyPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const pubRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  const privPkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const keys: KeyPair = {
    pub: bytesToB64(new Uint8Array(pubRaw)),
    priv: bytesToB64(new Uint8Array(privPkcs8)),
  };
  writeFileSync(KEY_FILE, JSON.stringify(keys, null, 2));
  console.log(`Generated new keypair at ${KEY_FILE}`);
  console.log(`Public key: ${keys.pub}`);
  return { keys, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey };
}

async function sign(privateKey: CryptoKey, data: any): Promise<string> {
  const encoded = new TextEncoder().encode(JSON.stringify(data));
  const sig = await crypto.subtle.sign("Ed25519", privateKey, encoded);
  return bytesToB64(new Uint8Array(sig));
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function bytesToB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function b64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

async function post(url: string, body: any): Promise<any> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}

async function get(url: string): Promise<any> {
  const res = await fetch(url);
  return res.json();
}

function die(msg: string): never {
  console.error(`Error: ${msg}`);
  process.exit(1);
}

// ─── Commands ─────────────────────────────────────────────────────────────────

async function cmdStatus() {
  const node = getNode();
  const data = await get(node);
  console.log(JSON.stringify(data, null, 2));
}

async function cmdKeys() {
  const { keys } = await loadOrCreateKeys();
  console.log(`Public key: ${keys.pub}`);
  console.log(`Key file:   ${KEY_FILE}`);
}

async function cmdDeploy() {
  const wasmPath = process.argv[3];
  if (!wasmPath) die("Usage: persistia deploy <contract.wasm>");

  const resolved = resolve(wasmPath);
  if (!existsSync(resolved)) die(`File not found: ${resolved}`);

  const wasmBytes = readFileSync(resolved);
  const wasmB64 = wasmBytes.toString("base64");

  const { keys, privateKey } = await loadOrCreateKeys();
  const node = getNode();

  const timestamp = Date.now();
  const payload = { wasm_b64: wasmB64 };
  const dataToSign = { type: "contract.deploy", payload, timestamp };
  const signature = await sign(privateKey, dataToSign);

  console.log(`Deploying ${wasmPath} (${wasmBytes.length} bytes) to ${node}...`);

  const result = await post(`${node}/contract/deploy`, {
    type: "contract.deploy",
    payload,
    pubkey: keys.pub,
    signature,
    timestamp,
  });

  if (result.ok) {
    console.log(`Deployed! Pending: ${result.pending || false}`);
    if (result.seq) console.log(`Sequence: ${result.seq}`);
  } else {
    console.error(`Deploy failed: ${result.error}`);
  }
}

async function cmdCall() {
  const address = process.argv[3];
  const method = process.argv[4];
  if (!address || !method) die("Usage: persistia call <address> <method> [args_json]");

  const argsJson = process.argv[5] || "{}";
  const argsB64 = bytesToB64(new TextEncoder().encode(argsJson));

  const { keys, privateKey } = await loadOrCreateKeys();
  const node = getNode();

  const timestamp = Date.now();
  const payload = { contract: address, method, args_b64: argsB64 };
  const dataToSign = { type: "contract.call", payload, timestamp };
  const signature = await sign(privateKey, dataToSign);

  const result = await post(`${node}/contract/call`, {
    type: "contract.call",
    payload,
    pubkey: keys.pub,
    signature,
    timestamp,
  });

  console.log(JSON.stringify(result, null, 2));
}

async function cmdQuery() {
  const address = process.argv[3];
  const method = process.argv[4];
  if (!address || !method) die("Usage: persistia query <address> <method> [args_b64]");

  const argsB64 = process.argv[5] || "";
  const node = getNode();

  const url = `${node}/contract/query?address=${encodeURIComponent(address)}&method=${encodeURIComponent(method)}${argsB64 ? `&args=${encodeURIComponent(argsB64)}` : ""}`;
  const result = await get(url);
  console.log(JSON.stringify(result, null, 2));
}

async function cmdInfo() {
  const address = process.argv[3];
  if (!address) die("Usage: persistia info <address>");

  const node = getNode();
  const result = await get(`${node}/contract/info?address=${encodeURIComponent(address)}`);
  console.log(JSON.stringify(result, null, 2));
}

async function cmdTriggerCreate() {
  const contract = process.argv[3];
  const method = process.argv[4];
  const intervalMs = process.argv[5];
  if (!contract || !method || !intervalMs) {
    die("Usage: persistia trigger-create <contract> <method> <interval_ms> [max_fires]");
  }

  const maxFires = parseInt(process.argv[6] || "0");
  const { keys, privateKey } = await loadOrCreateKeys();
  const node = getNode();

  const timestamp = Date.now();
  const payload = { contract, method, interval_ms: parseInt(intervalMs), max_fires: maxFires };
  const dataToSign = { type: "trigger.create", payload, timestamp };
  const signature = await sign(privateKey, dataToSign);

  const result = await post(`${node}/contract/trigger/create`, {
    type: "trigger.create",
    payload,
    pubkey: keys.pub,
    signature,
    timestamp,
  });
  console.log(JSON.stringify(result, null, 2));
}

async function cmdTriggerList() {
  const contract = process.argv[3];
  if (!contract) die("Usage: persistia trigger-list <contract>");
  const node = getNode();
  const result = await get(`${node}/contract/trigger/list?contract=${encodeURIComponent(contract)}`);
  console.log(JSON.stringify(result, null, 2));
}

async function cmdOracleRequest() {
  const contract = process.argv[3];
  const callbackMethod = process.argv[4];
  const url = process.argv[5];
  if (!contract || !callbackMethod || !url) {
    die("Usage: persistia oracle-request <contract> <callback_method> <url> [aggregation] [json_path]");
  }

  const aggregation = process.argv[6] || "identical";
  const jsonPath = process.argv[7] || undefined;
  const { keys, privateKey } = await loadOrCreateKeys();
  const node = getNode();

  const timestamp = Date.now();
  const payload = { contract, callback_method: callbackMethod, url, aggregation, json_path: jsonPath };
  const dataToSign = { type: "oracle.request", payload, timestamp };
  const signature = await sign(privateKey, dataToSign);

  const result = await post(`${node}/contract/oracle/request`, {
    type: "oracle.request",
    payload,
    pubkey: keys.pub,
    signature,
    timestamp,
  });
  console.log(JSON.stringify(result, null, 2));
}

async function cmdConsensus() {
  const node = getNode();
  const result = await get(`${node}/dag/status`);
  console.log(JSON.stringify(result, null, 2));
}

async function cmdPeers() {
  const node = getNode();
  const result = await get(`${node}/admin/peers`);
  console.log(JSON.stringify(result, null, 2));
}

async function cmdRegister() {
  const peerUrl = process.argv[3];
  if (!peerUrl) die("Usage: persistia register <peer_node_url>");

  const { keys, privateKey } = await loadOrCreateKeys();
  const node = getNode();

  const dataToSign = { pubkey: keys.pub, url: peerUrl };
  const signature = await sign(privateKey, JSON.stringify(dataToSign) as any);

  // Actually we need to sign the JSON string directly
  const encoded = new TextEncoder().encode(JSON.stringify(dataToSign));
  const sig = await crypto.subtle.sign("Ed25519", privateKey, encoded);
  const sigB64 = bytesToB64(new Uint8Array(sig));

  const result = await post(`${node}/admin/register`, {
    pubkey: keys.pub,
    url: peerUrl,
    signature: sigB64,
  });
  console.log(JSON.stringify(result, null, 2));
}

// ─── ZK Proof Commands ───────────────────────────────────────────────────────

async function cmdZkStatus() {
  const node = getNode();
  const result = await fetch(`${node}/proof/zk/status`).then(r => r.json());
  console.log(JSON.stringify(result, null, 2));
}

async function cmdZkLatest() {
  const node = getNode();
  const result = await fetch(`${node}/proof/zk/latest`).then(r => r.json());
  console.log(JSON.stringify(result, null, 2));
}

async function cmdZkGet() {
  const block = process.argv[3];
  if (!block) { console.error("Usage: persistia zk-get <block_number>"); process.exit(1); }
  const node = getNode();
  const result = await fetch(`${node}/proof/zk/get?block=${block}`).then(r => r.json());
  console.log(JSON.stringify(result, null, 2));
}

// ─── Main ─────────────────────────────────────────────────────────────────────

const HELP = `
Persistia CLI — Developer tools for the Persistia ledger

Usage: persistia <command> [args] [--node <url>]

Commands:
  status                              Node status and info
  keys                                Show or generate keypair
  deploy <contract.wasm>              Deploy a WASM smart contract
  call <address> <method> [args]      Call a contract method (creates event)
  query <address> <method> [args]     Query a contract (read-only, no event)
  info <address>                      Get contract metadata
  trigger-create <addr> <method> <ms> Create a cron trigger
  trigger-list <address>              List triggers for a contract
  oracle-request <addr> <cb> <url>    Request oracle data fetch
  consensus                           DAG consensus status
  peers                               List known peers
  register <peer_url>                 Register a peer node
  zk-status                           ZK proof coverage status
  zk-latest                           Latest ZK proof info
  zk-get <block>                      Get ZK proof for a block

Environment:
  PERSISTIA_NODE    Node URL (default: http://localhost:8787)
  --node <url>      Override node URL
`.trim();

async function main() {
  const cmd = process.argv[2];

  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
    console.log(HELP);
    return;
  }

  switch (cmd) {
    case "status": return cmdStatus();
    case "keys": return cmdKeys();
    case "deploy": return cmdDeploy();
    case "call": return cmdCall();
    case "query": return cmdQuery();
    case "info": return cmdInfo();
    case "trigger-create": return cmdTriggerCreate();
    case "trigger-list": return cmdTriggerList();
    case "oracle-request": return cmdOracleRequest();
    case "consensus": return cmdConsensus();
    case "peers": return cmdPeers();
    case "register": return cmdRegister();
    case "zk-status": return cmdZkStatus();
    case "zk-latest": return cmdZkLatest();
    case "zk-get": return cmdZkGet();
    default:
      console.error(`Unknown command: ${cmd}`);
      console.log(HELP);
      process.exit(1);
  }
}

main().catch(e => {
  console.error(e.message || e);
  process.exit(1);
});
