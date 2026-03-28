#!/usr/bin/env tsx
// Debug: verify a block's Schnorr signature using bb.js to check compatibility

import { Barretenberg } from "@aztec/bb.js";
import { createHash } from "crypto";

const NODE = "https://persistia.carnation-903.workers.dev";
const SHARD = "node-1";

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function main() {
  // Fetch block
  const blockNum = parseInt(process.argv[2] || "29104");
  const url = `${NODE}/proof/block?block=${blockNum}&shard=${SHARD}`;
  console.log(`Fetching block ${blockNum}...`);
  const res = await fetch(url);
  const block = await res.json() as any;

  console.log(`  active_nodes: ${block.active_nodes}`);
  console.log(`  signatures: ${block.signatures.length}`);
  console.log(`  mutations: ${block.mutations.length}`);

  const sig = block.signatures[0];
  if (!sig) { console.log("No signatures"); return; }

  console.log(`\nSignature 0:`);
  console.log(`  grumpkin_x: ${sig.grumpkin_x}`);
  console.log(`  grumpkin_y: ${sig.grumpkin_y}`);
  console.log(`  schnorr_s:  ${sig.schnorr_s}`);
  console.log(`  schnorr_e:  ${sig.schnorr_e}`);
  console.log(`  message:    "${sig.message}"`);

  // Reconstruct what the witness builder does
  const msgBytes = Buffer.from(sig.message, "utf-8");
  const msgHash = createHash("sha256").update(msgBytes).digest();
  console.log(`\n  msg SHA-256: ${bytesToHex(new Uint8Array(msgHash))}`);

  // Verify with bb.js
  const bb = await Barretenberg.new();

  const pubKeyX = hexToBytes(sig.grumpkin_x);
  const pubKeyY = hexToBytes(sig.grumpkin_y);
  const sBytes = hexToBytes(sig.schnorr_s);
  const eBytes = hexToBytes(sig.schnorr_e);

  console.log(`\n  s bytes (${sBytes.length}): ${bytesToHex(sBytes).substring(0, 30)}...`);
  console.log(`  e bytes (${eBytes.length}): ${bytesToHex(eBytes).substring(0, 30)}...`);

  // bb.js expects the signature as [s(32) || e(32)]
  const sigBytes = new Uint8Array(64);
  sigBytes.set(sBytes, 0);
  sigBytes.set(eBytes, 32);

  // Try verifying with the message hash (what witness builder passes)
  try {
    const result1 = await bb.schnorrVerifySignature({
      publicKey: { x: pubKeyX, y: pubKeyY },
      s: sBytes,
      e: eBytes,
      message: new Uint8Array(msgHash),
    });
    console.log(`\nbb.js verify (msg=SHA256 hash): ${JSON.stringify(result1)}`);
  } catch (e: any) {
    console.log(`\nbb.js verify (msg=SHA256 hash) error: ${e.message}`);
  }

  // Also try verifying with raw message bytes
  try {
    const result2 = await bb.schnorrVerifySignature({
      publicKey: { x: pubKeyX, y: pubKeyY },
      s: sBytes,
      e: eBytes,
      message: msgBytes,
    });
    console.log(`bb.js verify (msg=raw bytes): ${JSON.stringify(result2)}`);
  } catch (e: any) {
    console.log(`bb.js verify (msg=raw bytes) error: ${e.message}`);
  }

  // Also construct a fresh signature with bb.js and see if THAT verifies
  const testKey = new Uint8Array(32);
  testKey[31] = 1;
  const { publicKey: testPub } = await bb.schnorrComputePublicKey({ privateKey: testKey });
  const testSig = await bb.schnorrConstructSignature({ message: new Uint8Array(msgHash), privateKey: testKey });
  console.log(`\nbb.js construct sig shape: ${Object.keys(testSig)}`);
  try {
    const testVerify = await bb.schnorrVerifySignature({
      publicKey: testPub,
      s: testSig.s,
      e: testSig.e,
      message: new Uint8Array(msgHash),
    });
    console.log(`bb.js self-test (sign+verify): ${JSON.stringify(testVerify)}`);
  } catch (e: any) {
    console.log(`bb.js self-test error: ${e.message}`);
  }

  await bb.destroy();
}

main().catch(console.error);
