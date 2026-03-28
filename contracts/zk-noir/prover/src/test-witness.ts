#!/usr/bin/env tsx
import { Noir } from "@noir-lang/noir_js";
import { readFileSync } from "fs";
import { resolve } from "path";
import { buildSingleBlockWitness } from "./witness.js";

const NODE = "https://persistia.carnation-903.workers.dev";
const CIRCUIT_PATH = resolve(import.meta.dirname ?? ".", "../../target/persistia_state_proof.json");

async function main() {
  const blockNum = parseInt(process.argv[2] || "29104");
  const block = await (await fetch(`${NODE}/proof/block?block=${blockNum}&shard=node-1`)).json() as any;
  console.log("Block active_nodes:", block.active_nodes);
  console.log("Block sigs:", block.signatures.length);
  console.log("Block mutations:", block.mutations.length);

  const witness = await buildSingleBlockWitness(block, "0");
  console.log("\nWitness active_nodes:", witness.active_nodes);
  console.log("Witness sig_count:", witness.sig_count);

  const sig0 = witness.signatures[0];
  console.log("\nSig 0 enabled:", sig0.enabled);
  console.log("Sig 0 pubkey_x:", sig0.pubkey_x?.substring(0, 30));
  console.log("Sig 0 msg (first 8 bytes):", sig0.msg.slice(0, 8));
  console.log("Sig 0 sig (first 8 bytes):", sig0.signature.slice(0, 8));

  // Try to execute the circuit
  console.log("\nExecuting circuit...");
  const circuit = JSON.parse(readFileSync(CIRCUIT_PATH, "utf-8"));
  const noir = new Noir(circuit);
  try {
    const result = await noir.execute(witness as any);
    console.log("Circuit execution OK!");
    console.log("Public output:", result.returnValue);
  } catch (e: any) {
    console.log(`Circuit execution FAILED: ${e.message}`);

    // Debug: check what quorum is expected
    console.log(`\nDebug: active_nodes=${witness.active_nodes}`);
    console.log(`Expected quorum: active_nodes=1 → quorum=1`);
    console.log(`Enabled sigs: ${witness.signatures.filter(s => s.enabled).length}`);

    // Check if each sig is a valid format
    for (let i = 0; i < 4; i++) {
      const s = witness.signatures[i];
      console.log(`\nSig ${i}: enabled=${s.enabled}, msg_len=${s.msg.length}, sig_len=${s.signature.length}`);
      console.log(`  pubkey_x: ${s.pubkey_x?.substring(0, 20)}...`);
      console.log(`  pubkey_y: ${s.pubkey_y?.substring(0, 20)}...`);
    }
  }
}

main().catch(console.error);
