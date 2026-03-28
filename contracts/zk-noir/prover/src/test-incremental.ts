#!/usr/bin/env tsx
import { Noir } from "@noir-lang/noir_js";
import { readFileSync } from "fs";
import { resolve } from "path";
import { buildIncrementalWitness, buildMutationWitness } from "./witness.js";
import { SparseMerkleTree } from "./sparse-merkle-tree.js";

const NODE = "https://persistia.carnation-903.workers.dev";
const CIRCUIT_PATH = resolve(import.meta.dirname ?? ".", "../../target/persistia_incremental_proof.json");

async function main() {
  const blockNum = parseInt(process.argv[2] || "29104");
  const block = await (await fetch(`${NODE}/proof/block?block=${blockNum}&shard=node-1`)).json() as any;
  console.log("Block:", blockNum, "active_nodes:", block.active_nodes, "mutations:", block.mutations.length);

  // Build sparse Merkle tree and apply mutations
  const smt = new SparseMerkleTree();
  await smt.init();

  const mutations = (block.mutations ?? []).map((m: any) => {
    const w = buildMutationWitness(m);
    return { keyHex: w.key, newValueHex: w.new_value, isDelete: w.is_delete };
  });

  const { updates, prevRoot, newRoot } = await smt.applyMutations(mutations);
  console.log("Tree: prevRoot=", prevRoot.substring(0, 18), "newRoot=", newRoot.substring(0, 18));
  console.log("Mutations applied:", updates.length);

  const witness = await buildIncrementalWitness(block, updates, prevRoot, newRoot);
  console.log("\nWitness active_nodes:", witness.active_nodes);
  console.log("Witness sig_count:", witness.sig_count);
  console.log("Witness prev_state_root:", witness.prev_state_root.substring(0, 20));
  console.log("Witness new_state_root:", witness.new_state_root.substring(0, 20));

  // Execute circuit
  console.log("\nExecuting incremental circuit...");
  const circuit = JSON.parse(readFileSync(CIRCUIT_PATH, "utf-8"));
  const noir = new Noir(circuit);
  try {
    const result = await noir.execute(witness as any);
    console.log("Circuit execution OK!");
    console.log("Public output:", result.returnValue);
  } catch (e: any) {
    console.log(`Circuit execution FAILED: ${e.message}`);
  }
}

main().catch(console.error);
