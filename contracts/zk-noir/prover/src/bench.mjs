// Benchmark Noir circuit proving with Barretenberg backend.
// Uses the pre-compiled circuit and pre-generated witness from nargo.

import { Noir } from "@noir-lang/noir_js";
import { UltraHonkBackend } from "@aztec/bb.js";
import { readFileSync } from "fs";
import { gunzipSync } from "zlib";

const CIRCUIT_PATH = new URL("../../target/persistia_state_proof.json", import.meta.url).pathname;
const WITNESS_PATH = new URL("../../target/persistia_state_proof.gz", import.meta.url).pathname;

console.log("=== Persistia Noir Circuit Benchmark ===\n");

// Load compiled circuit
console.log("Loading circuit...");
const circuit = JSON.parse(readFileSync(CIRCUIT_PATH, "utf-8"));
console.log(`  ACIR opcodes: ${circuit.bytecode ? "present" : "missing"}`);

// Create backend
console.log("Initializing Barretenberg backend...");
const backend = new UltraHonkBackend(circuit.bytecode, { threads: 8 });

// Load pre-solved witness
console.log("Loading witness...");
const witnessGz = readFileSync(WITNESS_PATH);
const witnessBytes = gunzipSync(witnessGz);
console.log(`  Witness size: ${witnessBytes.length} bytes\n`);

// Benchmark proof generation
console.log("--- Proof Generation (UltraHonk) ---");
const proveStart = performance.now();
const proof = await backend.generateProof(witnessBytes);
const proveTime = performance.now() - proveStart;
console.log(`  Time: ${(proveTime / 1000).toFixed(2)}s`);
console.log(`  Proof size: ${proof.proof.length} bytes`);

// Benchmark verification
console.log("\n--- Verification ---");
const verifyStart = performance.now();
const valid = await backend.verifyProof(proof);
const verifyTime = performance.now() - verifyStart;
console.log(`  Time: ${(verifyTime / 1000).toFixed(2)}s`);
console.log(`  Valid: ${valid}`);

// Summary
console.log("\n=== Summary ===");
console.log(`  Witness solve (nargo execute): ~18s`);
console.log(`  Proof generation: ${(proveTime / 1000).toFixed(2)}s`);
console.log(`  Verification: ${(verifyTime / 1000).toFixed(2)}s`);
console.log(`  Proof size: ${proof.proof.length} bytes`);
console.log(`  vs SP1 (~70s prove): ~${(70000 / proveTime).toFixed(1)}x faster`);

await backend.destroy();
