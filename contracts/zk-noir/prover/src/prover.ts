#!/usr/bin/env tsx
// Persistia Noir Prover — Host-side proof generation and verification.
//
// Drop-in replacement for the SP1 prover (contracts/zk/prover/).
// Uses @noir-lang/noir_js + Barretenberg backend.
//
// Usage:
//   tsx prover.ts prove   --node http://localhost:8787 --block 5
//   tsx prover.ts execute --node http://localhost:8787 --block 5
//   tsx prover.ts verify  --proof proof.bin
//   tsx prover.ts watch   --node http://localhost:8787
//   tsx prover.ts bench   --block 5

import { Noir } from "@noir-lang/noir_js";
import { BarretenbergBackend } from "@noir-lang/backend_barretenberg";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { join, resolve } from "path";
import { buildSingleBlockWitness, buildBatchWitness, type CircuitWitness } from "./witness.js";

// ─── Circuit Loading ─────────────────────────────────────────────────────────

// The compiled circuit JSON is produced by `nargo compile` in the parent dir.
const CIRCUIT_PATH = resolve(import.meta.dirname ?? ".", "../../target/persistia_state_proof.json");

function loadCircuit() {
  if (!existsSync(CIRCUIT_PATH)) {
    console.error(`Circuit not found at ${CIRCUIT_PATH}`);
    console.error("Run 'nargo compile' in contracts/zk-noir/ first.");
    process.exit(1);
  }
  return JSON.parse(readFileSync(CIRCUIT_PATH, "utf-8"));
}

async function createProver() {
  const circuit = loadCircuit();
  const backend = new BarretenbergBackend(circuit, { threads: 8 });
  const noir = new Noir(circuit);
  return { backend, noir, circuit };
}

// ─── Node API ────────────────────────────────────────────────────────────────

function nodeUrl(base: string, path: string): string {
  try {
    const u = new URL(base);
    u.pathname = u.pathname.replace(/\/$/, "") + path;
    return u.toString();
  } catch {
    return `${base}${path}`;
  }
}

async function fetchBlock(nodeBase: string, blockNumber: number) {
  const url = nodeUrl(nodeBase, `/proof/block/${blockNumber}`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch block ${blockNumber}: ${res.status}`);
  return res.json();
}

async function fetchLatestBlock(nodeBase: string): Promise<number> {
  const url = nodeUrl(nodeBase, "/proof/zk/status");
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch ZK status: ${res.status}`);
  const data = await res.json() as any;
  return data.latest_block ?? data.latestBlock ?? 0;
}

async function submitProof(nodeBase: string, proofData: any) {
  const url = nodeUrl(nodeBase, "/proof/zk/submit");
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(proofData),
  });
  if (!res.ok) throw new Error(`Failed to submit proof: ${res.status}`);
  return res.json();
}

// ─── Commands ────────────────────────────────────────────────────────────────

async function cmdExecute(nodeBase: string, blockNumber: number) {
  console.log(`Executing circuit for block ${blockNumber} (no proof)...`);
  const { noir } = await createProver();

  const block = await fetchBlock(nodeBase, blockNumber);
  const witness = buildSingleBlockWitness(block, block.prev_state_root);

  const start = performance.now();
  const result = await noir.execute(witness as any);
  const elapsed = ((performance.now() - start) / 1000).toFixed(2);

  console.log(`Execution OK in ${elapsed}s`);
  console.log("Public output:", result.returnValue);
}

async function cmdProve(
  nodeBase: string,
  blockNumber: number,
  outputPath: string,
  prevProofPath?: string,
) {
  console.log(`Generating proof for block ${blockNumber}...`);
  const { noir, backend } = await createProver();

  const block = await fetchBlock(nodeBase, blockNumber);

  let opts: any = {};
  if (prevProofPath && existsSync(prevProofPath)) {
    const prevProof = JSON.parse(readFileSync(prevProofPath, "utf-8"));
    opts = {
      recursive: true,
      prevProvenBlocks: prevProof.proven_blocks,
      prevGenesisRoot: prevProof.genesis_root,
    };
    console.log(`Chaining from previous proof (${prevProof.proven_blocks} blocks proven)`);
  }

  const witness = buildSingleBlockWitness(block, block.prev_state_root, opts);

  const start = performance.now();
  const { witness: solvedWitness } = await noir.execute(witness as any);
  const proof = await backend.generateProof(solvedWitness);
  const elapsed = ((performance.now() - start) / 1000).toFixed(2);

  // Save proof
  const proofData = {
    proof: Buffer.from(proof.proof).toString("base64"),
    publicInputs: proof.publicInputs,
    block_number: blockNumber,
    proven_blocks: opts.recursive ? (opts.prevProvenBlocks + 1) : 1,
    genesis_root: opts.prevGenesisRoot ?? block.prev_state_root,
    state_root: block.state_root,
    prover: "noir-barretenberg",
    timestamp: new Date().toISOString(),
  };

  const dir = resolve(outputPath, "..");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(outputPath, JSON.stringify(proofData, null, 2));

  console.log(`Proof generated in ${elapsed}s → ${outputPath}`);
  console.log(`  State root: ${block.state_root}`);
  console.log(`  Proven blocks: ${proofData.proven_blocks}`);
  console.log(`  Proof size: ${proof.proof.length} bytes`);
}

async function cmdVerify(proofPath: string) {
  console.log(`Verifying proof from ${proofPath}...`);
  const { backend } = await createProver();

  const proofData = JSON.parse(readFileSync(proofPath, "utf-8"));
  const proof = {
    proof: Buffer.from(proofData.proof, "base64"),
    publicInputs: proofData.publicInputs,
  };

  const start = performance.now();
  const valid = await backend.verifyProof(proof);
  const elapsed = ((performance.now() - start) / 1000).toFixed(2);

  if (valid) {
    console.log(`Proof VALID (verified in ${elapsed}s)`);
    console.log(`  Block: ${proofData.block_number}`);
    console.log(`  State root: ${proofData.state_root}`);
    console.log(`  Proven blocks: ${proofData.proven_blocks}`);
  } else {
    console.error("Proof INVALID");
    process.exit(1);
  }
}

async function cmdWatch(
  nodeBase: string,
  proofDir: string,
  intervalSec: number,
  batchSize: number,
) {
  console.log(`Watching ${nodeBase} (interval=${intervalSec}s, batch=${batchSize})`);
  if (!existsSync(proofDir)) mkdirSync(proofDir, { recursive: true });

  let lastProvenBlock = 0;
  let prevProofPath: string | undefined;

  // Check for existing proofs to resume from
  const existing = existsSync(proofDir)
    ? readFileSync(join(proofDir, "latest.json"), "utf-8").catch(() => null)
    : null;

  while (true) {
    try {
      const latestBlock = await fetchLatestBlock(nodeBase);

      if (latestBlock > lastProvenBlock) {
        const startBlock = lastProvenBlock + 1;
        const endBlock = Math.min(startBlock + batchSize - 1, latestBlock);

        if (batchSize > 1 && endBlock > startBlock) {
          // Batch mode
          const blocks = [];
          for (let b = startBlock; b <= endBlock; b++) {
            blocks.push(await fetchBlock(nodeBase, b));
          }
          console.log(`Proving batch: blocks ${startBlock}-${endBlock}`);

          const { noir, backend } = await createProver();
          const witness = buildBatchWitness(
            blocks,
            blocks[0].prev_state_root,
            prevProofPath ? {
              recursive: true,
              prevProvenBlocks: lastProvenBlock,
              prevGenesisRoot: blocks[0].prev_state_root,
            } : undefined,
          );

          const start = performance.now();
          const { witness: solved } = await noir.execute(witness as any);
          const proof = await backend.generateProof(solved);
          const elapsed = ((performance.now() - start) / 1000).toFixed(2);

          const outPath = join(proofDir, `block_${endBlock}.json`);
          const proofData = {
            proof: Buffer.from(proof.proof).toString("base64"),
            publicInputs: proof.publicInputs,
            block_number: endBlock,
            proven_blocks: endBlock,
            state_root: blocks[blocks.length - 1].state_root,
            prover: "noir-barretenberg",
            timestamp: new Date().toISOString(),
          };
          writeFileSync(outPath, JSON.stringify(proofData, null, 2));
          writeFileSync(join(proofDir, "latest.json"), JSON.stringify(proofData, null, 2));

          console.log(`Batch proof generated in ${elapsed}s → ${outPath}`);
          lastProvenBlock = endBlock;
          prevProofPath = outPath;

          // Submit to node
          try {
            await submitProof(nodeBase, proofData);
            console.log("Proof submitted to node");
          } catch (e: any) {
            console.warn(`Submit failed (non-fatal): ${e.message}`);
          }
        } else {
          // Single block mode
          const outPath = join(proofDir, `block_${startBlock}.json`);
          await cmdProve(nodeBase, startBlock, outPath, prevProofPath);
          lastProvenBlock = startBlock;
          prevProofPath = outPath;
        }
      }
    } catch (e: any) {
      console.error(`Error: ${e.message}`);
    }

    await new Promise((r) => setTimeout(r, intervalSec * 1000));
  }
}

async function cmdBench(nodeBase: string, blockNumber: number) {
  console.log("=== Noir Circuit Benchmark ===\n");
  const { noir, backend } = await createProver();

  const block = await fetchBlock(nodeBase, blockNumber);
  const witness = buildSingleBlockWitness(block, block.prev_state_root);

  // Warmup
  console.log("Warming up...");
  await noir.execute(witness as any);

  // Benchmark execute (witness solving)
  console.log("\n--- Execute (witness solving) ---");
  const execTimes: number[] = [];
  for (let i = 0; i < 3; i++) {
    const start = performance.now();
    await noir.execute(witness as any);
    execTimes.push(performance.now() - start);
  }
  const avgExec = execTimes.reduce((a, b) => a + b) / execTimes.length;
  console.log(`  Avg: ${(avgExec / 1000).toFixed(3)}s`);

  // Benchmark proof generation
  console.log("\n--- Prove (full proof generation) ---");
  const start = performance.now();
  const { witness: solved } = await noir.execute(witness as any);
  const proof = await backend.generateProof(solved);
  const proveTime = performance.now() - start;
  console.log(`  Time: ${(proveTime / 1000).toFixed(3)}s`);
  console.log(`  Proof size: ${proof.proof.length} bytes`);

  // Benchmark verification
  console.log("\n--- Verify ---");
  const verifyStart = performance.now();
  const valid = await backend.verifyProof(proof);
  const verifyTime = performance.now() - verifyStart;
  console.log(`  Time: ${(verifyTime / 1000).toFixed(3)}s`);
  console.log(`  Valid: ${valid}`);

  console.log("\n=== Summary ===");
  console.log(`  Execute:  ${(avgExec / 1000).toFixed(3)}s`);
  console.log(`  Prove:    ${(proveTime / 1000).toFixed(3)}s`);
  console.log(`  Verify:   ${(verifyTime / 1000).toFixed(3)}s`);
  console.log(`  Proof:    ${proof.proof.length} bytes`);
  console.log(`  Speedup vs SP1 (~70s): ~${(70000 / proveTime).toFixed(1)}x`);
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const command = args[0];

function getArg(name: string, defaultVal?: string): string {
  const idx = args.indexOf(`--${name}`);
  if (idx >= 0 && idx + 1 < args.length) return args[idx + 1];
  if (defaultVal !== undefined) return defaultVal;
  throw new Error(`Missing required argument: --${name}`);
}

switch (command) {
  case "execute":
    cmdExecute(getArg("node", "http://localhost:8787"), parseInt(getArg("block")));
    break;
  case "prove":
    cmdProve(
      getArg("node", "http://localhost:8787"),
      parseInt(getArg("block")),
      getArg("output", "proof.json"),
      args.includes("--prev-proof") ? getArg("prev-proof") : undefined,
    );
    break;
  case "verify":
    cmdVerify(getArg("proof"));
    break;
  case "watch":
    cmdWatch(
      getArg("node", "http://localhost:8787"),
      getArg("proof-dir", "./proofs"),
      parseInt(getArg("interval", "10")),
      parseInt(getArg("batch", "1")),
    );
    break;
  case "bench":
    cmdBench(getArg("node", "http://localhost:8787"), parseInt(getArg("block")));
    break;
  default:
    console.log(`Persistia Noir Prover

Usage:
  tsx prover.ts execute --node <url> --block <n>      Execute without proof (test)
  tsx prover.ts prove   --node <url> --block <n>      Generate proof
  tsx prover.ts verify  --proof <path>                Verify a proof file
  tsx prover.ts watch   --node <url> [--batch <n>]    Watch and prove continuously
  tsx prover.ts bench   --node <url> --block <n>      Benchmark proving times`);
}
