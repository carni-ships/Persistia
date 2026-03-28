#!/usr/bin/env tsx
// Persistia Noir Prover — powered by the zkMetal SDK.
//
// Thin CLI wrapper around zkmetal's ProverEngine, Persistia adapter, and watch loops.
// Persistia-specific features (SnarkFold aggregation, incremental SMT) are kept local.
//
// Usage:
//   tsx prover.ts prove   --node http://localhost:8787 --block 5
//   tsx prover.ts watch   --node http://localhost:8787
//   tsx prover.ts watch-incremental --node http://localhost:8787
//   tsx prover.ts aggregate --block-start 1 --block-end 10

import { resolve, join } from "path";
import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync } from "fs";
import { execSync } from "child_process";

// zkMetal SDK imports
import {
  ProverEngine,
  extractInnerProof,
  proofToFields,
  setMaxMutations,
  watchSequential,
  watchPipelined,
  watchParallelMsgpack,
} from "zkmetal";
import type { VerifierTarget, ProofOutput, WatchOptions } from "zkmetal";
import {
  createPersistiaAdapter,
  PersistiaDataSource,
  PersistiaProofSink,
} from "zkmetal/adapters/persistia";

// Local imports for incremental proving (not in zkMetal SDK)
import { buildIncrementalMutationWitness, buildIncrementalWitness } from "./witness.js";
import { SparseMerkleTree } from "./sparse-merkle-tree.js";

// --- Persistia circuit configuration ---
// Persistia's circuit uses 512 mutations (zkMetal defaults to 1024).
setMaxMutations(512);

const CIRCUIT_PATH = resolve(import.meta.dirname ?? ".", "../../target/persistia_state_proof.json");
const INCREMENTAL_CIRCUIT_PATH = resolve(import.meta.dirname ?? ".", "../../target/persistia_incremental_proof.json");
const GENESIS_STATE_ROOT = "0";

// --- CLI helpers ---

const args = process.argv.slice(2);
const command = args[0];

function getArg(name: string, defaultVal?: string): string {
  const idx = args.indexOf(`--${name}`);
  if (idx >= 0 && idx + 1 < args.length) return args[idx + 1];
  if (defaultVal !== undefined) return defaultVal;
  throw new Error(`Missing required argument: --${name}`);
}

const useNative = args.includes("--native");
const verifierTarget: VerifierTarget = args.includes("--evm") ? "evm-no-zk" : "noir-recursive-no-zk";

// Inject shard parameter into the node URL if provided
function withShard(nodeBase: string): string {
  if (!args.includes("--shard")) return nodeBase;
  const shard = getArg("shard");
  const u = new URL(nodeBase);
  u.searchParams.set("shard", shard);
  return u.toString();
}

// --- Engine + Adapter factory ---

function createEngine(circuitPath = CIRCUIT_PATH): ProverEngine {
  return new ProverEngine({
    circuitPath,
    threads: 8,
    vkCacheDir: resolve(circuitPath, "../../target/bb_vk"),
  });
}

// --- Standard commands (delegated to zkMetal SDK) ---

async function cmdExecute(nodeBase: string, blockNumber: number) {
  console.log(`Executing circuit for block ${blockNumber} (no proof)...`);
  const engine = createEngine();
  const { witnessBuilder, dataSource } = createPersistiaAdapter(nodeBase);
  const block = await dataSource.fetchBlock(blockNumber);
  const witness = await witnessBuilder.buildWitness(block, blockNumber);
  const start = performance.now();
  const { returnValue } = await engine.execute(witness);
  const elapsed = ((performance.now() - start) / 1000).toFixed(2);
  console.log(`Execute OK (${elapsed}s). Return value:`, returnValue);
  await engine.destroy();
}

async function cmdProve(
  nodeBase: string,
  blockNumber: number,
  outputPath: string,
  prevProofPath?: string,
) {
  console.log(`Proving block ${blockNumber}...`);
  const engine = createEngine();
  const { dataSource, witnessBuilder, proofSink } = createPersistiaAdapter(nodeBase);

  const block = await dataSource.fetchBlock(blockNumber);

  // Build recursive inputs from previous proof if chaining
  let recursiveOpts: any;
  if (prevProofPath && existsSync(prevProofPath)) {
    const prevData = JSON.parse(readFileSync(prevProofPath, "utf-8"));
    const prevProofBytes = Buffer.from(prevData.proof, "base64");
    const innerProof = extractInnerProof(new Uint8Array(prevProofBytes));

    let vkAsFields = prevData.vkAsFields;
    let vkHash = prevData.vkHash;
    if (!vkAsFields || !vkHash) {
      const artifacts = await engine.generateRecursiveArtifacts({
        proof: prevProofBytes,
        publicInputs: prevData.publicInputs,
      });
      vkAsFields = artifacts.vkAsFields;
      vkHash = artifacts.vkHash;
    }

    recursiveOpts = {
      prevProvenBlocks: prevData.provenBlocks ?? prevData.proven_blocks ?? 1,
      prevGenesisRoot: prevData.genesis_root ?? prevData.meta?.genesis_root ?? GENESIS_STATE_ROOT,
      prevProof: innerProof,
      prevVk: vkAsFields,
      prevKeyHash: vkHash,
      prevPublicInputs: prevData.publicInputs,
    };
  }

  const witness = await witnessBuilder.buildWitness(block, blockNumber, recursiveOpts);

  const start = performance.now();
  const { witness: solvedWitness } = await engine.execute(witness);

  let proof: { proof: Uint8Array; publicInputs: string[]; vk?: Uint8Array };
  if (useNative && engine.nativeBbAvailable()) {
    proof = engine.nativeProve(solvedWitness, verifierTarget);
  } else {
    proof = await engine.prove(solvedWitness);
  }

  const artifacts = await engine.generateRecursiveArtifacts({
    proof: proof.proof,
    publicInputs: proof.publicInputs,
  });

  const elapsed = ((performance.now() - start) / 1000).toFixed(2);

  const stateRoot = (witness as any).new_state_root ?? GENESIS_STATE_ROOT;
  const genesisRoot = recursiveOpts?.prevGenesisRoot ?? GENESIS_STATE_ROOT;

  const proofOutput: ProofOutput = {
    proof: Buffer.from(proof.proof).toString("base64"),
    publicInputs: proof.publicInputs,
    vkAsFields: artifacts.vkAsFields,
    vkHash: artifacts.vkHash,
    vk: proof.vk ? Buffer.from(proof.vk).toString("base64") : undefined,
    blockNumber,
    provenBlocks: recursiveOpts ? recursiveOpts.prevProvenBlocks + 1 : 1,
    prover: useNative ? "zkmetal-native" : "zkmetal-wasm",
    timestamp: new Date().toISOString(),
    meta: {
      genesis_root: genesisRoot,
      state_root: stateRoot,
    },
  };

  const dir = resolve(outputPath, "..");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  // Write with flat fields for file readability + ProofOutput structure for SDK compatibility
  writeFileSync(outputPath, JSON.stringify({
    ...proofOutput,
    block_number: blockNumber,
    proven_blocks: proofOutput.provenBlocks,
    genesis_root: genesisRoot,
    state_root: stateRoot,
  }, null, 2));
  console.log(`Proof written to ${outputPath} (${elapsed}s)`);

  try {
    await proofSink.submitProof(proofOutput as any);
    console.log("Proof submitted to node.");
  } catch (e: any) {
    console.warn(`Could not submit: ${e.message}`);
  }

  await engine.destroy();
}

async function cmdVerify(proofPath: string) {
  const data = JSON.parse(readFileSync(proofPath, "utf-8"));
  const proofBytes = new Uint8Array(Buffer.from(data.proof, "base64"));
  const engine = createEngine();

  console.log(`Verifying ${proofPath}...`);
  const start = performance.now();

  let ok: boolean;
  if (useNative && engine.nativeBbAvailable() && data.vk) {
    const vkBytes = new Uint8Array(Buffer.from(data.vk, "base64"));
    ok = engine.nativeVerify(proofBytes, data.publicInputs, vkBytes);
  } else {
    ok = await engine.verify({ proof: proofBytes, publicInputs: data.publicInputs });
  }

  const elapsed = ((performance.now() - start) / 1000).toFixed(2);
  console.log(ok ? `VALID (${elapsed}s)` : `INVALID (${elapsed}s)`);
  await engine.destroy();
  if (!ok) process.exit(1);
}

async function cmdBench(nodeBase: string, blockNumber: number) {
  const engine = createEngine();
  const { dataSource, witnessBuilder } = createPersistiaAdapter(nodeBase);
  const block = await dataSource.fetchBlock(blockNumber);
  const witness = await witnessBuilder.buildWitness(block, blockNumber);

  console.log(`Benchmarking block ${blockNumber}...`);

  const t0 = performance.now();
  const { witness: solvedWitness } = await engine.execute(witness);
  const tExec = performance.now();

  const proof = await engine.prove(solvedWitness);
  const tProve = performance.now();

  const ok = await engine.verify(proof);
  const tVerify = performance.now();

  console.log(`Execute: ${((tExec - t0) / 1000).toFixed(2)}s`);
  console.log(`Prove:   ${((tProve - tExec) / 1000).toFixed(2)}s`);
  console.log(`Verify:  ${((tVerify - tProve) / 1000).toFixed(2)}s`);
  console.log(`Total:   ${((tVerify - t0) / 1000).toFixed(2)}s`);
  console.log(`Valid:   ${ok}`);

  if (useNative && engine.nativeBbAvailable()) {
    const { witness: sw2 } = await engine.execute(witness);
    const tN0 = performance.now();
    engine.nativeProve(sw2, verifierTarget);
    const tN1 = performance.now();
    console.log(`Native:  ${((tN1 - tN0) / 1000).toFixed(2)}s`);
  }

  await engine.destroy();
}

// --- Watch commands (delegated to zkMetal SDK watch loops) ---

async function cmdWatch(nodeBase: string, opts: WatchOptions) {
  const engine = createEngine();
  const { dataSource, witnessBuilder, proofSink } = createPersistiaAdapter(nodeBase);
  console.log(`[Persistia] Starting sequential watch on ${nodeBase}`);
  await watchSequential(engine, dataSource, witnessBuilder, proofSink, opts);
}

async function cmdWatchPipelined(nodeBase: string, opts: WatchOptions) {
  const engine = createEngine();
  const { dataSource, witnessBuilder, proofSink } = createPersistiaAdapter(nodeBase);
  console.log(`[Persistia] Starting pipelined watch on ${nodeBase}`);
  await watchPipelined(engine, dataSource, witnessBuilder, proofSink, opts);
}

async function cmdWatchParallel(nodeBase: string, opts: WatchOptions & { workers?: number }) {
  const engine = createEngine();
  const { dataSource, witnessBuilder, proofSink } = createPersistiaAdapter(nodeBase);
  console.log(`[Persistia] Starting parallel watch on ${nodeBase} (${opts.workers ?? 6} workers)`);
  await watchParallelMsgpack(engine, dataSource, witnessBuilder, proofSink, opts as any);
}

// --- SnarkFold Epoch Proof Aggregation (Persistia-specific) ---

async function cmdAggregate(
  nodeBase: string,
  proofDir: string,
  blockStart: number,
  blockEnd: number,
  outputPath: string,
) {
  if (blockEnd < blockStart) {
    console.error("block-end must be >= block-start");
    process.exit(1);
  }

  const blockCount = blockEnd - blockStart + 1;
  console.log(`SnarkFold: aggregating ${blockCount} proofs (blocks ${blockStart}-${blockEnd})`);

  // Collect all block proofs (from local dir or fetch from node)
  const proofs: any[] = [];
  for (let b = blockStart; b <= blockEnd; b++) {
    const localPath = join(proofDir, `block_${b}.json`);
    if (existsSync(localPath)) {
      proofs.push(JSON.parse(readFileSync(localPath, "utf-8")));
      continue;
    }
    try {
      const ds = new PersistiaDataSource(nodeBase);
      const url = nodeBase.replace(/\/$/, "") + `/proof/zk/get?block=${b}`;
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json() as any;
      if (!data.proof) throw new Error("No proof data");
      proofs.push(data);
    } catch (e: any) {
      console.error(`Missing proof for block ${b}: ${e.message}`);
      process.exit(1);
    }
  }

  console.log(`Collected ${proofs.length} proofs. Starting recursive fold...`);

  const engine = createEngine();
  await engine.init();
  const startTime = performance.now();

  let currentAggregate = proofs[0];
  let aggregatedBlocks = 1;

  for (let i = 1; i < proofs.length; i++) {
    const nextProof = proofs[i];
    const stepStart = performance.now();

    // Build fold witness: verify previous aggregate inside circuit, combine with next block
    const foldWitness: any = {
      prev_state_root: currentAggregate.state_root || GENESIS_STATE_ROOT,
      new_state_root: nextProof.state_root || GENESIS_STATE_ROOT,
      block_number: nextProof.block_number,
      active_nodes: nextProof.active_nodes || 1,
      mutations: Array.from({ length: 512 }, () => ({ key: "0", new_value: "0", is_delete: 0, enabled: 0 })),
      mutation_count: 0,
      signatures: Array.from({ length: 4 }, () => ({
        pubkey_x: "0", pubkey_y: "0",
        signature: Array(64).fill(0),
        msg: Array(32).fill(0),
        enabled: 0,
      })),
      sig_count: 0,
      prev_proven_blocks: aggregatedBlocks,
      prev_genesis_root: currentAggregate.genesis_root || GENESIS_STATE_ROOT,
    };

    // Add recursive proof fields from previous aggregate
    if (currentAggregate.publicInputs && currentAggregate.vkAsFields) {
      const proofBytes = new Uint8Array(Buffer.from(currentAggregate.proof, "base64"));
      const innerFields = extractInnerProof(proofBytes);
      while (innerFields.length < 449) innerFields.push("0x00");

      foldWitness.prev_proof = innerFields.slice(0, 449);
      foldWitness.prev_vk = currentAggregate.vkAsFields.slice(0, 115);
      foldWitness.prev_key_hash = currentAggregate.vkHash || "0x00";
      foldWitness.prev_public_inputs = currentAggregate.publicInputs.slice(0, 8);
    } else {
      foldWitness.prev_proof = Array(449).fill("0x00");
      foldWitness.prev_vk = Array(115).fill("0x00");
      foldWitness.prev_key_hash = "0x00";
      foldWitness.prev_public_inputs = Array(8).fill("0x00");
    }

    try {
      const { witness: solvedWitness } = await engine.execute(foldWitness);

      let proof: { proof: Uint8Array; publicInputs: string[] };
      if (useNative && engine.nativeBbAvailable()) {
        proof = engine.nativeProve(solvedWitness, verifierTarget);
      } else {
        proof = await engine.prove(solvedWitness);
      }

      const artifacts = await engine.generateRecursiveArtifacts(proof);

      currentAggregate = {
        proof: Buffer.from(proof.proof).toString("base64"),
        publicInputs: proof.publicInputs,
        vkAsFields: artifacts.vkAsFields,
        vkHash: artifacts.vkHash,
        block_number: nextProof.block_number,
        proven_blocks: aggregatedBlocks + 1,
        genesis_root: currentAggregate.genesis_root || GENESIS_STATE_ROOT,
        state_root: nextProof.state_root,
      };

      aggregatedBlocks++;
      const stepMs = (performance.now() - stepStart).toFixed(0);
      console.log(`  Fold step ${i}/${proofs.length - 1}: block ${nextProof.block_number} (${stepMs}ms, ${aggregatedBlocks} blocks aggregated)`);
    } catch (e: any) {
      console.error(`Fold step ${i} failed at block ${nextProof.block_number}: ${e.message}`);
      break;
    }
  }

  const totalSec = ((performance.now() - startTime) / 1000).toFixed(2);
  console.log(`\nSnarkFold complete: ${aggregatedBlocks} blocks in ${totalSec}s`);

  // Write epoch proof
  const epoch = Math.floor(blockStart / blockCount);
  const epochProof = {
    epoch,
    block_start: blockStart,
    block_end: blockStart + aggregatedBlocks - 1,
    proof_count: aggregatedBlocks,
    proof: currentAggregate.proof,
    publicInputs: currentAggregate.publicInputs,
    vkAsFields: currentAggregate.vkAsFields,
    vkHash: currentAggregate.vkHash,
    state_root: currentAggregate.state_root,
    genesis_root: currentAggregate.genesis_root,
    prover: "snarkfold-ultrahonk",
    timestamp: new Date().toISOString(),
  };

  const dir = resolve(outputPath, "..");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(outputPath, JSON.stringify(epochProof, null, 2));
  console.log(`Epoch proof written to ${outputPath}`);

  // Submit to node
  try {
    const res = await fetch(nodeBase.replace(/\/$/, "") + "/proof/epoch/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        epoch,
        block_start: blockStart,
        block_end: blockStart + aggregatedBlocks - 1,
        proof_count: aggregatedBlocks,
        proof: currentAggregate.proof,
        public_values: currentAggregate.publicInputs,
        state_root: currentAggregate.state_root,
        genesis_root: currentAggregate.genesis_root,
      }),
    });
    if (res.ok) console.log("Epoch proof submitted to node.");
    else console.warn(`Submit failed: ${res.status}`);
  } catch (e: any) {
    console.warn(`Could not submit epoch proof: ${e.message}`);
  }

  await engine.destroy();
}

// --- Incremental Circuit Prover (Persistia-specific, uses sparse Merkle tree) ---

async function cmdWatchIncremental(
  nodeBase: string,
  proofDir: string,
  intervalSec: number,
  startBlock?: number,
  treePath?: string,
) {
  if (!existsSync(INCREMENTAL_CIRCUIT_PATH)) {
    console.error(`Incremental circuit not found at ${INCREMENTAL_CIRCUIT_PATH}`);
    console.error("Run 'nargo compile --package persistia_incremental_proof' first.");
    process.exit(1);
  }

  if (!existsSync(proofDir)) mkdirSync(proofDir, { recursive: true });

  const engine = createEngine(INCREMENTAL_CIRCUIT_PATH);
  await engine.init();

  const ds = new PersistiaDataSource(nodeBase);
  const sink = new PersistiaProofSink(nodeBase);

  // Initialize sparse Merkle tree (persisted to disk)
  const smtPath = treePath ?? join(proofDir, "sparse_merkle_tree.json");
  const smt = new SparseMerkleTree(smtPath);
  await smt.init();

  let lastProvenBlock = startBlock ?? (await ds.fetchLatestBlockNumber());
  console.log(`Incremental prover watching ${nodeBase} (interval=${intervalSec}s, starting after block ${lastProvenBlock})`);
  console.log(`Sparse Merkle tree: ${smt.size} leaves, root=${smt.getRoot().substring(0, 18)}...`);
  console.log(`Circuit: ${INCREMENTAL_CIRCUIT_PATH}`);
  console.log(`Native bb: ${useNative && engine.nativeBbAvailable() ? "yes" : "no (WASM)"}`);

  while (true) {
    try {
      const latestBlock = await ds.fetchLatestBlockNumber();

      while (latestBlock > lastProvenBlock) {
        const blockNum = await ds.fetchNextBlockNumber(lastProvenBlock);
        if (blockNum === null || blockNum > latestBlock) break;

        try {
          const block = await ds.fetchBlock(blockNum);
          const allMutations = (block.mutations ?? []).map((m: any) => {
            const w = buildIncrementalMutationWitness(m);
            return { keyHex: w.key, newValueHex: w.new_value, isDelete: w.is_delete };
          });
          const mutations = allMutations.slice(0, 64);
          if (allMutations.length > 64) {
            console.log(`  Block ${blockNum}: truncated ${allMutations.length} mutations to 64`);
          }

          const { updates, prevRoot, newRoot } = await smt.applyMutations(mutations);
          const witness = await buildIncrementalWitness(block, updates, prevRoot, newRoot);

          const start = performance.now();
          const { witness: solvedWitness } = await engine.execute(witness as any);

          let proof: { proof: Uint8Array; publicInputs: string[] };
          if (useNative && engine.nativeBbAvailable()) {
            proof = engine.nativeProve(solvedWitness);
          } else {
            proof = await engine.prove(solvedWitness);
          }
          const elapsed = ((performance.now() - start) / 1000).toFixed(2);

          const proofOutput: ProofOutput = {
            proof: Buffer.from(proof.proof).toString("base64"),
            publicInputs: proof.publicInputs,
            blockNumber: blockNum,
            provenBlocks: 1,
            prover: useNative ? "persistia-incremental-native" : "persistia-incremental-wasm",
            timestamp: new Date().toISOString(),
            meta: {
              circuit: "incremental",
              tree_size: smt.size,
              mutations: mutations.length,
              state_root: newRoot,
            },
          };

          const outPath = join(proofDir, `block_${blockNum}.json`);
          writeFileSync(outPath, JSON.stringify(proofOutput, null, 2));
          console.log(`Block ${blockNum}: proof in ${elapsed}s (${mutations.length} mutations, tree=${smt.size} leaves)`);

          try { await sink.submitProof(proofOutput); } catch {}
        } catch (e: any) {
          console.log(`Block ${blockNum} skipped: ${e.message?.substring(0, 150)}`);
        }
        lastProvenBlock = blockNum;
      }
    } catch (e: any) {
      console.error(`Error: ${e.message}`);
    }

    await new Promise((r) => setTimeout(r, intervalSec * 1000));
  }
}

// --- bb utilities ---

function cmdBbVersion() {
  const engine = createEngine();
  const cfg = engine.getConfig();
  try {
    const version = execSync(`${cfg.bbPath} --version`, { encoding: "utf-8" }).trim();
    console.log(`bb version: ${version}`);
    console.log(`bb path:    ${cfg.bbPath}`);
    try {
      const latest = execSync(`npm view @aztec/bb.js version 2>/dev/null`, { encoding: "utf-8" }).trim();
      console.log(`Latest bb.js: ${latest}`);
      if (latest !== version) {
        console.log(`\nUpdate available! Run:\n  ~/.bb/bbup -v ${latest}\n  npm install @aztec/bb.js@${latest}`);
      } else {
        console.log("Up to date.");
      }
    } catch {}
  } catch {
    console.log("bb CLI not found. Install with:");
    console.log("  curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash");
    console.log("  bbup -v 4.1.2");
  }
}

function cmdGpuInfo() {
  const engine = createEngine();
  const info = engine.metalGpuInfo();
  if (info) {
    console.log(`GPU: ${info.gpu}`);
    console.log(`Unified memory: ${info.unified_memory}`);
    console.log(`Metal MSM: available`);
  } else {
    console.log("Metal GPU MSM: not available");
  }
}

// --- CLI dispatch ---

const nodeBase = withShard(getArg("node", "http://localhost:8787"));
const proofDir = getArg("proof-dir", "./proofs");
const intervalSec = parseInt(getArg("interval", "10"));

switch (command) {
  case "execute":
    cmdExecute(nodeBase, parseInt(getArg("block")));
    break;
  case "prove":
    cmdProve(
      nodeBase,
      parseInt(getArg("block")),
      getArg("output", "proof.json"),
      args.includes("--prev-proof") ? getArg("prev-proof") : undefined,
    );
    break;
  case "verify":
    cmdVerify(getArg("proof"));
    break;
  case "watch":
    cmdWatch(nodeBase, {
      proofDir,
      intervalSec,
      useNative,
      recursive: args.includes("--recursive"),
      startBlock: args.includes("--start") ? parseInt(getArg("start")) : undefined,
    });
    break;
  case "watch-pipelined":
    cmdWatchPipelined(nodeBase, {
      proofDir,
      intervalSec: parseInt(getArg("interval", "5")),
      useNative,
      recursive: args.includes("--recursive"),
      startBlock: args.includes("--start") ? parseInt(getArg("start")) : undefined,
    });
    break;
  case "watch-parallel":
  case "watch-parallel-msgpack":
    cmdWatchParallel(nodeBase, {
      proofDir,
      intervalSec: parseInt(getArg("interval", "5")),
      useNative,
      startBlock: args.includes("--start") ? parseInt(getArg("start")) : undefined,
      workers: parseInt(getArg("workers", "6")),
    } as any);
    break;
  case "watch-incremental":
    cmdWatchIncremental(
      nodeBase,
      proofDir,
      intervalSec,
      args.includes("--start") ? parseInt(getArg("start")) : undefined,
      args.includes("--tree") ? getArg("tree") : undefined,
    );
    break;
  case "aggregate":
    cmdAggregate(
      nodeBase,
      proofDir,
      parseInt(getArg("block-start")),
      parseInt(getArg("block-end")),
      getArg("output", "./proofs/epoch_latest.json"),
    );
    break;
  case "bench":
    cmdBench(nodeBase, parseInt(getArg("block")));
    break;
  case "bb-version":
    cmdBbVersion();
    break;
  case "gpu-info":
    cmdGpuInfo();
    break;
  default:
    console.log(`Persistia Noir Prover (powered by zkMetal SDK)

Usage:
  tsx prover.ts execute  --node <url> --block <n>      Execute without proof (test)
  tsx prover.ts prove    --node <url> --block <n>      Generate proof
  tsx prover.ts verify   --proof <path>                Verify a proof file
  tsx prover.ts watch    --node <url>                  Watch and prove (sequential)
  tsx prover.ts watch-pipelined --node <url>           Pipelined proving
  tsx prover.ts watch-parallel --node <url>            Parallel msgpack workers
  tsx prover.ts watch-incremental --node <url>         Incremental circuit (21x faster)
  tsx prover.ts aggregate --block-start N --block-end M  SnarkFold epoch aggregation
  tsx prover.ts bench    --node <url> --block <n>      Benchmark proving times
  tsx prover.ts bb-version                             Check bb CLI version
  tsx prover.ts gpu-info                               Metal GPU info

Options:
  --native       Use native bb CLI instead of WASM
  --evm          EVM-optimized proofs
  --recursive    Enable IVC chaining (watch modes)
  --workers N    Parallel workers (default: 6)
  --interval N   Poll interval in seconds
  --shard <id>   Shard parameter for node routing
  --start <n>    Resume from block number
  --tree <path>  Sparse Merkle tree path (incremental)`);
}
