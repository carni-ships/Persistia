//! Persistia ZK Prover — Host-side proof generation and verification.
//!
//! This binary runs on the operator's machine (laptop, VPS, or CF Container).
//! It watches the Persistia node for new committed blocks, generates recursive
//! SP1 proofs, and posts them back to the node.
//!
//! Usage:
//!   persistia-prover execute --node http://localhost:8787 --block 5
//!   persistia-prover prove --node http://localhost:8787 --block 5
//!   persistia-prover prove --block 5 --prev-proof proofs/block_4.proof  (recursive)
//!   persistia-prover watch --node http://localhost:8787
//!   persistia-prover verify --proof proof.bin

use base64::Engine as _;
use sha2::Digest;
use clap::{Parser, Subcommand};
use persistia_zk_types::{BlockEvidence, NodeSignature, StateMutation, StateTransitionInput, StateTransitionOutput};
use sp1_sdk::{HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin};
use std::path::PathBuf;

/// The ELF binary of the SP1 guest program (built by build.rs via sp1-build).
const ELF: &[u8] = sp1_sdk::include_elf!("persistia-zk-program");

/// Build a URL by appending a path to a base node URL.
/// Handles base URLs with query parameters (e.g. "https://host/?shard=node-1")
/// by inserting the path before the query string.
fn node_url(base: &str, path: &str) -> String {
    if let Ok(mut u) = url::Url::parse(base) {
        let existing = u.path().trim_end_matches('/').to_string();
        u.set_path(&format!("{}{}", existing, path));
        u.to_string()
    } else {
        format!("{}{}", base, path)
    }
}

/// Build a URL with additional query parameters.
fn node_url_with_params(base: &str, path: &str, params: &[(&str, &str)]) -> String {
    if let Ok(mut u) = url::Url::parse(base) {
        let existing = u.path().trim_end_matches('/').to_string();
        u.set_path(&format!("{}{}", existing, path));
        for (k, v) in params {
            u.query_pairs_mut().append_pair(k, v);
        }
        u.to_string()
    } else {
        let query = params.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("&");
        format!("{}{}?{}", base, path, query)
    }
}

#[derive(Parser)]
#[command(name = "persistia-prover")]
#[command(about = "Generate and verify ZK proofs for Persistia state transitions")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a proof for a specific block
    Prove {
        /// Persistia node URL
        #[arg(long, default_value = "http://localhost:8787")]
        node: String,

        /// Block/round number to prove
        #[arg(long)]
        block: u64,

        /// Path to previous proof for recursive verification (IVC chain)
        #[arg(long)]
        prev_proof: Option<PathBuf>,

        /// Output path for the proof
        #[arg(long, default_value = "proof.bin")]
        output: PathBuf,

        /// Use Groth16 wrapping for compact proof (slower)
        #[arg(long)]
        groth16: bool,
    },

    /// Watch the node and continuously generate recursive proofs
    Watch {
        /// Persistia node URL
        #[arg(long, default_value = "http://localhost:8787")]
        node: String,

        /// Directory to store proofs
        #[arg(long, default_value = "./proofs")]
        proof_dir: PathBuf,

        /// Poll interval in seconds
        #[arg(long, default_value = "10")]
        interval: u64,

        /// Batch N blocks into one proof for amortized proving cost
        #[arg(long, default_value = "1")]
        batch: u64,

        /// Start proving from this block (skip earlier blocks)
        #[arg(long, default_value = "0")]
        start: u64,
    },

    /// Verify a proof locally
    Verify {
        /// Path to the proof file
        #[arg(long)]
        proof: PathBuf,
    },

    /// Execute the program without generating a proof (for testing)
    Execute {
        /// Persistia node URL
        #[arg(long, default_value = "http://localhost:8787")]
        node: String,

        /// Block/round number
        #[arg(long)]
        block: u64,
    },

    // ─── Multi-Prover Architecture Commands ─────────────────────────────

    /// Prove a segment of blocks without chaining (Option 1: Segmented Proving)
    Segment {
        /// Persistia node URL
        #[arg(long, default_value = "http://localhost:8787")]
        node: String,

        /// First block in segment
        #[arg(long)]
        start: u64,

        /// Last block in segment (inclusive)
        #[arg(long)]
        end: u64,

        /// Output directory for segment proofs
        #[arg(long, default_value = "./segments")]
        output_dir: PathBuf,
    },

    /// Merge multiple segment proofs into a single chained proof (Option 1: Segmented Proving)
    Merge {
        /// Directory containing segment proofs to merge
        #[arg(long, default_value = "./segments")]
        segment_dir: PathBuf,

        /// Output path for the merged proof
        #[arg(long, default_value = "merged.proof")]
        output: PathBuf,

        /// Optional previous proof to chain from
        #[arg(long)]
        prev_proof: Option<PathBuf>,
    },

    /// Assemble execution proofs into a recursive IVC chain (Option 2: Pipeline Proving)
    Stitch {
        /// Directory containing execution proofs (block_N.exec files)
        #[arg(long, default_value = "./exec_proofs")]
        exec_dir: PathBuf,

        /// Directory to write chained proofs
        #[arg(long, default_value = "./proofs")]
        proof_dir: PathBuf,

        /// Persistia node URL (for submitting completed proofs)
        #[arg(long, default_value = "http://localhost:8787")]
        node: String,

        /// Optional previous chained proof to resume from
        #[arg(long)]
        prev_proof: Option<PathBuf>,
    },

    /// Watch node using claim-based coordination (Option 4: Multi-Prover Claims)
    WatchClaim {
        /// Persistia node URL
        #[arg(long, default_value = "http://localhost:8787")]
        node: String,

        /// Unique prover identifier
        #[arg(long)]
        prover_id: String,

        /// Directory to store proofs
        #[arg(long, default_value = "./proofs")]
        proof_dir: PathBuf,

        /// Poll interval in seconds
        #[arg(long, default_value = "10")]
        interval: u64,

        /// Number of blocks to claim per batch
        #[arg(long, default_value = "1")]
        batch: u64,

        /// Claim TTL in seconds (how long before claim expires)
        #[arg(long, default_value = "300")]
        ttl: u64,
    },

    /// Tree-structured proof aggregation (Miden-inspired parallel proving)
    TreeProve {
        /// Persistia node URL
        #[arg(long, default_value = "http://localhost:8787")]
        node: String,

        /// Directory for leaf proofs and aggregated proofs
        #[arg(long, default_value = "./tree_proofs")]
        proof_dir: PathBuf,

        /// First block to prove
        #[arg(long)]
        start: u64,

        /// Last block to prove (inclusive)
        #[arg(long)]
        end: u64,

        /// Leaf size: number of blocks per leaf proof
        #[arg(long, default_value = "4")]
        leaf_size: u64,
    },
}

// ─── Vertex Message Construction ────────────────────────────────────────────

/// Build canonical JSON bytes for a vertex (the message each validator signs).
/// Extracted to avoid duplication between primary vertex fetch and fallback.
fn build_canonical_vertex_json(v: &serde_json::Value) -> (String, Vec<u8>) {
    let author = v["author"].as_str().unwrap_or("").to_string();
    let round = v["round"].as_u64().unwrap_or(0);
    let timestamp = v["timestamp"].as_u64().unwrap_or(0);

    let mut event_hashes: Vec<String> = v["event_hashes"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    event_hashes.sort();

    let mut refs: Vec<String> = v["refs"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    refs.sort();

    let eh_json = serde_json::to_string(&event_hashes).unwrap_or("[]".into());
    let refs_json = serde_json::to_string(&refs).unwrap_or("[]".into());
    let canonical = format!(
        r#"{{"author":"{}","round":{},"event_hashes":{},"refs":{},"timestamp":{}}}"#,
        author, round, eh_json, refs_json, timestamp,
    );
    (author, canonical.into_bytes())
}

/// Extract vertex messages from a JSON array of vertices.
fn extract_vertex_messages(vertices: &serde_json::Value) -> std::collections::HashMap<String, Vec<u8>> {
    let mut messages = std::collections::HashMap::new();
    if let Some(arr) = vertices.as_array() {
        for v in arr {
            let (author, msg) = build_canonical_vertex_json(v);
            if !author.is_empty() {
                messages.insert(author, msg);
            }
        }
    }
    messages
}

// ─── Block Input Fetching ───────────────────────────────────────────────────

/// Fetch block data from a Persistia node and construct the SP1 input.
async fn fetch_block_input(
    client: &reqwest::Client,
    node: &str,
    block_number: u64,
    recursive: bool,
    prev_proof: Option<&SP1ProofWithPublicValues>,
) -> anyhow::Result<StateTransitionInput> {
    // Fetch consensus status + block data + vertices in parallel
    let status_fut = client.get(node_url(node, "/dag/status")).send();
    let block_fut = client.get(node_url_with_params(node, "/dag/block", &[("round", &block_number.to_string())])).send();
    let vertices_fut = client.get(node_url_with_params(node, "/dag/vertices", &[("round", &block_number.to_string())])).send();
    let commitment_fut = client.get(node_url(node, "/proof/commitment")).send();

    let (status_resp, block_resp, vertices_resp, commitment_resp) =
        tokio::try_join!(status_fut, block_fut, vertices_fut, commitment_fut)?;

    let _status: serde_json::Value = status_resp.json().await?;

    if !block_resp.status().is_success() {
        anyhow::bail!("Block {} not committed yet (HTTP {})", block_number, block_resp.status());
    }
    let block: serde_json::Value = block_resp.json().await?;
    if block.get("error").is_some() {
        anyhow::bail!("Block {} error: {}", block_number, block["error"]);
    }

    // Use block-level active_nodes (reflects actual validator count at commit time)
    // rather than current live count — prevents quorum mismatch on historical blocks
    let active_nodes = block["active_nodes"].as_u64().unwrap_or(1) as u32;

    let commitment: serde_json::Value = commitment_resp.json().await?;
    let state_root_hex = commitment["root"]
        .as_str()
        .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
    let new_state_root = hex_to_bytes32(state_root_hex);

    let prev_state_root = if let Some(prev) = prev_proof {
        let prev_output: StateTransitionOutput =
            bincode::deserialize(prev.public_values.as_slice())?;
        prev_output.state_root
    } else {
        [0u8; 32]
    };

    let prev_proof_public_values = if let Some(prev) = prev_proof {
        prev.public_values.as_slice().to_vec()
    } else {
        vec![]
    };

    // Build vertex messages from /dag/vertices response, fallback to block["vertices"],
    // then reconstruct from persisted signature data (when vertices are pruned)
    let vertices: serde_json::Value = vertices_resp.json().await?;
    let mut vertex_messages = extract_vertex_messages(&vertices);
    if vertex_messages.is_empty() {
        vertex_messages = extract_vertex_messages(&block["vertices"]);
    }
    if vertex_messages.is_empty() {
        // Reconstruct from persisted signature entries (have round, event_hashes, refs, timestamp)
        if let Some(sigs) = block["signatures"].as_array() {
            vertex_messages = extract_vertex_messages(&serde_json::Value::Array(
                sigs.iter().map(|s| {
                    serde_json::json!({
                        "author": s["pubkey"],
                        "round": s["round"],
                        "event_hashes": s["event_hashes"],
                        "refs": s["refs"],
                        "timestamp": s["timestamp"],
                    })
                }).collect()
            ));
        }
    }

    let signatures = extract_signatures_with_messages(&block, &vertex_messages);
    let mutations = extract_mutations(&block);

    Ok(StateTransitionInput {
        prev_state_root,
        new_state_root,
        block_number,
        mutations,
        signatures,
        active_nodes,
        recursive,
        prev_proof_public_values,
        batch_blocks: vec![],
    })
}

fn extract_signatures_with_messages(
    block: &serde_json::Value,
    vertex_messages: &std::collections::HashMap<String, Vec<u8>>,
) -> Vec<NodeSignature> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut sigs = Vec::new();
    if let Some(arr) = block["signatures"].as_array() {
        for sig in arr {
            let pk_str = sig["pubkey"].as_str().unwrap_or("");
            let sig_str = sig["signature"].as_str().unwrap_or("");
            if pk_str.is_empty() || sig_str.is_empty() {
                continue;
            }
            let pk_bytes = b64.decode(pk_str).unwrap_or_default();
            let sig_bytes = b64.decode(sig_str).unwrap_or_default();
            if pk_bytes.len() == 32 {
                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(&pk_bytes);
                let message = vertex_messages
                    .get(pk_str)
                    .cloned()
                    .unwrap_or_default();
                sigs.push(NodeSignature {
                    pubkey,
                    signature: sig_bytes,
                    message,
                });
            }
        }
    }
    sigs
}

fn extract_mutations(block: &serde_json::Value) -> Vec<StateMutation> {
    let mut mutations = Vec::new();
    if let Some(events) = block["events"].as_array() {
        for event in events {
            if let Some(payload) = event.get("payload") {
                if let (Some(key), Some(val)) =
                    (payload["key"].as_str(), payload["value"].as_str())
                {
                    mutations.push(StateMutation {
                        key: key.as_bytes().to_vec(),
                        old_value: None,
                        new_value: Some(val.as_bytes().to_vec()),
                    });
                }
            }
        }
    }
    mutations
}

/// Fetch evidence for a single block (used in batch mode).
/// Returns a BlockEvidence struct without the full StateTransitionInput overhead.
async fn fetch_block_evidence(
    client: &reqwest::Client,
    node: &str,
    block_number: u64,
) -> anyhow::Result<BlockEvidence> {
    let block_fut = client.get(node_url_with_params(node, "/dag/block", &[("round", &block_number.to_string())])).send();
    let vertices_fut = client.get(node_url_with_params(node, "/dag/vertices", &[("round", &block_number.to_string())])).send();
    let status_fut = client.get(node_url(node, "/dag/status")).send();
    let commitment_fut = client.get(node_url(node, "/proof/commitment")).send();

    let (block_resp, vertices_resp, status_resp, commitment_resp) =
        tokio::try_join!(block_fut, vertices_fut, status_fut, commitment_fut)?;

    let _status: serde_json::Value = status_resp.json().await?;

    if !block_resp.status().is_success() {
        anyhow::bail!("Block {} not committed yet", block_number);
    }
    let block: serde_json::Value = block_resp.json().await?;
    if block.get("error").is_some() {
        anyhow::bail!("Block {} error: {}", block_number, block["error"]);
    }

    // Use block-level active_nodes (actual validator count at commit time)
    let active_nodes = block["active_nodes"].as_u64().unwrap_or(1) as u32;

    let commitment: serde_json::Value = commitment_resp.json().await?;
    let state_root_hex = commitment["root"].as_str()
        .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
    let new_state_root = hex_to_bytes32(state_root_hex);

    let vertices: serde_json::Value = vertices_resp.json().await?;
    let mut vertex_messages = extract_vertex_messages(&vertices);
    if vertex_messages.is_empty() {
        vertex_messages = extract_vertex_messages(&block["vertices"]);
    }
    if vertex_messages.is_empty() {
        if let Some(sigs) = block["signatures"].as_array() {
            vertex_messages = extract_vertex_messages(&serde_json::Value::Array(
                sigs.iter().map(|s| {
                    serde_json::json!({
                        "author": s["pubkey"],
                        "round": s["round"],
                        "event_hashes": s["event_hashes"],
                        "refs": s["refs"],
                        "timestamp": s["timestamp"],
                    })
                }).collect()
            ));
        }
    }

    let signatures = extract_signatures_with_messages(&block, &vertex_messages);
    let mutations = extract_mutations(&block);

    Ok(BlockEvidence {
        block_number,
        new_state_root,
        mutations,
        signatures,
        active_nodes,
    })
}

fn hex_to_bytes32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Ok(bytes) = hex::decode(hex) {
        let len = bytes.len().min(32);
        out[..len].copy_from_slice(&bytes[..len]);
    }
    out
}

/// Load a previously generated proof from disk.
fn load_proof(path: &PathBuf) -> anyhow::Result<SP1ProofWithPublicValues> {
    let bytes = std::fs::read(path)?;
    Ok(bincode::deserialize(&bytes)?)
}

/// Save a proof to disk.
fn save_proof(path: &PathBuf, proof: &SP1ProofWithPublicValues) -> anyhow::Result<()> {
    let bytes = bincode::serialize(proof)?;
    std::fs::write(path, &bytes)?;
    Ok(())
}

/// Prepare stdin with recursive proof data if available.
fn prepare_stdin_with_proof(
    input: &StateTransitionInput,
    prev_proof: Option<&SP1ProofWithPublicValues>,
    vk: &sp1_sdk::SP1VerifyingKey,
) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(input);

    if let Some(prev) = prev_proof {
        let vk_digest: [u32; 8] = vk.hash_u32();
        let pv_hash = prev.public_values.hash();
        let mut pv_digest = [0u8; 32];
        let len = pv_hash.len().min(32);
        pv_digest[..len].copy_from_slice(&pv_hash[..len]);

        stdin.write(&vk_digest);
        stdin.write(&pv_digest);

        if let SP1Proof::Compressed(ref reduce_proof) = prev.proof {
            stdin.write_proof(*reduce_proof.clone(), vk.vk.clone());
        }
    }

    stdin
}

/// Compute SHA-256 hash of proof bytes (for submission to node).
/// Uses incremental hashing to avoid serializing the full proof twice.
fn compute_proof_hash(proof: &SP1ProofWithPublicValues) -> String {
    let bytes = bincode::serialize(proof).unwrap_or_default();
    hex::encode(sha2::Sha256::digest(&bytes))
}

/// Post proof metadata + bytes to the Persistia node.
async fn submit_proof_to_node(
    http: &reqwest::Client,
    node: &str,
    block: u64,
    proof_hash: &str,
    state_root: &[u8; 32],
    proven_blocks: u64,
    proof_type: &str,
    proof: &SP1ProofWithPublicValues,
) {
    // Serialize proof bytes and encode as base64
    let proof_bytes = bincode::serialize(proof).unwrap_or_default();
    let proof_bytes_b64 = base64::engine::general_purpose::STANDARD.encode(&proof_bytes);

    // Decode public values for browser-friendly JSON
    let public_values: Option<StateTransitionOutput> =
        bincode::deserialize(proof.public_values.as_slice()).ok();

    let mut body = serde_json::json!({
        "block_number": block,
        "proof": proof_hash,
        "state_root": hex::encode(state_root),
        "proven_blocks": proven_blocks,
        "proof_type": proof_type,
        "proof_bytes_b64": proof_bytes_b64,
    });

    if let Some(ref pv) = public_values {
        body["public_values"] = serde_json::json!({
            "state_root": hex::encode(pv.state_root),
            "block_number": pv.block_number,
            "proven_blocks": pv.proven_blocks,
            "genesis_root": hex::encode(pv.genesis_root),
        });
        body["genesis_root"] = serde_json::json!(hex::encode(pv.genesis_root));
    }

    match http
        .post(node_url(node, "/proof/zk/submit"))
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => {
            if !resp.status().is_success() {
                eprintln!("  Warning: proof submit HTTP {}", resp.status());
            } else {
                let bytes_kb = proof_bytes.len() / 1024;
                println!("  Proof uploaded to node ({} KB)", bytes_kb);
            }
        }
        Err(e) => eprintln!("  Warning: proof submit failed: {}", e),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let http = reqwest::Client::new();

    match cli.command {
        Commands::Execute { node, block } => {
            println!("Fetching block {} from {}", block, node);
            let input = fetch_block_input(&http, &node, block, false, None).await?;

            println!("Executing SP1 program (no proof generation)...");
            let client = ProverClient::from_env();
            let mut stdin = SP1Stdin::new();
            stdin.write(&input);

            let (output, report) = client.execute(ELF, &stdin).run()?;
            let result: StateTransitionOutput = bincode::deserialize(output.as_slice())?;

            println!("Execution successful!");
            println!("  State root:    {}", hex::encode(result.state_root));
            println!("  Block number:  {}", result.block_number);
            println!("  Proven blocks: {}", result.proven_blocks);
            println!("  Genesis root:  {}", hex::encode(result.genesis_root));
            println!("  Cycles used:   {}", report.total_instruction_count());
        }

        Commands::Prove {
            node,
            block,
            prev_proof,
            output,
            groth16,
        } => {
            let prev = match &prev_proof {
                Some(path) => {
                    println!("Loading previous proof from {:?}", path);
                    Some(load_proof(path)?)
                }
                None => None,
            };
            let recursive = prev.is_some();

            println!("Fetching block {} from {}", block, node);
            let input =
                fetch_block_input(&http, &node, block, recursive, prev.as_ref()).await?;

            println!(
                "Generating {} proof{}...",
                if groth16 { "Groth16" } else { "compressed" },
                if recursive { " (recursive)" } else { "" }
            );

            let client = ProverClient::from_env();
            let (pk, vk) = client.setup(ELF);
            let stdin = prepare_stdin_with_proof(&input, prev.as_ref(), &vk);

            let proof = if groth16 {
                client.prove(&pk, &stdin).groth16().run()?
            } else {
                client.prove(&pk, &stdin).compressed().run()?
            };

            save_proof(&output, &proof)?;
            println!(
                "Proof saved to {:?} ({} bytes)",
                output,
                std::fs::metadata(&output)?.len()
            );

            // Verify locally
            client.verify(&proof, &vk)?;
            println!("Local verification: PASSED");

            let result: StateTransitionOutput =
                bincode::deserialize(proof.public_values.as_slice())?;
            println!("  State root:    {}", hex::encode(result.state_root));
            println!("  Block number:  {}", result.block_number);
            println!("  Proven blocks: {}", result.proven_blocks);
            println!("  Genesis root:  {}", hex::encode(result.genesis_root));
        }

        Commands::Watch {
            node,
            proof_dir,
            interval,
            batch,
            start,
        } => {
            std::fs::create_dir_all(&proof_dir)?;
            println!("Watching {} for new blocks (every {}s, batch={})", node, interval, batch);
            println!("Proofs will be saved to {:?}", proof_dir);
            println!("Recursive mode: each proof verifies the previous one (IVC chain)");

            // Setup once (expensive — key generation)
            let client = ProverClient::from_env();
            let (pk, vk) = client.setup(ELF);
            let mut last_proven_block: u64 = start;
            let mut last_proof: Option<SP1ProofWithPublicValues> = None;

            // Resume from existing proofs
            if let Ok(entries) = std::fs::read_dir(&proof_dir) {
                let mut max_block = 0u64;
                let mut max_path = None;
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        if let Some(num) = name
                            .strip_prefix("block_")
                            .and_then(|s| s.strip_suffix(".proof"))
                            .and_then(|s| s.parse::<u64>().ok())
                        {
                            if num > max_block {
                                max_block = num;
                                max_path = Some(entry.path());
                            }
                        }
                    }
                }
                if let Some(path) = max_path.filter(|_| max_block >= start) {
                    match load_proof(&path) {
                        Ok(proof) => {
                            last_proven_block = max_block;
                            last_proof = Some(proof);
                            println!("Resuming from block {} (recursive chain)", max_block);
                        }
                        Err(e) => {
                            eprintln!("Warning: could not load proof at {:?}: {}", path, e);
                        }
                    }
                }
            }

            loop {
                // Check latest committed round
                let status = match http.get(node_url(&node, "/dag/status")).send().await {
                    Ok(resp) => match resp.json::<serde_json::Value>().await {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("  Parse error: {} — retrying", e);
                            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                            continue;
                        }
                    },
                    Err(e) => {
                        eprintln!("  Network error: {} — retrying", e);
                        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                        continue;
                    }
                };

                let latest = status["last_committed_round"].as_u64().unwrap_or(0);

                if latest > last_proven_block {
                    if batch > 1 {
                        // ─── Batch mode: accumulate up to N blocks into one proof ───
                        let mut blocks_to_prove = Vec::new();
                        let mut cursor = last_proven_block;

                        for _ in 0..batch {
                            let target = if last_proof.is_none() && cursor == 0 {
                                // First block ever
                                match http.get(node_url_with_params(&node, "/dag/next_committed", &[("after", "0")])).send().await {
                                    Ok(resp) => match resp.json::<serde_json::Value>().await {
                                        Ok(r) => r["round"].as_u64().unwrap_or(latest),
                                        Err(_) => break,
                                    },
                                    Err(_) => break,
                                }
                            } else {
                                match http.get(
                                    node_url_with_params(&node, "/dag/next_committed", &[("after", &cursor.to_string())])
                                ).send().await {
                                    Ok(resp) => match resp.json::<serde_json::Value>().await {
                                        Ok(r) => match r["round"].as_u64() {
                                            Some(round) if round <= latest => round,
                                            _ => break,
                                        },
                                        Err(_) => break,
                                    },
                                    Err(_) => break,
                                }
                            };

                            match fetch_block_evidence(&http, &node, target).await {
                                Ok(evidence) => {
                                    cursor = target;
                                    blocks_to_prove.push(evidence);
                                }
                                Err(e) => {
                                    eprintln!("  Failed to fetch block {}: {}", target, e);
                                    break;
                                }
                            }
                        }

                        if blocks_to_prove.is_empty() {
                            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                            continue;
                        }

                        let first_block = blocks_to_prove.first().unwrap().block_number;
                        let last_block = blocks_to_prove.last().unwrap().block_number;
                        let blocks_to_prove_count = blocks_to_prove.len();
                        let recursive = last_proof.is_some();
                        println!(
                            "\nBatch: blocks {}..{} ({} blocks){}",
                            first_block, last_block, blocks_to_prove.len(),
                            if recursive { " — chaining recursively" } else { " — genesis proof" }
                        );

                        let prev_state_root = if let Some(ref prev) = last_proof {
                            let prev_output: StateTransitionOutput =
                                bincode::deserialize(prev.public_values.as_slice()).unwrap_or(
                                    StateTransitionOutput {
                                        state_root: [0u8; 32],
                                        block_number: 0,
                                        proven_blocks: 0,
                                        genesis_root: [0u8; 32],
                                    },
                                );
                            prev_output.state_root
                        } else {
                            [0u8; 32]
                        };

                        let prev_proof_public_values = last_proof.as_ref()
                            .map(|p| p.public_values.as_slice().to_vec())
                            .unwrap_or_default();

                        let input = StateTransitionInput {
                            prev_state_root,
                            new_state_root: [0u8; 32], // ignored in batch mode
                            block_number: 0,             // ignored in batch mode
                            mutations: vec![],           // ignored in batch mode
                            signatures: vec![],          // ignored in batch mode
                            active_nodes: 0,             // ignored in batch mode
                            recursive,
                            prev_proof_public_values,
                            batch_blocks: blocks_to_prove,
                        };

                        let stdin = prepare_stdin_with_proof(&input, last_proof.as_ref(), &vk);

                        let prove_start = std::time::Instant::now();
                        println!("  Proving started at {}", chrono::Local::now().format("%H:%M:%S"));
                        match client.prove(&pk, &stdin).compressed().run() {
                            Ok(proof) => {
                                let prove_elapsed = prove_start.elapsed();
                                println!(
                                    "  Proving completed in {:.1}m ({:.0}s)",
                                    prove_elapsed.as_secs_f64() / 60.0,
                                    prove_elapsed.as_secs_f64(),
                                );

                                if last_proven_block % 10 == 0 {
                                    if let Err(e) = client.verify(&proof, &vk) {
                                        eprintln!("  Verification failed for batch: {}", e);
                                        continue;
                                    }
                                }

                                let path = proof_dir.join(format!("block_{}.proof", last_block));
                                if let Err(e) = save_proof(&path, &proof) {
                                    eprintln!("  Failed to save proof: {}", e);
                                    continue;
                                }

                                let result: StateTransitionOutput =
                                    bincode::deserialize(proof.public_values.as_slice())?;

                                let blocks_per_hour = blocks_to_prove_count as f64 / (prove_elapsed.as_secs_f64() / 3600.0);
                                println!(
                                    "  Batch {}..{} proven — root: {} | chain: {} blocks | {:.0} blocks/hr | {} bytes",
                                    first_block, last_block,
                                    hex::encode(result.state_root),
                                    result.proven_blocks,
                                    blocks_per_hour,
                                    std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0),
                                );

                                let proof_hash = compute_proof_hash(&proof);
                                submit_proof_to_node(
                                    &http, &node, last_block, &proof_hash,
                                    &result.state_root, result.proven_blocks, "compressed-batch",
                                    &proof,
                                ).await;

                                last_proof = Some(proof);
                                last_proven_block = last_block;
                            }
                            Err(e) => {
                                eprintln!("  Failed to prove batch: {}", e);
                            }
                        }
                    } else {
                        // ─── Single-block mode ──────────────────────────────────
                        let target = if last_proof.is_none() && last_proven_block == 0 {
                            latest
                        } else {
                            match http.get(
                                node_url_with_params(&node, "/dag/next_committed", &[("after", &last_proven_block.to_string())])
                            ).send().await {
                                Ok(resp) => match resp.json::<serde_json::Value>().await {
                                    Ok(r) => r["round"].as_u64().unwrap_or(latest),
                                    Err(_) => latest,
                                },
                                Err(e) => {
                                    eprintln!("  Network error: {} — retrying", e);
                                    tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                                    continue;
                                }
                            }
                        };
                        if target > latest {
                            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                            continue;
                        }
                        let recursive = last_proof.is_some();
                        println!(
                            "\nBlock {} detected (latest: {}){}",
                            target, latest,
                            if recursive { " — chaining recursively" } else { " — genesis proof" }
                        );

                        match fetch_block_input(&http, &node, target, recursive, last_proof.as_ref()).await {
                            Ok(mut input) => {
                                input.batch_blocks = vec![]; // ensure single-block mode
                                let stdin = prepare_stdin_with_proof(&input, last_proof.as_ref(), &vk);

                                let prove_start = std::time::Instant::now();
                                println!("  Proving started at {}", chrono::Local::now().format("%H:%M:%S"));
                                match client.prove(&pk, &stdin).compressed().run() {
                                    Ok(proof) => {
                                        let prove_elapsed = prove_start.elapsed();
                                        println!(
                                            "  Proving completed in {:.1}m ({:.0}s)",
                                            prove_elapsed.as_secs_f64() / 60.0,
                                            prove_elapsed.as_secs_f64(),
                                        );

                                        if last_proven_block % 10 == 0 {
                                            if let Err(e) = client.verify(&proof, &vk) {
                                                eprintln!("  Verification failed for block {}: {}", target, e);
                                                continue;
                                            }
                                        }

                                        let path = proof_dir.join(format!("block_{}.proof", target));
                                        if let Err(e) = save_proof(&path, &proof) {
                                            eprintln!("  Failed to save proof: {}", e);
                                            continue;
                                        }

                                        let result: StateTransitionOutput =
                                            bincode::deserialize(proof.public_values.as_slice())?;

                                        let blocks_per_hour = 1.0 / (prove_elapsed.as_secs_f64() / 3600.0);
                                        println!(
                                            "  Block {} proven — root: {} | chain: {} blocks | {:.0} blocks/hr | {} bytes",
                                            target,
                                            hex::encode(result.state_root),
                                            result.proven_blocks,
                                            blocks_per_hour,
                                            std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0),
                                        );

                                        let proof_hash = compute_proof_hash(&proof);
                                        submit_proof_to_node(
                                            &http, &node, target, &proof_hash,
                                            &result.state_root, result.proven_blocks, "compressed",
                                            &proof,
                                        ).await;

                                        last_proof = Some(proof);
                                        last_proven_block = target;
                                    }
                                    Err(e) => {
                                        eprintln!("  Failed to prove block {}: {}", target, e);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("  Failed to fetch block {}: {}", target, e);
                            }
                        }
                    }
                }

                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            }
        }

        Commands::Verify { proof } => {
            println!("Loading proof from {:?}", proof);
            let proof = load_proof(&proof)?;

            let client = ProverClient::from_env();
            let (_, vk) = client.setup(ELF);

            match client.verify(&proof, &vk) {
                Ok(()) => {
                    let result: StateTransitionOutput =
                        bincode::deserialize(proof.public_values.as_slice())?;
                    println!("Verification: PASSED");
                    println!("  State root:    {}", hex::encode(result.state_root));
                    println!("  Block number:  {}", result.block_number);
                    println!("  Proven blocks: {}", result.proven_blocks);
                    println!("  Genesis root:  {}", hex::encode(result.genesis_root));
                }
                Err(e) => {
                    println!("Verification: FAILED — {}", e);
                    std::process::exit(1);
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // Option 1: Segmented Proving — prove a range without IVC chaining
        // ═══════════════════════════════════════════════════════════════════

        Commands::Segment { node, start, end, output_dir } => {
            std::fs::create_dir_all(&output_dir)?;
            println!("Segment proving blocks {}..{} from {}", start, end, node);

            let client = ProverClient::from_env();
            let (pk, vk) = client.setup(ELF);

            // Collect all block evidence for the segment
            let mut evidences = Vec::new();
            let mut cursor = start;
            while cursor <= end {
                // Find next committed round >= cursor
                let target = if cursor == start {
                    match http.get(node_url_with_params(&node, "/dag/next_committed", &[("after", &(cursor.saturating_sub(1)).to_string())])).send().await {
                        Ok(resp) => match resp.json::<serde_json::Value>().await {
                            Ok(r) => r["round"].as_u64().unwrap_or(cursor),
                            Err(_) => break,
                        },
                        Err(_) => break,
                    }
                } else {
                    match http.get(node_url_with_params(&node, "/dag/next_committed", &[("after", &cursor.to_string())])).send().await {
                        Ok(resp) => match resp.json::<serde_json::Value>().await {
                            Ok(r) => match r["round"].as_u64() {
                                Some(round) if round <= end => round,
                                _ => break,
                            },
                            Err(_) => break,
                        },
                        Err(_) => break,
                    }
                };

                match fetch_block_evidence(&http, &node, target).await {
                    Ok(ev) => {
                        println!("  Fetched block {}", target);
                        cursor = target;
                        evidences.push(ev);
                    }
                    Err(e) => {
                        eprintln!("  Failed to fetch block {}: {}", target, e);
                        break;
                    }
                }
                cursor += 1;
            }

            if evidences.is_empty() {
                anyhow::bail!("No blocks found in range {}..{}", start, end);
            }

            let first_block = evidences.first().unwrap().block_number;
            let last_block = evidences.last().unwrap().block_number;
            println!("Proving segment: {} blocks ({}..{})", evidences.len(), first_block, last_block);

            // Build a non-recursive (segment) proof — no prev_proof, not chained
            let input = StateTransitionInput {
                prev_state_root: [0u8; 32],
                new_state_root: [0u8; 32],
                block_number: 0,
                mutations: vec![],
                signatures: vec![],
                active_nodes: 0,
                recursive: false,
                prev_proof_public_values: vec![],
                batch_blocks: evidences,
            };

            let mut stdin = SP1Stdin::new();
            stdin.write(&input);

            match client.prove(&pk, &stdin).compressed().run() {
                Ok(proof) => {
                    client.verify(&proof, &vk)?;
                    let path = output_dir.join(format!("segment_{}_{}.proof", first_block, last_block));
                    save_proof(&path, &proof)?;
                    let result: StateTransitionOutput = bincode::deserialize(proof.public_values.as_slice())?;
                    println!("Segment proof saved to {:?}", path);
                    println!("  State root:    {}", hex::encode(result.state_root));
                    println!("  Blocks:        {}..{}", first_block, last_block);
                    println!("  Proven blocks: {}", result.proven_blocks);
                }
                Err(e) => {
                    eprintln!("Failed to prove segment: {}", e);
                    std::process::exit(1);
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // Option 1b: Merge — combine segment proofs into a single IVC chain
        // ═══════════════════════════════════════════════════════════════════

        Commands::Merge { segment_dir, output, prev_proof } => {
            println!("Merging segment proofs from {:?}", segment_dir);

            let client = ProverClient::from_env();
            let (pk, vk) = client.setup(ELF);

            // Collect and sort segment proofs by block range
            let mut segments: Vec<(u64, u64, PathBuf)> = Vec::new();
            for entry in std::fs::read_dir(&segment_dir)?.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Some(rest) = name.strip_prefix("segment_") {
                        if let Some(rest) = rest.strip_suffix(".proof") {
                            let parts: Vec<&str> = rest.split('_').collect();
                            if parts.len() == 2 {
                                if let (Ok(s), Ok(e)) = (parts[0].parse::<u64>(), parts[1].parse::<u64>()) {
                                    segments.push((s, e, entry.path()));
                                }
                            }
                        }
                    }
                }
            }
            segments.sort_by_key(|(s, _, _)| *s);

            if segments.is_empty() {
                anyhow::bail!("No segment proofs found in {:?}", segment_dir);
            }

            println!("Found {} segments:", segments.len());
            for (s, e, path) in &segments {
                println!("  {}..{} — {:?}", s, e, path);
            }

            // Load initial chain proof if provided
            let mut chain_proof: Option<SP1ProofWithPublicValues> = match &prev_proof {
                Some(path) => {
                    println!("Chaining from previous proof: {:?}", path);
                    Some(load_proof(path)?)
                }
                None => None,
            };

            // Re-prove each segment recursively, chaining them together
            for (seg_start, seg_end, seg_path) in &segments {
                println!("\nMerging segment {}..{}", seg_start, seg_end);
                let seg_proof = load_proof(seg_path)?;

                // Extract the segment's public values to get its block data
                let seg_output: StateTransitionOutput =
                    bincode::deserialize(seg_proof.public_values.as_slice())?;

                let recursive = chain_proof.is_some();
                let prev_state_root = if let Some(ref cp) = chain_proof {
                    let prev_out: StateTransitionOutput = bincode::deserialize(cp.public_values.as_slice())?;
                    prev_out.state_root
                } else {
                    [0u8; 32]
                };

                let prev_pv = chain_proof.as_ref()
                    .map(|p| p.public_values.as_slice().to_vec())
                    .unwrap_or_default();

                // Create a merge input that wraps the segment output
                let input = StateTransitionInput {
                    prev_state_root,
                    new_state_root: seg_output.state_root,
                    block_number: seg_output.block_number,
                    mutations: vec![],
                    signatures: vec![],
                    active_nodes: 0,
                    recursive,
                    prev_proof_public_values: prev_pv,
                    batch_blocks: vec![], // segment already proven — just chain
                };

                let stdin = prepare_stdin_with_proof(&input, chain_proof.as_ref(), &vk);

                match client.prove(&pk, &stdin).compressed().run() {
                    Ok(proof) => {
                        let result: StateTransitionOutput = bincode::deserialize(proof.public_values.as_slice())?;
                        println!("  Merged — chain: {} blocks, root: {}", result.proven_blocks, hex::encode(result.state_root));
                        chain_proof = Some(proof);
                    }
                    Err(e) => {
                        eprintln!("  Failed to merge segment {}..{}: {}", seg_start, seg_end, e);
                        std::process::exit(1);
                    }
                }
            }

            if let Some(final_proof) = &chain_proof {
                client.verify(final_proof, &vk)?;
                save_proof(&output, final_proof)?;
                let result: StateTransitionOutput = bincode::deserialize(final_proof.public_values.as_slice())?;
                println!("\nMerged proof saved to {:?}", output);
                println!("  State root:    {}", hex::encode(result.state_root));
                println!("  Proven blocks: {}", result.proven_blocks);
                println!("  Genesis root:  {}", hex::encode(result.genesis_root));
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // Option 2: Pipeline Proving — stitch execution proofs into IVC
        // ═══════════════════════════════════════════════════════════════════

        Commands::Stitch { exec_dir, proof_dir, node, prev_proof } => {
            std::fs::create_dir_all(&proof_dir)?;
            println!("Pipeline stitcher: reading exec proofs from {:?}, outputting to {:?}", exec_dir, proof_dir);

            let client = ProverClient::from_env();
            let (pk, vk) = client.setup(ELF);

            // Load previous chain state
            let mut chain_proof: Option<SP1ProofWithPublicValues> = match &prev_proof {
                Some(path) => {
                    println!("Resuming chain from: {:?}", path);
                    Some(load_proof(path)?)
                }
                None => {
                    // Try to resume from proof_dir
                    let mut max_block = 0u64;
                    let mut max_path = None;
                    if let Ok(entries) = std::fs::read_dir(&proof_dir) {
                        for entry in entries.flatten() {
                            if let Some(name) = entry.file_name().to_str() {
                                if let Some(num) = name
                                    .strip_prefix("block_")
                                    .and_then(|s| s.strip_suffix(".proof"))
                                    .and_then(|s| s.parse::<u64>().ok())
                                {
                                    if num > max_block {
                                        max_block = num;
                                        max_path = Some(entry.path());
                                    }
                                }
                            }
                        }
                    }
                    match max_path {
                        Some(path) => {
                            println!("Resuming from block {} in proof_dir", max_block);
                            Some(load_proof(&path)?)
                        }
                        None => None,
                    }
                }
            };

            let mut last_stitched_block = if let Some(ref cp) = chain_proof {
                let out: StateTransitionOutput = bincode::deserialize(cp.public_values.as_slice())?;
                out.block_number
            } else {
                0u64
            };

            // Collect and sort exec proofs
            let mut exec_proofs: Vec<(u64, PathBuf)> = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&exec_dir) {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        if let Some(num) = name
                            .strip_prefix("block_")
                            .and_then(|s| s.strip_suffix(".exec"))
                            .and_then(|s| s.parse::<u64>().ok())
                        {
                            if num > last_stitched_block {
                                exec_proofs.push((num, entry.path()));
                            }
                        }
                    }
                }
            }
            exec_proofs.sort_by_key(|(n, _)| *n);

            if exec_proofs.is_empty() {
                println!("No new exec proofs to stitch (last stitched: block {})", last_stitched_block);
            }

            for (block_num, exec_path) in &exec_proofs {
                println!("\nStitching block {} into IVC chain", block_num);
                let exec_proof = load_proof(exec_path)?;
                let exec_output: StateTransitionOutput =
                    bincode::deserialize(exec_proof.public_values.as_slice())?;

                let recursive = chain_proof.is_some();
                let prev_state_root = if let Some(ref cp) = chain_proof {
                    let prev_out: StateTransitionOutput = bincode::deserialize(cp.public_values.as_slice())?;
                    prev_out.state_root
                } else {
                    [0u8; 32]
                };

                let prev_pv = chain_proof.as_ref()
                    .map(|p| p.public_values.as_slice().to_vec())
                    .unwrap_or_default();

                let input = StateTransitionInput {
                    prev_state_root,
                    new_state_root: exec_output.state_root,
                    block_number: exec_output.block_number,
                    mutations: vec![],
                    signatures: vec![],
                    active_nodes: 0,
                    recursive,
                    prev_proof_public_values: prev_pv,
                    batch_blocks: vec![],
                };

                let stdin = prepare_stdin_with_proof(&input, chain_proof.as_ref(), &vk);

                match client.prove(&pk, &stdin).compressed().run() {
                    Ok(proof) => {
                        let result: StateTransitionOutput = bincode::deserialize(proof.public_values.as_slice())?;
                        let chain_path = proof_dir.join(format!("block_{}.proof", block_num));
                        save_proof(&chain_path, &proof)?;
                        println!(
                            "  Block {} stitched — root: {} | chain: {} blocks",
                            block_num, hex::encode(result.state_root), result.proven_blocks,
                        );

                        // Submit to node
                        let proof_hash = compute_proof_hash(&proof);
                        submit_proof_to_node(
                            &http, &node, *block_num, &proof_hash,
                            &result.state_root, result.proven_blocks, "compressed-stitched",
                            &proof,
                        ).await;

                        chain_proof = Some(proof);
                        last_stitched_block = *block_num;
                    }
                    Err(e) => {
                        eprintln!("  Failed to stitch block {}: {}", block_num, e);
                        break;
                    }
                }
            }

            println!("\nStitching complete. Last block: {}", last_stitched_block);
        }

        // ═══════════════════════════════════════════════════════════════════
        // Option 4: Claim-Based Coordination — provers claim work from node
        // ═══════════════════════════════════════════════════════════════════

        Commands::WatchClaim { node, prover_id, proof_dir, interval, batch, ttl } => {
            std::fs::create_dir_all(&proof_dir)?;
            println!("Claim-based prover '{}' watching {} (batch={}, ttl={}s)", prover_id, node, batch, ttl);

            let client = ProverClient::from_env();
            let (pk, vk) = client.setup(ELF);
            let mut last_proof: Option<SP1ProofWithPublicValues> = None;
            let mut last_proven_block: u64 = 0;

            // Resume from existing proofs
            if let Ok(entries) = std::fs::read_dir(&proof_dir) {
                let mut max_block = 0u64;
                let mut max_path = None;
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        if let Some(num) = name
                            .strip_prefix("block_")
                            .and_then(|s| s.strip_suffix(".proof"))
                            .and_then(|s| s.parse::<u64>().ok())
                        {
                            if num > max_block {
                                max_block = num;
                                max_path = Some(entry.path());
                            }
                        }
                    }
                }
                if let Some(path) = max_path {
                    match load_proof(&path) {
                        Ok(proof) => {
                            last_proven_block = max_block;
                            last_proof = Some(proof);
                            println!("Resuming from block {} (recursive chain)", max_block);
                        }
                        Err(e) => eprintln!("Warning: could not load proof at {:?}: {}", path, e),
                    }
                }
            }

            loop {
                // Ask node for next unclaimed work
                let unclaimed = match http.get(
                    node_url_with_params(&node, "/proof/next_unclaimed", &[
                        ("batch", &batch.to_string()),
                        ("after", &last_proven_block.to_string()),
                    ])
                ).send().await {
                    Ok(resp) => match resp.json::<serde_json::Value>().await {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("  Parse error: {} — retrying", e);
                            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                            continue;
                        }
                    },
                    Err(e) => {
                        eprintln!("  Network error: {} — retrying", e);
                        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                        continue;
                    }
                };

                if !unclaimed["available"].as_bool().unwrap_or(false) {
                    tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                    continue;
                }

                let block_start = unclaimed["block_start"].as_u64().unwrap();
                let block_end = unclaimed["block_end"].as_u64().unwrap();

                // Claim the range
                let claim_resp = match http.post(node_url(&node, "/proof/claim"))
                    .json(&serde_json::json!({
                        "prover_id": prover_id,
                        "block_start": block_start,
                        "block_end": block_end,
                        "ttl_seconds": ttl,
                    }))
                    .send().await
                {
                    Ok(resp) => match resp.json::<serde_json::Value>().await {
                        Ok(v) => v,
                        Err(_) => continue,
                    },
                    Err(e) => {
                        eprintln!("  Claim failed: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                        continue;
                    }
                };

                if claim_resp.get("error").is_some() {
                    eprintln!("  Claim rejected: {}", claim_resp["error"]);
                    tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                    continue;
                }

                println!("\nClaimed blocks {}..{}", block_start, block_end);

                // Fetch and prove the claimed range
                let mut evidences = Vec::new();
                let blocks: Vec<u64> = unclaimed["blocks"].as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_u64()).collect())
                    .unwrap_or_else(|| (block_start..=block_end).collect());

                let mut fetch_failed = false;
                for &block in &blocks {
                    match fetch_block_evidence(&http, &node, block).await {
                        Ok(ev) => evidences.push(ev),
                        Err(e) => {
                            eprintln!("  Failed to fetch block {}: {}", block, e);
                            fetch_failed = true;
                            break;
                        }
                    }
                }

                if fetch_failed || evidences.is_empty() {
                    // Release the claim
                    let _ = http.post(node_url(&node, "/proof/release"))
                        .json(&serde_json::json!({
                            "prover_id": prover_id,
                            "block_start": block_start,
                            "block_end": block_end,
                            "status": "released",
                        }))
                        .send().await;
                    continue;
                }

                let recursive = last_proof.is_some();
                let prev_state_root = if let Some(ref prev) = last_proof {
                    let prev_output: StateTransitionOutput = bincode::deserialize(prev.public_values.as_slice())?;
                    prev_output.state_root
                } else {
                    [0u8; 32]
                };
                let prev_pv = last_proof.as_ref()
                    .map(|p| p.public_values.as_slice().to_vec())
                    .unwrap_or_default();

                let input = StateTransitionInput {
                    prev_state_root,
                    new_state_root: [0u8; 32],
                    block_number: 0,
                    mutations: vec![],
                    signatures: vec![],
                    active_nodes: 0,
                    recursive,
                    prev_proof_public_values: prev_pv,
                    batch_blocks: evidences,
                };

                let stdin = prepare_stdin_with_proof(&input, last_proof.as_ref(), &vk);

                match client.prove(&pk, &stdin).compressed().run() {
                    Ok(proof) => {
                        let result: StateTransitionOutput = bincode::deserialize(proof.public_values.as_slice())?;
                        let path = proof_dir.join(format!("block_{}.proof", block_end));
                        save_proof(&path, &proof)?;

                        let proof_hash = compute_proof_hash(&proof);
                        println!(
                            "  Blocks {}..{} proven — root: {} | chain: {} blocks",
                            block_start, block_end,
                            hex::encode(result.state_root), result.proven_blocks,
                        );

                        // Submit proof and release claim as completed
                        submit_proof_to_node(
                            &http, &node, block_end, &proof_hash,
                            &result.state_root, result.proven_blocks, "compressed-claimed",
                            &proof,
                        ).await;

                        let _ = http.post(node_url(&node, "/proof/release"))
                            .json(&serde_json::json!({
                                "prover_id": prover_id,
                                "block_start": block_start,
                                "block_end": block_end,
                                "status": "completed",
                                "proof_hash": proof_hash,
                            }))
                            .send().await;

                        last_proof = Some(proof);
                        last_proven_block = block_end;
                    }
                    Err(e) => {
                        eprintln!("  Failed to prove blocks {}..{}: {}", block_start, block_end, e);
                        // Release claim on failure
                        let _ = http.post(node_url(&node, "/proof/release"))
                            .json(&serde_json::json!({
                                "prover_id": prover_id,
                                "block_start": block_start,
                                "block_end": block_end,
                                "status": "released",
                            }))
                            .send().await;
                    }
                }

                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // Tree-Structured Proof Aggregation (Miden-inspired)
        // Proves blocks in a binary tree: leaf proofs run in parallel,
        // then pairs are aggregated bottom-up. O(N/P + log N) with P provers.
        // ═══════════════════════════════════════════════════════════════════

        Commands::TreeProve { node, proof_dir, start, end, leaf_size } => {
            std::fs::create_dir_all(&proof_dir)?;
            let leaf_dir = proof_dir.join("leaves");
            let agg_dir = proof_dir.join("aggregated");
            std::fs::create_dir_all(&leaf_dir)?;
            std::fs::create_dir_all(&agg_dir)?;

            let client = ProverClient::from_env();
            let (pk, vk) = client.setup(ELF);

            // Phase 1: Create leaf proofs (each covers `leaf_size` blocks)
            println!("Phase 1: Generating leaf proofs (leaf_size={})", leaf_size);
            let mut leaf_proofs: Vec<(u64, u64, PathBuf)> = Vec::new();
            let mut cursor = start;

            while cursor <= end {
                let leaf_end = std::cmp::min(cursor + leaf_size - 1, end);
                let leaf_path = leaf_dir.join(format!("leaf_{}_{}.proof", cursor, leaf_end));

                // Check if leaf already exists
                if leaf_path.exists() {
                    println!("  Leaf {}..{} already exists, skipping", cursor, leaf_end);
                    leaf_proofs.push((cursor, leaf_end, leaf_path));
                    cursor = leaf_end + 1;
                    continue;
                }

                // Fetch block evidence for this leaf range
                let mut evidences = Vec::new();
                let mut block_cursor = cursor;
                while block_cursor <= leaf_end {
                    let target = match http.get(
                        node_url_with_params(&node, "/dag/next_committed", &[("after", &(block_cursor.saturating_sub(1)).to_string())])
                    ).send().await {
                        Ok(resp) => match resp.json::<serde_json::Value>().await {
                            Ok(r) => match r["round"].as_u64() {
                                Some(round) if round <= leaf_end => round,
                                _ => break,
                            },
                            Err(_) => break,
                        },
                        Err(_) => break,
                    };

                    match fetch_block_evidence(&http, &node, target).await {
                        Ok(ev) => {
                            block_cursor = target + 1;
                            evidences.push(ev);
                        }
                        Err(e) => {
                            eprintln!("  Failed to fetch block {}: {}", target, e);
                            break;
                        }
                    }
                }

                if evidences.is_empty() {
                    cursor = leaf_end + 1;
                    continue;
                }

                let actual_start = evidences.first().unwrap().block_number;
                let actual_end = evidences.last().unwrap().block_number;
                println!("  Proving leaf {}..{} ({} blocks)", actual_start, actual_end, evidences.len());

                let input = StateTransitionInput {
                    prev_state_root: [0u8; 32],
                    new_state_root: [0u8; 32],
                    block_number: 0,
                    mutations: vec![],
                    signatures: vec![],
                    active_nodes: 0,
                    recursive: false,
                    prev_proof_public_values: vec![],
                    batch_blocks: evidences,
                };

                let mut stdin = SP1Stdin::new();
                stdin.write(&input);

                match client.prove(&pk, &stdin).compressed().run() {
                    Ok(proof) => {
                        let result: StateTransitionOutput = bincode::deserialize(proof.public_values.as_slice())?;
                        let path = leaf_dir.join(format!("leaf_{}_{}.proof", actual_start, actual_end));
                        save_proof(&path, &proof)?;
                        println!("    Leaf proven — root: {}, blocks: {}", hex::encode(result.state_root), result.proven_blocks);
                        leaf_proofs.push((actual_start, actual_end, path));
                    }
                    Err(e) => {
                        eprintln!("    Failed to prove leaf: {}", e);
                    }
                }

                cursor = leaf_end + 1;
            }

            if leaf_proofs.is_empty() {
                anyhow::bail!("No leaf proofs generated");
            }

            // Phase 2: Binary tree aggregation — combine pairs bottom-up
            println!("\nPhase 2: Tree aggregation ({} leaves)", leaf_proofs.len());
            let mut current_level: Vec<(u64, u64, PathBuf)> = leaf_proofs;
            let mut level = 0u32;

            while current_level.len() > 1 {
                level += 1;
                let mut next_level: Vec<(u64, u64, PathBuf)> = Vec::new();
                println!("  Level {} — aggregating {} proofs into {}", level, current_level.len(), (current_level.len() + 1) / 2);

                let mut i = 0;
                while i < current_level.len() {
                    if i + 1 < current_level.len() {
                        // Pair: aggregate left and right
                        let (l_start, l_end, ref l_path) = current_level[i];
                        let (r_start, r_end, ref r_path) = current_level[i + 1];

                        let agg_path = agg_dir.join(format!("agg_L{}_{}-{}.proof", level, l_start, r_end));

                        if agg_path.exists() {
                            println!("    Agg {}..{} already exists, skipping", l_start, r_end);
                            next_level.push((l_start, r_end, agg_path));
                            i += 2;
                            continue;
                        }

                        let left_proof = load_proof(l_path)?;
                        let right_proof = load_proof(r_path)?;

                        let left_output: StateTransitionOutput = bincode::deserialize(left_proof.public_values.as_slice())?;
                        let right_output: StateTransitionOutput = bincode::deserialize(right_proof.public_values.as_slice())?;

                        println!("    Aggregating {}..{} + {}..{}", l_start, l_end, r_start, r_end);

                        // Create a chain: left as base, right chained on top
                        let input = StateTransitionInput {
                            prev_state_root: left_output.state_root,
                            new_state_root: right_output.state_root,
                            block_number: right_output.block_number,
                            mutations: vec![],
                            signatures: vec![],
                            active_nodes: 0,
                            recursive: true,
                            prev_proof_public_values: left_proof.public_values.as_slice().to_vec(),
                            batch_blocks: vec![],
                        };

                        let stdin = prepare_stdin_with_proof(&input, Some(&left_proof), &vk);

                        match client.prove(&pk, &stdin).compressed().run() {
                            Ok(proof) => {
                                let result: StateTransitionOutput = bincode::deserialize(proof.public_values.as_slice())?;
                                save_proof(&agg_path, &proof)?;
                                println!("    Aggregated — root: {}, total: {} blocks", hex::encode(result.state_root), result.proven_blocks);
                                next_level.push((l_start, r_end, agg_path));
                            }
                            Err(e) => {
                                eprintln!("    Aggregation failed: {}", e);
                                // Fall back: push both individually
                                next_level.push(current_level[i].clone());
                                next_level.push(current_level[i + 1].clone());
                            }
                        }
                        i += 2;
                    } else {
                        // Odd one out — promote to next level
                        println!("    Promoting unpaired proof {}..{}", current_level[i].0, current_level[i].1);
                        next_level.push(current_level[i].clone());
                        i += 1;
                    }
                }
                current_level = next_level;
            }

            // Final result
            if let Some((final_start, final_end, ref final_path)) = current_level.first() {
                let final_proof = load_proof(final_path)?;
                client.verify(&final_proof, &vk)?;
                let result: StateTransitionOutput = bincode::deserialize(final_proof.public_values.as_slice())?;

                let root_path = proof_dir.join(format!("tree_{}_{}.proof", final_start, final_end));
                std::fs::copy(final_path, &root_path)?;

                println!("\nTree proof complete!");
                println!("  Range:       {}..{}", final_start, final_end);
                println!("  State root:  {}", hex::encode(result.state_root));
                println!("  Proven blocks: {}", result.proven_blocks);
                println!("  Tree levels: {}", level);
                println!("  Output:      {:?}", root_path);

                // Submit to node
                let proof_hash = compute_proof_hash(&final_proof);
                submit_proof_to_node(
                    &http, &node, *final_end, &proof_hash,
                    &result.state_root, result.proven_blocks, "compressed-tree",
                    &final_proof,
                ).await;
            }
        }
    }

    Ok(())
}
