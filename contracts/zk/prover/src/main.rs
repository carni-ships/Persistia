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
use persistia_zk_types::{NodeSignature, StateMutation, StateTransitionInput, StateTransitionOutput};
use sp1_sdk::{HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin};
use std::path::PathBuf;

/// The ELF binary of the SP1 guest program (built by build.rs via sp1-build).
const ELF: &[u8] = sp1_sdk::include_elf!("persistia-zk-program");

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
}

/// Fetch block data from a Persistia node and construct the SP1 input.
async fn fetch_block_input(
    node: &str,
    block_number: u64,
    recursive: bool,
    prev_proof: Option<&SP1ProofWithPublicValues>,
) -> anyhow::Result<StateTransitionInput> {
    let client = reqwest::Client::new();

    // Fetch consensus status for active node count
    let status: serde_json::Value = client
        .get(format!("{}/dag/status", node))
        .send()
        .await?
        .json()
        .await?;

    let active_nodes = status["active_nodes"].as_u64().unwrap_or(1) as u32;

    // Fetch the committed block/vertex data
    let block_resp = client
        .get(format!("{}/dag/block?round={}", node, block_number))
        .send()
        .await?;
    if !block_resp.status().is_success() {
        anyhow::bail!("Block {} not committed yet (HTTP {})", block_number, block_resp.status());
    }
    let block: serde_json::Value = block_resp.json().await?;
    if block.get("error").is_some() {
        anyhow::bail!("Block {} error: {}", block_number, block["error"]);
    }

    // Extract state roots from the proof endpoints
    let commitment: serde_json::Value = client
        .get(format!("{}/proof/commitment", node))
        .send()
        .await?
        .json()
        .await?;

    let state_root_hex = commitment["root"]
        .as_str()
        .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");

    let new_state_root = hex_to_bytes32(state_root_hex);

    // For the previous state root, use the previous proof's output or zeros for genesis.
    let prev_state_root = if let Some(prev) = prev_proof {
        let prev_output: StateTransitionOutput =
            bincode::deserialize(prev.public_values.as_slice())?;
        prev_output.state_root
    } else {
        [0u8; 32]
    };

    // Build previous proof's public values for chain integrity checking inside guest
    let prev_proof_public_values = if let Some(prev) = prev_proof {
        prev.public_values.as_slice().to_vec()
    } else {
        vec![]
    };

    // Fetch all vertices for this round to get per-validator canonical JSON.
    // Each validator signs their OWN vertex, not a shared block hash.
    let vertices: serde_json::Value = client
        .get(format!("{}/dag/vertices?round={}", node, block_number))
        .send()
        .await?
        .json()
        .await?;

    // Build a map: pubkey → canonical JSON bytes (the message that was signed)
    let mut vertex_messages: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
    if let Some(arr) = vertices.as_array() {
        for v in arr {
            let author = v["author"].as_str().unwrap_or("");
            let round = v["round"].as_u64().unwrap_or(0);
            let timestamp = v["timestamp"].as_u64().unwrap_or(0);

            // Reconstruct sorted event_hashes and refs arrays
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

            // Canonical JSON must match JS key order exactly:
            // JSON.stringify({ author, round, event_hashes: sorted, refs: sorted, timestamp })
            // serde_json::json! uses BTreeMap (alphabetical), so we manually construct the string.
            let eh_json = serde_json::to_string(&event_hashes).unwrap_or("[]".into());
            let refs_json = serde_json::to_string(&refs).unwrap_or("[]".into());
            let canonical = format!(
                r#"{{"author":"{}","round":{},"event_hashes":{},"refs":{},"timestamp":{}}}"#,
                author, round, eh_json, refs_json, timestamp,
            );
            vertex_messages.insert(author.to_string(), canonical.into_bytes());
        }
    }

    // Also try the block response itself if it contains vertex data
    if vertex_messages.is_empty() {
        if let Some(arr) = block["vertices"].as_array() {
            for v in arr {
                let author = v["author"].as_str().unwrap_or("");
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
                let refs_json_str = serde_json::to_string(&refs).unwrap_or("[]".into());
                let canonical = format!(
                    r#"{{"author":"{}","round":{},"event_hashes":{},"refs":{},"timestamp":{}}}"#,
                    author, round, eh_json, refs_json_str, timestamp,
                );
                vertex_messages.insert(author.to_string(), canonical.into_bytes());
            }
        }
    }

    // Extract signatures with per-vertex messages
    let signatures = extract_signatures_with_messages(&block, &vertex_messages);

    // Extract mutations (state changes in this block)
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
                // Look up the canonical JSON message this validator signed
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

fn hex_to_bytes32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Ok(bytes) = hex::decode(hex) {
        let len = bytes.len().min(32);
        out[..len].copy_from_slice(&bytes[..len]);
    }
    out
}

fn hex_to_bytes64(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap_or_else(|_| vec![0u8; 64])
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
/// For recursive verification, the guest program reads:
///   1. The input (StateTransitionInput with recursive=true)
///   2. The vkey digest ([u32; 8])
///   3. The public values digest ([u8; 32])
/// And then the SP1 runtime internally provides the proof via write_proof.
fn prepare_stdin_with_proof(
    input: &StateTransitionInput,
    prev_proof: Option<&SP1ProofWithPublicValues>,
    vk: &sp1_sdk::SP1VerifyingKey,
) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(input);

    if let Some(prev) = prev_proof {
        // Write vkey digest and pv digest for the guest to read
        let vk_digest: [u32; 8] = vk.hash_u32();
        let pv_hash = prev.public_values.hash();
        let mut pv_digest = [0u8; 32];
        let len = pv_hash.len().min(32);
        pv_digest[..len].copy_from_slice(&pv_hash[..len]);

        stdin.write(&vk_digest);
        stdin.write(&pv_digest);

        // Extract the inner compressed proof and stark vk for write_proof.
        // write_proof expects SP1ReduceProof<InnerSC> and StarkVerifyingKey<CoreSC>.
        if let SP1Proof::Compressed(ref reduce_proof) = prev.proof {
            stdin.write_proof(*reduce_proof.clone(), vk.vk.clone());
        }
    }

    stdin
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Execute { node, block } => {
            println!("Fetching block {} from {}", block, node);
            let input = fetch_block_input(&node, block, false, None).await?;

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
            // Load previous proof if provided (for recursive IVC chain)
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
                fetch_block_input(&node, block, recursive, prev.as_ref()).await?;

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
        } => {
            std::fs::create_dir_all(&proof_dir)?;
            println!("Watching {} for new blocks (every {}s)", node, interval);
            println!("Proofs will be saved to {:?}", proof_dir);
            println!("Recursive mode: each proof verifies the previous one (IVC chain)");

            let client = ProverClient::from_env();
            let (pk, vk) = client.setup(ELF);
            let mut last_proven_block: u64 = 0;
            let mut last_proof: Option<SP1ProofWithPublicValues> = None;

            // Check for existing proofs to resume from
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
                        Err(e) => {
                            eprintln!("Warning: could not load proof at {:?}: {}", path, e);
                        }
                    }
                }
            }

            loop {
                // Check latest committed round
                let status_result: Result<serde_json::Value, anyhow::Error> = async {
                    Ok(reqwest::get(format!("{}/dag/status", node))
                        .await?
                        .json()
                        .await?)
                }.await;
                let status = match status_result {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("  Network error fetching status: {} — retrying", e);
                        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                        continue;
                    }
                };

                let latest = status["last_committed_round"].as_u64().unwrap_or(0);

                if latest > last_proven_block {
                    // For genesis (no previous proof), start from latest committed round.
                    // For recursive, find the next committed round after last_proven_block.
                    // Not all rounds are committed in Bullshark DAG (gaps are normal).
                    let target = if last_proof.is_none() && last_proven_block == 0 {
                        latest
                    } else {
                        // Find next committed round (not all rounds commit in Bullshark DAG)
                        match async {
                            let r: serde_json::Value = reqwest::get(
                                format!("{}/dag/next_committed?after={}", node, last_proven_block)
                            ).await?.json().await?;
                            Ok::<u64, anyhow::Error>(r["round"].as_u64().unwrap_or(latest))
                        }.await {
                            Ok(r) => r,
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
                        target,
                        latest,
                        if recursive { " — chaining recursively" } else { " — genesis proof" }
                    );

                    match fetch_block_input(&node, target, recursive, last_proof.as_ref()).await {
                        Ok(input) => {
                            let stdin = prepare_stdin_with_proof(&input, last_proof.as_ref(), &vk);

                            match client.prove(&pk, &stdin).compressed().run() {
                                Ok(proof) => {
                                    if let Err(e) = client.verify(&proof, &vk) {
                                        eprintln!("  Verification failed for block {}: {}", target, e);
                                        continue;
                                    }

                                    let path = proof_dir.join(format!("block_{}.proof", target));
                                    if let Err(e) = save_proof(&path, &proof) {
                                        eprintln!("  Failed to save proof: {}", e);
                                        continue;
                                    }

                                    let result: StateTransitionOutput =
                                        bincode::deserialize(proof.public_values.as_slice())?;

                                    println!(
                                        "  Block {} proven — root: {} | chain: {} blocks | {} bytes",
                                        target,
                                        hex::encode(result.state_root),
                                        result.proven_blocks,
                                        std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0),
                                    );

                                    // Post proof metadata to node (proof hash, not full blob)
                                    let proof_bytes = bincode::serialize(&proof).unwrap_or_default();
                                    let proof_hash = hex::encode(
                                        sha2::Sha256::digest(&proof_bytes)
                                    );
                                    let http = reqwest::Client::new();
                                    match http
                                        .post(format!("{}/proof/zk/submit", node))
                                        .json(&serde_json::json!({
                                            "block_number": target,
                                            "proof": proof_hash,
                                            "state_root": hex::encode(result.state_root),
                                            "proven_blocks": result.proven_blocks,
                                            "proof_type": "compressed",
                                        }))
                                        .send()
                                        .await
                                    {
                                        Ok(resp) => {
                                            if !resp.status().is_success() {
                                                eprintln!("  Warning: proof submit HTTP {}", resp.status());
                                            }
                                        }
                                        Err(e) => eprintln!("  Warning: proof submit failed: {}", e),
                                    }

                                    // Update state for next recursive proof
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
    }

    Ok(())
}
