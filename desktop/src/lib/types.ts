export interface DagStatus {
  current_round: number;
  last_committed_round: number;
  finalized_seq: number;
  active_nodes: number;
  pending_events: number;
  max_events_per_vertex: number;
  round_interval_ms: number;
  adaptive?: {
    enabled: boolean;
    prover_lag: number;
    consecutive_empty_rounds: number;
  };
}

export interface ZkStatus {
  total_proofs: number;
  latest_proven_block: number;
  last_committed_round: number;
  proof_gap: number;
  max_chain_length: number;
  active_lineage?: {
    chain_length: number;
    last_block: number;
    gap: number;
    genesis_root: string;
  };
}

export interface Peer {
  id: string;
  url: string;
  pubkey: string;
  last_seen: string;
  last_vertex_round: number;
}

export interface ProofEntry {
  block_number: number;
  state_root: string;
  proven_blocks: number;
  proof_type: string;
  submitted_at: string;
  genesis_root: string;
  prover?: string;
}

export interface AnchorStatus {
  bundle?: {
    last_committed_round: number;
    status: string;
  };
}

export interface ProcessStatus {
  running: boolean;
  pid: number | null;
  mode: string | null;
  uptime_secs: number | null;
}

export interface AppConfig {
  node_url: string;
  shard: string;
  prover_mode: string;
  prover_interval: number;
  prover_workers: number;
  prover_native: boolean;
  prover_recursive: boolean;
  generator_agents: number;
  generator_interval: number;
}

export interface GpuInfo {
  bb_available: boolean;
  bb_version: string | null;
  metal_msm_available: boolean;
  gpu_name: string | null;
  unified_memory: boolean | null;
}

export interface ResourcePaths {
  node_bin: string;
  bb_bin: string;
  circuits_dir: string;
  prover_dir: string;
  scripts_dir: string;
}
