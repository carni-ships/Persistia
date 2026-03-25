// ─── Shared Types ─────────────────────────────────────────────────────────────

export interface SignedEvent {
  type: string;
  payload: any;
  pubkey: string;    // base64 of raw Ed25519 public key (32 bytes)
  signature: string; // base64 of Ed25519 signature (64 bytes)
  timestamp: number;
}

export interface StoredEvent extends SignedEvent {
  seq: number;
  hash: string;
}

export interface DAGVertex {
  author: string;         // node pubkey (base64)
  round: number;
  event_hashes: string[]; // hashes of events bundled in this vertex
  events: SignedEvent[];   // the actual events
  refs: string[];          // hashes of parent vertices (round r-1)
  timestamp: number;
  signature: string;       // Ed25519 over canonical vertex content
}

export interface StoredVertex extends DAGVertex {
  hash: string;            // SHA-256 of canonical content
}

export interface CommitInfo {
  round: number;
  anchor_hash: string;
  committed_at: number;
}

export interface NodeInfo {
  pubkey: string;
  url: string;
  last_vertex_round: number;
  last_seen: number;
  is_self: boolean;
}

export interface ConsensusStatus {
  node_pubkey: string;
  current_round: number;
  finalized_seq: number;
  finalized_root: string;
  last_committed_round: number;
  active_nodes: number;
  pending_events: number;
}

// ─── Contract Types ──────────────────────────────────────────────────────────

export interface ContractInfo {
  address: string;
  deployer: string;
  wasm_hash: string;
  created_at: number;
  deploy_seq: number;
}

export interface ContractCallResult {
  ok: boolean;
  return_data?: string;  // base64-encoded
  logs: string[];
  error?: string;
}

// ─── Oracle Types ────────────────────────────────────────────────────────────

export interface OracleRequestInfo {
  id: string;
  contract: string;
  callback_method: string;
  url: string;
  json_path?: string;
  aggregation: "identical" | "median" | "majority";
  status: "pending" | "fetching" | "aggregating" | "delivered" | "failed";
  created_at: number;
  result_value?: string;
  result_sources?: number;
  delivered_at?: number;
}

// ─── Gossip Types ───────────────────────────────────────────────────────

export interface GossipPeerInfo {
  pubkey: string;
  url: string;
  last_seen: number;
  failures: number;
}

// ─── Anchor Types ───────────────────────────────────────────────────────

export interface AnchorInfo {
  id: string;
  state_root: string;
  finalized_seq: number;
  last_committed_round: number;
  arweave_tx?: string;
  celestia_height?: number;
  status: string;
  timestamp: number;
}

// ─── Trigger Types ───────────────────────────────────────────────────────────

export interface TriggerInfo {
  id: string;
  contract: string;
  method: string;
  args_b64: string;
  interval_ms: number;
  next_fire: number;
  creator: string;
  enabled: boolean;
  created_at: number;
  last_fired: number;
  fire_count: number;
  max_fires: number;
}

// ─── Wallet Types ───────────────────────────────────────────────────────────

export interface WalletAccount {
  address: string;         // persistia1... (Bech32)
  pubkey: string;          // base64 Ed25519 public key
  key_type: "ed25519" | "secp256k1";
  nonce: number;
  created_at: number;
}

export interface TokenTransfer {
  from: string;            // Bech32 address
  to: string;              // Bech32 address
  denom: string;
  amount: string;          // stringified bigint
}
