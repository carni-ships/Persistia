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
  schnorr_sig?: {          // Schnorr-on-Grumpkin signature for ZK proving
    schnorr_s: string;     // hex-encoded 32 bytes
    schnorr_e: string;     // hex-encoded 32 bytes
    grumpkin_x: string;    // hex-encoded Grumpkin pubkey x
    grumpkin_y: string;    // hex-encoded Grumpkin pubkey y
  };
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
  berachain_tx?: string;
  berachain_block?: number;
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

// ─── Oracle Network Types ───────────────────────────────────────────────────

export type OracleFeedCategory = "price" | "random" | "data" | "cross_chain";
export type OracleFeedStatus = "active" | "paused" | "stale";
export type OracleAggregation = "weighted_median" | "identical" | "median" | "majority";

export interface FeedSource {
  type: "http" | "chainlink" | "pyth" | "redstone" | "redstone_bolt" | "coingecko" | "binance";
  endpoint: string;       // URL, contract address, or price ID
  json_path?: string;     // for HTTP type
  weight: number;         // 1-10, influences weighted median
  rpc_url?: string;       // for chainlink (Ethereum/Berachain RPC)
}

export interface OracleFeedConfig {
  id: string;                            // e.g., "BTC/USD"
  description: string;
  decimals: number;
  heartbeat_ms: number;
  deviation_bps: number;                 // 50 = 0.5%
  aggregation: OracleAggregation;
  sources: FeedSource[];
  status: OracleFeedStatus;
  category: OracleFeedCategory;
  created_at: number;
  updated_at: number;
  current_round: number;
}

export interface FeedRound {
  feed_id: string;
  round: number;
  value: string;
  value_num: number | null;
  observers: number;
  observations_hash: string;
  committed_at: number;
}

export interface OracleObservation {
  feed_id: string;
  round: number;
  observer: string;
  value: string;
  value_num: number | null;
  observed_at: number;
}

export interface OracleObservationBatch {
  observer: string;
  round_timestamp: number;
  observations: OracleObservation[];
  signature: string;
}

export interface OracleSubscription {
  id: string;
  feed_id: string;
  contract: string;
  callback_method: string;
  deviation_bps: number;
  min_interval_ms: number;
  last_delivered_at: number;
  last_delivered_value: string | null;
  enabled: boolean;
  created_at: number;
}

export interface VRFRequest {
  id: string;
  seed: string;
  contract: string;
  callback_method: string;
  round: number;
  status: "pending" | "collecting" | "delivered" | "failed";
  result: string | null;
  created_at: number;
  delivered_at: number | null;
}

export interface VRFPartial {
  request_id: string;
  validator: string;
  partial_sig: string;
  created_at: number;
}

export interface MirrorResult {
  value: number;
  decimals: number;
  source_ts: number;
}

export interface FeedLatest {
  feed_id: string;
  value: string;
  value_num: number | null;
  round: number;
  observers: number;
  committed_at: number;
  stale: boolean;
}

// ─── Feed Demand Map Types ──────────────────────────────────────────────────

export interface FeedDemand {
  feed_id: string;
  read_count: number;       // pull reads since last gossip
  subscription_count: number; // active push subscriptions
  last_active: number;      // timestamp of last consumer interaction
}

export interface FeedDemandMap {
  demands: FeedDemand[];
  sender: string;           // validator pubkey
  timestamp: number;
}

// ─── Validator Blackboard Types ─────────────────────────────────────────────

export interface BlackboardItem {
  id: string;               // unique ID (timestamp-based)
  author: string;           // validator pubkey
  prefix: "STATUS" | "ALERT" | "DEBUG" | "FINDING" | "TIP";
  text: string;
  timestamp: number;
  expires_at: number;       // timestamp for TTL expiry
}

export interface BlackboardDigest {
  item_ids: string[];
  sender: string;
}

// ─── Feed Leader Election Types ─────────────────────────────────────────────

export interface FeedLeaderAssignment {
  feed_id: string;
  leader_pubkey: string;
  epoch: number;            // changes on validator set change
}

// ─── Source Scoring Types ───────────────────────────────────────────────────

export interface SourceStats {
  feed_id: string;
  source_index: number;     // index in feed's sources array
  source_type: string;
  success_count: number;
  failure_count: number;
  total_latency_ms: number; // cumulative, divide by success_count for avg
  last_success: number;
  last_failure: number;
  avg_freshness_ms: number; // avg age of source_ts relative to fetch time
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

// ─── Fraud Proof Types ──────────────────────────────────────────────────────

export type ChallengeStatus =
  | "open"          // challenge window active, no challenge yet
  | "challenged"    // challenge submitted, awaiting response
  | "finalized"     // unchallenged, window expired
  | "resolved_valid"   // ZK proof confirmed proposer correct, challenger slashed
  | "resolved_fraud"   // fraud confirmed, proposer slashed
  | "timeout"          // proposer failed to respond, treated as fraud

export interface ChallengeWindow {
  block_number: number;
  proposer: string;          // pubkey of anchor vertex author
  post_state_root: string;
  expires_at_round: number;
  status: ChallengeStatus;
}

export interface ChallengeRecord {
  id: string;
  block_number: number;
  challenger: string;        // pubkey
  bond_hold_id: string;
  claimed_invalid_root: string | null;  // challenger's computed post-state root (if different)
  response_deadline_round: number;
  status: ChallengeStatus;
  created_at: number;
  resolved_at: number | null;
  resolution_proof_hash: string | null;
  resolution_type: "zk_proof" | "timeout" | "withdrawn" | null;
}

export interface ChallengeWitness {
  block_number: number;
  prev_state_root: string;
  post_state_root: string;
  events: SignedEvent[];
  event_hashes: string[];
  mutations: { key: string; old_value: string | null; new_value: string | null }[];
  commit_signatures: { pubkey: string; signature: string; message: string }[];
  active_nodes: number;
  prev_header_hash: string;
  validator_set_hash: string;
}
