// ─── Service Federation ─────────────────────────────────────────────────────────
// Pools validator compute resources for multi-node AI service execution.
//
// Three execution modes:
//   1. Solo:     Single node executes (current behavior, no gossip needed)
//   2. Verified: Request gossiped to N peers, each executes independently,
//                ≥ min_responses must agree on output_hash for quorum
//   3. Parallel: Batchable work split across validators, results recombined
//
// Flow (verified mode):
//   Client → Node A (originator):
//     1. Pre-commit + execute locally
//     2. Gossip service_request to peers
//     3. Peers execute, gossip service_response back
//     4. Originator collects responses, checks output_hash agreement
//     5. If quorum met → return result with multi-node attestation
//     6. If quorum fails → return solo result with warning

import { sha256 } from "./consensus";
import type { GossipManager, ServiceRequestPayload, ServiceResponsePayload } from "./gossip";
import type { ValidatorRegistry } from "./validator-registry";

// ─── Configuration ──────────────────────────────────────────────────────────

const REQUEST_TIMEOUT_MS = 30_000;       // max time to wait for peer responses
const MIN_FEDERATION_NODES = 2;          // need at least 2 nodes for verified mode
const MAX_PENDING_REQUESTS = 100;        // prevent memory bloat
const RESPONSE_CLEANUP_MS = 60_000;      // purge stale pending requests

// ─── Types ────────────────────────────────────────────────────────────────────

export type FederationMode = "solo" | "verified" | "parallel";

export interface FederationRequest {
  request_id: string;
  service: string;
  model: string;
  input_hash: string;
  input_body_b64: string;
  mode: FederationMode;
  originator_pubkey: string;
  min_responses: number;
  created_at: number;
  expires_at: number;
  local_output_hash: string | null;
  local_attestation_id: string | null;
  responses: Map<string, ServiceResponsePayload>;  // pubkey → response
  resolve: ((result: FederationResult) => void) | null;
  timeout: ReturnType<typeof setTimeout> | null;
}

export interface FederationResult {
  mode: FederationMode;
  request_id: string;
  agreed: boolean;                       // true if quorum met on output_hash
  output_hash: string;                   // the agreed-upon hash (or local if solo/no-quorum)
  participating_nodes: string[];         // pubkeys of all nodes that responded
  agreeing_nodes: string[];              // pubkeys that agreed with the majority
  attestation_ids: string[];             // all attestation IDs from participating nodes
  total_responses: number;
  required_responses: number;
}

// ─── ServiceFederation ──────────────────────────────────────────────────────

export class ServiceFederation {
  private gossip: GossipManager;
  private validators: ValidatorRegistry;
  private selfPubkey: string;
  private selfUrl: string;
  private pending: Map<string, FederationRequest> = new Map();

  constructor(
    gossip: GossipManager,
    validators: ValidatorRegistry,
    selfPubkey: string,
    selfUrl: string,
  ) {
    this.gossip = gossip;
    this.validators = validators;
    this.selfPubkey = selfPubkey;
    this.selfUrl = selfUrl;
  }

  // ─── Originator Side ──────────────────────────────────────────────────

  /**
   * Initiate a federated service request. Returns a promise that resolves
   * when quorum is reached or timeout expires.
   */
  async initiateRequest(params: {
    service: string;
    model: string;
    inputBodyB64: string;
    mode: FederationMode;
    localOutputHash: string;
    localAttestationId: string;
  }): Promise<FederationResult> {
    // Check if federation is possible
    const activeCount = this.validators.getActiveCount();
    if (params.mode !== "solo" && activeCount < MIN_FEDERATION_NODES) {
      // Not enough nodes — fall back to solo
      return this.soloResult(params.localOutputHash, params.localAttestationId);
    }

    if (params.mode === "solo") {
      return this.soloResult(params.localOutputHash, params.localAttestationId);
    }

    // Evict stale pending requests
    this.cleanup();

    if (this.pending.size >= MAX_PENDING_REQUESTS) {
      return this.soloResult(params.localOutputHash, params.localAttestationId);
    }

    const request_id = await sha256(`fed:${this.selfPubkey}:${Date.now()}:${Math.random()}`);
    const input_hash = await sha256(params.inputBodyB64);
    const min_responses = Math.max(2, Math.ceil(activeCount * 2 / 3));
    const expires_at = Date.now() + REQUEST_TIMEOUT_MS;

    const fedReq: FederationRequest = {
      request_id,
      service: params.service,
      model: params.model,
      input_hash,
      input_body_b64: params.inputBodyB64,
      mode: params.mode,
      originator_pubkey: this.selfPubkey,
      min_responses,
      created_at: Date.now(),
      expires_at,
      local_output_hash: params.localOutputHash,
      local_attestation_id: params.localAttestationId,
      responses: new Map(),
      resolve: null,
      timeout: null,
    };

    // Count ourselves as a response
    fedReq.responses.set(this.selfPubkey, {
      request_id,
      responder_pubkey: this.selfPubkey,
      output_hash: params.localOutputHash,
      attestation_id: params.localAttestationId,
      timestamp: Date.now(),
    });

    this.pending.set(request_id, fedReq);

    // Gossip the request to peers
    const gossipPayload: ServiceRequestPayload = {
      request_id,
      service: params.service,
      model: params.model,
      input_hash,
      input_body_b64: params.inputBodyB64,
      mode: params.mode === "parallel" ? "parallel" : "verified",
      originator_pubkey: this.selfPubkey,
      originator_url: this.selfUrl,
      min_responses,
      expires_at,
    };

    const envelope = await this.gossip.createEnvelope("service_request", gossipPayload);
    if (envelope) {
      this.gossip.flood(envelope).catch(() => {});
    }

    // Wait for responses or timeout
    return new Promise<FederationResult>((resolve) => {
      fedReq.resolve = resolve;
      fedReq.timeout = setTimeout(() => {
        this.finalizeRequest(request_id);
      }, REQUEST_TIMEOUT_MS);
    });
  }

  // ─── Responder Side ───────────────────────────────────────────────────

  /**
   * Handle an incoming service_request from a peer.
   * Returns the request payload if this node should execute it, null if not.
   */
  shouldHandleRequest(payload: ServiceRequestPayload): boolean {
    // Don't handle our own requests
    if (payload.originator_pubkey === this.selfPubkey) return false;

    // Check expiry
    if (Date.now() > payload.expires_at) return false;

    // Check if we're an active validator
    const self = this.validators.getValidator(this.selfPubkey);
    if (!self || self.status !== "active") return false;

    return true;
  }

  /**
   * After executing a federated request locally, send the response back
   * to the originator via gossip.
   */
  async sendResponse(params: {
    request_id: string;
    output_hash: string;
    output_body_b64?: string;
    attestation_id: string;
  }): Promise<void> {
    const responsePayload: ServiceResponsePayload = {
      request_id: params.request_id,
      responder_pubkey: this.selfPubkey,
      output_hash: params.output_hash,
      output_body_b64: params.output_body_b64,
      attestation_id: params.attestation_id,
      timestamp: Date.now(),
    };

    const envelope = await this.gossip.createEnvelope("service_response", responsePayload);
    if (envelope) {
      this.gossip.flood(envelope).catch(() => {});
    }
  }

  // ─── Response Collection (Originator) ─────────────────────────────────

  /**
   * Handle an incoming service_response. If quorum is reached, resolve the
   * pending promise immediately.
   */
  handleResponse(payload: ServiceResponsePayload): void {
    const fedReq = this.pending.get(payload.request_id);
    if (!fedReq) return;

    // Don't accept duplicate responses from the same node
    if (fedReq.responses.has(payload.responder_pubkey)) return;

    // Validate the responder is an active validator
    const validator = this.validators.getValidator(payload.responder_pubkey);
    if (!validator || validator.status !== "active") return;

    fedReq.responses.set(payload.responder_pubkey, payload);

    // Check if we've reached quorum
    if (this.checkQuorum(fedReq)) {
      this.finalizeRequest(payload.request_id);
    }
  }

  // ─── Quorum Logic ─────────────────────────────────────────────────────

  private checkQuorum(fedReq: FederationRequest): boolean {
    // Count votes per output_hash
    const hashVotes = new Map<string, number>();
    for (const resp of fedReq.responses.values()) {
      const count = (hashVotes.get(resp.output_hash) || 0) + 1;
      hashVotes.set(resp.output_hash, count);
      if (count >= fedReq.min_responses) return true;
    }
    return false;
  }

  private finalizeRequest(requestId: string): void {
    const fedReq = this.pending.get(requestId);
    if (!fedReq || !fedReq.resolve) return;

    // Clear timeout
    if (fedReq.timeout) clearTimeout(fedReq.timeout);

    // Find the majority output_hash
    const hashVotes = new Map<string, string[]>();
    for (const [pubkey, resp] of fedReq.responses) {
      const voters = hashVotes.get(resp.output_hash) || [];
      voters.push(pubkey);
      hashVotes.set(resp.output_hash, voters);
    }

    let majorityHash = fedReq.local_output_hash || "";
    let majorityVoters: string[] = [];
    for (const [hash, voters] of hashVotes) {
      if (voters.length > majorityVoters.length) {
        majorityHash = hash;
        majorityVoters = voters;
      }
    }

    const allNodes = Array.from(fedReq.responses.keys());
    const allAttestations = Array.from(fedReq.responses.values()).map(r => r.attestation_id);

    const result: FederationResult = {
      mode: fedReq.mode,
      request_id: requestId,
      agreed: majorityVoters.length >= fedReq.min_responses,
      output_hash: majorityHash,
      participating_nodes: allNodes,
      agreeing_nodes: majorityVoters,
      attestation_ids: allAttestations,
      total_responses: fedReq.responses.size,
      required_responses: fedReq.min_responses,
    };

    fedReq.resolve(result);
    fedReq.resolve = null;
    this.pending.delete(requestId);
  }

  private soloResult(outputHash: string, attestationId: string): FederationResult {
    return {
      mode: "solo",
      request_id: "",
      agreed: true,
      output_hash: outputHash,
      participating_nodes: [this.selfPubkey],
      agreeing_nodes: [this.selfPubkey],
      attestation_ids: [attestationId],
      total_responses: 1,
      required_responses: 1,
    };
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [id, req] of this.pending) {
      if (now - req.created_at > RESPONSE_CLEANUP_MS) {
        if (req.resolve) this.finalizeRequest(id);
        else this.pending.delete(id);
      }
    }
  }

  // ─── Queries ──────────────────────────────────────────────────────────

  getPendingCount(): number {
    return this.pending.size;
  }

  getStats(): { pending: number; active_nodes: number; federation_capable: boolean } {
    return {
      pending: this.pending.size,
      active_nodes: this.validators.getActiveCount(),
      federation_capable: this.validators.getActiveCount() >= MIN_FEDERATION_NODES,
    };
  }
}
