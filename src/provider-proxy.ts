// ─── Provider Proxy ──────────────────────────────────────────────────────────────
// Routes AI service requests to external providers with automatic failover.
// Tries providers cheapest-first, marks down on failure, retries next.
// Falls back to local Workers AI if all external providers fail.
//
// Pattern from apimarket's proxy.js: stateless routing with sequential failover.

import type { ProviderRegistry, ProviderRecord } from "./provider-registry";
import type { ServiceAttestationManager } from "./service-attestations";
import type { SettlementBatcher } from "./settlement";

// ─── Configuration ──────────────────────────────────────────────────────────

const PROXY_TIMEOUT_MS = 30_000;         // 30s timeout per provider attempt
const MAX_RETRIES = 3;                    // max providers to try before falling back

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ProxyResult {
  response: Response;
  provider: ProviderRecord | null;       // null = served by local Workers AI
  attempts: number;
  source: "external" | "local";
}

// ─── Provider Proxy ─────────────────────────────────────────────────────────

export class ProviderProxy {
  private registry: ProviderRegistry;
  private settler: SettlementBatcher;
  private attestationMgr: ServiceAttestationManager | null;

  constructor(
    registry: ProviderRegistry,
    settler: SettlementBatcher,
    attestationMgr: ServiceAttestationManager | null,
  ) {
    this.registry = registry;
    this.settler = settler;
    this.attestationMgr = attestationMgr;
  }

  /**
   * Route a service request to the best available external provider.
   * Tries cheapest first with failover. Returns null if no external provider available.
   */
  async routeToProvider(params: {
    serviceType: string;
    model: string;
    requestBody: string;
    buyerAddress: string;
  }): Promise<ProxyResult | null> {
    const providers = this.registry.getActive(params.serviceType, params.model);
    if (providers.length === 0) return null;

    let attempts = 0;
    const maxAttempts = Math.min(providers.length, MAX_RETRIES);

    for (let i = 0; i < maxAttempts; i++) {
      const provider = providers[i];
      attempts++;

      try {
        const response = await this.forwardToProvider(provider, params.serviceType, params.requestBody);

        if (response.ok) {
          // Mark provider healthy
          this.registry.markHealthy(provider.provider_id);

          // Record settlement (non-blocking)
          const shouldFlush = this.settler.record(
            params.buyerAddress,
            provider.provider_id,
            provider.price,
          );

          // Create attestation for the external response
          if (this.attestationMgr) {
            try {
              const preCommit = await this.attestationMgr.preCommit(
                params.serviceType, params.model, params.requestBody,
              );
              const clone = response.clone();
              const outputBytes = await clone.arrayBuffer();
              const attestation = await this.attestationMgr.attest({
                service: params.serviceType,
                model: params.model,
                input_hash: preCommit.input_hash,
                output_bytes: new Uint8Array(outputBytes),
                pre_commitment: preCommit.pre_commitment,
                nonce: preCommit.nonce,
              });

              // Attach attestation + provider metadata to response
              const attested = new Response(response.body, response);
              attested.headers.set("X-Attestation-Id", attestation.attestation_id);
              attested.headers.set("X-Provider-Id", provider.provider_id);
              attested.headers.set("X-Provider-Price", provider.price.toString());
              attested.headers.set("X-Provider-Source", "external");

              return { response: attested, provider, attempts, source: "external" };
            } catch {
              // Attestation failed — still return the response
            }
          }

          // No attestation — just attach provider metadata
          const tagged = new Response(response.body, response);
          tagged.headers.set("X-Provider-Id", provider.provider_id);
          tagged.headers.set("X-Provider-Price", provider.price.toString());
          tagged.headers.set("X-Provider-Source", "external");

          return { response: tagged, provider, attempts, source: "external" };
        }

        // Non-OK response — mark failure and try next
        this.registry.markFailed(provider.provider_id);

      } catch (e) {
        // Network error / timeout — mark failure and try next
        this.registry.markFailed(provider.provider_id);
      }
    }

    // All external providers failed
    return null;
  }

  /**
   * Forward a request to an external provider endpoint.
   * Expects OpenAI-compatible /v1/chat/completions or similar.
   */
  private async forwardToProvider(
    provider: ProviderRecord,
    serviceType: string,
    requestBody: string,
  ): Promise<Response> {
    // Map service types to standard API paths
    const pathMap: Record<string, string> = {
      llm: "/v1/chat/completions",
      code: "/v1/chat/completions",
      embed: "/v1/embeddings",
      tts: "/v1/audio/speech",
      stt: "/v1/audio/transcriptions",
      image: "/v1/images/generations",
      translate: "/v1/translate",
      summarize: "/v1/summarize",
      classify: "/v1/classify",
      vision: "/v1/chat/completions",
    };

    const path = pathMap[serviceType] || `/v1/${serviceType}`;
    const url = new URL(path, provider.endpoint_url).toString();

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), PROXY_TIMEOUT_MS);

    try {
      return await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: requestBody,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Get proxy stats.
   */
  getStats(): {
    external_providers: number;
    available_models: number;
    pending_settlements: number;
    pending_settlement_amount: bigint;
  } {
    const providerStats = this.registry.getStats();
    return {
      external_providers: providerStats.active_providers,
      available_models: providerStats.total_models,
      pending_settlements: this.settler.getPendingCount(),
      pending_settlement_amount: this.settler.getPendingAmount(),
    };
  }
}
