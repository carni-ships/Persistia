// ─── Node Capability Manifest ────────────────────────────────────────────────
// Every node in the Persistia network advertises what it can do.
// Heterogeneous nodes (CF Workers, Oracle Cloud VMs, AWS t2.micro, etc.)
// have different capabilities — the manifest lets the network route work
// to the right node type.
//
// The manifest is included in gossip peer exchange and stored per-peer
// so that any node can answer: "who can run LLM inference?" or
// "who has GPU compute?" without asking everyone.

// ─── Types ───────────────────────────────────────────────────────────────────

export type RuntimeType =
  | "cloudflare-worker"    // CF Workers + Durable Objects
  | "standalone-express"   // Express + SQLite on bare VM
  | "docker"               // Containerized (Railway, Fly, etc.)
  | "serverless"           // Lambda, GCF, Azure Functions
  | "custom";              // Anything else

export type CapabilityFlag =
  | "consensus"            // Can participate in BFT consensus (create vertices, vote)
  | "gossip"               // Can relay gossip messages
  | "inference-local"      // Has local AI inference (Workers AI, Ollama, vLLM, etc.)
  | "inference-pool"       // Has inference pool (routes to free-tier providers)
  | "inference-gpu"        // Has GPU for inference (CUDA, ROCm, Metal)
  | "zk-prove"             // Can generate ZK proofs (needs 4GB+ RAM)
  | "wasm-exec"            // Can execute WASM smart contracts
  | "oracle"               // Can fetch oracle feeds
  | "storage"              // Has persistent storage (SQLite, R2, etc.)
  | "websocket"            // Can serve WebSocket connections
  | "browser-render"       // Has headless browser (CF Browser Rendering)
  | "relay"                // Can relay cross-shard messages
  | "snapshot"             // Can serve state snapshots for new nodes
  | "anchor"               // Can post DA anchors (Celestia, Arweave)
  | "tts"                  // Text-to-speech capability
  | "stt"                  // Speech-to-text capability
  | "image-gen"            // Image generation capability
  | "embeddings";          // Vector embeddings capability

export interface InferenceCapability {
  provider: string;         // "workers-ai", "ollama", "vllm", "inference-pool"
  models: string[];         // available model IDs or abstract names
  max_tokens?: number;      // max context/output
  gpu?: string;             // GPU type if applicable ("T4", "A10G", "M1-Metal", etc.)
  vram_mb?: number;         // GPU VRAM in MB
  tps?: number;             // estimated tokens per second
}

export interface ResourceLimits {
  cpu_cores?: number;       // available CPU cores
  ram_mb?: number;          // available RAM in MB
  storage_gb?: number;      // available storage in GB
  bandwidth_gb?: number;    // monthly bandwidth in GB
  max_request_ms?: number;  // max request duration (e.g. 30s for CF Workers)
  requests_per_day?: number; // daily request limit
}

export interface NodeManifest {
  // Identity
  pubkey: string;            // Ed25519 public key (base64)
  url: string;               // Public HTTP endpoint
  version: string;           // Node software version

  // Runtime
  runtime: RuntimeType;
  platform: string;          // "cloudflare", "oracle-arm", "aws-x86", "gcp-e2", etc.
  region?: string;           // Geographic region hint

  // Capabilities
  capabilities: CapabilityFlag[];
  inference?: InferenceCapability[];

  // Resources
  resources?: ResourceLimits;

  // Liveness
  uptime_secs?: number;      // seconds since last restart
  last_heartbeat: number;    // unix timestamp of last manifest broadcast
  manifest_version: number;  // increment on any manifest change (monotonic)
}

// ─── Manifest Builder ────────────────────────────────────────────────────────

export function buildCloudflareManifest(
  pubkey: string,
  url: string,
  opts?: {
    hasAI?: boolean;
    hasBrowser?: boolean;
    hasR2?: boolean;
    hasQueue?: boolean;
    inferencePoolModels?: string[];
  },
): NodeManifest {
  const caps: CapabilityFlag[] = [
    "consensus", "gossip", "storage", "websocket", "relay", "snapshot", "oracle",
  ];

  const inference: InferenceCapability[] = [];

  if (opts?.hasAI) {
    caps.push("inference-local", "tts", "stt", "image-gen", "embeddings");
    inference.push({
      provider: "workers-ai",
      models: [
        "llama-3.3-70b", "qwen3-30b", "deepseek-r1-32b", "mistral-7b",
        "llama-3.2-3b", "gemma-3-12b",
      ],
      max_tokens: 4096,
      tps: 40, // estimated for Workers AI
    });
  }

  if (opts?.inferencePoolModels && opts.inferencePoolModels.length > 0) {
    caps.push("inference-pool");
    inference.push({
      provider: "inference-pool",
      models: opts.inferencePoolModels,
      max_tokens: 4096,
    });
  }

  if (opts?.hasBrowser) {
    caps.push("browser-render");
  }

  // CF Workers can execute WASM
  caps.push("wasm-exec");

  return {
    pubkey,
    url,
    version: "0.5.0",
    runtime: "cloudflare-worker",
    platform: "cloudflare",
    capabilities: caps,
    inference,
    resources: {
      cpu_cores: 1,             // CF Workers are single-threaded
      ram_mb: 128,              // 128MB limit per Worker
      max_request_ms: 30_000,   // 30s CPU time limit
      requests_per_day: 100_000, // free tier
    },
    last_heartbeat: Date.now(),
    manifest_version: 1,
  };
}

export function buildStandaloneManifest(
  pubkey: string,
  url: string,
  opts: {
    platform: string;         // "oracle-arm", "aws-x86", "azure-b1s", "bare-metal", etc.
    region?: string;
    cpuCores?: number;
    ramMb?: number;
    storageGb?: number;
    gpu?: string;
    vramMb?: number;
    ollamaModels?: string[];
    vllmModels?: string[];
    inferencePoolModels?: string[];
    canProve?: boolean;       // enough RAM for ZK proofs
  },
): NodeManifest {
  const caps: CapabilityFlag[] = [
    "consensus", "gossip", "storage", "websocket", "relay", "snapshot", "oracle",
  ];

  const inference: InferenceCapability[] = [];

  // Ollama local inference
  if (opts.ollamaModels && opts.ollamaModels.length > 0) {
    caps.push("inference-local");
    inference.push({
      provider: "ollama",
      models: opts.ollamaModels,
      gpu: opts.gpu,
      vram_mb: opts.vramMb,
      tps: opts.gpu ? 60 : 10, // rough estimate
    });
  }

  // vLLM inference
  if (opts.vllmModels && opts.vllmModels.length > 0) {
    caps.push("inference-local", "inference-gpu");
    inference.push({
      provider: "vllm",
      models: opts.vllmModels,
      gpu: opts.gpu,
      vram_mb: opts.vramMb,
      tps: opts.gpu ? 100 : 15,
    });
  }

  // Inference pool (free tier aggregation)
  if (opts.inferencePoolModels && opts.inferencePoolModels.length > 0) {
    caps.push("inference-pool");
    inference.push({
      provider: "inference-pool",
      models: opts.inferencePoolModels,
    });
  }

  // ZK proving (needs 4GB+ RAM)
  if (opts.canProve || (opts.ramMb && opts.ramMb >= 4096)) {
    caps.push("zk-prove");
  }

  return {
    pubkey,
    url,
    version: "0.5.0",
    runtime: "standalone-express",
    platform: opts.platform,
    region: opts.region,
    capabilities: caps,
    inference,
    resources: {
      cpu_cores: opts.cpuCores,
      ram_mb: opts.ramMb,
      storage_gb: opts.storageGb,
    },
    last_heartbeat: Date.now(),
    manifest_version: 1,
  };
}

// ─── Manifest Registry ───────────────────────────────────────────────────────
// Tracks manifests from all known peers. Updated via gossip peer exchange.

export class ManifestRegistry {
  private manifests = new Map<string, NodeManifest>(); // pubkey → manifest
  private staleThresholdMs = 5 * 60_000; // 5 minutes

  /** Register or update a node's manifest */
  set(manifest: NodeManifest): void {
    const existing = this.manifests.get(manifest.pubkey);
    // Only accept newer manifests
    if (existing && existing.manifest_version >= manifest.manifest_version) {
      return;
    }
    this.manifests.set(manifest.pubkey, manifest);
  }

  /** Get a specific node's manifest */
  get(pubkey: string): NodeManifest | undefined {
    return this.manifests.get(pubkey);
  }

  /** Get all non-stale manifests */
  all(): NodeManifest[] {
    const cutoff = Date.now() - this.staleThresholdMs;
    return [...this.manifests.values()].filter(m => m.last_heartbeat > cutoff);
  }

  /** Find nodes with a specific capability */
  withCapability(cap: CapabilityFlag): NodeManifest[] {
    return this.all().filter(m => m.capabilities.includes(cap));
  }

  /** Find nodes that can serve a specific model */
  withModel(modelName: string): NodeManifest[] {
    return this.all().filter(m =>
      m.inference?.some(i => i.models.includes(modelName))
    );
  }

  /** Find nodes with GPU inference */
  withGpu(): NodeManifest[] {
    return this.all().filter(m =>
      m.capabilities.includes("inference-gpu") ||
      m.inference?.some(i => !!i.gpu)
    );
  }

  /** Find nodes that can generate ZK proofs */
  withZkProving(): NodeManifest[] {
    return this.withCapability("zk-prove");
  }

  /** Find the best node for a given inference request */
  bestForInference(modelName: string): NodeManifest | null {
    const candidates = this.withModel(modelName);
    if (candidates.length === 0) return null;

    // Prefer: GPU > local > pool, then by estimated TPS
    return candidates.sort((a, b) => {
      const aInf = a.inference?.find(i => i.models.includes(modelName));
      const bInf = b.inference?.find(i => i.models.includes(modelName));

      // GPU nodes first
      const aGpu = a.capabilities.includes("inference-gpu") ? 1 : 0;
      const bGpu = b.capabilities.includes("inference-gpu") ? 1 : 0;
      if (aGpu !== bGpu) return bGpu - aGpu;

      // Local inference over pool
      const aLocal = a.capabilities.includes("inference-local") ? 1 : 0;
      const bLocal = b.capabilities.includes("inference-local") ? 1 : 0;
      if (aLocal !== bLocal) return bLocal - aLocal;

      // Higher TPS preferred
      return (bInf?.tps || 0) - (aInf?.tps || 0);
    })[0];
  }

  /** Get network capability summary */
  summary(): NetworkCapabilitySummary {
    const nodes = this.all();
    const caps = new Map<CapabilityFlag, number>();
    const runtimes = new Map<RuntimeType, number>();
    const platforms = new Map<string, number>();
    const allModels = new Set<string>();
    let totalCpu = 0;
    let totalRamMb = 0;
    let totalStorageGb = 0;
    let gpuNodes = 0;

    for (const m of nodes) {
      // Count capabilities
      for (const c of m.capabilities) {
        caps.set(c, (caps.get(c) || 0) + 1);
      }
      // Count runtimes
      runtimes.set(m.runtime, (runtimes.get(m.runtime) || 0) + 1);
      // Count platforms
      platforms.set(m.platform, (platforms.get(m.platform) || 0) + 1);
      // Collect models
      for (const inf of m.inference || []) {
        for (const model of inf.models) allModels.add(model);
        if (inf.gpu) gpuNodes++;
      }
      // Sum resources
      totalCpu += m.resources?.cpu_cores || 0;
      totalRamMb += m.resources?.ram_mb || 0;
      totalStorageGb += m.resources?.storage_gb || 0;
    }

    return {
      total_nodes: nodes.length,
      capabilities: Object.fromEntries(caps),
      runtimes: Object.fromEntries(runtimes),
      platforms: Object.fromEntries(platforms),
      total_models: allModels.size,
      models: [...allModels].sort(),
      gpu_nodes: gpuNodes,
      aggregate_resources: {
        cpu_cores: totalCpu,
        ram_mb: totalRamMb,
        storage_gb: totalStorageGb,
      },
    };
  }

  /** Remove stale manifests */
  cleanup(): number {
    const cutoff = Date.now() - this.staleThresholdMs;
    let removed = 0;
    for (const [key, m] of this.manifests) {
      if (m.last_heartbeat < cutoff) {
        this.manifests.delete(key);
        removed++;
      }
    }
    return removed;
  }
}

export interface NetworkCapabilitySummary {
  total_nodes: number;
  capabilities: Record<string, number>;
  runtimes: Record<string, number>;
  platforms: Record<string, number>;
  total_models: number;
  models: string[];
  gpu_nodes: number;
  aggregate_resources: {
    cpu_cores: number;
    ram_mb: number;
    storage_gb: number;
  };
}
