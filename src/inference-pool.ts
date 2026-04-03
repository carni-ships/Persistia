// ─── Free Inference Pool ─────────────────────────────────────────────────────
// Aggregates free-tier inference from 12+ providers behind a unified OpenAI-
// compatible interface.  Each provider has its own rate limits and daily quotas;
// the pool tracks usage in-memory (resets on Worker eviction) and cascades
// through providers until one succeeds.
//
// Usage:
//   const pool = new InferencePool(env);   // reads API keys from env
//   const res  = await pool.chat(messages, { model: "llama-3.3-70b" });

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface PoolChatOptions {
  model?: string;           // abstract model hint (e.g. "llama-3.3-70b")
  max_tokens?: number;
  temperature?: number;
  provider?: string;        // force a specific provider
  caller_id?: string;       // caller identity for per-user metering (IP, user ID, API key)
  tools?: any[];            // OpenAI-compatible function calling tools
  tool_choice?: any;        // "auto", "none", or specific tool
}

export interface EmbedOptions {
  model?: string;           // abstract model hint (e.g. "bge-m3")
  caller_id?: string;
}

export interface EmbedResult {
  provider: string;
  model: string;
  data: { object: "embedding"; embedding: number[]; index: number }[];
  usage?: { prompt_tokens?: number; total_tokens?: number };
  latency_ms: number;
}

export interface PoolChatResult {
  provider: string;
  model: string;
  content: string;
  usage?: { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number };
  latency_ms: number;
  tool_calls?: any[];    // OpenAI-compatible tool_calls from the model
}

export interface ProviderStatus {
  id: string;
  name: string;
  enabled: boolean;
  requests_today: number;
  daily_limit: number;
  rpm_limit: number;
  requests_this_minute: number;
  models: string[];
  last_error?: string;
}

// ─── Provider Definition ─────────────────────────────────────────────────────

interface ProviderDef {
  id: string;
  name: string;
  baseUrl: string;
  envKey: string;             // env var name for API key
  dailyLimit: number;         // requests per day (0 = unlimited / credit-based)
  rpmLimit: number;           // requests per minute
  models: Record<string, string>; // abstract name → provider model ID
  headers?: (key: string) => Record<string, string>;  // custom headers
  transformBody?: (body: any) => any;                  // transform before send
  extractContent?: (json: any) => string;              // extract from response
}

// ─── Provider Registry ───────────────────────────────────────────────────────

const PROVIDERS: ProviderDef[] = [
  {
    id: "groq",
    name: "Groq",
    baseUrl: "https://api.groq.com/openai/v1",
    envKey: "GROQ_API_KEY",
    dailyLimit: 14400,
    rpmLimit: 30,
    models: {
      "llama-3.3-70b": "llama-3.3-70b-versatile",
      "llama-3.1-8b": "llama-3.1-8b-instant",
      "gemma2-9b": "gemma2-9b-it",
      "mixtral-8x7b": "mixtral-8x7b-32768",
      "deepseek-r1-70b": "deepseek-r1-distill-llama-70b",
    },
  },
  {
    id: "cerebras",
    name: "Cerebras",
    baseUrl: "https://api.cerebras.ai/v1",
    envKey: "CEREBRAS_API_KEY",
    dailyLimit: 1000,    // ~1M tokens/day ≈ ~1000 requests
    rpmLimit: 30,
    models: {
      "llama-3.3-70b": "llama-3.3-70b",
      "llama-3.1-8b": "llama3.1-8b",
      "qwen-2.5-32b": "qwen-2.5-32b",
    },
  },
  {
    id: "sambanova",
    name: "SambaNova",
    baseUrl: "https://api.sambanova.ai/v1",
    envKey: "SAMBANOVA_API_KEY",
    dailyLimit: 200,     // ~200K tokens/day ≈ ~200 requests
    rpmLimit: 10,
    models: {
      "llama-3.1-405b": "Meta-Llama-3.1-405B-Instruct",
      "llama-3.3-70b": "Meta-Llama-3.3-70B-Instruct",
      "llama-3.1-8b": "Meta-Llama-3.1-8B-Instruct",
      "deepseek-r1": "DeepSeek-R1",
      "deepseek-v3": "DeepSeek-V3-0324",
      "qwen-2.5-72b": "Qwen2.5-72B-Instruct",
    },
  },
  {
    id: "gemini",
    name: "Google Gemini",
    baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai",
    envKey: "GEMINI_API_KEY",
    dailyLimit: 1500,    // varies by model, conservative
    rpmLimit: 15,
    models: {
      "gemini-2.5-pro": "gemini-2.5-pro-preview-05-06",
      "gemini-2.5-flash": "gemini-2.5-flash-preview-05-20",
      "gemini-2.0-flash": "gemini-2.0-flash",
      "gemini-1.5-flash": "gemini-1.5-flash",
    },
  },
  {
    id: "mistral",
    name: "Mistral",
    baseUrl: "https://api.mistral.ai/v1",
    envKey: "MISTRAL_API_KEY",
    dailyLimit: 0,       // 1B tokens/month, effectively unlimited daily
    rpmLimit: 1,         // 1 RPS
    models: {
      "mistral-small": "mistral-small-latest",
      "mistral-medium": "mistral-medium-latest",
      "codestral": "codestral-latest",
      "pixtral": "pixtral-12b-2409",
    },
  },
  {
    id: "openrouter",
    name: "OpenRouter",
    baseUrl: "https://openrouter.ai/api/v1",
    envKey: "OPENROUTER_API_KEY",
    dailyLimit: 200,     // 20 RPM × ~10 min active use
    rpmLimit: 20,
    models: {
      "llama-3.3-70b": "meta-llama/llama-3.3-70b-instruct:free",
      "gemma2-9b": "google/gemma-2-9b-it:free",
      "qwen-2.5-72b": "qwen/qwen-2.5-72b-instruct:free",
      "phi-3-mini": "microsoft/phi-3-mini-128k-instruct:free",
      "deepseek-r1": "deepseek/deepseek-r1:free",
      "mistral-7b": "mistralai/mistral-7b-instruct:free",
    },
    headers: (key) => ({
      Authorization: `Bearer ${key}`,
      "HTTP-Referer": "https://persistia.carnation-903.workers.dev",
      "X-Title": "Persistia",
    }),
  },
  {
    id: "together",
    name: "Together.ai",
    baseUrl: "https://api.together.xyz/v1",
    envKey: "TOGETHER_API_KEY",
    dailyLimit: 0,       // credit-based ($25 free)
    rpmLimit: 60,
    models: {
      "llama-3.3-70b": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
      "llama-3.1-8b": "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
      "deepseek-r1": "deepseek-ai/DeepSeek-R1",
      "qwen-2.5-72b": "Qwen/Qwen2.5-72B-Instruct-Turbo",
      "mixtral-8x7b": "mistralai/Mixtral-8x7B-Instruct-v0.1",
    },
  },
  {
    id: "nvidia",
    name: "NVIDIA NIM",
    baseUrl: "https://integrate.api.nvidia.com/v1",
    envKey: "NVIDIA_API_KEY",
    dailyLimit: 0,       // 1000 inference credits total
    rpmLimit: 40,
    models: {
      "llama-3.3-70b": "meta/llama-3.3-70b-instruct",
      "llama-3.1-405b": "meta/llama-3.1-405b-instruct",
      "deepseek-r1": "deepseek-ai/deepseek-r1",
      "mistral-large": "mistralai/mistral-large-2-instruct",
    },
  },
  {
    id: "deepseek",
    name: "DeepSeek",
    baseUrl: "https://api.deepseek.com/v1",
    envKey: "DEEPSEEK_API_KEY",
    dailyLimit: 50,      // 5M free tokens, conserve at ~50 req/day
    rpmLimit: 10,
    models: {
      "deepseek-chat": "deepseek-chat",
      "deepseek-r1": "deepseek-reasoner",
    },
  },
  {
    id: "github",
    name: "GitHub Models",
    baseUrl: "https://models.inference.ai.azure.com",
    envKey: "GITHUB_TOKEN",
    dailyLimit: 50,      // 50-150 RPD depending on model
    rpmLimit: 10,
    models: {
      "gpt-4o-mini": "gpt-4o-mini",
      "llama-3.3-70b": "Meta-Llama-3.3-70B-Instruct",
      "deepseek-r1": "DeepSeek-R1",
      "phi-4": "Phi-4",
      "mistral-large": "Mistral-Large-2411",
    },
  },
  {
    id: "cohere",
    name: "Cohere",
    baseUrl: "https://api.cohere.com/v2",
    envKey: "COHERE_API_KEY",
    dailyLimit: 33,      // 1000/month ≈ 33/day
    rpmLimit: 10,
    models: {
      "command-r-plus": "command-r-plus",
      "command-r": "command-r",
      "command-light": "command-light",
    },
    // Cohere v2 uses OpenAI-compatible chat format
  },
  {
    id: "cloudflare",
    name: "Cloudflare Workers AI",
    baseUrl: "__WORKERS_AI__",   // special: uses env.AI.run() directly
    envKey: "__BUILTIN__",
    dailyLimit: 200,     // ~9000 neurons/day ≈ ~200 LLM calls
    rpmLimit: 60,
    models: {
      "llama-3.3-70b": "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
      "qwen3-30b": "@cf/qwen/qwen3-30b-a3b",
      "deepseek-r1-32b": "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b",
      "mistral-7b": "@cf/mistral/mistral-7b-instruct-v0.2",
      "llama-3.2-3b": "@cf/meta/llama-3.2-3b-instruct",
      "gemma-3-12b": "@cf/google/gemma-3-12b-it",
    },
  },
];

// ─── Model Routing Table ─────────────────────────────────────────────────────
// Maps abstract model names to ordered provider preferences.
// First available (has key + under limits) wins.

const MODEL_PREFERENCES: Record<string, string[]> = {
  "llama-3.3-70b":  ["groq", "cerebras", "sambanova", "together", "nvidia", "openrouter", "github", "cloudflare"],
  "llama-3.1-8b":   ["groq", "cerebras", "sambanova", "together", "cloudflare"],
  "llama-3.1-405b": ["sambanova", "nvidia"],
  "deepseek-r1":    ["sambanova", "together", "nvidia", "openrouter", "github", "deepseek"],
  "deepseek-chat":  ["deepseek"],
  "gemini-2.5-pro": ["gemini"],
  "gemini-2.5-flash": ["gemini"],
  "gemini-2.0-flash": ["gemini"],
  "qwen-2.5-72b":   ["sambanova", "together", "openrouter"],
  "mistral-small":   ["mistral"],
  "codestral":       ["mistral"],
  "command-r-plus":  ["cohere"],
  "gpt-4o-mini":     ["github"],
  "phi-4":           ["github"],
};

// ─── Embedding Providers ─────────────────────────────────────────────────────

interface EmbedProviderDef {
  id: string;
  name: string;
  baseUrl: string;
  envKey: string;
  model: string;       // provider's model ID
  dimensions: number;
}

const EMBED_PROVIDERS: EmbedProviderDef[] = [
  { id: "cloudflare", name: "Cloudflare Workers AI", baseUrl: "__WORKERS_AI__", envKey: "__BUILTIN__", model: "@cf/baai/bge-m3", dimensions: 1024 },
  { id: "cohere", name: "Cohere", baseUrl: "https://api.cohere.com/v2", envKey: "COHERE_API_KEY", model: "embed-english-v3.0", dimensions: 1024 },
  { id: "together", name: "Together.ai", baseUrl: "https://api.together.xyz/v1", envKey: "TOGETHER_API_KEY", model: "togethercomputer/m2-bert-80M-8k-retrieval", dimensions: 768 },
  { id: "nvidia", name: "NVIDIA NIM", baseUrl: "https://integrate.api.nvidia.com/v1", envKey: "NVIDIA_API_KEY", model: "nvidia/nv-embedqa-e5-v5", dimensions: 1024 },
  { id: "mistral", name: "Mistral", baseUrl: "https://api.mistral.ai/v1", envKey: "MISTRAL_API_KEY", model: "mistral-embed", dimensions: 1024 },
];

const EMBED_PREFERENCES = ["cloudflare", "cohere", "together", "nvidia", "mistral"];

// Default model when none specified
const DEFAULT_MODEL = "llama-3.3-70b";

// ─── Rate Limiter ────────────────────────────────────────────────────────────

interface UsageTracker {
  date: string;
  daily: number;
  minuteWindow: number;  // unix minute
  minuteCount: number;
  lastError?: string;
  lastErrorTime?: number;
}

// ─── Per-Caller Metering ─────────────────────────────────────────────────────
// Prevents a single user from exhausting the global free-tier budget.
// Tracks by caller_id (IP address, Telegram user ID, API key, etc.)

interface CallerMeter {
  date: string;
  daily: number;
  minuteWindow: number;
  minuteCount: number;
  hourWindow: number;
  hourCount: number;
}

/** Configurable limits per caller */
export interface MeteringConfig {
  perCallerDailyLimit: number;    // max requests/day per caller (default: 100)
  perCallerRpmLimit: number;      // max requests/minute per caller (default: 5)
  perCallerRphLimit: number;      // max requests/hour per caller (default: 30)
  globalDailyLimit: number;       // max total requests/day across all callers (default: 5000)
  globalRpmLimit: number;         // max total requests/minute (default: 30)
  bypassSecret?: string;          // secret key to bypass metering (for admin use)
}

const DEFAULT_METERING: MeteringConfig = {
  perCallerDailyLimit: 100,
  perCallerRpmLimit: 5,
  perCallerRphLimit: 30,
  globalDailyLimit: 5000,
  globalRpmLimit: 30,
};

export interface MeteringResult {
  allowed: boolean;
  reason?: string;
  caller_daily_used: number;
  caller_daily_limit: number;
  global_daily_used: number;
  global_daily_limit: number;
}

class CallerMeteringSystem {
  private callers = new Map<string, CallerMeter>();
  private global: CallerMeter = { date: "", daily: 0, minuteWindow: 0, minuteCount: 0, hourWindow: 0, hourCount: 0 };
  private config: MeteringConfig;

  constructor(config?: Partial<MeteringConfig>) {
    this.config = { ...DEFAULT_METERING, ...config };
  }

  /** Check if a caller is allowed to make a request */
  check(callerId: string): MeteringResult {
    const now = new Date();
    const today = now.toISOString().slice(0, 10);
    const currentMinute = Math.floor(now.getTime() / 60_000);
    const currentHour = Math.floor(now.getTime() / 3_600_000);

    // Reset global if new day
    if (this.global.date !== today) {
      this.global = { date: today, daily: 0, minuteWindow: currentMinute, minuteCount: 0, hourWindow: currentHour, hourCount: 0 };
    }
    if (this.global.minuteWindow !== currentMinute) { this.global.minuteWindow = currentMinute; this.global.minuteCount = 0; }
    if (this.global.hourWindow !== currentHour) { this.global.hourWindow = currentHour; this.global.hourCount = 0; }

    // Check global limits first
    if (this.global.daily >= this.config.globalDailyLimit) {
      return { allowed: false, reason: "Global daily limit reached", caller_daily_used: 0, caller_daily_limit: this.config.perCallerDailyLimit, global_daily_used: this.global.daily, global_daily_limit: this.config.globalDailyLimit };
    }
    if (this.global.minuteCount >= this.config.globalRpmLimit) {
      return { allowed: false, reason: "Global rate limit (requests/minute)", caller_daily_used: 0, caller_daily_limit: this.config.perCallerDailyLimit, global_daily_used: this.global.daily, global_daily_limit: this.config.globalDailyLimit };
    }

    // Get or create caller meter
    let meter = this.callers.get(callerId);
    if (!meter || meter.date !== today) {
      meter = { date: today, daily: 0, minuteWindow: currentMinute, minuteCount: 0, hourWindow: currentHour, hourCount: 0 };
      this.callers.set(callerId, meter);
    }
    if (meter.minuteWindow !== currentMinute) { meter.minuteWindow = currentMinute; meter.minuteCount = 0; }
    if (meter.hourWindow !== currentHour) { meter.hourWindow = currentHour; meter.hourCount = 0; }

    const base = { caller_daily_used: meter.daily, caller_daily_limit: this.config.perCallerDailyLimit, global_daily_used: this.global.daily, global_daily_limit: this.config.globalDailyLimit };

    // Check per-caller limits
    if (meter.daily >= this.config.perCallerDailyLimit) {
      return { allowed: false, reason: `Daily limit reached (${this.config.perCallerDailyLimit}/day per user)`, ...base };
    }
    if (meter.minuteCount >= this.config.perCallerRpmLimit) {
      return { allowed: false, reason: `Rate limit (${this.config.perCallerRpmLimit}/min per user)`, ...base };
    }
    if (meter.hourCount >= this.config.perCallerRphLimit) {
      return { allowed: false, reason: `Hourly limit (${this.config.perCallerRphLimit}/hr per user)`, ...base };
    }

    return { allowed: true, ...base };
  }

  /** Record a successful request */
  record(callerId: string): void {
    const now = new Date();
    const today = now.toISOString().slice(0, 10);
    const currentMinute = Math.floor(now.getTime() / 60_000);
    const currentHour = Math.floor(now.getTime() / 3_600_000);

    // Update global
    if (this.global.date !== today) this.global = { date: today, daily: 0, minuteWindow: currentMinute, minuteCount: 0, hourWindow: currentHour, hourCount: 0 };
    this.global.daily++;
    this.global.minuteCount++;
    this.global.hourCount++;

    // Update caller
    let meter = this.callers.get(callerId);
    if (!meter || meter.date !== today) {
      meter = { date: today, daily: 0, minuteWindow: currentMinute, minuteCount: 0, hourWindow: currentHour, hourCount: 0 };
      this.callers.set(callerId, meter);
    }
    meter.daily++;
    meter.minuteCount++;
    meter.hourCount++;
  }

  /** Get metering stats */
  stats(): { global: { daily: number; limit: number }; callers: number; top_callers: { id: string; daily: number }[] } {
    const today = new Date().toISOString().slice(0, 10);
    const active = [...this.callers.entries()]
      .filter(([_, m]) => m.date === today && m.daily > 0)
      .map(([id, m]) => ({ id: id.slice(0, 16) + "...", daily: m.daily }))
      .sort((a, b) => b.daily - a.daily)
      .slice(0, 10);

    return {
      global: { daily: this.global.date === today ? this.global.daily : 0, limit: this.config.globalDailyLimit },
      callers: active.length,
      top_callers: active,
    };
  }

  /** Evict stale caller entries (call periodically) */
  cleanup(): number {
    const today = new Date().toISOString().slice(0, 10);
    let removed = 0;
    for (const [key, meter] of this.callers) {
      if (meter.date !== today) {
        this.callers.delete(key);
        removed++;
      }
    }
    return removed;
  }
}

// ─── Inference Pool ──────────────────────────────────────────────────────────

export class InferencePool {
  private providers: Map<string, ProviderDef> = new Map();
  private usage: Map<string, UsageTracker> = new Map();
  private env: Record<string, any>;
  private metering: CallerMeteringSystem;

  constructor(env: Record<string, any>, meteringConfig?: Partial<MeteringConfig>) {
    this.env = env;
    // Read metering config from env vars, falling back to defaults
    this.metering = new CallerMeteringSystem({
      perCallerDailyLimit: parseInt(env.POOL_PER_USER_DAILY_LIMIT || "0") || DEFAULT_METERING.perCallerDailyLimit,
      perCallerRpmLimit: parseInt(env.POOL_PER_USER_RPM || "0") || DEFAULT_METERING.perCallerRpmLimit,
      perCallerRphLimit: parseInt(env.POOL_PER_USER_RPH || "0") || DEFAULT_METERING.perCallerRphLimit,
      globalDailyLimit: parseInt(env.POOL_GLOBAL_DAILY_LIMIT || "0") || DEFAULT_METERING.globalDailyLimit,
      globalRpmLimit: parseInt(env.POOL_GLOBAL_RPM || "0") || DEFAULT_METERING.globalRpmLimit,
      bypassSecret: env.POOL_ADMIN_SECRET,
      ...meteringConfig,
    });
    for (const p of PROVIDERS) {
      // Only register providers we have keys for (or builtins)
      if (p.envKey === "__BUILTIN__" || env[p.envKey]) {
        this.providers.set(p.id, p);
      }
    }
  }

  /** Get metering stats */
  meteringStats() { return this.metering.stats(); }

  /** Check if a caller is allowed (without recording usage) */
  checkCaller(callerId: string): MeteringResult { return this.metering.check(callerId); }

  /** List all configured providers with usage stats */
  status(): ProviderStatus[] {
    const now = new Date();
    const today = now.toISOString().slice(0, 10);
    const currentMinute = Math.floor(now.getTime() / 60_000);

    return [...this.providers.values()].map((p) => {
      const u = this.usage.get(p.id);
      return {
        id: p.id,
        name: p.name,
        enabled: true,
        requests_today: u?.date === today ? u.daily : 0,
        daily_limit: p.dailyLimit,
        rpm_limit: p.rpmLimit,
        requests_this_minute: u?.minuteWindow === currentMinute ? u.minuteCount : 0,
        models: Object.keys(p.models),
        last_error: u?.lastError,
      };
    });
  }

  /** Get all available abstract model names across all providers */
  availableModels(): string[] {
    const models = new Set<string>();
    for (const p of this.providers.values()) {
      for (const m of Object.keys(p.models)) {
        models.add(m);
      }
    }
    return [...models].sort();
  }

  /** Chat completion — cascades through providers until one succeeds */
  async chat(messages: ChatMessage[], opts: PoolChatOptions = {}): Promise<PoolChatResult> {
    // Per-caller metering check
    const callerId = opts.caller_id || "anonymous";
    const meterResult = this.metering.check(callerId);
    if (!meterResult.allowed) {
      throw new Error(`Rate limited: ${meterResult.reason} (used ${meterResult.caller_daily_used}/${meterResult.caller_daily_limit} today)`);
    }

    const abstractModel = opts.model || DEFAULT_MODEL;

    // Determine provider order
    let providerOrder: string[];
    if (opts.provider) {
      providerOrder = [opts.provider];
    } else {
      providerOrder = MODEL_PREFERENCES[abstractModel] || [...this.providers.keys()];
    }

    const errors: string[] = [];

    for (const pid of providerOrder) {
      const provider = this.providers.get(pid);
      if (!provider) continue;

      const providerModelId = provider.models[abstractModel];
      if (!providerModelId) continue;

      // Check rate limits
      if (!this.checkLimits(provider)) {
        errors.push(`${pid}: rate limited`);
        continue;
      }

      // Check error cooldown (back off 60s after errors)
      const u = this.usage.get(pid);
      if (u?.lastErrorTime && Date.now() - u.lastErrorTime < 60_000) {
        errors.push(`${pid}: cooling down after error`);
        continue;
      }

      try {
        const start = Date.now();
        let result: PoolChatResult;

        if (provider.baseUrl === "__WORKERS_AI__") {
          result = await this.callWorkersAI(provider, providerModelId, messages, opts, start);
        } else {
          result = await this.callOpenAICompatible(provider, providerModelId, messages, opts, start);
        }

        this.recordUsage(pid);
        this.metering.record(callerId);
        return result;
      } catch (e: any) {
        const msg = e.message || String(e);
        errors.push(`${pid}: ${msg}`);
        this.recordError(pid, msg);
      }
    }

    throw new Error(
      `All providers exhausted for model "${abstractModel}". Tried: ${errors.join("; ")}`
    );
  }

  // ── Internal ───────────────────────────────────────────────────────────────

  private checkLimits(provider: ProviderDef): boolean {
    const now = new Date();
    const today = now.toISOString().slice(0, 10);
    const currentMinute = Math.floor(now.getTime() / 60_000);

    let u = this.usage.get(provider.id);
    if (!u || u.date !== today) {
      u = { date: today, daily: 0, minuteWindow: currentMinute, minuteCount: 0 };
      this.usage.set(provider.id, u);
    }

    // Reset minute counter if new minute
    if (u.minuteWindow !== currentMinute) {
      u.minuteWindow = currentMinute;
      u.minuteCount = 0;
    }

    // Check daily limit (0 = unlimited)
    if (provider.dailyLimit > 0 && u.daily >= provider.dailyLimit) {
      return false;
    }

    // Check RPM
    if (u.minuteCount >= provider.rpmLimit) {
      return false;
    }

    return true;
  }

  private recordUsage(providerId: string) {
    const now = new Date();
    const today = now.toISOString().slice(0, 10);
    const currentMinute = Math.floor(now.getTime() / 60_000);

    let u = this.usage.get(providerId);
    if (!u || u.date !== today) {
      u = { date: today, daily: 0, minuteWindow: currentMinute, minuteCount: 0 };
      this.usage.set(providerId, u);
    }
    if (u.minuteWindow !== currentMinute) {
      u.minuteWindow = currentMinute;
      u.minuteCount = 0;
    }
    u.daily++;
    u.minuteCount++;
  }

  private recordError(providerId: string, message: string) {
    const u = this.usage.get(providerId) || {
      date: new Date().toISOString().slice(0, 10),
      daily: 0,
      minuteWindow: 0,
      minuteCount: 0,
    };
    u.lastError = message.slice(0, 200);
    u.lastErrorTime = Date.now();
    this.usage.set(providerId, u);
  }

  private async callWorkersAI(
    provider: ProviderDef,
    modelId: string,
    messages: ChatMessage[],
    opts: PoolChatOptions,
    start: number,
  ): Promise<PoolChatResult> {
    if (!this.env.AI) throw new Error("Workers AI not available");

    const result = await this.env.AI.run(modelId, {
      messages,
      max_tokens: Math.min(opts.max_tokens || 1024, 4096),
    });

    const content = result?.response || result?.result || JSON.stringify(result);
    return {
      provider: provider.id,
      model: modelId,
      content: typeof content === "string" ? content : JSON.stringify(content),
      latency_ms: Date.now() - start,
    };
  }

  private async callOpenAICompatible(
    provider: ProviderDef,
    modelId: string,
    messages: ChatMessage[],
    opts: PoolChatOptions,
    start: number,
  ): Promise<PoolChatResult> {
    const apiKey = this.env[provider.envKey];
    if (!apiKey) throw new Error(`No API key (${provider.envKey})`);

    const headers: Record<string, string> = provider.headers
      ? provider.headers(apiKey)
      : {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        };

    if (!headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }

    let body: any = {
      model: modelId,
      messages,
      max_tokens: opts.max_tokens || 1024,
      ...(opts.temperature !== undefined ? { temperature: opts.temperature } : {}),
      ...(opts.tools && opts.tools.length > 0 ? { tools: opts.tools } : {}),
      ...(opts.tool_choice ? { tool_choice: opts.tool_choice } : {}),
    };

    if (provider.transformBody) {
      body = provider.transformBody(body);
    }

    const res = await fetch(`${provider.baseUrl}/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      throw new Error(`HTTP ${res.status}: ${errText.slice(0, 300)}`);
    }

    const json = await res.json() as any;

    let content: string;
    if (provider.extractContent) {
      content = provider.extractContent(json);
    } else {
      content = json.choices?.[0]?.message?.content || "";
    }

    // Preserve tool_calls from the response if present
    const toolCalls = json.choices?.[0]?.message?.tool_calls;

    return {
      provider: provider.id,
      model: modelId,
      content,
      usage: json.usage,
      latency_ms: Date.now() - start,
      ...(toolCalls ? { tool_calls: toolCalls } : {}),
    } as PoolChatResult;
  }

  /** Streaming chat — returns a ReadableStream of SSE chunks */
  async chatStream(messages: ChatMessage[], opts: PoolChatOptions = {}): Promise<{
    stream: ReadableStream;
    provider: string;
    model: string;
  }> {
    const callerId = opts.caller_id || "anonymous";
    const meterResult = this.metering.check(callerId);
    if (!meterResult.allowed) {
      throw new Error(`Rate limited: ${meterResult.reason}`);
    }

    const abstractModel = opts.model || DEFAULT_MODEL;
    let providerOrder = opts.provider
      ? [opts.provider]
      : MODEL_PREFERENCES[abstractModel] || [...this.providers.keys()];

    const errors: string[] = [];

    for (const pid of providerOrder) {
      const provider = this.providers.get(pid);
      if (!provider) continue;
      const providerModelId = provider.models[abstractModel];
      if (!providerModelId) continue;
      if (!this.checkLimits(provider)) { errors.push(`${pid}: rate limited`); continue; }
      const u = this.usage.get(pid);
      if (u?.lastErrorTime && Date.now() - u.lastErrorTime < 60_000) { errors.push(`${pid}: cooling down`); continue; }

      // Workers AI doesn't support streaming via fetch — fall back to non-stream
      if (provider.baseUrl === "__WORKERS_AI__") {
        try {
          const start = Date.now();
          const result = await this.callWorkersAI(provider, providerModelId, messages, opts, start);
          this.recordUsage(pid);
          this.metering.record(callerId);
          // Wrap non-streaming result as SSE stream
          const completionId = `chatcmpl-${crypto.randomUUID().slice(0, 12)}`;
          const stream = new ReadableStream({
            start(controller) {
              const chunk = { id: completionId, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: providerModelId, choices: [{ index: 0, delta: { role: "assistant", content: result.content }, finish_reason: null }] };
              controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(chunk)}\n\n`));
              const done = { ...chunk, choices: [{ index: 0, delta: {}, finish_reason: "stop" }] };
              controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(done)}\n\n`));
              controller.enqueue(new TextEncoder().encode("data: [DONE]\n\n"));
              controller.close();
            },
          });
          return { stream, provider: pid, model: providerModelId };
        } catch (e: any) {
          errors.push(`${pid}: ${e.message}`);
          this.recordError(pid, e.message);
          continue;
        }
      }

      try {
        const apiKey = this.env[provider.envKey];
        if (!apiKey) throw new Error(`No API key (${provider.envKey})`);

        const headers: Record<string, string> = provider.headers
          ? provider.headers(apiKey)
          : { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" };
        if (!headers["Content-Type"]) headers["Content-Type"] = "application/json";

        let body: any = {
          model: providerModelId,
          messages,
          max_tokens: opts.max_tokens || 1024,
          stream: true,
          ...(opts.temperature !== undefined ? { temperature: opts.temperature } : {}),
          ...(opts.tools?.length ? { tools: opts.tools } : {}),
          ...(opts.tool_choice ? { tool_choice: opts.tool_choice } : {}),
        };
        if (provider.transformBody) body = provider.transformBody(body);

        const res = await fetch(`${provider.baseUrl}/chat/completions`, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
        });

        if (!res.ok) {
          const errText = await res.text().catch(() => "");
          throw new Error(`HTTP ${res.status}: ${errText.slice(0, 300)}`);
        }

        this.recordUsage(pid);
        this.metering.record(callerId);

        // Pass through the SSE stream directly from the provider
        return { stream: res.body!, provider: pid, model: providerModelId };
      } catch (e: any) {
        errors.push(`${pid}: ${e.message}`);
        this.recordError(pid, e.message);
      }
    }

    throw new Error(`All providers exhausted for streaming "${abstractModel}". Tried: ${errors.join("; ")}`);
  }

  /** Generate embeddings */
  async embed(input: string | string[], opts: EmbedOptions = {}): Promise<EmbedResult> {
    const callerId = opts.caller_id || "anonymous";
    const meterResult = this.metering.check(callerId);
    if (!meterResult.allowed) {
      throw new Error(`Rate limited: ${meterResult.reason}`);
    }

    const texts = Array.isArray(input) ? input : [input];

    for (const epId of EMBED_PREFERENCES) {
      const ep = EMBED_PROVIDERS.find(p => p.id === epId);
      if (!ep) continue;
      if (ep.envKey !== "__BUILTIN__" && !this.env[ep.envKey]) continue;

      // Check provider rate limits (reuse chat provider limits if available)
      const chatProvider = this.providers.get(ep.id);
      if (chatProvider && !this.checkLimits(chatProvider)) continue;

      try {
        const start = Date.now();

        if (ep.baseUrl === "__WORKERS_AI__") {
          if (!this.env.AI) throw new Error("Workers AI not available");
          const result = await this.env.AI.run(ep.model, { text: texts });
          const embeddings = (result?.data || result || []).map((vec: number[], i: number) => ({
            object: "embedding" as const, embedding: vec, index: i,
          }));
          if (chatProvider) this.recordUsage(ep.id);
          this.metering.record(callerId);
          return { provider: ep.id, model: ep.model, data: embeddings, latency_ms: Date.now() - start };
        }

        const apiKey = this.env[ep.envKey];
        const headers: Record<string, string> = {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        };

        const res = await fetch(`${ep.baseUrl}/embeddings`, {
          method: "POST",
          headers,
          body: JSON.stringify({ model: ep.model, input: texts }),
        });

        if (!res.ok) {
          const errText = await res.text().catch(() => "");
          throw new Error(`HTTP ${res.status}: ${errText.slice(0, 200)}`);
        }

        const json = await res.json() as any;
        if (chatProvider) this.recordUsage(ep.id);
        this.metering.record(callerId);

        return {
          provider: ep.id,
          model: ep.model,
          data: json.data || [],
          usage: json.usage,
          latency_ms: Date.now() - start,
        };
      } catch (e: any) {
        if (chatProvider) this.recordError(ep.id, e.message);
        continue;
      }
    }

    throw new Error("No embedding providers available");
  }
}

// ─── Singleton Pool ──────────────────────────────────────────────────────────
// Persists usage tracking across requests within the same Worker isolate.

let _poolInstance: InferencePool | null = null;
let _poolEnvHash = "";

function getPool(env: Record<string, any>): InferencePool {
  // Cheap identity check — recreate only if env object changes
  const hash = Object.keys(env).filter(k => k.endsWith("_KEY") || k === "GITHUB_TOKEN").sort().join(",");
  if (!_poolInstance || hash !== _poolEnvHash) {
    _poolInstance = new InferencePool(env);
    _poolEnvHash = hash;
  }
  return _poolInstance;
}

// ─── HTTP Handler ────────────────────────────────────────────────────────────
// Handles three API surfaces:
//
// OpenAI-compatible (drop-in for OpenRouter/Venice/any OpenAI SDK):
//   POST /v1/chat/completions   — chat completions
//   GET  /v1/models             — model listing
//
// Anthropic-compatible (drop-in for Claude Code / Anthropic SDK):
//   POST /v1/messages           — messages API
//
// Persistia native:
//   GET  /api/pool/status       — provider status + usage
//   GET  /api/pool/models       — models + routing details
//   POST /api/pool/chat         — chat (same as /v1/chat/completions)

export async function handlePoolRoute(
  path: string,
  request: Request,
  env: Record<string, any>,
): Promise<Response> {
  const pool = getPool(env);

  // ── Normalize route ────────────────────────────────────────────────────
  let route: string;
  if (path.startsWith("/v1/")) {
    route = path.replace(/^\/v1\/?/, "v1/").replace(/\/$/, "");
  } else {
    route = path.replace(/^\/api\/pool\/?/, "").replace(/\/$/, "");
  }

  // ── GET / — API info ───────────────────────────────────────────────────
  if (route === "" || route === "status") {
    const providers = pool.status();
    const totalCapacity = providers.reduce((s, p) => s + (p.daily_limit || 500), 0);
    return json({
      name: "Persistia Inference Gateway",
      description: "Free multi-provider AI inference — like OpenRouter, but free. " +
        "Aggregates free tiers from 12+ providers behind OpenAI and Anthropic-compatible APIs.",
      version: "1.0.0",
      openai_compatible: true,
      anthropic_compatible: true,
      endpoints: {
        chat_completions: "/v1/chat/completions",
        messages: "/v1/messages",
        models: "/v1/models",
        status: "/api/pool/status",
      },
      providers,
      models: pool.availableModels(),
      aggregate_daily_capacity: totalCapacity,
    });
  }

  // ── GET /v1/models — OpenAI-compatible model listing ───────────────────
  if (route === "v1/models" || route === "models") {
    const models = pool.availableModels();
    const providerStatus = pool.status();
    const providerMap = new Map(providerStatus.map(p => [p.id, p]));

    // Build routing details for native /api/pool/models
    const routing: Record<string, string[]> = {};
    for (const m of models) {
      routing[m] = MODEL_PREFERENCES[m] || [];
    }

    // OpenAI-compatible format
    const data = models.map(m => {
      const providerIds = MODEL_PREFERENCES[m] || [];
      const availableProviders = providerIds.filter(pid => providerMap.has(pid));
      return {
        id: m,
        object: "model" as const,
        created: 1700000000,
        owned_by: "persistia",
        providers: availableProviders,
        routing: routing[m],
      };
    });

    return json({
      object: "list",
      data,
    });
  }

  // ── GET /api/pool/metering — usage stats + top callers ───────────────
  if (route === "metering") {
    return json(pool.meteringStats());
  }

  // ── POST /v1/chat/completions or /api/pool/chat ────────────────────────
  if (route === "v1/chat/completions" || route === "chat") {
    if (request.method !== "POST") {
      return json({ error: { message: "POST required", type: "invalid_request_error" } }, 405);
    }

    let body: any;
    try {
      body = await request.json();
    } catch {
      return json({ error: { message: "Invalid JSON", type: "invalid_request_error" } }, 400);
    }

    const messages = body.messages;
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return json({
        error: { message: "messages array required [{role, content}]", type: "invalid_request_error" },
      }, 400);
    }

    // Extract caller identity for metering
    const callerId = extractCallerId(request, env);

    // ── Streaming mode ────────────────────────────────────────────────
    if (body.stream === true) {
      try {
        const { stream, provider: prov, model: mod } = await pool.chatStream(messages, {
          model: body.model,
          max_tokens: body.max_tokens,
          temperature: body.temperature,
          provider: body.provider,
          caller_id: callerId,
          tools: body.tools,
          tool_choice: body.tool_choice,
        });
        return new Response(stream, {
          headers: {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Provider": prov,
            "X-Model": mod,
          },
        });
      } catch (e: any) {
        return json({ error: { message: e.message, type: "server_error" } }, 503);
      }
    }

    // ── Non-streaming mode ────────────────────────────────────────────
    try {
      const result = await pool.chat(messages, {
        model: body.model,
        max_tokens: body.max_tokens,
        temperature: body.temperature,
        provider: body.provider,
        caller_id: callerId,
        tools: body.tools,
        tool_choice: body.tool_choice,
      });

      // Build message object — include tool_calls if present
      const message: any = { role: "assistant", content: result.content };
      if (result.tool_calls) {
        message.tool_calls = result.tool_calls;
      }

      return json({
        id: `chatcmpl-${crypto.randomUUID().slice(0, 12)}`,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: result.model,
        choices: [{
          index: 0,
          message,
          finish_reason: result.tool_calls ? "tool_calls" : "stop",
        }],
        usage: result.usage || {
          prompt_tokens: 0,
          completion_tokens: 0,
          total_tokens: 0,
        },
        // Persistia extensions
        provider: result.provider,
        latency_ms: result.latency_ms,
      });
    } catch (e: any) {
      return json({
        error: { message: e.message, type: "server_error" },
      }, 503);
    }
  }

  // ── POST /v1/embeddings — OpenAI-compatible embeddings ──────────────
  if (route === "v1/embeddings" || route === "embeddings") {
    if (request.method !== "POST") {
      return json({ error: { message: "POST required", type: "invalid_request_error" } }, 405);
    }

    let body: any;
    try {
      body = await request.json();
    } catch {
      return json({ error: { message: "Invalid JSON", type: "invalid_request_error" } }, 400);
    }

    const input = body.input;
    if (!input) {
      return json({ error: { message: "input required (string or string[])", type: "invalid_request_error" } }, 400);
    }

    const callerId = extractCallerId(request, env);

    try {
      const result = await pool.embed(input, { model: body.model, caller_id: callerId });
      return json({
        object: "list",
        data: result.data,
        model: result.model,
        usage: result.usage || { prompt_tokens: 0, total_tokens: 0 },
        // Persistia extensions
        provider: result.provider,
        latency_ms: result.latency_ms,
      });
    } catch (e: any) {
      return json({ error: { message: e.message, type: "server_error" } }, 503);
    }
  }

  // ── POST /v1/messages — Anthropic-compatible messages API ────────────
  if (route === "v1/messages") {
    if (request.method !== "POST") {
      return anthropicError("POST required", "invalid_request_error", 405);
    }

    let body: any;
    try {
      body = await request.json();
    } catch {
      return anthropicError("Invalid JSON", "invalid_request_error", 400);
    }

    // Validate required fields per Anthropic spec
    const anthropicMessages = body.messages;
    if (!anthropicMessages || !Array.isArray(anthropicMessages) || anthropicMessages.length === 0) {
      return anthropicError("messages array is required", "invalid_request_error", 400);
    }
    if (!body.max_tokens) {
      return anthropicError("max_tokens is required", "invalid_request_error", 400);
    }

    // Convert Anthropic messages → OpenAI messages for the pool
    const openaiMessages: ChatMessage[] = [];

    // Anthropic system prompt is top-level, not in messages
    if (body.system) {
      const systemText = typeof body.system === "string"
        ? body.system
        : Array.isArray(body.system)
          ? body.system.map((b: any) => b.text || "").join("\n")
          : "";
      if (systemText) {
        openaiMessages.push({ role: "system", content: systemText });
      }
    }

    // Convert content blocks → plain text
    for (const msg of anthropicMessages) {
      let content: string;
      if (typeof msg.content === "string") {
        content = msg.content;
      } else if (Array.isArray(msg.content)) {
        // Extract text from content blocks, skip images/tool_use/etc.
        content = msg.content
          .filter((b: any) => b.type === "text")
          .map((b: any) => b.text || "")
          .join("\n");
        if (!content) {
          // Fallback: if only non-text blocks, describe them
          content = msg.content.map((b: any) => {
            if (b.type === "tool_result") return `[tool result: ${b.content || ""}]`;
            if (b.type === "tool_use") return `[tool call: ${b.name}]`;
            if (b.type === "image") return "[image]";
            return `[${b.type}]`;
          }).join("\n");
        }
      } else {
        content = String(msg.content || "");
      }
      openaiMessages.push({
        role: msg.role === "assistant" ? "assistant" : "user",
        content,
      });
    }

    // Map Anthropic model names to pool models
    const modelMap: Record<string, string> = {
      "claude-opus-4-6": "llama-3.3-70b",
      "claude-sonnet-4-6": "llama-3.3-70b",
      "claude-haiku-4-5-20251001": "llama-3.1-8b",
      "claude-3-5-sonnet-20241022": "llama-3.3-70b",
      "claude-3-5-haiku-20241022": "llama-3.1-8b",
      "claude-3-opus-20240229": "llama-3.3-70b",
      "claude-3-sonnet-20240229": "llama-3.3-70b",
      "claude-3-haiku-20240307": "llama-3.1-8b",
    };
    const requestedModel = body.model || "";
    const poolModel = modelMap[requestedModel] || "llama-3.3-70b";

    const callerId = extractCallerId(request, env);

    try {
      const result = await pool.chat(openaiMessages, {
        model: poolModel,
        max_tokens: body.max_tokens,
        temperature: body.temperature,
        provider: body.provider,
        caller_id: callerId,
      });

      // Build Anthropic-format response
      const msgId = `msg_${crypto.randomUUID().replace(/-/g, "").slice(0, 20)}`;
      return json({
        id: msgId,
        type: "message",
        role: "assistant",
        content: [{ type: "text", text: result.content }],
        model: requestedModel || result.model,
        stop_reason: "end_turn",
        stop_sequence: null,
        usage: {
          input_tokens: result.usage?.prompt_tokens || 0,
          output_tokens: result.usage?.completion_tokens || 0,
          cache_creation_input_tokens: 0,
          cache_read_input_tokens: 0,
        },
        // Persistia extensions (ignored by Anthropic SDK)
        _provider: result.provider,
        _actual_model: result.model,
        _latency_ms: result.latency_ms,
      });
    } catch (e: any) {
      return anthropicError(e.message, "api_error", 503);
    }
  }

  return json({
    error: {
      message: `Unknown route: ${path}`,
      type: "invalid_request_error",
      hint: "Use /v1/chat/completions, /v1/messages, /v1/models, or /api/pool/status",
    },
  }, 404);
}

function anthropicError(message: string, type: string, status: number): Response {
  return json({ type: "error", error: { type, message } }, status);
}

/** Extract a caller identifier from the request for per-user metering */
function extractCallerId(request: Request, env: Record<string, any>): string {
  // Priority: Authorization header → X-API-Key → CF-Connecting-IP → fallback

  // Check for admin bypass
  const authHeader = request.headers.get("Authorization") || "";
  const apiKey = request.headers.get("X-API-Key") || "";
  if (env.POOL_ADMIN_SECRET && (authHeader === `Bearer ${env.POOL_ADMIN_SECRET}` || apiKey === env.POOL_ADMIN_SECRET)) {
    return "__admin__"; // Admin gets generous limits (effectively the global limit)
  }

  // Use API key as identity if provided (and it's not "free" or empty)
  if (apiKey && apiKey !== "free" && apiKey !== "unused") {
    return `key:${apiKey}`;
  }
  if (authHeader.startsWith("Bearer ") && authHeader.length > 12) {
    const token = authHeader.slice(7);
    if (token !== "free" && token !== "unused") {
      return `key:${token}`;
    }
  }

  // Fall back to IP address
  const ip = request.headers.get("CF-Connecting-IP")
    || request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim()
    || request.headers.get("X-Real-IP")
    || "unknown";
  return `ip:${ip}`;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
