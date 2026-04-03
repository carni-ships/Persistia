// ─── AI Services Gateway ──────────────────────────────────────────────────────
// Exposes Cloudflare Workers AI + Browser Rendering as MPP-paywalled endpoints.
// Each service validates input, calls env.AI.run() or env.BROWSER, returns typed output.
// Every paid call produces a signed attestation (commit-reveal + hash chain).

import type { ServiceAttestationManager, ServiceAttestation } from "./service-attestations";
import { InferencePool } from "./inference-pool";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ModelOption {
  id: string;
  name: string;
  description?: string;
}

export interface ServiceDefinition {
  id: string;
  name: string;
  description: string;
  endpoint: string;
  method: "POST" | "GET";
  models: ModelOption[];
  defaultModel: string;
  outputType: "json" | "audio" | "image" | "text";
  category: "ai" | "utility";
  price: string;
  denom: string;
  inputFields: Record<string, { type: string; required: boolean; description: string; maxLength?: number }>;
}

// ─── Model Definitions ────────────────────────────────────────────────────────

const LLM_MODELS: ModelOption[] = [
  { id: "@cf/meta/llama-3.3-70b-instruct-fp8-fast", name: "Llama 3.3 70B", description: "Best quality, multilingual" },
  { id: "@cf/qwen/qwen3-30b-a3b", name: "Qwen3 30B", description: "Reasoning + instruction following" },
  { id: "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b", name: "DeepSeek-R1 32B", description: "Strong reasoning" },
  { id: "@cf/mistral/mistral-7b-instruct-v0.2", name: "Mistral 7B", description: "Fast, 32k context" },
  { id: "@cf/meta/llama-3.2-3b-instruct", name: "Llama 3.2 3B", description: "Lightweight, fast" },
  { id: "@cf/google/gemma-3-12b-it", name: "Gemma 3 12B", description: "Multimodal, 128k context" },
];

const TTS_MODELS: ModelOption[] = [
  { id: "@cf/myshell-ai/melotts", name: "MeloTTS", description: "Multi-lingual, cheapest" },
  { id: "@cf/deepgram/aura-2-en", name: "Aura-2 EN", description: "Context-aware English" },
  { id: "@cf/deepgram/aura-2-es", name: "Aura-2 ES", description: "Context-aware Spanish" },
  { id: "@cf/deepgram/aura-1", name: "Aura-1", description: "Original context-aware TTS" },
];

const STT_MODELS: ModelOption[] = [
  { id: "@cf/openai/whisper-large-v3-turbo", name: "Whisper Large v3 Turbo", description: "Best accuracy" },
  { id: "@cf/openai/whisper", name: "Whisper", description: "Multilingual ASR" },
  { id: "@cf/openai/whisper-tiny-en", name: "Whisper Tiny EN", description: "Fastest, English only" },
];

const IMAGE_MODELS: ModelOption[] = [
  { id: "@cf/black-forest-labs/flux-1-schnell", name: "FLUX.1 schnell", description: "Fast, high quality" },
  { id: "@cf/stabilityai/stable-diffusion-xl-base-1.0", name: "Stable Diffusion XL", description: "1024px diffusion" },
  { id: "@cf/bytedance/stable-diffusion-xl-lightning", name: "SDXL Lightning", description: "Few-step generation" },
  { id: "@cf/lykon/dreamshaper-8-lcm", name: "Dreamshaper 8", description: "Photorealistic" },
];

const EMBED_MODELS: ModelOption[] = [
  { id: "@cf/baai/bge-m3", name: "BGE-M3", description: "Multi-lingual, multi-granularity" },
  { id: "@cf/baai/bge-large-en-v1.5", name: "BGE Large EN", description: "1024-dim English" },
  { id: "@cf/baai/bge-small-en-v1.5", name: "BGE Small EN", description: "384-dim, fastest" },
];

const TRANSLATE_MODELS: ModelOption[] = [
  { id: "@cf/meta/m2m100-1.2b", name: "M2M100 1.2B", description: "100+ languages, many-to-many" },
];

const VISION_MODELS: ModelOption[] = [
  { id: "@cf/meta/llama-3.2-11b-vision-instruct", name: "Llama 3.2 11B Vision", description: "Image reasoning + captioning" },
];

const CLASSIFY_MODELS: ModelOption[] = [
  { id: "@cf/huggingface/distilbert-sst-2-int8", name: "DistilBERT SST-2", description: "Sentiment classification" },
];

const SUMMARIZE_MODELS: ModelOption[] = [
  { id: "@cf/facebook/bart-large-cnn", name: "BART Large CNN", description: "News summarization" },
];

const CODE_MODELS: ModelOption[] = [
  { id: "@cf/qwen/qwen2.5-coder-32b-instruct", name: "Qwen2.5 Coder 32B", description: "Code generation + completion" },
];

// ─── Service Catalog ──────────────────────────────────────────────────────────

export const SERVICE_CATALOG: ServiceDefinition[] = [
  {
    id: "llm", name: "LLM Chat", description: "Large language model chat completions (OpenAI-compatible messages format)",
    endpoint: "/api/llm", method: "POST", models: LLM_MODELS, defaultModel: LLM_MODELS[0].id,
    outputType: "json", category: "ai", price: "100", denom: "PERSIST",
    inputFields: {
      messages: { type: "array", required: true, description: "OpenAI-format messages array [{role, content}]" },
      model: { type: "string", required: false, description: "Model ID (defaults to Llama 3.3 70B)" },
      max_tokens: { type: "number", required: false, description: "Max output tokens (default 1024)" },
    },
  },
  {
    id: "tts", name: "Text-to-Speech", description: "Convert text to natural-sounding audio",
    endpoint: "/api/tts", method: "POST", models: TTS_MODELS, defaultModel: TTS_MODELS[0].id,
    outputType: "audio", category: "ai", price: "50", denom: "PERSIST",
    inputFields: {
      text: { type: "string", required: true, description: "Text to synthesize", maxLength: 5000 },
      model: { type: "string", required: false, description: "TTS model ID" },
    },
  },
  {
    id: "stt", name: "Speech-to-Text", description: "Transcribe audio to text (Whisper)",
    endpoint: "/api/stt", method: "POST", models: STT_MODELS, defaultModel: STT_MODELS[0].id,
    outputType: "json", category: "ai", price: "50", denom: "PERSIST",
    inputFields: {
      audio: { type: "file", required: true, description: "Audio file (base64-encoded)" },
      model: { type: "string", required: false, description: "STT model ID" },
    },
  },
  {
    id: "image", name: "Image Generation", description: "Generate images from text prompts",
    endpoint: "/api/image", method: "POST", models: IMAGE_MODELS, defaultModel: IMAGE_MODELS[0].id,
    outputType: "image", category: "ai", price: "200", denom: "PERSIST",
    inputFields: {
      prompt: { type: "string", required: true, description: "Image description prompt", maxLength: 2000 },
      model: { type: "string", required: false, description: "Image model ID" },
      steps: { type: "number", required: false, description: "Inference steps (default 4)" },
    },
  },
  {
    id: "embed", name: "Text Embeddings", description: "Generate vector embeddings for text",
    endpoint: "/api/embed", method: "POST", models: EMBED_MODELS, defaultModel: EMBED_MODELS[0].id,
    outputType: "json", category: "ai", price: "10", denom: "PERSIST",
    inputFields: {
      text: { type: "string", required: true, description: "Text to embed", maxLength: 10000 },
      model: { type: "string", required: false, description: "Embeddings model ID" },
    },
  },
  {
    id: "translate", name: "Translation", description: "Translate text between 100+ languages",
    endpoint: "/api/translate", method: "POST", models: TRANSLATE_MODELS, defaultModel: TRANSLATE_MODELS[0].id,
    outputType: "json", category: "ai", price: "20", denom: "PERSIST",
    inputFields: {
      text: { type: "string", required: true, description: "Text to translate", maxLength: 5000 },
      source_lang: { type: "string", required: true, description: "Source language code (e.g. en)" },
      target_lang: { type: "string", required: true, description: "Target language code (e.g. fr)" },
      model: { type: "string", required: false, description: "Translation model ID" },
    },
  },
  {
    id: "vision", name: "Image Understanding", description: "Analyze and describe images with vision LLM",
    endpoint: "/api/vision", method: "POST", models: VISION_MODELS, defaultModel: VISION_MODELS[0].id,
    outputType: "json", category: "ai", price: "150", denom: "PERSIST",
    inputFields: {
      image: { type: "file", required: true, description: "Image (base64-encoded)" },
      prompt: { type: "string", required: false, description: "Question about the image" },
      model: { type: "string", required: false, description: "Vision model ID" },
    },
  },
  {
    id: "classify", name: "Text Classification", description: "Classify text sentiment (positive/negative)",
    endpoint: "/api/classify", method: "POST", models: CLASSIFY_MODELS, defaultModel: CLASSIFY_MODELS[0].id,
    outputType: "json", category: "ai", price: "10", denom: "PERSIST",
    inputFields: {
      text: { type: "string", required: true, description: "Text to classify", maxLength: 5000 },
      model: { type: "string", required: false, description: "Classification model ID" },
    },
  },
  {
    id: "summarize", name: "Summarization", description: "Summarize long text into concise form",
    endpoint: "/api/summarize", method: "POST", models: SUMMARIZE_MODELS, defaultModel: SUMMARIZE_MODELS[0].id,
    outputType: "json", category: "ai", price: "30", denom: "PERSIST",
    inputFields: {
      text: { type: "string", required: true, description: "Text to summarize", maxLength: 20000 },
      max_length: { type: "number", required: false, description: "Max summary length in tokens" },
      model: { type: "string", required: false, description: "Summarization model ID" },
    },
  },
  {
    id: "code", name: "Code Generation", description: "Generate and complete code with Qwen2.5-Coder",
    endpoint: "/api/code", method: "POST", models: CODE_MODELS, defaultModel: CODE_MODELS[0].id,
    outputType: "json", category: "ai", price: "100", denom: "PERSIST",
    inputFields: {
      messages: { type: "array", required: true, description: "OpenAI-format messages [{role, content}]" },
      model: { type: "string", required: false, description: "Code model ID" },
      max_tokens: { type: "number", required: false, description: "Max output tokens (default 2048)" },
    },
  },
  {
    id: "screenshot", name: "Webpage Screenshot", description: "Capture a webpage as an image using headless Chrome",
    endpoint: "/api/screenshot", method: "POST", models: [], defaultModel: "",
    outputType: "image", category: "utility", price: "50", denom: "PERSIST",
    inputFields: {
      url: { type: "string", required: true, description: "URL to screenshot" },
      width: { type: "number", required: false, description: "Viewport width (default 1280, max 1920)" },
      height: { type: "number", required: false, description: "Viewport height (default 720, max 1080)" },
    },
  },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function validateModel(modelId: string, allowed: ModelOption[]): string | null {
  if (allowed.length === 0) return null;
  if (!allowed.some((m) => m.id === modelId)) {
    return `Invalid model. Allowed: ${allowed.map((m) => m.id).join(", ")}`;
  }
  return null;
}

// ─── Service Handlers ─────────────────────────────────────────────────────────

async function handleLLM(ai: any, body: any): Promise<Response> {
  const { messages, model, max_tokens } = body;
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return jsonResponse({ error: "messages array required (OpenAI format: [{role, content}])" }, 400);
  }
  const modelId = model || LLM_MODELS[0].id;
  const err = validateModel(modelId, LLM_MODELS);
  if (err) return jsonResponse({ error: err }, 400);

  const result = await ai.run(modelId, {
    messages,
    max_tokens: Math.min(max_tokens || 1024, 4096),
  });
  return jsonResponse({ model: modelId, result });
}

async function handleTTS(ai: any, body: any): Promise<Response> {
  const { text, model } = body;
  if (!text || typeof text !== "string") {
    return jsonResponse({ error: "text string required" }, 400);
  }
  if (text.length > 5000) {
    return jsonResponse({ error: "text too long (max 5000 chars)" }, 400);
  }
  const modelId = model || TTS_MODELS[0].id;
  const err = validateModel(modelId, TTS_MODELS);
  if (err) return jsonResponse({ error: err }, 400);

  const audio = await ai.run(modelId, { prompt: text });
  return new Response(audio, {
    headers: { "Content-Type": "audio/wav", "X-Model": modelId },
  });
}

async function handleSTT(ai: any, body: any): Promise<Response> {
  const { audio, model } = body;
  if (!audio || typeof audio !== "string") {
    return jsonResponse({ error: "audio required (base64-encoded audio data)" }, 400);
  }
  const modelId = model || STT_MODELS[0].id;
  const err = validateModel(modelId, STT_MODELS);
  if (err) return jsonResponse({ error: err }, 400);

  const bytes = Uint8Array.from(atob(audio), (c) => c.charCodeAt(0));
  const result = await ai.run(modelId, { audio: [...bytes] });
  return jsonResponse({ model: modelId, result });
}

async function handleImageGen(ai: any, body: any): Promise<Response> {
  const { prompt, model, steps } = body;
  if (!prompt || typeof prompt !== "string") {
    return jsonResponse({ error: "prompt string required" }, 400);
  }
  if (prompt.length > 2000) {
    return jsonResponse({ error: "prompt too long (max 2000 chars)" }, 400);
  }
  const modelId = model || IMAGE_MODELS[0].id;
  const err = validateModel(modelId, IMAGE_MODELS);
  if (err) return jsonResponse({ error: err }, 400);

  const image = await ai.run(modelId, {
    prompt,
    num_steps: Math.min(steps || 4, 20),
  });
  return new Response(image, {
    headers: { "Content-Type": "image/png", "X-Model": modelId },
  });
}

async function handleEmbed(ai: any, body: any): Promise<Response> {
  const { text, model } = body;
  if (!text || typeof text !== "string") {
    return jsonResponse({ error: "text string required" }, 400);
  }
  if (text.length > 10000) {
    return jsonResponse({ error: "text too long (max 10000 chars)" }, 400);
  }
  const modelId = model || EMBED_MODELS[0].id;
  const err = validateModel(modelId, EMBED_MODELS);
  if (err) return jsonResponse({ error: err }, 400);

  const result = await ai.run(modelId, { text: [text] });
  return jsonResponse({ model: modelId, result });
}

async function handleTranslate(ai: any, body: any): Promise<Response> {
  const { text, source_lang, target_lang, model } = body;
  if (!text || typeof text !== "string") {
    return jsonResponse({ error: "text string required" }, 400);
  }
  if (!source_lang || !target_lang) {
    return jsonResponse({ error: "source_lang and target_lang required" }, 400);
  }
  if (text.length > 5000) {
    return jsonResponse({ error: "text too long (max 5000 chars)" }, 400);
  }
  const modelId = model || TRANSLATE_MODELS[0].id;
  const err = validateModel(modelId, TRANSLATE_MODELS);
  if (err) return jsonResponse({ error: err }, 400);

  const result = await ai.run(modelId, {
    text,
    source_lang,
    target_lang,
  });
  return jsonResponse({ model: modelId, result });
}

async function handleVision(ai: any, body: any): Promise<Response> {
  const { image, prompt, model } = body;
  if (!image || typeof image !== "string") {
    return jsonResponse({ error: "image required (base64-encoded)" }, 400);
  }
  const modelId = model || VISION_MODELS[0].id;
  const err = validateModel(modelId, VISION_MODELS);
  if (err) return jsonResponse({ error: err }, 400);

  const imageBytes = Uint8Array.from(atob(image), (c) => c.charCodeAt(0));
  const result = await ai.run(modelId, {
    messages: [
      {
        role: "user",
        content: [
          { type: "image", image: [...imageBytes] },
          { type: "text", text: prompt || "Describe this image in detail." },
        ],
      },
    ],
  });
  return jsonResponse({ model: modelId, result });
}

async function handleClassify(ai: any, body: any): Promise<Response> {
  const { text, model } = body;
  if (!text || typeof text !== "string") {
    return jsonResponse({ error: "text string required" }, 400);
  }
  if (text.length > 5000) {
    return jsonResponse({ error: "text too long (max 5000 chars)" }, 400);
  }
  const modelId = model || CLASSIFY_MODELS[0].id;
  const err = validateModel(modelId, CLASSIFY_MODELS);
  if (err) return jsonResponse({ error: err }, 400);

  const result = await ai.run(modelId, { text });
  return jsonResponse({ model: modelId, result });
}

async function handleSummarize(ai: any, body: any): Promise<Response> {
  const { text, max_length, model } = body;
  if (!text || typeof text !== "string") {
    return jsonResponse({ error: "text string required" }, 400);
  }
  if (text.length > 20000) {
    return jsonResponse({ error: "text too long (max 20000 chars)" }, 400);
  }
  const modelId = model || SUMMARIZE_MODELS[0].id;
  const err = validateModel(modelId, SUMMARIZE_MODELS);
  if (err) return jsonResponse({ error: err }, 400);

  const result = await ai.run(modelId, {
    input_text: text,
    max_length: max_length || 1024,
  });
  return jsonResponse({ model: modelId, result });
}

async function handleCode(ai: any, body: any): Promise<Response> {
  const { messages, model, max_tokens } = body;
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return jsonResponse({ error: "messages array required (OpenAI format)" }, 400);
  }
  const modelId = model || CODE_MODELS[0].id;
  const err = validateModel(modelId, CODE_MODELS);
  if (err) return jsonResponse({ error: err }, 400);

  const result = await ai.run(modelId, {
    messages,
    max_tokens: Math.min(max_tokens || 2048, 4096),
  });
  return jsonResponse({ model: modelId, result });
}

async function handleScreenshot(browser: any, body: any): Promise<Response> {
  if (!browser) {
    return jsonResponse({ error: "Browser rendering not available on this node" }, 503);
  }
  const { url, width, height } = body;
  if (!url || typeof url !== "string") {
    return jsonResponse({ error: "url string required" }, 400);
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return jsonResponse({ error: "Invalid URL" }, 400);
  }
  // SSRF protection
  const host = parsed.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host.startsWith("127.") ||
    host.startsWith("10.") ||
    host.startsWith("192.168.") ||
    host.startsWith("172.16.") ||
    host.endsWith(".local") ||
    host === "0.0.0.0"
  ) {
    return jsonResponse({ error: "Cannot screenshot private/internal URLs" }, 400);
  }

  // @cloudflare/puppeteer dynamic import (available in Workers with browser binding)
  const puppeteer = await import(/* @vite-ignore */ "@cloudflare/puppeteer").catch(() => { throw new Error("@cloudflare/puppeteer not available"); });
  const instance = await puppeteer.default.launch(browser);
  try {
    const page = await instance.newPage();
    await page.setViewport({
      width: Math.min(width || 1280, 1920),
      height: Math.min(height || 720, 1080),
    });
    await page.goto(url, { waitUntil: "networkidle0", timeout: 10_000 });
    const screenshot = await page.screenshot({ type: "png" });
    return new Response(screenshot, {
      headers: { "Content-Type": "image/png" },
    });
  } finally {
    await instance.close();
  }
}

// ─── Catalog (free, no payment required) ──────────────────────────────────────

export function handleCatalog(): Response {
  return jsonResponse({
    version: "1.0",
    protocol: "MPP/0.1",
    description: "Persistia AI Services Gateway — pay-per-call AI inference via the Machine Payment Protocol",
    denom: "PERSIST",
    free_neurons_per_day: 10000,
    services: SERVICE_CATALOG,
  });
}

// ─── Dispatcher ───────────────────────────────────────────────────────────────

const HANDLERS: Record<string, (ai: any, body: any) => Promise<Response>> = {
  llm: handleLLM,
  tts: handleTTS,
  stt: handleSTT,
  image: handleImageGen,
  embed: handleEmbed,
  translate: handleTranslate,
  vision: handleVision,
  classify: handleClassify,
  summarize: handleSummarize,
  code: handleCode,
};

// ─── AI Neuron Budget (free-tier: 10K neurons/day) ───────────────────────────

const DAILY_NEURON_BUDGET = 9000; // leave 10% headroom below 10K limit
const NEURON_COST_ESTIMATE: Record<string, number> = {
  chat: 1000,       // LLM inference
  summarize: 800,
  sentiment: 300,
  embedding: 200,
  classify: 300,
  tts: 500,
  translate: 500,
  code: 1000,
  screenshot: 0,    // uses Browser binding, not AI neurons
};

// In-memory daily tracking (resets on DO eviction, which is fine — it's a soft limit)
let _neuronBudget = { date: "", used: 0 };

function checkNeuronBudget(service: string): { ok: boolean; remaining: number } {
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  if (_neuronBudget.date !== today) {
    _neuronBudget = { date: today, used: 0 };
  }
  const cost = NEURON_COST_ESTIMATE[service] ?? 500;
  const remaining = DAILY_NEURON_BUDGET - _neuronBudget.used;
  if (cost > remaining) {
    return { ok: false, remaining };
  }
  _neuronBudget.used += cost;
  return { ok: true, remaining: remaining - cost };
}

export function getNeuronBudgetStatus(): { date: string; used: number; budget: number; remaining: number } {
  const today = new Date().toISOString().slice(0, 10);
  if (_neuronBudget.date !== today) return { date: today, used: 0, budget: DAILY_NEURON_BUDGET, remaining: DAILY_NEURON_BUDGET };
  return { date: _neuronBudget.date, used: _neuronBudget.used, budget: DAILY_NEURON_BUDGET, remaining: DAILY_NEURON_BUDGET - _neuronBudget.used };
}

export async function dispatchApiRoute(
  path: string,
  request: Request,
  env: { AI?: any; BROWSER?: any },
  attestationMgr?: ServiceAttestationManager | null,
): Promise<Response> {
  // /api/catalog — free GET endpoint
  const service = path.replace(/^\/api\//, "").replace(/\/$/, "");

  if (service === "catalog") {
    return handleCatalog();
  }

  // Attestation query endpoints (free, GET)
  if (service === "attestation" || service === "attestations" || service === "verify") {
    // These are handled in PersistiaDO directly
    return jsonResponse({ error: "Route to DO handler" }, 500);
  }

  // All other services require POST
  if (request.method !== "POST") {
    return jsonResponse({ error: "POST required" }, 405);
  }

  // Screenshot uses Browser binding, not AI
  if (service === "screenshot") {
    let body: any;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ error: "Invalid JSON body" }, 400);
    }
    try {
      const response = await handleScreenshot(env.BROWSER, body);
      return attestationMgr
        ? await wrapWithAttestation(response, service, "", JSON.stringify(body), attestationMgr)
        : response;
    } catch (e: any) {
      return jsonResponse({ error: "Screenshot failed", detail: e.message }, 500);
    }
  }

  // AI services
  if (!env.AI) {
    return jsonResponse({ error: "Workers AI not available on this node" }, 503);
  }

  const handler = HANDLERS[service];
  if (!handler) {
    return jsonResponse({
      error: `Unknown service: ${service}`,
      available: Object.keys(HANDLERS),
    }, 404);
  }

  // Neuron budget check — if exhausted, cascade LLM/code to inference pool
  const budget = checkNeuronBudget(service);
  if (!budget.ok) {
    if (service === "llm" || service === "code") {
      // Fall back to free inference pool
      try {
        let body: any;
        try { body = await request.clone().json(); } catch { return jsonResponse({ error: "Invalid JSON body" }, 400); }
        const pool = new InferencePool(env);
        const result = await pool.chat(body.messages || [], {
          model: body.model?.includes("llama") ? "llama-3.3-70b" : body.model?.includes("deepseek") ? "deepseek-r1" : "llama-3.3-70b",
          max_tokens: body.max_tokens,
        });
        return jsonResponse({
          model: result.model,
          provider: result.provider,
          source: "inference-pool",
          result: { response: result.content },
          usage: result.usage,
          latency_ms: result.latency_ms,
        });
      } catch (poolErr: any) {
        return jsonResponse({
          error: "Daily AI neuron budget exhausted and inference pool unavailable",
          detail: poolErr.message,
          remaining: budget.remaining,
        }, 429);
      }
    }
    return jsonResponse({
      error: "Daily AI neuron budget exhausted",
      remaining: budget.remaining,
      hint: "Use /api/pool/chat for LLM inference via free external providers",
    }, 429);
  }

  let body: any;
  let bodyRaw: string;
  try {
    bodyRaw = await request.text();
    body = JSON.parse(bodyRaw);
  } catch {
    return jsonResponse({ error: "Invalid JSON body" }, 400);
  }

  // Determine model for attestation
  const svcDef = SERVICE_CATALOG.find(s => s.id === service);
  const modelId = body.model || svcDef?.defaultModel || "unknown";

  // Pre-commit before inference (if attestation manager available)
  let preCommit: { pre_commitment: string; nonce: string; input_hash: string } | null = null;
  if (attestationMgr) {
    preCommit = await attestationMgr.preCommit(service, modelId, bodyRaw);
  }

  try {
    const response = await handler(env.AI, body);

    // Post-commit: create signed attestation
    if (attestationMgr && preCommit && response.ok) {
      return await wrapWithAttestation(response, service, modelId, bodyRaw, attestationMgr, preCommit);
    }
    return response;
  } catch (e: any) {
    return jsonResponse({ error: "AI inference failed", detail: e.message }, 500);
  }
}

/**
 * Clone a response, hash its body for the attestation, and attach
 * the attestation as an X-Attestation header.
 */
async function wrapWithAttestation(
  response: Response,
  service: string,
  model: string,
  inputRaw: string,
  mgr: ServiceAttestationManager,
  preCommit?: { pre_commitment: string; nonce: string; input_hash: string },
): Promise<Response> {
  try {
    // Clone so we can read the body for hashing while still returning it
    const clone = response.clone();
    const outputBytes = await clone.arrayBuffer();

    // If no pre-commit was provided (e.g. screenshot), create one now
    const pc = preCommit || await mgr.preCommit(service, model, inputRaw);

    const attestation = await mgr.attest({
      service,
      model: model || service,
      input_hash: pc.input_hash,
      output_bytes: new Uint8Array(outputBytes),
      pre_commitment: pc.pre_commitment,
      nonce: pc.nonce,
    });

    // Build new response with attestation header
    const attested = new Response(response.body, response);
    attested.headers.set("X-Attestation-Id", attestation.attestation_id);
    attested.headers.set("X-Attestation", btoa(JSON.stringify({
      attestation_id: attestation.attestation_id,
      prev_hash: attestation.prev_hash,
      model: attestation.model,
      input_hash: attestation.input_hash,
      output_hash: attestation.output_hash,
      pre_commitment: attestation.pre_commitment,
      node_pubkey: attestation.node_pubkey,
      node_signature: attestation.node_signature,
      timestamp: attestation.timestamp,
    })));
    return attested;
  } catch {
    // If attestation fails, still return the original response
    return response;
  }
}
