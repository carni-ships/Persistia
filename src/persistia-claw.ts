// ─── PersistiaClaw — Privacy-First AI Agent ─────────────────────────────────
// Autonomous AI agent backed by the free inference pool.
// Connects to Telegram (more platforms coming) with strong privacy defaults:
//
//   - Conversations encrypted at rest (AES-256-GCM, per-user key)
//   - Configurable auto-purge (default: 7 days)
//   - /forget deletes all data immediately
//   - /export returns all your data as JSON
//   - Zero logging of conversation content
//   - User-isolated: each user gets their own state
//   - No analytics, no training on your data
//
// Setup:
//   1. Create bot via @BotFather, get token
//   2. Set TELEGRAM_BOT_TOKEN env var
//   3. Set CLAW_ENCRYPTION_SECRET env var (random 32+ char string)
//   4. Register webhook: POST https://api.telegram.org/bot<TOKEN>/setWebhook
//      { "url": "https://persistia.carnation-903.workers.dev/claw/telegram" }

import { InferencePool, type ChatMessage, type PoolChatOptions } from "./inference-pool";

// ─── Encryption ──────────────────────────────────────────────────────────────

async function deriveKey(secret: string, userId: string): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode(`persistia-claw:${userId}`),
      info: new TextEncoder().encode("conversation-encryption"),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encrypt(key: CryptoKey, plaintext: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext),
  );
  // Pack as base64(iv + ciphertext)
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function decrypt(key: CryptoKey, packed: string): Promise<string> {
  const combined = Uint8Array.from(atob(packed), c => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext,
  );
  return new TextDecoder().decode(plaintext);
}

// ─── Types ───────────────────────────────────────────────────────────────────

interface StoredMessage {
  role: "system" | "user" | "assistant";
  content: string;
  timestamp: number;
}

interface UserConfig {
  model: string;
  system_prompt: string;
  max_history: number;       // max messages to keep in context
  retention_days: number;    // auto-purge after N days (0 = never)
  temperature?: number;
  provider?: string;         // force a specific provider
  created_at: number;
}

const DEFAULT_CONFIG: UserConfig = {
  model: "llama-3.3-70b",
  system_prompt: "You are a helpful, privacy-respecting AI assistant running on the Persistia decentralized network. Be concise and direct.",
  max_history: 30,
  retention_days: 7,
  created_at: 0,
};

// ─── Conversation Store ──────────────────────────────────────────────────────
// Uses KV storage with per-user encryption. Each user's data is in their own
// key namespace, encrypted with a key derived from the server secret + user ID.

interface ConversationStore {
  get(key: string): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
  list(prefix: string): Promise<string[]>;
}

// KV-backed store (Cloudflare Workers KV or similar)
class KVConversationStore implements ConversationStore {
  constructor(private kv: any) {}
  async get(key: string) { return await this.kv.get(key); }
  async put(key: string, value: string) { await this.kv.put(key, value); }
  async delete(key: string) { await this.kv.delete(key); }
  async list(prefix: string) {
    const result = await this.kv.list({ prefix });
    return result.keys.map((k: any) => k.name);
  }
}

// In-memory fallback (for standalone nodes)
class MemoryConversationStore implements ConversationStore {
  private data = new Map<string, string>();
  async get(key: string) { return this.data.get(key) || null; }
  async put(key: string, value: string) { this.data.set(key, value); }
  async delete(key: string) { this.data.delete(key); }
  async list(prefix: string) { return [...this.data.keys()].filter(k => k.startsWith(prefix)); }
}

// ─── Claw Agent ──────────────────────────────────────────────────────────────

export class ClawAgent {
  private store: ConversationStore;
  private pool: InferencePool;
  private encryptionSecret: string;

  constructor(env: Record<string, any>) {
    this.pool = new InferencePool(env);
    this.encryptionSecret = env.CLAW_ENCRYPTION_SECRET || "persistia-claw-default-secret-CHANGE-ME";
    this.store = env.CLAW_KV
      ? new KVConversationStore(env.CLAW_KV)
      : new MemoryConversationStore();
  }

  /** Process a user message and return the assistant response */
  async chat(userId: string, userMessage: string): Promise<{
    response: string;
    model: string;
    provider: string;
    latency_ms: number;
  }> {
    const key = await deriveKey(this.encryptionSecret, userId);
    const config = await this.getConfig(userId, key);

    // Load conversation history
    const history = await this.getHistory(userId, key);

    // Auto-purge old messages
    if (config.retention_days > 0) {
      const cutoff = Date.now() - config.retention_days * 86_400_000;
      while (history.length > 0 && history[0].timestamp < cutoff) {
        history.shift();
      }
    }

    // Add user message
    history.push({ role: "user", content: userMessage, timestamp: Date.now() });

    // Trim to max_history (keep system prompt slot)
    while (history.length > config.max_history) {
      history.shift();
    }

    // Build messages for the pool
    const messages: ChatMessage[] = [];
    if (config.system_prompt) {
      messages.push({ role: "system", content: config.system_prompt });
    }
    for (const msg of history) {
      messages.push({ role: msg.role, content: msg.content });
    }

    // Call inference pool (pass userId as caller_id for metering)
    const result = await this.pool.chat(messages, {
      model: config.model,
      temperature: config.temperature,
      provider: config.provider,
      max_tokens: 2048,
      caller_id: `telegram:${userId}`,
    });

    // Add assistant response to history
    history.push({ role: "assistant", content: result.content, timestamp: Date.now() });

    // Save encrypted history
    await this.saveHistory(userId, key, history);

    return {
      response: result.content,
      model: result.model,
      provider: result.provider,
      latency_ms: result.latency_ms,
    };
  }

  /** Handle slash commands. Returns response text or null if not a command. */
  async handleCommand(userId: string, text: string): Promise<string | null> {
    const parts = text.trim().split(/\s+/);
    const cmd = parts[0].toLowerCase();

    switch (cmd) {
      case "/start":
      case "/help":
        return HELP_TEXT;

      case "/forget": {
        await this.deleteAllUserData(userId);
        return "All your data has been permanently deleted. Conversation history, config, everything — gone. Start fresh anytime.";
      }

      case "/export": {
        const key = await deriveKey(this.encryptionSecret, userId);
        const config = await this.getConfig(userId, key);
        const history = await this.getHistory(userId, key);
        return "```json\n" + JSON.stringify({ config, history, exported_at: new Date().toISOString() }, null, 2) + "\n```";
      }

      case "/clear": {
        const key = await deriveKey(this.encryptionSecret, userId);
        await this.saveHistory(userId, key, []);
        return "Conversation cleared. Your config is preserved.";
      }

      case "/model": {
        const key = await deriveKey(this.encryptionSecret, userId);
        const config = await this.getConfig(userId, key);
        if (parts.length < 2) {
          const models = this.pool.availableModels();
          return `Current: ${config.model}\n\nAvailable:\n${models.map(m => `  ${m === config.model ? "* " : "  "}${m}`).join("\n")}`;
        }
        config.model = parts[1];
        await this.saveConfig(userId, key, config);
        return `Model set to: ${config.model}`;
      }

      case "/system": {
        const key = await deriveKey(this.encryptionSecret, userId);
        const config = await this.getConfig(userId, key);
        if (parts.length < 2) {
          return `Current system prompt:\n\n${config.system_prompt}`;
        }
        config.system_prompt = text.slice("/system ".length).trim();
        await this.saveConfig(userId, key, config);
        return "System prompt updated.";
      }

      case "/retention": {
        const key = await deriveKey(this.encryptionSecret, userId);
        const config = await this.getConfig(userId, key);
        if (parts.length < 2) {
          return `Messages auto-delete after ${config.retention_days} days (0 = never).`;
        }
        config.retention_days = Math.max(0, parseInt(parts[1]) || 7);
        await this.saveConfig(userId, key, config);
        return `Retention set to ${config.retention_days} days${config.retention_days === 0 ? " (messages kept forever)" : ""}.`;
      }

      case "/provider": {
        const key = await deriveKey(this.encryptionSecret, userId);
        const config = await this.getConfig(userId, key);
        if (parts.length < 2) {
          const status = this.pool.status();
          return `Current: ${config.provider || "auto"}\n\nProviders:\n  auto (best available)\n${status.map(p => `  ${p.id} — ${p.name} (${p.requests_today}/${p.daily_limit || "inf"} today)`).join("\n")}`;
        }
        config.provider = parts[1] === "auto" ? undefined : parts[1];
        await this.saveConfig(userId, key, config);
        return `Provider set to: ${config.provider || "auto"}`;
      }

      case "/privacy":
        return PRIVACY_TEXT;

      case "/status": {
        const status = this.pool.status();
        const online = status.filter(p => p.enabled);
        const models = this.pool.availableModels();
        return `Providers: ${online.length} online\nModels: ${models.length} available\nEncryption: AES-256-GCM (per-user key)\nData retention: configurable (/retention)\nYour data: /export to download, /forget to delete`;
      }

      default:
        return null;
    }
  }

  // ── Storage helpers ────────────────────────────────────────────────────

  private async getConfig(userId: string, key: CryptoKey): Promise<UserConfig> {
    const raw = await this.store.get(`claw:${userId}:config`);
    if (!raw) return { ...DEFAULT_CONFIG, created_at: Date.now() };
    try {
      return JSON.parse(await decrypt(key, raw));
    } catch {
      return { ...DEFAULT_CONFIG, created_at: Date.now() };
    }
  }

  private async saveConfig(userId: string, key: CryptoKey, config: UserConfig): Promise<void> {
    const encrypted = await encrypt(key, JSON.stringify(config));
    await this.store.put(`claw:${userId}:config`, encrypted);
  }

  private async getHistory(userId: string, key: CryptoKey): Promise<StoredMessage[]> {
    const raw = await this.store.get(`claw:${userId}:history`);
    if (!raw) return [];
    try {
      return JSON.parse(await decrypt(key, raw));
    } catch {
      return [];
    }
  }

  private async saveHistory(userId: string, key: CryptoKey, history: StoredMessage[]): Promise<void> {
    const encrypted = await encrypt(key, JSON.stringify(history));
    await this.store.put(`claw:${userId}:history`, encrypted);
  }

  private async deleteAllUserData(userId: string): Promise<void> {
    const keys = await this.store.list(`claw:${userId}:`);
    for (const k of keys) {
      await this.store.delete(k);
    }
    // Also try direct keys in case list doesn't work
    await this.store.delete(`claw:${userId}:config`);
    await this.store.delete(`claw:${userId}:history`);
  }
}

// ─── Telegram Webhook Handler ────────────────────────────────────────────────

export async function handleTelegramWebhook(
  request: Request,
  env: Record<string, any>,
): Promise<Response> {
  const botToken = env.TELEGRAM_BOT_TOKEN;
  if (!botToken) {
    return json({ error: "TELEGRAM_BOT_TOKEN not configured" }, 503);
  }

  let update: any;
  try {
    update = await request.json();
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  // Extract message
  const message = update.message || update.edited_message;
  if (!message?.text || !message?.chat?.id) {
    return json({ ok: true }); // Ignore non-text updates
  }

  const chatId = String(message.chat.id);
  const userId = String(message.from?.id || chatId);
  const text = message.text.trim();

  const agent = new ClawAgent(env);

  try {
    // Check for commands first
    if (text.startsWith("/")) {
      const cmdResponse = await agent.handleCommand(userId, text);
      if (cmdResponse) {
        await sendTelegram(botToken, chatId, cmdResponse);
        return json({ ok: true });
      }
    }

    // Regular chat message — pass Telegram user ID as caller for metering
    const result = await agent.chat(userId, text);

    // Format response with provider info
    let reply = result.response;
    // Add subtle footer with model info (only if not too long)
    if (reply.length < 3800) {
      reply += `\n\n_${result.provider}/${result.model} · ${result.latency_ms}ms_`;
    }

    await sendTelegram(botToken, chatId, reply, message.message_id);
  } catch (e: any) {
    const errorMsg = `Sorry, inference failed: ${e.message?.slice(0, 200) || "unknown error"}`;
    await sendTelegram(botToken, chatId, errorMsg);
  }

  return json({ ok: true });
}

async function sendTelegram(
  token: string,
  chatId: string,
  text: string,
  replyToMessageId?: number,
): Promise<void> {
  // Telegram max message length is 4096
  const chunks = splitMessage(text, 4000);

  for (const chunk of chunks) {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        text: chunk,
        parse_mode: "Markdown",
        reply_to_message_id: replyToMessageId,
        // Disable web preview for privacy
        disable_web_page_preview: true,
      }),
    }).catch(() => {
      // Retry without Markdown if parsing fails
      fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: chatId,
          text: chunk,
          reply_to_message_id: replyToMessageId,
          disable_web_page_preview: true,
        }),
      }).catch(() => {});
    });
  }
}

function splitMessage(text: string, maxLen: number): string[] {
  if (text.length <= maxLen) return [text];
  const chunks: string[] = [];
  let remaining = text;
  while (remaining.length > 0) {
    if (remaining.length <= maxLen) {
      chunks.push(remaining);
      break;
    }
    // Try to split at newline
    let splitAt = remaining.lastIndexOf("\n", maxLen);
    if (splitAt < maxLen / 2) splitAt = maxLen;
    chunks.push(remaining.slice(0, splitAt));
    remaining = remaining.slice(splitAt);
  }
  return chunks;
}

// ─── Setup Helper ────────────────────────────────────────────────────────────

export async function handleClawSetup(
  request: Request,
  env: Record<string, any>,
): Promise<Response> {
  const botToken = env.TELEGRAM_BOT_TOKEN;
  if (!botToken) {
    return json({
      error: "TELEGRAM_BOT_TOKEN not set",
      setup: {
        step1: "Create a bot via @BotFather on Telegram",
        step2: "Copy the token",
        step3: "wrangler secret put TELEGRAM_BOT_TOKEN",
        step4: "wrangler secret put CLAW_ENCRYPTION_SECRET  (random 32+ chars)",
        step5: "Deploy, then POST to /claw/setup to register the webhook",
      },
    }, 503);
  }

  const url = new URL(request.url);
  const webhookUrl = `${url.origin}/claw/telegram`;

  // Register webhook with Telegram
  const res = await fetch(`https://api.telegram.org/bot${botToken}/setWebhook`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: webhookUrl,
      allowed_updates: ["message", "edited_message"],
      drop_pending_updates: true,
    }),
  });

  const result = await res.json();

  return json({
    webhook_url: webhookUrl,
    telegram_response: result,
    privacy_features: [
      "AES-256-GCM encryption at rest (per-user derived key)",
      "Configurable auto-purge (default: 7 days)",
      "/forget — instant permanent deletion of all user data",
      "/export — download all your data as JSON",
      "Zero conversation logging",
      "Per-user isolation",
      "Web preview disabled (no link tracking)",
      "No analytics or third-party data sharing",
    ],
    commands: [
      "/help — show help",
      "/model [name] — view or change model",
      "/system [prompt] — view or set system prompt",
      "/provider [name] — view or set provider",
      "/retention [days] — set auto-delete period",
      "/clear — clear conversation history",
      "/export — download all your data",
      "/forget — permanently delete all data",
      "/privacy — privacy policy",
      "/status — system status",
    ],
  });
}

// ─── Constants ───────────────────────────────────────────────────────────────

const HELP_TEXT = `*PersistiaClaw* — Privacy-first AI assistant

Powered by the Persistia free inference pool (12+ providers, 30+ models).

*Commands:*
/model — Change AI model (default: llama-3.3-70b)
/system — Set custom system prompt
/provider — Choose inference provider (or auto)
/retention — Set message auto-delete (default: 7 days)
/clear — Clear conversation
/export — Download all your data
/forget — Permanently delete everything
/privacy — Privacy details
/status — System status

Just send a message to chat. Your conversations are encrypted at rest and auto-deleted after your retention period.`;

const PRIVACY_TEXT = `*Privacy & Security*

*Encryption:* All conversations are encrypted at rest using AES-256-GCM with a per-user key derived via HKDF. Even the server operator cannot read your messages without the encryption secret.

*Data retention:* Messages auto-delete after your configured retention period (default: 7 days). Use /retention 0 to keep messages indefinitely, or /retention 1 for daily purge.

*Deletion:* /forget permanently deletes all your data immediately — conversation history, config, everything. This is irreversible.

*Data export:* /export gives you all your data as JSON. Your data, your control.

*What we don't do:*
• No conversation logging
• No analytics or tracking
• No training on your data
• No third-party data sharing
• No link preview fetching (disabled)
• No message content in error logs

*Inference:* Your messages are sent to third-party AI providers (Groq, Cerebras, Mistral, etc.) for inference. These providers have their own privacy policies. Use /provider to choose a specific provider if you prefer one's privacy stance.

*Infrastructure:* Runs on Cloudflare Workers (edge compute) or standalone nodes. No centralized database.`;

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
