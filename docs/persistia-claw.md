# PersistiaClaw

Privacy-first AI agent powered by the Persistia free inference pool. Like OpenClaw, but hosted, free, and encrypted.

## What It Is

PersistiaClaw is an autonomous AI assistant that connects to messaging platforms (starting with Telegram) and routes all inference through Persistia's free inference gateway — 12+ providers, 30+ models, $0 cost. Every conversation is encrypted at rest with per-user keys.

## Architecture

```
Telegram / WhatsApp / Discord / Slack (future)
        |
        v
  /claw/telegram webhook (Cloudflare Worker)
        |
        v
  ClawAgent (per-user state)
    - Decrypt conversation history (AES-256-GCM)
    - Apply retention policy (auto-purge)
    - Build messages array
        |
        v
  InferencePool (cascading provider router)
    - Per-user metering (100 req/day, 5 req/min)
    - Per-provider rate limits + daily quotas
    - Fallback cascade: Groq -> Cerebras -> Gemini -> ...
        |
        v
  Free-tier AI provider (Groq, Cerebras, Mistral, etc.)
        |
        v
  Response -> Encrypt updated history -> Send via Telegram API
```

## Security & Privacy

### Encryption

| Layer | Method | Details |
|-------|--------|---------|
| At rest | AES-256-GCM | Per-user key derived via HKDF(server_secret, user_id) |
| Key derivation | HKDF-SHA256 | Salt: `persistia-claw:{userId}`, Info: `conversation-encryption` |
| In transit | HTTPS/TLS | All provider APIs and Telegram API over TLS |
| Key storage | Server secret | Single `CLAW_ENCRYPTION_SECRET` env var, never exposed |

### Data Lifecycle

```
Message received
  -> Decrypt history with user's derived key
  -> Process (add message, trim to max_history, purge expired)
  -> Send to inference provider (text only, no metadata)
  -> Encrypt updated history
  -> Store encrypted blob
  -> Response sent to user

/forget command
  -> Delete all keys matching claw:{userId}:*
  -> Immediate, permanent, irreversible
```

### What We Don't Do

- No conversation content in logs or error messages
- No analytics, tracking, or telemetry
- No training on user data
- No third-party data sharing beyond inference providers
- No link preview fetching (Telegram web preview disabled)
- No message content in crash reports
- No persistent user profiles beyond encrypted config

### What We Do Disclose

- Messages are sent to third-party AI providers for inference (Groq, Cerebras, Mistral, Google, etc.)
- Each provider has its own privacy policy
- Users can force a specific provider via `/provider` command
- Provider identity is shown on every response

## Metering & Abuse Prevention

### Per-User Limits (Default)

| Limit | Value | Configurable Via |
|-------|-------|------------------|
| Requests per minute | 5 | `POOL_PER_USER_RPM` env var |
| Requests per hour | 30 | `POOL_PER_USER_RPH` env var |
| Requests per day | 100 | `POOL_PER_USER_DAILY_LIMIT` env var |

### Global Limits (Default)

| Limit | Value | Configurable Via |
|-------|-------|------------------|
| Global requests per minute | 30 | `POOL_GLOBAL_RPM` env var |
| Global requests per day | 5,000 | `POOL_GLOBAL_DAILY_LIMIT` env var |

### Caller Identification

The metering system identifies callers by (in priority order):
1. `X-API-Key` header (for API users)
2. `Authorization: Bearer <token>` header
3. `CF-Connecting-IP` / `X-Forwarded-For` (for web/anonymous users)
4. Telegram user ID (for bot users, prefixed `telegram:`)

Admin bypass: set `POOL_ADMIN_SECRET` env var, pass it as Bearer token.

### Per-Provider Limits

Each upstream provider has its own rate limits enforced independently:

| Provider | Daily Limit | RPM |
|----------|-------------|-----|
| Groq | 14,400 | 30 |
| Cerebras | 1,000 | 30 |
| SambaNova | 200 | 10 |
| Gemini | 1,500 | 15 |
| Mistral | unlimited | 1 |
| OpenRouter | 200 | 20 |
| Together.ai | credit-based | 60 |
| NVIDIA NIM | credit-based | 40 |
| DeepSeek | 50 | 10 |
| GitHub Models | 50 | 10 |
| Cohere | 33 | 10 |
| Cloudflare Workers AI | 200 | 60 |

## API Endpoints

### Telegram Webhook

```
POST /claw/telegram
```

Receives Telegram webhook updates. Register via `/claw/setup`.

### Setup

```
GET /claw/setup
POST /claw/setup
```

Registers the Telegram webhook and returns configuration info.

### Inference Gateway (OpenAI-Compatible)

```
POST /v1/chat/completions
GET  /v1/models
```

Drop-in replacement for OpenAI API. Works with any OpenAI SDK.

### Inference Gateway (Anthropic-Compatible)

```
POST /v1/messages
```

Drop-in replacement for Anthropic Messages API.

### Pool Management

```
GET /api/pool/status     — Provider status + usage
GET /api/pool/models     — Available models + routing
GET /api/pool/metering   — Per-user usage stats + top callers
POST /api/pool/chat      — Chat completions (same as /v1/chat/completions)
```

## User Commands (Telegram)

| Command | Description |
|---------|-------------|
| `/help` | Show help text |
| `/model [name]` | View or change AI model (default: `llama-3.3-70b`) |
| `/system [prompt]` | View or set custom system prompt |
| `/provider [name]` | View or set inference provider (`auto` for best available) |
| `/retention [days]` | Set auto-delete period (default: 7, 0 = keep forever) |
| `/clear` | Clear conversation history (keeps config) |
| `/export` | Download all your data as JSON |
| `/forget` | Permanently delete all data (irreversible) |
| `/privacy` | View full privacy policy |
| `/status` | View system status (providers online, models, encryption) |

## Setup Guide

### 1. Create Telegram Bot

1. Open Telegram, message [@BotFather](https://t.me/BotFather)
2. Send `/newbot`, follow prompts
3. Copy the bot token

### 2. Configure Secrets

```bash
# Required
wrangler secret put TELEGRAM_BOT_TOKEN      # from BotFather
wrangler secret put CLAW_ENCRYPTION_SECRET   # random 32+ char string

# Inference provider keys (add as many as you want)
wrangler secret put GROQ_API_KEY
wrangler secret put CEREBRAS_API_KEY
wrangler secret put GEMINI_API_KEY
wrangler secret put MISTRAL_API_KEY
wrangler secret put SAMBANOVA_API_KEY
wrangler secret put OPENROUTER_API_KEY
wrangler secret put TOGETHER_API_KEY
wrangler secret put NVIDIA_API_KEY
wrangler secret put DEEPSEEK_API_KEY
wrangler secret put GITHUB_TOKEN
wrangler secret put COHERE_API_KEY

# Optional: metering config
# (set in wrangler.toml [vars] or as secrets)
# POOL_PER_USER_DAILY_LIMIT = "100"
# POOL_PER_USER_RPM = "5"
# POOL_GLOBAL_DAILY_LIMIT = "5000"
# POOL_ADMIN_SECRET = "your-admin-key"

# Optional: KV namespace for persistent conversation storage
# wrangler kv:namespace create CLAW_KV
# Add the binding to wrangler.toml
```

### 3. Deploy

```bash
wrangler deploy
```

### 4. Register Webhook

```bash
curl https://persistia.carnation-903.workers.dev/claw/setup
```

### 5. Test

Open Telegram, message your bot, say "Hello!"

## Standalone Node Setup

PersistiaClaw also runs on standalone nodes (Oracle Cloud, AWS, etc.):

```bash
cd standalone
# Set env vars
export TELEGRAM_BOT_TOKEN="..."
export CLAW_ENCRYPTION_SECRET="..."
export GROQ_API_KEY="..."

# Run
tsx src/server.ts --port 3000

# Register webhook manually
curl -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/setWebhook" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://your-node.example.com/claw/telegram"}'
```

## Comparison

| Feature | OpenClaw | NanoClaw | IronClaw | PersistiaClaw |
|---------|----------|----------|----------|---------------|
| Hosting | Self-hosted | Self-hosted | Self-hosted | Hosted (decentralized) |
| AI cost | You pay API keys | You pay API keys | You pay API keys | Free (12+ providers) |
| Setup | Complex (50+ integrations) | Medium (Docker) | Medium (Rust) | 2 secrets + deploy |
| Encryption | Your responsibility | Container isolation | WASM sandbox | AES-256-GCM per-user |
| Data deletion | Manual | Manual | Manual | `/forget` (instant) |
| Data export | Varies | Varies | Varies | `/export` (JSON) |
| Rate limiting | None | None | None | Per-user + global |
| Platforms | 50+ | 50+ (via OpenClaw) | Limited | Telegram (more coming) |
| LOC | ~200K+ | ~3,900 | ~10K+ | ~450 |
| GitHub stars | 60K+ | Growing | Growing | New |

## Roadmap

- [ ] WhatsApp integration (via WhatsApp Business API)
- [ ] Discord bot integration
- [ ] Slack app integration
- [ ] Signal integration (via signal-cli)
- [ ] Tool execution (web search, code execution, file management)
- [ ] Multi-modal support (image analysis via vision models)
- [ ] Persistent KV storage (Cloudflare KV or D1)
- [ ] User-provided API keys (bring your own, bypass free tier limits)
- [ ] Group chat support
- [ ] Scheduled messages / reminders
- [ ] Webhook integrations (GitHub, calendar, etc.)
