# Persistia Backlog

> All remaining roadmap items across Inference Gateway, PersistiaClaw, Consensus, and Infrastructure.
> Last updated: 2026-04-02

---

## Inference Gateway

### High Priority

- [ ] **Persistent metering storage** — Current in-memory metering resets on Worker eviction. Use Cloudflare D1 or KV to persist per-caller usage counters across restarts.
- [ ] **User-provided API keys** — Let users bring their own provider keys via `X-Provider-Key` header to bypass free-tier limits. Route directly to provider with user's key.
- [ ] **Response caching** — Cache identical prompts (hash of model+messages) in KV with configurable TTL. Reduces provider load and latency for repeated queries.
- [ ] **Provider health monitoring** — Track error rates per provider over sliding windows. Auto-disable providers with >50% error rate. Expose health dashboard.
- [ ] **Image/vision model support** — Route `image_url` content blocks to vision-capable providers (Gemini, GPT-4V via OpenRouter). Validate base64 size limits.

### Medium Priority

- [ ] **Prompt routing intelligence** — Analyze prompt complexity/length to route to best provider (short prompts → Groq for speed, long context → Gemini for 1M window).
- [ ] **Multi-modal support** — Audio transcription (Groq Whisper), image generation (Cloudflare Workers AI Stable Diffusion), TTS.
- [ ] **OpenAI Assistants API compatibility** — Threads, runs, file search. Enables drop-in replacement for OpenAI Assistants SDK users.
- [ ] **Batch API** — Accept array of chat completion requests, process in parallel across providers, return results. Useful for evaluation pipelines.
- [ ] **Usage analytics dashboard** — Per-user usage history, popular models, provider distribution, latency percentiles. Expose at `/api/pool/analytics`.
- [ ] **Provider cost tracking** — Track which free-tier quotas are being consumed fastest. Alert when a provider is near daily exhaustion.
- [ ] **Retry with model fallback** — When a specific model fails on all providers, fall back to a similar model (e.g., Llama 3.3 70B → Llama 3.1 70B → Qwen 72B).

### Low Priority

- [ ] **Custom model aliases** — Let users define model aliases (e.g., "fast" → groq:llama-3.3-70b, "smart" → gemini:gemini-2.0-flash).
- [ ] **Webhook callbacks** — For long-running completions, accept a webhook URL and POST the result when ready.
- [ ] **Provider leaderboard** — Public page showing real-time speed, uptime, and model availability per provider.

---

## PersistiaClaw (AI Agent)

### High Priority

- [ ] **Persistent KV storage** — Move conversation storage from in-memory to Cloudflare KV (CLAW_KV binding). Conversations survive Worker restarts.
- [ ] **WhatsApp integration** — WhatsApp Business API webhook handler. Similar architecture to Telegram handler.
- [ ] **Discord bot integration** — Discord gateway or webhook-based bot. Support slash commands mapping to Claw commands.
- [ ] **Tool execution** — Web search (via Brave/DuckDuckGo API), code execution (via Cloudflare Workers sandbox), URL content fetching.
- [ ] **Streaming responses** — Stream AI responses to Telegram via message editing (send partial → edit with more text → edit with final).

### Medium Priority

- [ ] **Slack app integration** — Slack Events API handler for direct messages and mentions.
- [ ] **Signal integration** — Via signal-cli or signal-bot library.
- [ ] **Group chat support** — Handle group messages in Telegram/Discord. Context isolation per group. @mention trigger.
- [ ] **Multi-modal input** — Accept images in Telegram, route to vision models (Gemini, GPT-4V). OCR for documents.
- [ ] **Scheduled messages / reminders** — `/remind 3h Check deployment` — store in KV, use Durable Object alarm to trigger.
- [ ] **Conversation summarization** — When history exceeds max_history, summarize older messages instead of truncating.
- [ ] **Admin dashboard** — Web UI showing active users, message volume, provider usage, error rates per Claw instance.

### Low Priority

- [ ] **Webhook integrations** — GitHub (PR notifications), Google Calendar (reminders), RSS feeds.
- [ ] **Custom personas** — Pre-built system prompts (coding assistant, writing helper, language tutor) selectable via `/persona`.
- [ ] **Voice messages** — Transcribe Telegram voice messages via Groq Whisper, respond with TTS.
- [ ] **Plugin system** — Let users add custom tools/integrations via a simple plugin API.

---

## Consensus & Ledger

### High Priority

- [ ] **Cross-shard transactions** — Atomic operations spanning multiple shards. Two-phase commit or saga pattern.
- [ ] **State snapshots** — Periodic state snapshots for fast node sync. New nodes download snapshot + replay recent blocks instead of full history.
- [ ] **Garbage collection** — Prune old DAG vertices that are finalized and have no pending references. Reduce storage growth.

### Medium Priority

- [ ] **Dynamic validator set** — Add/remove validators without restarting the network. Stake-based or reputation-based admission.
- [ ] **Light client protocol** — Merkle proof verification without full state. Enable browser-based validation.
- [ ] **Transaction receipts** — Emit structured receipts with logs/events for each committed transaction. Enable event-driven apps.
- [ ] **Read replicas** — Non-voting nodes that sync state for read-heavy workloads. Reduce load on validator DOs.

### Low Priority

- [ ] **DAG visualization** — Real-time WebSocket-driven DAG graph showing vertices, edges, rounds, and finalization.
- [ ] **Formal verification** — TLA+ or Alloy spec of the BFT consensus protocol.
- [ ] **Performance benchmarking** — Automated TPS benchmarking under various network conditions and validator counts.

---

## Oracle Network

### High Priority

- [ ] **Multi-source aggregation mode** — Optional median/TWAP aggregation across 2+ sources per feed for high-value use cases.
- [ ] **Historical price storage** — Store price history in D1/KV for TWAP, VWAP, and volatility calculations.
- [ ] **Push oracle reliability** — Retry logic, dead-letter queue, and monitoring for cross-chain relay failures.

### Medium Priority

- [ ] **Custom feed registration** — API to register new price feeds pointing to arbitrary on-chain or off-chain sources.
- [ ] **Deviation-triggered updates** — Push updates only when price deviates >X% from last pushed value (gas optimization).
- [ ] **Oracle staking** — Require attestors to stake tokens. Slash for providing stale/incorrect data.

### Low Priority

- [ ] **Oracle dashboard** — Web UI showing all feeds, latest prices, update frequency, staleness alerts.
- [ ] **Chainlink Functions integration** — Use Chainlink Functions for custom off-chain computation.

---

## Infrastructure & DevOps

### High Priority

- [ ] **Standalone node Docker image** — Dockerfile for the Express+SQLite standalone validator. One-command deploy.
- [ ] **Auto-discovery / bootstrap** — New nodes auto-discover peers via DNS seeds or a bootstrap endpoint instead of hardcoded peer lists.
- [ ] **Monitoring & alerting** — Grafana dashboards + PagerDuty/Discord alerts for node health, consensus liveness, provider status.
- [ ] **Heterogeneous node sync** — Ensure CF Worker nodes and standalone nodes can seamlessly sync state and participate in consensus.

### Medium Priority

- [ ] **Terraform/Pulumi templates** — Infrastructure-as-code for deploying standalone nodes on Oracle Cloud, AWS, GCP free tiers.
- [ ] **CI/CD pipeline** — GitHub Actions for automated testing, build verification, and deployment on push to main.
- [ ] **Load testing** — k6 or artillery scripts for stress testing inference gateway, consensus, and oracle endpoints.
- [ ] **Log aggregation** — Ship Worker logs to Grafana Loki or similar for centralized debugging.

### Low Priority

- [ ] **Multi-region deployment** — Deploy CF Workers to specific regions for latency optimization. Standalone nodes in diverse geos.
- [ ] **Chaos engineering** — Automated failure injection (kill nodes, partition network, spike load) to validate resilience.
- [ ] **Documentation site** — Static site (Astro/VitePress) with guides, API reference, and architecture docs.

---

## Service Federation & Marketplace

### High Priority

- [ ] **Provider bond/slash mechanism** — Implement the staking and slashing logic for inference providers in the marketplace.
- [ ] **Escrow & settlement** — Hold payment in escrow during inference, release on verified completion.
- [ ] **Provider reputation system** — Track latency, error rate, and uptime per provider. Surface scores in marketplace.

### Medium Priority

- [ ] **SLA enforcement** — Define and enforce SLAs (max latency, uptime guarantees) with automated penalties.
- [ ] **Provider self-registration** — API for new inference providers to register, stake, and start receiving traffic.
- [ ] **Billing integration** — Stripe/crypto payment rails for paid tiers above free limits.

---

## ZK Proving

### High Priority

- [ ] **Proof batching** — Aggregate multiple state transitions into a single ZK proof for gas efficiency.
- [ ] **Proof verification on-chain** — Deploy and test Jolt/Noir verifier contracts on target L1/L2 chains.

### Medium Priority

- [ ] **Recursive proofs** — Compose incremental Merkle proofs into recursive SNARKs for compact state certificates.
- [ ] **Prover marketplace** — Outsource proof generation to nodes with GPU capability. Pay per proof.
- [ ] **zkMetal SDK release** — Publish the generic Noir prover SDK as a standalone npm/crate package.

---

*Total: ~60 items across 7 workstreams. Priorities are relative within each section.*
