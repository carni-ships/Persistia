# Free-Tier Compute & Infrastructure Reference (2025-2026)

> Definitive reference for deploying Persistia validator nodes and AI inference at zero cost.
> Last updated: 2026-04-02

---

## 1. Free VPS / Cloud Compute

### Oracle Cloud Infrastructure (OCI) -- BEST IN CLASS

| Resource | Spec |
|---|---|
| ARM VM (Ampere A1) | **4 OCPUs, 24 GB RAM** (splittable into up to 4 VMs) |
| AMD VM (x86) | 2x VM.Standard.E2.1.Micro -- 1/8 OCPU, 1 GB RAM each |
| Boot volume | 200 GB total block storage |
| Outbound bandwidth | 10 TB/month |
| Duration | **Always free** (no expiry, no credit card trial) |
| Object Storage | 10 GB (Standard), 10 GB (Infrequent Access) |
| Autonomous DB | 2x 20 GB each |

**Persistia use case:** Run 2-4 validator nodes on the ARM allocation. The 24 GB RAM is enough for nodes + lightweight AI inference. Best free compute available anywhere.

**Gotchas:** Capacity for ARM instances is frequently unavailable in popular regions (US-East, US-West). Use less popular regions (e.g., Seoul, Osaka, Mumbai). Instances can be reclaimed if idle for extended periods -- keep a heartbeat running. Account creation sometimes gets flagged and rejected.

---

### AWS Free Tier

| Resource | Spec |
|---|---|
| EC2 | t2.micro or t3.micro -- 1 vCPU, 1 GB RAM, 750 hrs/month |
| EBS | 30 GB SSD storage |
| Bandwidth | 100 GB outbound/month (as of 2024+) |
| Duration | **12 months from account creation** |
| Lambda | 1M requests + 400,000 GB-seconds/month (always free) |
| S3 | 5 GB storage (12-month) |
| DynamoDB | 25 GB storage, 25 read/write units (always free) |

**New accounts (after July 2025):** Get access to t3.micro, t3.small, t4g.micro, t4g.small, c7i-flex.large, m7i-flex.large for 6 months or until credits exhausted.

**Persistia use case:** Single validator node on t2/t3.micro. Lambda for relay endpoints. DynamoDB for state caching.

**Gotchas:** t3.micro defaults to "Unlimited" burst mode which can incur surprise charges. Explicitly set to "Standard" mode. 12-month expiry means this is a bootstrap resource, not permanent infrastructure. EBS volumes persist (and cost money) even after instance termination.

---

### Microsoft Azure

| Resource | Spec |
|---|---|
| B1S VM | 1 vCPU, 1 GB RAM, 750 hrs/month |
| B2pts v2 (ARM) | 2 vCPU, 0.5 GB RAM, 750 hrs/month |
| B2ats v2 (AMD) | 2 vCPU, 0.5 GB RAM, 750 hrs/month |
| Managed Disk | 2x 64 GB P6 SSD |
| Bandwidth | 15 GB outbound/month |
| Duration | **12 months from account creation** |
| Initial credit | $200 for first 30 days |
| Always free | App Service (10 web apps), Functions (1M requests), Cosmos DB (25 GB) |

**Persistia use case:** B1S for a validator node. Azure Functions for webhook relay. Cosmos DB for cross-chain attestation storage.

**Gotchas:** Public IPs are charged after Oct 2025 (~$3.65/month). Use internal networking or tunnel through Cloudflare to avoid. The $200 credit burns fast if you accidentally spin up non-free resources. Disk must be P6 SSD specifically to stay free.

---

### Google Cloud Platform (GCP)

| Resource | Spec |
|---|---|
| e2-micro VM | 2 vCPU (shared), 1 GB RAM, ~730 hrs/month |
| Storage | 30 GB standard persistent disk |
| Bandwidth | 1 GB outbound/month (to non-China/Australia destinations) |
| Duration | **Always free** |
| Cloud Functions | 2M invocations/month (always free) |
| Cloud Run | 2M requests/month, 360,000 GB-seconds (always free) |
| Firestore | 1 GB storage, 50K reads, 20K writes/day (always free) |
| Initial credit | $300 for 90 days (new accounts) |

**Persistia use case:** Always-free e2-micro for a persistent validator. Cloud Run for serverless API endpoints. Firestore for light state storage.

**Gotchas:** 1 GB/month outbound bandwidth is very restrictive for a gossip-heavy node. Only one e2-micro per account is free. Must be in specific regions (Oregon, Iowa, South Carolina). The $300 trial credit is generous for initial testing.

---

### IBM Cloud

| Resource | Spec |
|---|---|
| Cloud Functions | 5M executions/month |
| Object Storage | 25 GB/month |
| Cloudant DB | 1 GB storage |
| Db2 Database | 100 MB storage |
| API Connect | 50K API calls/month |
| Duration | **Always free** (Lite plans) |

**Persistia use case:** Cloud Functions for lightweight relay or webhook processing. Object Storage for proof/snapshot archival.

**Gotchas:** No free VMs. Lite plan apps sleep after 10 days of inactivity. Lite service instances deleted after 30 days of no development activity. Not suitable for always-on validator nodes.

---

### Alibaba Cloud

| Resource | Spec |
|---|---|
| ECS (t5/t6 micro) | Small burstable instance (limited regions) |
| OSS | Object storage free quota |
| Duration | ECS trial up to 12 months; some services always-free |

**Persistia use case:** Additional geographic diversity for a validator in Asia-Pacific regions.

**Gotchas:** Documentation is less clear than Western providers. Region restrictions apply. Free tier details change frequently. Account verification can be difficult for non-Chinese users.

---

### Promotional Credits (Not Always-Free)

| Provider | Credit | Duration | Notes |
|---|---|---|---|
| DigitalOcean | $200 | 60 days | Via referral links |
| Vultr | $300 | 30 days | + $100 deposit match |
| Hetzner | None (referral $10) | -- | Cheapest paid VPS ($3.29/mo for 2 vCPU/2 GB) |

---

## 2. Free GPU Compute

### Google Colab

| Resource | Spec |
|---|---|
| GPU | NVIDIA T4 (16 GB) or K80 (12 GB), availability varies |
| RAM | ~12.7 GB system RAM |
| Session limit | 12 hours max, idle disconnect after ~90 min |
| Storage | ~78 GB ephemeral disk (resets each session) |
| Duration | **Always free** (no time limit on account) |

**Persistia use case:** Batch ZK proof generation. AI model fine-tuning. Not suitable for always-on inference (sessions are ephemeral).

**Gotchas:** GPU type is not guaranteed -- you get whatever is available. Heavy users get deprioritized. Cannot run long-running servers. No persistent storage.

---

### Kaggle Notebooks

| Resource | Spec |
|---|---|
| GPU | NVIDIA P100 (16 GB) or dual T4 |
| TPU | TPU v3-8 available |
| GPU hours | **30 hours/week** |
| TPU hours | 20 hours/week |
| RAM | 32 GB system RAM, 4 CPUs |
| Session limit | 9 hours max for GPU/TPU sessions |
| Storage | ~70 GB ephemeral |
| Duration | **Always free** |

**Persistia use case:** Best free GPU for batch ZK proof generation and model training. 30 hrs/week is very generous.

**Gotchas:** No internet access by default in GPU sessions (must enable). Output size limited to 20 GB. Cannot run persistent servers.

---

### Lightning.ai

| Resource | Spec |
|---|---|
| GPU | ~22 hours/month of GPU time |
| CPU Studio | 1 free CPU studio running 24/7 |
| Storage | Persistent across sessions |
| Duration | **Always free** |

**Persistia use case:** The always-on CPU Studio could run a lightweight validator or relay. GPU hours for proof generation.

**Gotchas:** GPU allocation is limited and can be throttled under heavy platform load.

---

### Paperspace Gradient

| Resource | Spec |
|---|---|
| GPU | Free tier with M4000 (8 GB) or similar |
| Session limit | 6 hours max |
| Storage | 5 GB persistent storage |
| Duration | **Always free** |

**Persistia use case:** Persistent notebook environment -- installed packages survive between sessions. Good for iterative ZK circuit development.

**Gotchas:** Free GPU availability is limited. Queue times can be long. Free tier GPU is older/slower.

---

### Combined GPU Strategy

Rotating across platforms yields ~50+ free GPU hours per week:
- Kaggle: 30 hrs/week (P100/T4)
- Colab: ~10-20 hrs/week (T4, availability-dependent)
- Lightning.ai: ~5 hrs/week
- Paperspace: ~5 hrs/week

---

## 3. Free Serverless / Edge

### Cloudflare Workers -- PERSISTIA PRIMARY PLATFORM

| Resource | Free Tier Limit |
|---|---|
| Requests | 100,000/day |
| CPU time | 10 ms per invocation |
| Worker size | 3 MB (compressed) |
| KV reads | 100,000/day |
| KV writes | 1,000/day |
| KV storage | 1 GB total |
| D1 reads | 5M rows/day |
| D1 writes | 100K rows/day |
| D1 storage | 5 GB per database |
| R2 storage | 10 GB |
| R2 Class A ops | 1M/month (writes) |
| R2 Class B ops | 10M/month (reads) |
| Durable Objects | SQLite-backed, 5 GB total storage |
| Pages | Unlimited static sites, 500 builds/month |
| Duration | **Always free** |

**Persistia use case:** This IS the primary Persistia infrastructure. DOs for validator state, R2 for snapshots/proofs, KV for caching, Workers for routing. All on the free plan.

**Gotchas:** 10ms CPU time limit per request is tight for heavy computation (consensus logic, proof verification). Durable Object storage billing started Jan 2026 -- monitor usage. 100K requests/day is ~1.15 req/sec average which can be limiting for high-traffic nodes.

---

### Vercel (Hobby)

| Resource | Free Tier Limit |
|---|---|
| Bandwidth | 100 GB/month |
| Edge Requests | 1M/month |
| Serverless Invocations | 1M/month |
| CPU time | 4 hours active/month |
| Function duration | 60 seconds max |
| Build minutes | 6,000/month |
| Blob Storage | 1 GB |
| Image Optimizations | 5,000/month |
| Duration | **Always free** (Hobby plan) |

**Persistia use case:** Frontend hosting for explorer/dashboard. Serverless functions for read-only API proxies.

**Gotchas:** Hobby plan is strictly non-commercial use only. Running revenue-generating services violates ToS. No WebSocket support on serverless functions.

---

### Netlify

| Resource | Free Tier Limit |
|---|---|
| Bandwidth | 100 GB/month |
| Serverless Functions | 125,000 invocations/site/month |
| Edge Functions | 1M requests/month |
| Build minutes | 300/month |
| Forms | 100 submissions/month |
| Duration | **Always free** |

**Persistia use case:** Static site hosting for documentation or light frontends.

**Gotchas:** 300 build minutes is low for frequent deploys. Serverless function execution limited to 10 seconds (26 seconds for background functions).

---

### Deno Deploy

| Resource | Free Tier Limit |
|---|---|
| Requests | 1M/month |
| Bandwidth | 100 GB/month |
| KV storage | 1 GB |
| Duration | **Always free** |

**Persistia use case:** Lightweight API relay or oracle data proxy. Native TypeScript runtime.

**Gotchas:** Limited ecosystem compared to Node.js. No persistent compute (request-based only).

---

### Fly.io

| Resource | Free Tier Limit |
|---|---|
| VMs | 3x 256 MB shared-cpu VMs |
| Volumes | 3 GB persistent storage |
| Bandwidth | 100 GB outbound/month |
| Duration | Credit-based ($5 one-time for new accounts) |

**Persistia use case:** Small always-on validator nodes with persistent volumes. Closest to a "free VPS" in the serverless category.

**Gotchas:** No true free tier for new accounts anymore -- just a $5 credit. VMs are very small (256 MB). Credit card required.

---

### Railway

| Resource | Free Tier Limit |
|---|---|
| RAM | 500 MB |
| Bandwidth | 1 GB |
| Storage | 5 GB persistent |
| Execution | $5 credit/month |
| Duration | **Always free** ($5/month credit) |

**Persistia use case:** Quick-deploy Node.js validator for testing.

**Gotchas:** $5 credit burns quickly with always-on services. Very limited resources.

---

### Render

| Resource | Free Tier Limit |
|---|---|
| Web Services | Free instances (sleep after 15 min inactivity) |
| Static Sites | Unlimited |
| PostgreSQL | Free for 90 days, then deleted |
| Bandwidth | 100 GB/month |
| Duration | **Always free** (with inactivity limits) |

**Persistia use case:** Static frontend hosting. Not suitable for always-on validators due to sleep behavior.

**Gotchas:** Free services spin down after 15 minutes of inactivity with ~30 second cold start. Free PostgreSQL databases are deleted after 90 days.

---

## 4. Free AI Inference APIs

### Google Gemini (AI Studio) -- MOST GENEROUS

| Resource | Spec |
|---|---|
| Models | Gemini 2.5 Pro, 2.5 Flash, Flash-Lite, 2.0 Flash |
| Rate limit | 5-15 RPM, 100-1,000 RPD (varies by model) |
| Context | Up to 1M tokens |
| Cost | **Free forever, no credit card** |

**Persistia use case:** Primary AI inference for service federation verification. 1M context window for complex reasoning tasks.

**Gotchas:** Rate limits are low (5 RPM for Pro). Not suitable for high-throughput real-time inference. Data may be used for training on free tier.

---

### Groq

| Resource | Spec |
|---|---|
| Models | Llama 3.3 70B, Mixtral, Gemma 2, others |
| Rate limit | 30 RPM, 1,000 RPD, 6,000 tokens/min |
| Speed | 1,000+ tokens/second |
| Cost | **Free tier, no credit card** |

**Persistia use case:** Ultra-fast inference for real-time AI verification. Best latency of any free provider.

**Gotchas:** Daily request cap (1,000) limits total throughput. Model selection is smaller than other providers.

---

### Cerebras

| Resource | Spec |
|---|---|
| Models | Llama 3.3 70B, Qwen3 235B, GPT-OSS-120B |
| Rate limit | 30 RPM, 14,400 RPD |
| Speed | ~1,800 tokens/second |
| Cost | **Free tier** |

**Persistia use case:** Highest daily quota among speed-focused providers. 14,400 RPD is substantial for batch AI verification.

**Gotchas:** Smaller model catalog. Cerebras-specific hardware may introduce inference differences.

---

### Mistral AI

| Resource | Spec |
|---|---|
| Models | Mistral Large 3, Small 3.1, Ministral 8B, Codestral |
| Rate limit | 1 req/second, 1B tokens/month |
| Cost | **Free tier** |

**Persistia use case:** 1B tokens/month is extremely generous for development and moderate production use. Good for code-related AI tasks with Codestral.

**Gotchas:** 1 req/sec hard limit constrains burst throughput.

---

### Cohere

| Resource | Spec |
|---|---|
| Models | Command A, Command R+, Aya Expanse 32B, Embed v4 |
| Rate limit | 20 RPM, 1,000 calls/month |
| Embeddings | Free embedding API access |
| Cost | **Free tier (Trial keys)** |

**Persistia use case:** Best free option for embeddings and RAG pipelines. Embed v4 for semantic search in service federation.

**Gotchas:** 1,000 calls/month is quite limited. Trial keys have lower priority.

---

### OpenRouter

| Resource | Spec |
|---|---|
| Models | DeepSeek R1/V3, Llama 4 Maverick/Scout, Qwen3 235B, many more |
| Rate limit | 20 RPM, 50 RPD (free); 1,000 RPD with $10+ balance |
| Cost | **Free tier (community-funded)** |

**Persistia use case:** Unified API gateway to dozens of models. Good for A/B testing different models for verification tasks.

**Gotchas:** 50 RPD without balance is very limited. Free models may have inconsistent availability. Quality depends on which provider is routing.

---

### SambaNova

| Resource | Spec |
|---|---|
| Models | Llama 3.3 70B, Llama 3.1 (up to 405B), Qwen 2.5 72B |
| Rate limit | 10-30 RPM (varies by model size) |
| Credits | $5 initial (valid 30 days) + persistent free tier |
| Cost | **Free tier** |

**Persistia use case:** Access to 405B parameter models for free. Best for complex reasoning tasks requiring largest models.

---

### Fireworks AI

| Resource | Spec |
|---|---|
| Models | Llama 3.1 405B, DeepSeek R1, Mixtral, many open-source |
| Rate limit | 10 RPM (no payment), up to 6,000 RPM (with payment on file) |
| Cost | **Free tier** |

**Persistia use case:** Fast optimized inference. Adding a payment method (without spending) unlocks massive rate limits.

---

### Hugging Face Inference API

| Resource | Spec |
|---|---|
| Models | Thousands of community-hosted models |
| Rate limit | Varies by model popularity |
| Cost | **Free tier** |

**Persistia use case:** Access to niche/specialized models not available elsewhere. Good for experimentation.

**Gotchas:** Free-tier models load on-demand with 30+ second cold starts. Unreliable for production use.

---

### Combined AI Inference Strategy

For Persistia's service federation verification:
1. **Primary:** Gemini 2.5 Flash (fast, generous limits, 1M context)
2. **Speed-critical:** Groq or Cerebras (1000+ tok/s)
3. **Bulk processing:** Mistral (1B tokens/month)
4. **Embeddings/RAG:** Cohere Embed v4
5. **Large model reasoning:** SambaNova (405B access)
6. **Fallback/routing:** OpenRouter (multi-model gateway)

---

## 5. Free Database / Storage

### Cloudflare (D1, KV, R2, DO)

See Section 3 above for full Cloudflare limits. Summary:
- **D1:** 5 GB storage, 5M reads/day, 100K writes/day
- **KV:** 1 GB storage, 100K reads/day, 1K writes/day
- **R2:** 10 GB storage, zero egress fees
- **Durable Objects:** 5 GB SQLite storage

---

### Supabase

| Resource | Free Tier Limit |
|---|---|
| Database (Postgres) | 500 MB |
| File storage | 1 GB |
| Bandwidth | 5 GB egress |
| Edge Functions | 500,000 invocations/month |
| Auth users | 50,000 MAU |
| Realtime | Unlimited connections |
| Projects | 2 active |
| Duration | **Always free** |

**Persistia use case:** PostgreSQL for relational state queries. Realtime subscriptions for live dashboard data. Auth for explorer/wallet frontend.

**Gotchas:** Projects pause after 1 week of inactivity. 500 MB database is small. No backups on free tier. Limited to 2 active projects.

---

### Neon (Serverless Postgres)

| Resource | Free Tier Limit |
|---|---|
| Storage | 0.5 GB per project (5 GB aggregate) |
| Compute | 100 CU-hours/month per project |
| Branches | Unlimited |
| Projects | Up to 20 |
| Egress | 5 GB/month |
| Scale-to-zero | 5-minute idle timeout |
| Duration | **Always free** |

**Persistia use case:** Branching is killer for testing schema migrations. Scale-to-zero means you only use compute when queried. 20 projects = 20 separate databases for different services.

**Gotchas:** 0.5 GB per project is quite small. Scale-to-zero means cold starts on first query (~500ms). Acquired by Databricks in 2025.

---

### Turso (LibSQL/SQLite)

| Resource | Free Tier Limit |
|---|---|
| Storage | 5 GB total (some sources report 9 GB) |
| Databases | 100-500 |
| Row reads | 500M/month |
| Duration | **Always free** |

**Persistia use case:** Edge SQLite perfect for Persistia's architecture (already SQLite-based). Embedded replicas for read-heavy workloads. Works natively with standalone node's better-sqlite3 compatibility layer.

**Gotchas:** Free tier specs have changed recently -- verify on turso.tech/pricing. LibSQL is a SQLite fork, not standard SQLite.

---

### Upstash (Redis + Kafka)

| Resource | Free Tier Limit |
|---|---|
| Redis | 10,000 commands/day, 256 MB storage |
| Kafka | 10,000 messages/day |
| QStash | 500 messages/day |
| Duration | **Always free** |

**Persistia use case:** Redis for caching oracle data. QStash for reliable webhook delivery. Kafka for cross-shard message relay.

---

### PlanetScale

**No longer offers a free tier.** Minimum pricing starts at $34/month. Not recommended.

---

## 6. Free CI/CD & Dev Tools

### GitHub Actions

| Resource | Free Tier Limit |
|---|---|
| Public repos | **Unlimited minutes** |
| Private repos | 2,000 minutes/month (Linux) |
| Storage | 500 MB artifacts |
| Concurrent jobs | 20 |
| Duration | **Always free** |

**Persistia use case:** CI/CD for the main repo. Automated testing, deployment scripts, proof verification pipelines. Public repo = unlimited.

**Gotchas:** Jan 2026: runner prices dropped 39%. March 2026: planned $0.002/min self-hosted runner charge was postponed indefinitely after community backlash. macOS minutes count at 10x, Windows at 2x.

---

### GitLab CI/CD

| Resource | Free Tier Limit |
|---|---|
| Compute minutes | 400/month (shared runners) |
| Self-hosted runners | **Unlimited** |
| Storage | 10 GB |
| Users | 5 per group |
| Duration | **Always free** |

**Persistia use case:** Alternative CI/CD pipeline. Self-hosted runners on OCI free ARM instances = unlimited CI with 0 cost.

**Gotchas:** 400 minutes is low for active development. 5-user limit per group.

---

### Other Dev Tools

| Tool | Free Tier |
|---|---|
| **Sentry** | 5K errors/month, 10K performance transactions |
| **Grafana Cloud** | 10K metrics, 50 GB logs, 50 GB traces |
| **Betterstack (Logtail)** | 1 GB logs/month |
| **UptimeRobot** | 50 monitors, 5-min intervals |
| **Checkly** | 150K API check runs/month |

---

## 7. Student / Education Programs

### GitHub Student Developer Pack

| Benefit | Details |
|---|---|
| GitHub Pro | Free while a student |
| GitHub Copilot | Free AI pair programmer |
| DigitalOcean | $200 credit |
| Azure | $100 credit |
| Namecheap | Free .me domain (1 year) |
| JetBrains | All IDEs free |
| Heroku | Platform credit |
| 100+ tools | Various free access |
| Duration | Valid while enrolled in accredited institution |

**Eligibility:** Age 13+, enrolled in accredited degree/vocational program. Requires school email or student ID upload.

---

### Azure for Students

| Resource | Spec |
|---|---|
| Credit | $100 (renewable annually) |
| Always free | 25+ Azure services |
| No credit card | Required for students 13-17 |
| Services | App Service, Functions, MySQL, DevOps, Notification Hubs |
| Duration | Renewable each academic year |

---

### AWS Educate

| Resource | Spec |
|---|---|
| Credit | Varies by program (typically $30-$100) |
| Labs | Hands-on cloud labs |
| Duration | While enrolled |

---

### Google Cloud for Education

| Resource | Spec |
|---|---|
| Credit | Typically $50-$300 via course coupons |
| Qwiklabs | Free access to training labs |
| Duration | Semester-based |

---

### JetBrains Education

| Resource | Spec |
|---|---|
| All IDEs | IntelliJ, WebStorm, PyCharm, etc. -- all free |
| Duration | Renewable annually while a student |

---

## Summary: Optimal Free Infrastructure for Persistia

### Always-On Validator Nodes (Zero Cost)

| Slot | Provider | Spec | Region |
|---|---|---|---|
| Node 1-3 | Cloudflare DO | Primary shards (existing) | Edge (global) |
| Node 4 | Oracle Cloud ARM | 4 OCPU / 24 GB | Asia-Pacific |
| Node 5 | GCP e2-micro | 2 vCPU / 1 GB | US (Oregon) |
| Node 6 | AWS t2.micro | 1 vCPU / 1 GB | US (12-month) |
| Node 7 | Azure B1S | 1 vCPU / 1 GB | EU (12-month) |

### AI Inference (Zero Cost)

| Task | Provider | Why |
|---|---|---|
| Primary verification | Gemini 2.5 Flash | Best free limits, 1M context |
| Speed-critical | Groq | 1000+ tok/s |
| Bulk processing | Mistral | 1B tokens/month |
| Embeddings | Cohere | Best free embedding API |
| Fallback | OpenRouter | Multi-model routing |

### GPU Compute (Zero Cost)

| Task | Provider | Hours/week |
|---|---|---|
| ZK proof batches | Kaggle | 30 hrs (P100) |
| Model fine-tuning | Colab | 10-20 hrs (T4) |
| Persistent dev | Lightning.ai | 5 hrs + 24/7 CPU |

### Total Free Infrastructure Value

Conservative monthly estimate of equivalent paid resources:
- Oracle ARM (4 OCPU/24 GB): ~$50/month
- AWS + Azure + GCP VMs: ~$30/month
- Cloudflare Workers/DO/R2: ~$25/month
- GPU compute (50+ hrs/week): ~$200/month
- AI inference APIs: ~$100/month
- Databases: ~$30/month
- CI/CD: ~$15/month

**Estimated total: ~$450/month in compute at zero cost.**
