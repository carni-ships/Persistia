# Cloudflare Tools Roadmap (2026-03-27)

Evaluated the full CF developer platform for Persistia. Prioritized by effort vs impact.

## Immediate Wins (free, minimal effort)

- **Turnstile** — Protect faucet + game endpoints from bots. Free, unlimited. ~30 min.
- **Rate Limiting binding** — Throttle /faucet, /contract/deploy, WebSocket messages. In-Worker, zero latency. ~1 hour.
- **R2 Event Notifications** — Trigger on ZK proof/snapshot uploads → notify via existing Queue. ~1 hour.
- **Workers Logs** — Persistent searchable console.log. Just enable. ~5 min.
- **Analytics Engine** — Consensus metrics (round times, quorum, finality), game metrics, token economics. SQL-queryable. ~Few hours.

## Short-Term (days, high value)

- **Agents SDK + MCP** — Expose ledger as MCP server. AI agents can query balances, submit txs, deploy contracts. Native MPP/x402 support. Most aligned new CF feature. ~2-3 days. **IN PROGRESS**
- **Workflows** — Durable execution for ZK proof pipeline (collect → witness → prove → store → verify), node bootstrap/sync, oracle lifecycle. Auto-retry on failure. ~2-3 days.
- **AI Gateway** — Cache + log + rate-limit Workers AI calls. Deduplicate identical inference across nodes. Cost monitoring. Free. ~1 day.
- **Workers Builds** — CI/CD: auto-deploy on git push, preview URLs for PRs. ~1 day.
- **Vitest (`@cloudflare/vitest-pool-workers`)** — Test consensus, contracts, DO behavior in real Workers runtime. No test suite exists yet. ~2-3 days.

## Strategic (weeks, transformative)

- **Dynamic Workers** (open beta March 2026) — Isolate WASM contract execution in separate V8 sandboxes. Stronger security than in-process execution. 100x faster than containers.
- **Containers** — Run SP1/Noir ZK prover in real containers (needs more CPU/memory than Worker isolates). Pay-per-second.
- **KV** — Cache read-only data at edge (node status, block counts, shard routing). 100K reads/day free.
- **Vectorize** — Semantic search over game world, AI agent memory, contract discovery. Pairs with embeddings model.
- **Tracing (OpenTelemetry)** — End-to-end distributed traces across consensus pipeline.

## Not Relevant

- D1 (DO SQLite covers all needs), Hyperdrive (no external DB), Pub/Sub (deprecated), Stream (no video), Argo (paid, marginal), Better Auth (wallet auth not OAuth), Hono/itty-router (refactor not worth it mid-flight), PartyKit (abstraction over same DOs we already use directly)
