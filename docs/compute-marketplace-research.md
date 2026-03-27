# Compute Marketplace Research (2026-03-27)

Research into decentralized compute marketplaces where Persistia node operators could buy/sell compute for income.

## Key Finding

No marketplace supports Cloudflare Workers as a compute provider — they all require persistent processes + GPU hardware. CF Workers' role is as an orchestrator/consumer, not a provider.

## Summary Matrix

| Platform | CF Worker? | Small VPS (CPU)? | Small VPS (GPU)? | API Available? | Payment Token |
|----------|-----------|-------------------|-------------------|----------------|---------------|
| Bittensor | No | Some subnets | Yes (competitive) | Python SDK | TAO |
| Vast.ai | No | No | Yes | REST API + CLI | USD/Crypto |
| Akash | No | Marginally | Yes | CLI + SDK | AKT/USDC |
| Render | No | No | Yes (waitlist) | Proprietary | RENDER |
| io.net | No | No | Yes | Dashboard + API | IO |
| Livepeer | No | Delegate only | Yes | CLI | LPT + ETH |
| Ritual | No | Maybe (small models) | Yes | Infernet SDK | TBD |
| Spheron | No | Fizz node (light) | Yes | CLI + API | SPHN |
| Prime Intellect | No | No | H100-class only | Early | TBD |

## Platform Details

### 1. Bittensor (TAO)
- Decentralized AI network with subnets for specific AI tasks (LLM, image gen, embeddings, etc.)
- Miners earn TAO by serving inference requests scored by validators (Yuma Consensus)
- Registration cost: 0.1–200+ TAO depending on subnet
- Emissions every ~72 minutes
- Competitive mining on inference subnets requires A100/H100-class GPUs
- Relevant subnets: 1 (Chat), 4 (Multi-modal), 5 (Image Gen), 18 (Cortex.t inference API), 33 (Embeddings)
- Bridging: TAO → wTAO (Ethereum) → swap to USDC/ETH

### 2. Vast.ai
- P2P GPU marketplace ("Airbnb for GPUs")
- Hosts set prices; Vast takes ~15-20% commission
- REST API at `console.vast.ai/api/v0/` for programmatic listing/renting
- Requires bare metal Linux + NVIDIA GPUs + Docker
- Earnings: RTX 3090 ~$0.10-0.30/hr, A100 ~$0.80-2.00/hr, H100 ~$2-4/hr
- Most API-friendly option for programmatic compute trading

### 3. The Innovation Game
- Could not identify a specific compute marketplace by this name
- May refer to a newer project post mid-2025, a Bittensor subnet concept, or Luke Hohmann's product discovery games

### 4. Akash Network (AKT)
- Decentralized cloud on Cosmos SDK; tenants post Docker manifests, providers bid
- Provider requires Kubernetes cluster, public IP, 5 AKT minimum deposit
- Payments per block (~6 seconds), in AKT or USDC
- CPU-only: ~$10-50/month; GPU providers earn more
- Best for persistent workloads (game servers, provers) at lower cost than traditional cloud

### 5. Render Network (RENDER)
- GPU rendering + AI/ML compute; waitlist/approval to become operator
- Requires NVIDIA GPU (GTX 1070+), proprietary node software
- Reputation-based job allocation; earnings $50-500/month variable
- Token on Solana

### 6. io.net (IO)
- Decentralized GPU cloud aggregating supply from data centers + individuals
- Periodic GPU benchmarks verify capabilities; earnings scale with GPU tier
- Docker + worker binary setup; IO token on Solana

### 7. Livepeer (LPT)
- Decentralized video transcoding on Ethereum/Arbitrum
- Orchestrators stake 100+ LPT, earn ETH fees + LPT inflation rewards
- Delegators earn passive yield without hardware
- Expanding into AI inference jobs
- Delegation is passive income opportunity (no hardware needed)

### 8. Ritual
- AI coprocessor/oracle for blockchains (Infernet product)
- Nodes run Docker containers with AI models, serve on-chain inference requests
- Supports TEE, ZK, or optimistic verification
- Could be a consumer for Persistia rather than a provider integration

### 9. Spheron (SPHN)
- Decentralized compute marketplace with Fizz nodes (lightweight tier)
- Fizz: Docker + binary, 4+ CPU, 8GB+ RAM, optional GPU
- Closest to small VPS participation; early stage economics

### 10. Prime Intellect
- Decentralized AI training (DiLoCo distributed optimization)
- H100-class GPUs only; training focus, not inference
- Early stage, token economics not public

## Additional Opportunities

- **Nosana (NOS)** — Solana-based GPU inference, consumer GPU friendly
- **Golem (GLM)** — Oldest decentralized compute; low barrier, low earnings (~$5-30/mo)
- **Flux (FLUX)** — Cumulus tier: 2 cores, 4GB RAM, 50GB SSD qualifies
- **Grass** — Bandwidth/scraping network; very lightweight (browser extension)
- **Koii Network** — Lightweight task nodes; closest to CF Worker spirit (2 cores, 4GB RAM)
- **Meson Network / Theta** — CDN bandwidth marketplaces; lightweight
- **Hyperbolic** — AI inference marketplace similar to Vast.ai

## Practical Integration Paths

1. **Vast.ai as "compute treasury"** — REST API to rent GPUs on demand, sell spare time
2. **Akash for persistent workloads** — Deploy provers/game servers cheaply
3. **Livepeer delegation** — Passive LPT yield from treasury (no hardware)
4. **Koii/Grass/Flux Cumulus** — Lowest barrier for VPS-based node operators
