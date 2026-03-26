# Persistia ZK Prover — Operator Guide

## Overview

The Persistia ZK prover generates SP1 STARK proofs of state transitions for committed blocks. Each proof attests that a batch of blocks was executed correctly. Proofs are posted back to the Persistia node where anyone can verify them.

## Prerequisites

- **Rust toolchain** — `rustup` with nightly and the `succinct` target:
  ```bash
  curl -L https://sp1up.succinct.xyz | bash
  sp1up
  ```
- **Hardware** — STARK proving is CPU-intensive. Minimum: 4 cores, 8GB RAM. Recommended: 6+ P-cores, 16GB+ RAM. Apple Silicon M-series or AMD Ryzen work well.
- **Network** — Access to a Persistia node endpoint (public or local).

## Quick Start

```bash
cd contracts/zk/prover

# 1. Build the prover (first build compiles the SP1 guest program — takes a few minutes)
cargo build --release

# 2. Start proving against the production node
./run-local.sh watch \
  --node "https://persistia.carnation-903.workers.dev/?shard=node-1" \
  --batch 32 \
  --start 0
```

The `--start 0` flag begins a fresh proof lineage from the genesis of the current chain state. If you want to resume from a specific block, set `--start <block_number>`.

## Configuration

### `run-local.sh` (recommended)

The `run-local.sh` wrapper sets optimized environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `SP1_PROVER` | `cpu` | Prover backend (cpu, mock, cuda, network) |
| `RAYON_NUM_THREADS` | `6` | CPU threads — set to your P-core count |
| `SP1_DEV_FRI_QUERIES` | `33` | FRI query count — lower = faster, larger proofs |
| `MALLOC_NANO_ZONE` | `0` | macOS allocator hint to reduce fragmentation |
| `RUST_LOG` | `info` | Log verbosity |

**Tuning for your machine:**
- Set `RAYON_NUM_THREADS` to your performance core count (not total cores). On Apple Silicon, E-cores create stragglers in STARK FFTs.
- `SP1_DEV_FRI_QUERIES=33` gives ~3x speedup over default (~100 queries). Use higher values for production-grade proofs.

### `run-supervised.sh` (production)

For long-running prover operations, use the supervisor script which handles crashes, stalls, and vk mismatches:

```bash
./run-supervised.sh \
  --node "https://persistia.carnation-903.workers.dev/?shard=node-1" \
  --batch 32
```

| Env Variable | Default | Purpose |
|-------------|---------|---------|
| `STALL_TIMEOUT` | `3600` | Seconds without new proof before restart |
| `MAX_RESTARTS` | `20` | Max consecutive failures before giving up |
| `RESTART_DELAY` | `30` | Seconds between restarts |

## Commands

### `watch` — Continuous batch proving (primary mode)

```bash
./run-local.sh watch \
  --node <NODE_URL> \
  --batch <N>       \  # blocks per proof (default: 1, recommended: 32)
  --start <BLOCK>   \  # starting block number
  --interval <SECS>    # poll interval (default: 10s)
```

The prover will:
1. Poll the node for committed blocks after `--start`
2. Batch N blocks into a single proof
3. Chain proofs recursively (each proof verifies the previous one — IVC)
4. Save proofs to `./proofs/block_<N>.proof`
5. Submit proofs to the node via `POST /proof/zk/submit`

### `prove` — Single block proof

```bash
./run-local.sh prove --node <NODE_URL> --block <N> --output proof.bin
# Recursive (chain from previous proof):
./run-local.sh prove --node <NODE_URL> --block <N> --prev-proof proofs/block_<N-1>.proof
```

### `verify` — Verify a proof locally

```bash
./run-local.sh verify --proof proofs/block_100.proof
```

### `execute` — Dry run (no proof generation)

```bash
./run-local.sh execute --node <NODE_URL> --block <N>
```

Useful for testing that block data is valid before committing to a full proof.

## Proof Lineages

Each prover binary produces proofs tied to its verification key (vk). If you rebuild the prover (e.g. after updating the guest program), the vk changes and old proofs become incompatible. The prover will automatically start a new proof lineage.

The dashboard tracks lineages separately — you'll see the active lineage and any old ones.

## Multi-Prover Setup

Multiple provers can work on different block ranges. To avoid duplicate work:

1. **Check current status** — `GET /proof/zk/status` returns `latest_proven_block` and lineage info
2. **Pick uncovered ranges** — Start your prover from after the latest proven block
3. **Claim-based coordination** — The node supports proof claims:
   - `POST /proof/zk/claim` — Claim a block range before proving
   - Other provers will see claimed ranges and skip them

Example: if node shows `latest_proven_block: 500`, start your prover with `--start 501`.

## Monitoring

- **Dashboard** — The web dashboard shows ZK proof status, lineage tracking, and proving throughput
- **Node API** — `GET /proof/zk/status` returns JSON with proof stats
- **Prover output** — The prover prints timing info per batch:
  ```
  Batch 100..132 proven — 32 blocks | 45.2m | 42 blocks/hr | proof: 1.2MB
  ```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `sp1 vk hash mismatch` | Prover was rebuilt with new binary. Restart with fresh `--start` block or let `run-supervised.sh` handle it |
| `Out of memory` | Reduce `--batch` size or `RAYON_NUM_THREADS` |
| `block not found` | The block hasn't been committed yet. Increase `--interval` or wait |
| Slow proving | Tune `RAYON_NUM_THREADS` to P-core count, lower `SP1_DEV_FRI_QUERIES` |
| Prover stalls | Use `run-supervised.sh` which auto-detects and restarts on stalls |
