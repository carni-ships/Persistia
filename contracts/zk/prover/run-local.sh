#!/usr/bin/env bash
# Optimized prover launch for Apple Silicon M3 Pro (6P+6E, 18GB)
#
# Usage:
#   ./run-local.sh watch --node http://localhost:8787
#   ./run-local.sh prove --block 5
#   ./run-local.sh watch --node http://localhost:8787 --batch 4

set -euo pipefail

# ─── SP1 Backend ─────────────────────────────────────────────────────────────
# Use CPU prover (no CUDA on macOS). Valid values: mock, cpu, cuda, network
export SP1_PROVER=cpu

# ─── Parallelism ─────────────────────────────────────────────────────────────
# Restrict to 6 performance cores — E-cores create stragglers in STARK FFTs
export RAYON_NUM_THREADS=6

# ─── Memory ──────────────────────────────────────────────────────────────────
# Hint to jemalloc/system allocator: keep arena count low to reduce fragmentation
export MALLOC_NANO_ZONE=0

# ─── SP1 Tuning ──────────────────────────────────────────────────────────────
# Reduce FRI queries for faster local proving (larger proof, same soundness for dev)
# Default is ~100 queries; 33 gives ~3x speedup with slightly larger proofs.
# Set to higher value for production proofs.
export SP1_DEV_FRI_QUERIES="${SP1_DEV_FRI_QUERIES:-33}"

# ─── Rust logging ────────────────────────────────────────────────────────────
export RUST_LOG="${RUST_LOG:-info}"

# ─── Build + Run ─────────────────────────────────────────────────────────────
exec cargo run --release --bin persistia-prover -- "$@"
