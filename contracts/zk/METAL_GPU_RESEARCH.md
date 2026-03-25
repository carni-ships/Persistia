# Metal GPU STARK Prover — Research Notes

**Date:** March 25, 2026
**Status:** Research complete, not yet implemented
**Priority:** Future development roadmap

## Context

SP1's STARK prover runs CPU-only on Apple Silicon (no CUDA). The M3 Pro's GPU (18 cores, 30 TFLOPS) sits idle during proving. This document evaluates whether Metal GPU compute could accelerate Persistia's ZK proving pipeline.

## Current Prover Performance (M3 Pro CPU)

- SP1 v4.0.0, CPU prover, 6 P-cores (RAYON_NUM_THREADS=6)
- Batch-32 mode, ~60-90 seconds per block (compressed proofs)
- SHA-256 precompile patch applied (20-40% speedup)
- FRI queries reduced to 33 (dev mode, ~3x faster)

## STARK Computational Bottlenecks

| Operation | % of Proving Time | GPU-Parallelizable? | Metal Suitability |
|-----------|-------------------|---------------------|-------------------|
| NTT/FFT (Baby Bear field) | 60-70% | Excellent | Excellent |
| Merkle tree hashing | 15-20% | Good | Good |
| FRI folding layers | 10-15% | Good (reuses NTT) | Good |
| Polynomial interpolation | ~5% | Limited | Moderate |

Baby Bear field (mod 2^31 - 2^27 + 1) is 31-bit — fits cleanly in Metal's 32-bit compute model. No 64-bit emulation needed. M3 Pro unified memory eliminates PCIe transfer overhead.

## Three Approaches Evaluated

### Approach A: ICICLE v3.6 Metal Integration (RECOMMENDED)

ICICLE by Ingonyama has a production Metal backend (released Aug 2024).

**Supported Metal operations:**
- NTT (Number Theoretic Transform) — accelerated
- MSM (Multi-Scalar Multiplication) — accelerated
- Sumcheck — accelerated
- Poseidon/Poseidon2 hashing — not yet (roadmap)
- Merkle trees — not yet (roadmap)

**Effort:** 2-6 weeks
**Expected speedup:** 2-3x over CPU
**Risk:** Low — production-tested, Rust API available
**Licensing:** Free for R&D, requires sales contact for production

**Implementation steps:**
1. Set up ICICLE v3.6 Metal backend on M3 Pro
2. Benchmark ICICLE NTT vs Plonky3 CPU on Persistia trace sizes
3. Write thin Rust shim layer for NTT dispatch
4. Hook into SP1's polynomial evaluation path
5. Verify proof correctness against CPU baseline
6. Tune threadgroup sizes and tile memory usage

### Approach B: Direct Metal Backend for Plonky3/SP1

Fork Plonky3's field/poly modules, implement Metal compute kernels.

**Effort:** 6-12 months (single senior engineer)
**Expected speedup:** 2-3x
**Risk:** High — Plonky3 API instability, maintenance burden
**Not recommended** unless contributing upstream.

### Approach C: Custom Metal STARK Prover

Write a minimal STARK prover targeting only Persistia's circuit (Ed25519 + Merkle).

**Effort:** 3-6 months (team of 2-3)
**Expected speedup:** 2.5-3.5x
**Risk:** Very high — needs crypto audit, breaks SP1 compatibility
**Not recommended** unless fully decoupling from SP1.

## Hardware Reality Check

| Spec | M3 Pro | RTX 4090 | H100 |
|------|--------|----------|------|
| Peak FP32 | 30 TFLOPS | 1,456 TFLOPS | 3,958 TFLOPS |
| Memory BW | 150 GB/s (unified) | 1,008 GB/s | 3,350 GB/s |
| PCIe overhead | None (unified) | Significant | Significant |

M3 Pro has a 50x raw compute deficit vs data center GPUs. Metal is a **local dev optimization**, not a production proving strategy.

## Production Proving Alternatives

- **SP1 Network** (`SP1_PROVER=network`): Cloud GPU cluster, 10-50x faster, ~$0.01-0.10/proof, zero code changes
- **Cloud CUDA** (AWS g6.xlarge / A100): Industry standard, ~40 sec/Ethereum block
- **Future M-series**: M4 Max/Ultra will have significantly better GPU — Metal investment carries forward

## Decision

**For now:** Use CPU prover with applied optimizations (SHA-256 precompile, hex streaming, batch-32). Monitor ICICLE Metal roadmap for Merkle tree support.

**When to revisit:**
- ICICLE adds Merkle tree Metal acceleration
- Proving gap exceeds 100+ rounds consistently
- Moving to M4 Pro/Max hardware (better GPU)
- Production deployment requires local proving (no cloud dependency)

## References

- ICICLE v3.6 Metal: https://medium.com/@ingonyama/icicle-goes-metal-v3-6-163fa7bbfa44
- LambdaClass Rust+Metal FFT: https://blog.lambdaclass.com/using-metal-and-rust-to-make-fft-even-faster/
- SP1 Hardware Acceleration: https://docs.succinct.xyz/docs/sp1/generating-proofs/hardware-acceleration
- Baby Bear Field: https://hackmd.io/@Voidkai/BkNX3xUZA
- WebGPU STARK (zkSecurity): https://blog.zksecurity.xyz/posts/webgpu/
