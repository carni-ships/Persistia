#!/usr/bin/env bash
# Supervised prover — auto-restarts on crash, stall detection, vk mismatch recovery.
#
# Usage:
#   ./run-supervised.sh --node https://persistia.carnation-903.workers.dev/?shard=node-1 --batch 32
#
# Environment:
#   STALL_TIMEOUT   — seconds without new proof before restart (default: 3600)
#   MAX_RESTARTS    — give up after N consecutive failures (default: 20)
#   RESTART_DELAY   — seconds to wait between restarts (default: 30)

set -uo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────
STALL_TIMEOUT="${STALL_TIMEOUT:-3600}"    # 1 hour without progress = stall
MAX_RESTARTS="${MAX_RESTARTS:-20}"
RESTART_DELAY="${RESTART_DELAY:-30}"
PROOF_DIR="./proofs"
LOG_FILE="./prover-supervisor.log"

# ─── SP1 Environment (same as run-local.sh) ──────────────────────────────────
export SP1_PROVER=cpu
export RAYON_NUM_THREADS=6
export MALLOC_NANO_ZONE=0
export SP1_DEV_FRI_QUERIES="${SP1_DEV_FRI_QUERIES:-33}"
export RUST_LOG="${RUST_LOG:-info}"

# ─── Parse --node from args to query status ───────────────────────────────────
NODE_URL=""
for i in "$@"; do
  case "$prev" in
    --node) NODE_URL="$i" ;;
  esac
  prev="$i"
done

if [ -z "$NODE_URL" ]; then
  echo "Error: --node is required"
  exit 1
fi

# ─── Helpers ──────────────────────────────────────────────────────────────────
log() {
  local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
  echo "$msg"
  echo "$msg" >> "$LOG_FILE"
}

get_latest_proven() {
  local status
  status=$(curl -s "${NODE_URL%/}/proof/zk/status" 2>/dev/null)
  echo "$status" | python3 -c "import sys,json; print(json.load(sys.stdin).get('latest_proven_block', 0))" 2>/dev/null || echo "0"
}

get_latest_proof_file() {
  ls -t "$PROOF_DIR"/block_*.proof 2>/dev/null | head -1
}

get_latest_proof_block() {
  local f
  f=$(get_latest_proof_file)
  if [ -n "$f" ]; then
    basename "$f" | sed 's/block_//;s/\.proof//'
  else
    echo "0"
  fi
}

# ─── Supervisor Loop ─────────────────────────────────────────────────────────
consecutive_failures=0
restart_count=0

log "Prover supervisor starting"
log "  Node:          $NODE_URL"
log "  Stall timeout: ${STALL_TIMEOUT}s"
log "  Max restarts:  $MAX_RESTARTS"
log "  Args:          $*"

while true; do
  if [ "$consecutive_failures" -ge "$MAX_RESTARTS" ]; then
    log "FATAL: $MAX_RESTARTS consecutive failures — giving up"
    exit 1
  fi

  # Determine start block: resume from latest proof file or latest on-chain
  local_latest=$(get_latest_proof_block)
  chain_latest=$(get_latest_proven)
  start_from=$((local_latest > chain_latest ? local_latest : chain_latest))

  if [ "$start_from" -eq 0 ]; then
    # No proofs exist — start near chain head as genesis
    committed=$(curl -s "${NODE_URL%/}/dag/status" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('last_committed_round', 0))" 2>/dev/null || echo "0")
    start_from=$((committed > 100 ? committed - 100 : 0))
    log "No existing proofs — starting genesis from block $start_from"
  fi

  restart_count=$((restart_count + 1))
  log "Starting prover (attempt #$restart_count, resuming from block $start_from)"

  # Launch prover, capture PID
  cargo run --release --bin persistia-prover -- "$@" --start "$start_from" 2>&1 | tee -a "$LOG_FILE" &
  PROVER_PID=$!

  # Monitor for stalls
  last_proof_time=$(date +%s)
  last_proof_block=$start_from

  while kill -0 "$PROVER_PID" 2>/dev/null; do
    sleep 60

    # Check if a new proof appeared
    current_block=$(get_latest_proof_block)
    if [ "$current_block" -gt "$last_proof_block" ] 2>/dev/null; then
      last_proof_block=$current_block
      last_proof_time=$(date +%s)
      consecutive_failures=0
      log "Progress: block $current_block proven"
    fi

    # Check for stall
    now=$(date +%s)
    stalled_for=$((now - last_proof_time))
    if [ "$stalled_for" -ge "$STALL_TIMEOUT" ]; then
      log "STALL detected: no progress for ${stalled_for}s — killing prover"
      kill "$PROVER_PID" 2>/dev/null
      wait "$PROVER_PID" 2>/dev/null
      break
    fi
  done

  # Prover exited — check why
  wait "$PROVER_PID" 2>/dev/null
  exit_code=$?

  if [ "$exit_code" -eq 0 ]; then
    log "Prover exited cleanly (code 0) — restarting to check for new blocks"
    consecutive_failures=0
  elif [ "$exit_code" -eq 143 ] || [ "$exit_code" -eq 137 ]; then
    log "Prover was killed (signal) — restarting"
  else
    consecutive_failures=$((consecutive_failures + 1))
    log "Prover crashed (exit code $exit_code) — failure #$consecutive_failures"

    # Check for vk mismatch (common after rebuild)
    if grep -q "vk hash mismatch" "$LOG_FILE" 2>/dev/null; then
      log "VK mismatch detected — program was rebuilt. Starting fresh genesis."
      # Move old proofs aside
      if [ -d "$PROOF_DIR" ] && ls "$PROOF_DIR"/block_*.proof >/dev/null 2>&1; then
        backup="./proofs-backup-$(date +%s)"
        mv "$PROOF_DIR" "$backup"
        mkdir -p "$PROOF_DIR"
        log "Old proofs moved to $backup"
      fi
      consecutive_failures=0  # Don't count vk mismatch as a real failure
    fi
  fi

  log "Restarting in ${RESTART_DELAY}s..."
  sleep "$RESTART_DELAY"
done
