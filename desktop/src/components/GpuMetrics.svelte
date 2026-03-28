<script lang="ts">
  import { gpuInfo, zkStatus, dagStatus } from "../lib/stores";

  let proofGap = $derived($zkStatus?.proof_gap ?? 0);
  let proverLag = $derived($dagStatus?.adaptive?.prover_lag ?? 0);
</script>

<div class="gpu-metrics">
  <h3>Prover Metrics</h3>
  <div class="metrics-grid">
    <div class="metric">
      <span class="metric-label">bb CLI</span>
      <span class="metric-value" class:ok={$gpuInfo?.bb_available} class:missing={!$gpuInfo?.bb_available}>
        {$gpuInfo?.bb_version ?? "not found"}
      </span>
    </div>
    <div class="metric">
      <span class="metric-label">Metal GPU</span>
      <span class="metric-value" class:ok={$gpuInfo?.metal_msm_available} class:missing={!$gpuInfo?.metal_msm_available}>
        {$gpuInfo?.metal_msm_available ? ($gpuInfo?.gpu_name ?? "available") : "unavailable"}
      </span>
    </div>
    <div class="metric">
      <span class="metric-label">Proof Gap</span>
      <span class="metric-value" class:warn={proofGap > 10} class:ok={proofGap <= 10}>
        {proofGap} blocks
      </span>
    </div>
    <div class="metric">
      <span class="metric-label">Prover Lag</span>
      <span class="metric-value" class:warn={proverLag > 5} class:ok={proverLag <= 5}>
        {proverLag} rounds
      </span>
    </div>
    <div class="metric">
      <span class="metric-label">Chain Length</span>
      <span class="metric-value">{$zkStatus?.max_chain_length ?? 0}</span>
    </div>
    {#if $gpuInfo?.unified_memory !== null && $gpuInfo?.unified_memory !== undefined}
      <div class="metric">
        <span class="metric-label">Unified Memory</span>
        <span class="metric-value">{$gpuInfo?.unified_memory ? "yes" : "no"}</span>
      </div>
    {/if}
  </div>
</div>

<style>
  .gpu-metrics {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
  }

  h3 {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-dim);
    margin-bottom: 12px;
  }

  .metrics-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }

  .metric {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 8px;
    background: var(--surface-2);
    border-radius: 6px;
  }

  .metric-label {
    font-size: 10px;
    text-transform: uppercase;
    color: var(--text-dim);
  }

  .metric-value {
    font-size: 12px;
    font-weight: 600;
  }

  .ok { color: var(--green); }
  .warn { color: var(--yellow); }
  .missing { color: var(--red); }
</style>
