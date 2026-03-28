<script lang="ts">
  import { dagStatus } from "../lib/stores";
  import FinalityLevels from "./FinalityLevels.svelte";
  import ValidatorList from "./ValidatorList.svelte";
  import GpuMetrics from "./GpuMetrics.svelte";
</script>

<div class="dashboard">
  <div class="left-col">
    <FinalityLevels />
    <div class="adaptive">
      <h3>Adaptive Parameters</h3>
      <div class="params">
        <div class="param">
          <span class="param-label">Round Interval</span>
          <span class="param-value">{$dagStatus?.round_interval_ms ?? "--"}ms</span>
        </div>
        <div class="param">
          <span class="param-label">Max Events/Vertex</span>
          <span class="param-value">{$dagStatus?.max_events_per_vertex ?? "--"}</span>
        </div>
        <div class="param">
          <span class="param-label">Pending Events</span>
          <span class="param-value">{$dagStatus?.pending_events ?? "--"}</span>
        </div>
        <div class="param">
          <span class="param-label">Utilization</span>
          <span class="param-value">
            {$dagStatus
              ? Math.round(($dagStatus.pending_events / Math.max($dagStatus.max_events_per_vertex, 1)) * 100)
              : "--"}%
          </span>
        </div>
        {#if $dagStatus?.adaptive}
          <div class="param">
            <span class="param-label">Adaptive Mode</span>
            <span class="param-value" style="color: var(--green)">{$dagStatus.adaptive.enabled ? "ON" : "OFF"}</span>
          </div>
          <div class="param">
            <span class="param-label">Empty Rounds</span>
            <span class="param-value">{$dagStatus.adaptive.consecutive_empty_rounds}</span>
          </div>
        {/if}
      </div>
    </div>
  </div>
  <div class="right-col">
    <ValidatorList />
    <GpuMetrics />
  </div>
</div>

<style>
  .dashboard {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
  }

  .left-col, .right-col {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .adaptive {
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

  .params {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
  }

  .param {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 8px;
    background: var(--surface-2);
    border-radius: 6px;
  }

  .param-label {
    font-size: 10px;
    text-transform: uppercase;
    color: var(--text-dim);
  }

  .param-value {
    font-size: 13px;
    font-weight: 600;
  }
</style>
