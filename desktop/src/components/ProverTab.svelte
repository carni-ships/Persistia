<script lang="ts">
  import { config, proverStatus, proverLogs } from "../lib/stores";
  import { startProver, stopProver, saveConfig } from "../lib/ipc";
  import { uptimeStr } from "../lib/format";
  import LogPanel from "./LogPanel.svelte";
  import GpuMetrics from "./GpuMetrics.svelte";

  let error = $state("");

  async function handleStart() {
    try {
      error = "";
      await saveConfig($config);
      await startProver();
    } catch (e: any) {
      error = e.toString();
    }
  }

  async function handleStop() {
    try {
      error = "";
      await stopProver();
    } catch (e: any) {
      error = e.toString();
    }
  }
</script>

<div class="prover-tab">
  <div class="config-panel">
    <h3>Prover Configuration</h3>
    <div class="form-grid">
      <label>
        <span>Node URL</span>
        <input type="text" bind:value={$config.node_url} />
      </label>
      <label>
        <span>Shard</span>
        <input type="text" bind:value={$config.shard} />
      </label>
      <label>
        <span>Mode</span>
        <select bind:value={$config.prover_mode}>
          <option value="watch">Sequential</option>
          <option value="watch-pipelined">Pipelined</option>
          <option value="watch-parallel">Parallel (msgpack)</option>
          <option value="watch-incremental">Incremental (SMT)</option>
        </select>
      </label>
      <label>
        <span>Interval (sec)</span>
        <input type="number" bind:value={$config.prover_interval} min="1" max="120" />
      </label>
      {#if $config.prover_mode === "watch-parallel"}
        <label>
          <span>Workers</span>
          <input type="number" bind:value={$config.prover_workers} min="1" max="16" />
        </label>
      {/if}
      <div class="checkboxes">
        <label class="checkbox">
          <input type="checkbox" bind:checked={$config.prover_native} />
          <span>Native bb</span>
        </label>
        <label class="checkbox">
          <input type="checkbox" bind:checked={$config.prover_recursive} />
          <span>Recursive IVC</span>
        </label>
      </div>
    </div>

    <div class="controls">
      {#if $proverStatus.running}
        <button class="btn btn-stop" onclick={handleStop}>Stop Prover</button>
        <span class="status-text">
          Running ({$proverStatus.mode}) &middot; PID {$proverStatus.pid} &middot; {uptimeStr($proverStatus.uptime_secs ?? 0)}
        </span>
      {:else}
        <button class="btn btn-start" onclick={handleStart}>Start Prover</button>
      {/if}
      {#if error}
        <span class="error-text">{error}</span>
      {/if}
    </div>
  </div>

  <div class="bottom-row">
    <div class="log-container">
      <LogPanel lines={$proverLogs} onClear={() => proverLogs.clear()} />
    </div>
    <div class="metrics-container">
      <GpuMetrics />
    </div>
  </div>
</div>

<style>
  .prover-tab {
    display: flex;
    flex-direction: column;
    gap: 16px;
    height: calc(100vh - 180px);
  }

  .config-panel {
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

  .form-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-bottom: 14px;
  }

  label {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  label span {
    font-size: 10px;
    text-transform: uppercase;
    color: var(--text-dim);
  }

  input[type="text"],
  input[type="number"],
  select {
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 6px 10px;
    color: var(--text);
    outline: none;
  }

  input:focus, select:focus {
    border-color: var(--accent);
  }

  .checkboxes {
    display: flex;
    gap: 16px;
    align-items: end;
    padding-bottom: 4px;
  }

  .checkbox {
    flex-direction: row;
    align-items: center;
    gap: 6px;
    cursor: pointer;
  }

  .checkbox span {
    text-transform: none;
    font-size: 12px;
    color: var(--text);
  }

  .controls {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .btn {
    padding: 8px 20px;
    border: none;
    border-radius: 6px;
    font-weight: 600;
    cursor: pointer;
    font-size: 12px;
  }

  .btn-start {
    background: var(--green);
    color: #000;
  }

  .btn-start:hover { filter: brightness(1.1); }

  .btn-stop {
    background: var(--red);
    color: #fff;
  }

  .btn-stop:hover { filter: brightness(1.1); }

  .status-text {
    font-size: 11px;
    color: var(--green);
  }

  .error-text {
    font-size: 11px;
    color: var(--red);
  }

  .bottom-row {
    display: grid;
    grid-template-columns: 1fr 300px;
    gap: 16px;
    flex: 1;
    min-height: 0;
  }

  .log-container {
    min-height: 0;
    display: flex;
  }

  .metrics-container {
    align-self: start;
  }
</style>
