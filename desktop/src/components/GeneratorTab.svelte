<script lang="ts">
  import { config, generatorStatus, generatorLogs } from "../lib/stores";
  import { startGenerator, stopGenerator, saveConfig } from "../lib/ipc";
  import { uptimeStr } from "../lib/format";
  import LogPanel from "./LogPanel.svelte";

  let error = $state("");

  async function handleStart() {
    try {
      error = "";
      await saveConfig($config);
      await startGenerator();
    } catch (e: any) {
      error = e.toString();
    }
  }

  async function handleStop() {
    try {
      error = "";
      await stopGenerator();
    } catch (e: any) {
      error = e.toString();
    }
  }
</script>

<div class="generator-tab">
  <div class="config-panel">
    <h3>Event Generator Configuration</h3>
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
        <span>Agents</span>
        <input type="number" bind:value={$config.generator_agents} min="1" max="10" />
      </label>
      <label>
        <span>Interval (ms)</span>
        <input type="number" bind:value={$config.generator_interval} min="100" max="10000" step="100" />
      </label>
    </div>

    <div class="controls">
      {#if $generatorStatus.running}
        <button class="btn btn-stop" onclick={handleStop}>Stop Generator</button>
        <span class="status-text">
          Running &middot; PID {$generatorStatus.pid} &middot; {uptimeStr($generatorStatus.uptime_secs ?? 0)}
        </span>
      {:else}
        <button class="btn btn-start" onclick={handleStart}>Start Generator</button>
      {/if}
      {#if error}
        <span class="error-text">{error}</span>
      {/if}
    </div>

    <div class="desc">
      The event generator creates procedural villages, roads, towers, and landmarks on the Persistia world.
      Each agent builds structures independently with Ed25519-signed events.
    </div>
  </div>

  <div class="log-container">
    <LogPanel lines={$generatorLogs} onClear={() => generatorLogs.clear()} />
  </div>
</div>

<style>
  .generator-tab {
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
  input[type="number"] {
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 6px 10px;
    color: var(--text);
    outline: none;
  }

  input:focus { border-color: var(--accent); }

  .controls {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
  }

  .btn {
    padding: 8px 20px;
    border: none;
    border-radius: 6px;
    font-weight: 600;
    cursor: pointer;
    font-size: 12px;
  }

  .btn-start { background: var(--green); color: #000; }
  .btn-start:hover { filter: brightness(1.1); }
  .btn-stop { background: var(--red); color: #fff; }
  .btn-stop:hover { filter: brightness(1.1); }

  .status-text { font-size: 11px; color: var(--green); }
  .error-text { font-size: 11px; color: var(--red); }

  .desc {
    font-size: 11px;
    color: var(--text-dim);
    line-height: 1.5;
  }

  .log-container {
    flex: 1;
    min-height: 0;
    display: flex;
  }
</style>
