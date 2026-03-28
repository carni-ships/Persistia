<script lang="ts">
  import { onMount } from "svelte";
  import { loadConfig, checkGpuInfo, getProverStatus, getGeneratorStatus, onProverStdout, onProverStderr, onGeneratorStdout, onGeneratorStderr, onProverStatus, onGeneratorStatus } from "./lib/ipc";
  import { config, gpuInfo, proverStatus, generatorStatus, proverLogs, generatorLogs, startPolling, activeTab } from "./lib/stores";
  import Header from "./components/Header.svelte";
  import StatsBar from "./components/StatsBar.svelte";
  import TabBar from "./components/TabBar.svelte";
  import DashboardTab from "./components/DashboardTab.svelte";
  import ProverTab from "./components/ProverTab.svelte";
  import GeneratorTab from "./components/GeneratorTab.svelte";
  import ProofsTab from "./components/ProofsTab.svelte";

  onMount(async () => {
    // Load persisted config
    try {
      const cfg = await loadConfig();
      config.set(cfg);
      startPolling(cfg);
    } catch {
      startPolling($config);
    }

    // Load GPU info
    try {
      const info = await checkGpuInfo();
      gpuInfo.set(info);
    } catch {}

    // Sync process statuses
    try {
      proverStatus.set(await getProverStatus());
      generatorStatus.set(await getGeneratorStatus());
    } catch {}

    // Subscribe to log streams
    onProverStdout((line) => proverLogs.push(line));
    onProverStderr((line) => proverLogs.push(`[err] ${line}`));
    onGeneratorStdout((line) => generatorLogs.push(line));
    onGeneratorStderr((line) => generatorLogs.push(`[err] ${line}`));
    onProverStatus((s) => proverStatus.set(s));
    onGeneratorStatus((s) => generatorStatus.set(s));
  });

  // Restart polling when config changes
  config.subscribe((cfg) => {
    startPolling(cfg);
  });
</script>

<div class="app">
  <Header />
  <StatsBar />
  <TabBar />
  <main class="content">
    {#if $activeTab === "dashboard"}
      <DashboardTab />
    {:else if $activeTab === "prover"}
      <ProverTab />
    {:else if $activeTab === "generator"}
      <GeneratorTab />
    {:else if $activeTab === "proofs"}
      <ProofsTab />
    {/if}
  </main>
</div>

<style>
  :global(:root) {
    --bg: #0a0a0f;
    --surface: #12121a;
    --surface-2: #1a1a25;
    --border: #2a2a3a;
    --text: #e0e0e8;
    --text-dim: #7a7a8e;
    --accent: #6c5ce7;
    --accent-dim: rgba(108,92,231,0.15);
    --green: #00d2a0;
    --green-dim: rgba(0,210,160,0.15);
    --yellow: #ffd166;
    --yellow-dim: rgba(255,209,102,0.15);
    --red: #ff6b6b;
    --red-dim: rgba(255,107,107,0.15);
    --blue: #48bfe3;
    --blue-dim: rgba(72,191,227,0.15);
  }

  :global(*) { margin: 0; padding: 0; box-sizing: border-box; }

  :global(body) {
    background: var(--bg);
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    min-height: 100vh;
    overflow: hidden;
  }

  :global(input, select, button) {
    font-family: inherit;
    font-size: inherit;
  }

  .app {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }

  .content {
    flex: 1;
    overflow-y: auto;
    padding: 16px 24px;
  }
</style>
