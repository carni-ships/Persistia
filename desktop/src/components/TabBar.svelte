<script lang="ts">
  import { activeTab, proverStatus, generatorStatus } from "../lib/stores";

  const tabs = [
    { id: "dashboard", label: "Dashboard" },
    { id: "prover", label: "Prover" },
    { id: "generator", label: "Generator" },
    { id: "proofs", label: "Proofs" },
  ];
</script>

<nav class="tab-bar">
  {#each tabs as tab}
    <button
      class="tab"
      class:active={$activeTab === tab.id}
      onclick={() => activeTab.set(tab.id)}
    >
      {tab.label}
      {#if tab.id === "prover" && $proverStatus.running}
        <span class="running-dot"></span>
      {/if}
      {#if tab.id === "generator" && $generatorStatus.running}
        <span class="running-dot"></span>
      {/if}
    </button>
  {/each}
</nav>

<style>
  .tab-bar {
    display: flex;
    gap: 0;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    padding: 0 24px;
  }

  .tab {
    padding: 10px 20px;
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--text-dim);
    cursor: pointer;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 6px;
    transition: all 0.15s;
  }

  .tab:hover {
    color: var(--text);
  }

  .tab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }

  .running-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 4px var(--green);
    animation: pulse 2s infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }
</style>
