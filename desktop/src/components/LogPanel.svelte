<script lang="ts">
  import { tick } from "svelte";

  interface Props {
    lines: string[];
    onClear?: () => void;
  }

  let { lines, onClear }: Props = $props();

  let container: HTMLDivElement;
  let autoScroll = $state(true);

  function handleScroll() {
    if (!container) return;
    const atBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 40;
    autoScroll = atBottom;
  }

  $effect(() => {
    if (lines.length && autoScroll && container) {
      tick().then(() => {
        container.scrollTop = container.scrollHeight;
      });
    }
  });
</script>

<div class="log-panel">
  <div class="log-header">
    <span class="log-count">{lines.length} lines</span>
    <div class="log-actions">
      {#if !autoScroll}
        <button class="log-btn" onclick={() => { autoScroll = true; container.scrollTop = container.scrollHeight; }}>Resume scroll</button>
      {/if}
      {#if onClear}
        <button class="log-btn" onclick={onClear}>Clear</button>
      {/if}
    </div>
  </div>
  <div class="log-body" bind:this={container} onscroll={handleScroll}>
    {#each lines as line, i}
      <div class="log-line" class:error={line.startsWith("[err]")}>{line}</div>
    {/each}
    {#if lines.length === 0}
      <div class="log-empty">No output yet</div>
    {/if}
  </div>
</div>

<style>
  .log-panel {
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 200px;
  }

  .log-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 6px 12px;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    font-size: 11px;
  }

  .log-count { color: var(--text-dim); }

  .log-actions { display: flex; gap: 8px; }

  .log-btn {
    background: var(--accent-dim);
    color: var(--accent);
    border: none;
    padding: 2px 8px;
    border-radius: 3px;
    cursor: pointer;
    font-size: 10px;
  }

  .log-btn:hover { background: var(--accent); color: #fff; }

  .log-body {
    flex: 1;
    overflow-y: auto;
    padding: 8px 12px;
    background: var(--bg);
    font-size: 11px;
    line-height: 1.6;
  }

  .log-line {
    white-space: pre-wrap;
    word-break: break-all;
  }

  .error { color: var(--red); }

  .log-empty {
    color: var(--text-dim);
    font-style: italic;
    padding: 20px;
    text-align: center;
  }
</style>
