<script lang="ts">
  import { dagStatus, zkStatus, anchorStatus } from "../lib/stores";
  import { formatNumber } from "../lib/format";

  let levels = $derived.by(() => {
    const dag = $dagStatus;
    const zk = $zkStatus;
    const anchor = $anchorStatus;

    return [
      {
        label: "L0 Optimistic",
        value: dag?.pending_events ?? 0,
        desc: "pending events",
        color: "var(--text-dim)",
      },
      {
        label: "L1 DAG Inclusion",
        value: dag?.current_round ?? 0,
        desc: "current round",
        color: "var(--blue)",
      },
      {
        label: "L2 BFT Commit",
        value: dag?.last_committed_round ?? 0,
        desc: "committed round",
        color: "var(--green)",
      },
      {
        label: "L3 ZK Proven",
        value: zk?.latest_proven_block ?? 0,
        desc: `gap: ${zk?.proof_gap ?? "?"}`,
        color: "var(--accent)",
      },
      {
        label: "L4 DA Anchored",
        value: anchor?.bundle?.last_committed_round ?? 0,
        desc: anchor?.bundle?.status ?? "unknown",
        color: "var(--yellow)",
      },
    ];
  });

  let maxVal = $derived(Math.max(...levels.map((l) => l.value), 1));
</script>

<div class="finality">
  <h3>Finality Levels</h3>
  <div class="levels">
    {#each levels as level}
      <div class="level">
        <div class="level-header">
          <span class="level-label" style="color: {level.color}">{level.label}</span>
          <span class="level-value">{formatNumber(level.value)}</span>
        </div>
        <div class="bar-bg">
          <div
            class="bar-fill"
            style="width: {(level.value / maxVal) * 100}%; background: {level.color}"
          ></div>
        </div>
        <span class="level-desc">{level.desc}</span>
      </div>
    {/each}
  </div>
</div>

<style>
  .finality {
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
    margin-bottom: 14px;
  }

  .levels { display: flex; flex-direction: column; gap: 10px; }

  .level-header {
    display: flex;
    justify-content: space-between;
    font-size: 11px;
    margin-bottom: 4px;
  }

  .level-label { font-weight: 600; }
  .level-value { color: var(--text); font-weight: 500; }

  .bar-bg {
    height: 6px;
    background: var(--surface-2);
    border-radius: 3px;
    overflow: hidden;
  }

  .bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.5s ease;
  }

  .level-desc {
    font-size: 10px;
    color: var(--text-dim);
    margin-top: 2px;
  }
</style>
