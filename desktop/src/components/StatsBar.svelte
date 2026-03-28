<script lang="ts">
  import { dagStatus, zkStatus, peers } from "../lib/stores";
  import { formatNumber } from "../lib/format";
</script>

<div class="stats-bar">
  <div class="stat">
    <span class="stat-label">Round</span>
    <span class="stat-value">{$dagStatus ? formatNumber($dagStatus.current_round) : "--"}</span>
  </div>
  <div class="stat">
    <span class="stat-label">Finalized</span>
    <span class="stat-value green">{$dagStatus ? formatNumber($dagStatus.last_committed_round) : "--"}</span>
  </div>
  <div class="stat">
    <span class="stat-label">Events</span>
    <span class="stat-value">{$dagStatus ? formatNumber($dagStatus.finalized_seq) : "--"}</span>
  </div>
  <div class="stat">
    <span class="stat-label">Validators</span>
    <span class="stat-value blue">{$peers.length || ($dagStatus?.active_nodes ?? "--")}</span>
  </div>
  <div class="stat">
    <span class="stat-label">ZK Proofs</span>
    <span class="stat-value accent">{$zkStatus ? formatNumber($zkStatus.total_proofs) : "--"}</span>
  </div>
</div>

<style>
  .stats-bar {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 1px;
    background: var(--border);
    border-bottom: 1px solid var(--border);
  }

  .stat {
    background: var(--surface);
    padding: 12px 20px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
  }

  .stat-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-dim);
  }

  .stat-value {
    font-size: 20px;
    font-weight: 600;
  }

  .green { color: var(--green); }
  .blue { color: var(--blue); }
  .accent { color: var(--accent); }
</style>
