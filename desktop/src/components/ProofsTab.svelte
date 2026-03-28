<script lang="ts">
  import { proofChain, zkStatus } from "../lib/stores";
  import { shortKey, timeAgo, formatNumber } from "../lib/format";

  let expanded = $state<number | null>(null);

  function toggle(blockNum: number) {
    expanded = expanded === blockNum ? null : blockNum;
  }
</script>

<div class="proofs-tab">
  <div class="summary">
    <div class="summary-card">
      <span class="summary-label">Total Proofs</span>
      <span class="summary-value">{formatNumber($zkStatus?.total_proofs ?? 0)}</span>
    </div>
    <div class="summary-card">
      <span class="summary-label">Latest Proven</span>
      <span class="summary-value">{formatNumber($zkStatus?.latest_proven_block ?? 0)}</span>
    </div>
    <div class="summary-card">
      <span class="summary-label">Proof Gap</span>
      <span class="summary-value" class:warn={($zkStatus?.proof_gap ?? 0) > 10}>
        {formatNumber($zkStatus?.proof_gap ?? 0)}
      </span>
    </div>
    <div class="summary-card">
      <span class="summary-label">Chain Length</span>
      <span class="summary-value">{formatNumber($zkStatus?.max_chain_length ?? 0)}</span>
    </div>
  </div>

  {#if $zkStatus?.active_lineage}
    <div class="lineage">
      <span class="lineage-label">Active lineage:</span>
      chain={$zkStatus.active_lineage.chain_length},
      last={$zkStatus.active_lineage.last_block},
      gap={$zkStatus.active_lineage.gap},
      genesis={shortKey($zkStatus.active_lineage.genesis_root)}
    </div>
  {/if}

  <div class="table-container">
    <table>
      <thead>
        <tr>
          <th>Block</th>
          <th>Proven Blocks</th>
          <th>State Root</th>
          <th>Type</th>
          <th>Submitted</th>
        </tr>
      </thead>
      <tbody>
        {#each $proofChain as proof}
          <tr class="proof-row" onclick={() => toggle(proof.block_number)}>
            <td class="block-num">{formatNumber(proof.block_number)}</td>
            <td>{proof.proven_blocks}</td>
            <td class="mono">{shortKey(proof.state_root)}</td>
            <td>
              <span class="badge">{proof.proof_type || "ultrahonk"}</span>
            </td>
            <td class="dim">{proof.submitted_at ? timeAgo(proof.submitted_at) : "--"}</td>
          </tr>
          {#if expanded === proof.block_number}
            <tr class="detail-row">
              <td colspan="5">
                <div class="detail">
                  <div><strong>State Root:</strong> {proof.state_root}</div>
                  <div><strong>Genesis Root:</strong> {proof.genesis_root}</div>
                  {#if proof.prover}
                    <div><strong>Prover:</strong> {proof.prover}</div>
                  {/if}
                </div>
              </td>
            </tr>
          {/if}
        {:else}
          <tr>
            <td colspan="5" class="empty">No proofs in chain yet</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>

<style>
  .proofs-tab {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .summary {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
  }

  .summary-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .summary-label {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-dim);
  }

  .summary-value {
    font-size: 22px;
    font-weight: 700;
    color: var(--accent);
  }

  .warn { color: var(--yellow) !important; }

  .lineage {
    font-size: 11px;
    color: var(--text-dim);
    background: var(--surface);
    padding: 8px 14px;
    border-radius: 6px;
    border: 1px solid var(--border);
  }

  .lineage-label {
    color: var(--accent);
    font-weight: 600;
  }

  .table-container {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th {
    text-align: left;
    padding: 10px 14px;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-dim);
    border-bottom: 1px solid var(--border);
    background: var(--surface-2);
  }

  td {
    padding: 8px 14px;
    font-size: 12px;
    border-bottom: 1px solid var(--border);
  }

  .proof-row { cursor: pointer; }
  .proof-row:hover { background: var(--surface-2); }

  .block-num { font-weight: 600; color: var(--accent); }
  .mono { font-family: inherit; }
  .dim { color: var(--text-dim); }

  .badge {
    font-size: 10px;
    padding: 2px 6px;
    border-radius: 3px;
    background: var(--accent-dim);
    color: var(--accent);
  }

  .detail-row td { padding: 0; }

  .detail {
    padding: 12px 14px;
    background: var(--surface-2);
    font-size: 11px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .detail strong { color: var(--text-dim); }

  .empty {
    text-align: center;
    color: var(--text-dim);
    padding: 30px !important;
    font-style: italic;
  }
</style>
