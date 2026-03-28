<script lang="ts">
  import { peers } from "../lib/stores";
  import { timeAgo, shortKey, nodeColor } from "../lib/format";
</script>

<div class="validators">
  <h3>Validators ({$peers.length})</h3>
  {#if $peers.length === 0}
    <div class="empty">No peers connected</div>
  {:else}
    <div class="peer-list">
      {#each $peers as peer}
        <div class="peer">
          <div class="peer-avatar" style="background: {nodeColor(peer.id || peer.pubkey)}"></div>
          <div class="peer-info">
            <div class="peer-id">{peer.id || shortKey(peer.pubkey)}</div>
            <div class="peer-meta">
              Round {peer.last_vertex_round} &middot; {peer.last_seen ? timeAgo(peer.last_seen) : "unknown"}
            </div>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .validators {
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

  .empty {
    color: var(--text-dim);
    font-style: italic;
    font-size: 11px;
  }

  .peer-list { display: flex; flex-direction: column; gap: 8px; }

  .peer {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px;
    background: var(--surface-2);
    border-radius: 6px;
  }

  .peer-avatar {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .peer-info { min-width: 0; }

  .peer-id {
    font-weight: 600;
    font-size: 12px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .peer-meta {
    font-size: 10px;
    color: var(--text-dim);
  }
</style>
