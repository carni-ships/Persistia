<script lang="ts">
  import { connected, config } from "../lib/stores";
</script>

<header>
  <div class="logo">
    <span class="logo-text">PERSISTIA</span>
    <span class="version">v0.1.0</span>
  </div>
  <div class="status">
    <span class="node-url">{$config.node_url}</span>
    <span class="dot" class:online={$connected} class:offline={!$connected}></span>
    <span class="shard">{$config.shard}</span>
  </div>
</header>

<style>
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 24px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    -webkit-app-region: drag;
  }

  .logo {
    display: flex;
    align-items: baseline;
    gap: 8px;
  }

  .logo-text {
    font-size: 16px;
    font-weight: 700;
    letter-spacing: 2px;
    color: var(--accent);
  }

  .version {
    font-size: 10px;
    color: var(--text-dim);
  }

  .status {
    display: flex;
    align-items: center;
    gap: 10px;
    -webkit-app-region: no-drag;
  }

  .node-url {
    font-size: 11px;
    color: var(--text-dim);
  }

  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
  }

  .online {
    background: var(--green);
    box-shadow: 0 0 6px var(--green);
  }

  .offline {
    background: var(--red);
    box-shadow: 0 0 6px var(--red);
  }

  .shard {
    font-size: 11px;
    color: var(--accent);
    background: var(--accent-dim);
    padding: 2px 8px;
    border-radius: 4px;
  }
</style>
