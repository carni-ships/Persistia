import { writable } from "svelte/store";
import type {
  DagStatus,
  ZkStatus,
  Peer,
  ProofEntry,
  AnchorStatus,
  AppConfig,
  ProcessStatus,
  GpuInfo,
} from "./types";

// Chain state
export const dagStatus = writable<DagStatus | null>(null);
export const zkStatus = writable<ZkStatus | null>(null);
export const peers = writable<Peer[]>([]);
export const proofChain = writable<ProofEntry[]>([]);
export const anchorStatus = writable<AnchorStatus | null>(null);

// App state
export const config = writable<AppConfig>({
  node_url: "https://persistia.carnation-903.workers.dev",
  shard: "node-1",
  prover_mode: "watch",
  prover_interval: 10,
  prover_workers: 6,
  prover_native: true,
  prover_recursive: false,
  generator_agents: 3,
  generator_interval: 500,
});

export const proverStatus = writable<ProcessStatus>({
  running: false,
  pid: null,
  mode: null,
  uptime_secs: null,
});

export const generatorStatus = writable<ProcessStatus>({
  running: false,
  pid: null,
  mode: null,
  uptime_secs: null,
});

export const gpuInfo = writable<GpuInfo | null>(null);
export const connected = writable(false);
export const activeTab = writable("dashboard");

// Log buffers
const MAX_LINES = 5000;

function createLogStore() {
  const { subscribe, update } = writable<string[]>([]);
  return {
    subscribe,
    push(line: string) {
      update((lines) => {
        lines.push(line);
        if (lines.length > MAX_LINES) lines.splice(0, lines.length - MAX_LINES);
        return lines;
      });
    },
    clear() {
      update(() => []);
    },
  };
}

export const proverLogs = createLogStore();
export const generatorLogs = createLogStore();

// ─── WebSocket subscription (SpacetimeDB-style push, replaces polling) ──────

let ws: WebSocket | null = null;
let wsReconnectTimer: ReturnType<typeof setTimeout> | null = null;
let pollInterval: ReturnType<typeof setInterval> | null = null;

function getBaseUrl(cfg: AppConfig): string {
  const url = cfg.node_url.replace(/\/$/, "");
  return cfg.shard ? `${url}?shard=${cfg.shard}` : url;
}

function getWsUrl(cfg: AppConfig): string {
  const base = cfg.node_url.replace(/\/$/, "").replace(/^http/, "ws");
  return cfg.shard ? `${base}/ws?shard=${cfg.shard}` : `${base}/ws`;
}

function appendShard(baseWithShard: string, path: string): string {
  const hasQuery = baseWithShard.includes("?");
  const pathHasQuery = path.includes("?");
  if (hasQuery && pathHasQuery) {
    return baseWithShard.split("?")[0] + path + "&" + baseWithShard.split("?")[1];
  }
  if (hasQuery) {
    return baseWithShard.split("?")[0] + path + "?" + baseWithShard.split("?")[1];
  }
  return baseWithShard + path;
}

async function fetchJson<T>(baseUrl: string, path: string): Promise<T | null> {
  try {
    const url = appendShard(baseUrl, path);
    const res = await fetch(url);
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

/** Handle incoming WebSocket messages and update stores */
function handleWsMessage(data: string) {
  try {
    const msg = JSON.parse(data);
    switch (msg.type) {
      // Push-based status updates (subscribed channels)
      case "status.update":
        dagStatus.set(msg as DagStatus);
        connected.set(true);
        break;
      case "peers.update":
        if (msg.peers) peers.set(msg.peers);
        break;
      // Real-time events
      case "pending":
      case "finalized_batch":
        // Trigger a single poll to refresh ZK + proof chain status
        // (these are derived from multiple tables, not worth duplicating logic)
        break;
      case "zk.proof_submitted":
        // Proof chain updated — refresh
        break;
    }
  } catch {
    // Ignore parse errors
  }
}

function connectWebSocket(cfg: AppConfig) {
  if (ws) {
    try { ws.close(); } catch {}
    ws = null;
  }

  try {
    const url = getWsUrl(cfg);
    ws = new WebSocket(url);

    ws.onopen = () => {
      connected.set(true);
      // Subscribe to push channels for status, peers, dag updates
      ws!.send(JSON.stringify({
        type: "subscribe",
        channels: ["status", "peers", "dag", "zk"],
      }));
      // Request initial status
      ws!.send(JSON.stringify({ type: "status" }));
    };

    ws.onmessage = (ev) => handleWsMessage(ev.data as string);

    ws.onclose = () => {
      connected.set(false);
      ws = null;
      // Reconnect after 3s
      wsReconnectTimer = setTimeout(() => connectWebSocket(cfg), 3000);
    };

    ws.onerror = () => {
      // onclose will fire after this, triggering reconnect
    };
  } catch {
    connected.set(false);
    wsReconnectTimer = setTimeout(() => connectWebSocket(cfg), 3000);
  }
}

// Slow polling as fallback for data not pushed via WS (ZK status, proof chain, anchors)
async function pollSlow(cfg: AppConfig) {
  const base = getBaseUrl(cfg);
  const [zk, anchor, chain] = await Promise.all([
    fetchJson<ZkStatus>(base, "/proof/zk/status"),
    fetchJson<AnchorStatus>(base, "/anchor/latest"),
    fetchJson<ProofEntry[]>(base, "/proof/zk/chain"),
  ]);
  if (zk) zkStatus.set(zk);
  if (anchor) anchorStatus.set(anchor);
  if (chain) proofChain.set(chain);
}

// Full poll fallback (used when WS is not connected)
async function pollFull(cfg: AppConfig) {
  const base = getBaseUrl(cfg);
  const [dag, zk, peerList, anchor, chain] = await Promise.all([
    fetchJson<DagStatus>(base, "/dag/status"),
    fetchJson<ZkStatus>(base, "/proof/zk/status"),
    fetchJson<{ peers: Peer[] }>(base, "/admin/peers"),
    fetchJson<AnchorStatus>(base, "/anchor/latest"),
    fetchJson<ProofEntry[]>(base, "/proof/zk/chain"),
  ]);
  connected.set(dag !== null);
  if (dag) dagStatus.set(dag);
  if (zk) zkStatus.set(zk);
  if (peerList?.peers) peers.set(peerList.peers);
  if (anchor) anchorStatus.set(anchor);
  if (chain) proofChain.set(chain);
}

export function startPolling(cfg: AppConfig) {
  stopPolling();

  // Primary: WebSocket push for status + peers (instant updates)
  connectWebSocket(cfg);

  // Secondary: slow poll for ZK/proof/anchor data every 10s (not pushed via WS)
  pollSlow(cfg);
  pollInterval = setInterval(() => pollSlow(cfg), 10_000);
}

export function stopPolling() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
  if (wsReconnectTimer) {
    clearTimeout(wsReconnectTimer);
    wsReconnectTimer = null;
  }
  if (ws) {
    try { ws.close(); } catch {}
    ws = null;
  }
}
